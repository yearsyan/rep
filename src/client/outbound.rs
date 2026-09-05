use anyhow::{Result, bail};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};
use tracing::warn;

use crate::config::RetryConfig;

/// 连接目标。每次尝试都重新走 DNS 解析，目标地址变化可被感知；
/// 按客户端 IPv6 探测结果调整地址族尝试顺序，失败按间隔退避重试。
pub async fn connect_target(
    host: &str,
    port: u16,
    cfg: &RetryConfig,
    ipv6_ok: bool,
) -> Result<TcpStream> {
    let timeout = Duration::from_secs(cfg.connect_timeout_secs.max(1));
    let attempts = cfg.target_attempts.max(1);
    let mut last = String::new();
    for attempt in 1..=attempts {
        match tokio::time::timeout(timeout, connect_tcp((host, port), ipv6_ok)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = format!("{e:#}"),
            Err(_) => last = format!("connect timeout after {}s", timeout.as_secs()),
        }
        warn!("connect {host}:{port} failed (attempt {attempt}/{attempts}): {last}");
        if attempt < attempts {
            tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
        }
    }
    bail!("connect {host}:{port} failed after {attempts} attempts: {last}")
}

/// 目标连接和隧道服务端连接共用 DNS 解析与错峰 TCP 连接；期限由调用方统一控制。
pub(super) async fn connect_tcp(addr: impl ToSocketAddrs, ipv6_ok: bool) -> Result<TcpStream> {
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| anyhow::anyhow!("dns lookup: {e}"))?
        .collect();
    if addrs.is_empty() {
        bail!("no address resolved");
    }
    // 探测不到 IPv6 时仅把 IPv4 放在前面；所有解析结果仍会尝试，不过滤目标。
    prioritize_addresses(&mut addrs, ipv6_ok);
    connect_addresses(addrs, TcpStream::connect).await
}

/// 每隔 250ms 发起下一地址；全部在途连接失败时立即推进。
/// 首个地址黑洞不会耗尽整轮预算，外层超时仍包含 DNS 和所有 TCP 尝试。
async fn connect_addresses<T, F, Fut>(addrs: Vec<SocketAddr>, connect: F) -> Result<T>
where
    T: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<T>> + Send + 'static,
{
    let mut addrs = addrs.into_iter().peekable();
    let mut pending = JoinSet::new();
    let mut last = anyhow::anyhow!("no address tried");
    let delay = Duration::from_millis(250);
    let mut next_attempt = Instant::now();
    loop {
        if pending.is_empty() {
            let Some(addr) = addrs.next() else {
                return Err(last);
            };
            pending.spawn(connect(addr));
            next_attempt = Instant::now() + delay;
        }
        tokio::select! {
            biased;
            result = pending.join_next() => match result {
                Some(Ok(Ok(stream))) => {
                    pending.shutdown().await;
                    return Ok(stream);
                }
                Some(Ok(Err(e))) => last = e.into(),
                Some(Err(e)) => last = e.into(),
                None => unreachable!("at least one connection is pending"),
            },
            _ = sleep_until(next_attempt), if addrs.peek().is_some() => {
                pending.spawn(connect(addrs.next().unwrap()));
                next_attempt = Instant::now() + delay;
            }
        }
    }
}

fn prioritize_addresses(addrs: &mut [SocketAddr], ipv6_ok: bool) {
    if !ipv6_ok {
        addrs.sort_by_key(SocketAddr::is_ipv6);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_is_preferred_without_dropping_any_target() {
        let original: Vec<SocketAddr> = vec![
            "[2606:4700:4700::1111]:443".parse().unwrap(),
            "[::1]:8080".parse().unwrap(),
            "127.0.0.1:8080".parse().unwrap(),
        ];
        let mut ordered = original.clone();

        prioritize_addresses(&mut ordered, false);

        assert!(ordered[0].is_ipv4());
        assert_eq!(ordered.len(), original.len());
        assert!(original.iter().all(|addr| ordered.contains(addr)));
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct OnDrop(Arc<AtomicUsize>);
    impl Drop for OnDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn tcp_connector_reaches_next_address_while_first_accept_queue_is_full() {
        use tokio::net::{TcpListener, TcpSocket};
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let first = socket.listen(1).unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();
        let mut occupied = Vec::new();
        let mut blocked = false;
        for _ in 0..32 {
            match tokio::time::timeout(Duration::from_millis(100), TcpStream::connect(first_addr))
                .await
            {
                Ok(result) => occupied.push(result.unwrap()),
                Err(_) => {
                    blocked = true;
                    break;
                }
            }
        }
        assert!(blocked, "failed to fill local accept queue");
        let addresses = [first_addr, second_addr];
        let stream =
            tokio::time::timeout(Duration::from_secs(2), connect_tcp(&addresses[..], true))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), second_addr);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_first_address_falls_back_and_is_cancelled() {
        let first: SocketAddr = "[::1]:80".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            connect_addresses(vec![first, second], |addr| {
                let guard = OnDrop(dropped.clone());
                async move {
                    let _guard = guard;
                    if addr == first {
                        std::future::pending::<()>().await;
                    }
                    Ok(addr)
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, second);
        assert_eq!(started.elapsed(), Duration::from_millis(250));
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn immediate_failures_do_not_delay_next_address() {
        let addrs = vec![
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];
        let started = Instant::now();
        let error = connect_addresses::<(), _, _>(addrs, |_| async {
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("refused"));
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_race_drops_all_pending_connections() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let addrs = vec![
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                connect_addresses::<(), _, _>(addrs, |_| {
                    let guard = OnDrop(dropped.clone());
                    async move {
                        let _guard = guard;
                        std::future::pending().await
                    }
                })
            )
            .await
            .is_err()
        );
        tokio::task::yield_now().await;
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }
}
