use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use h2::client;
use h2::{Ping, RecvStream, SendStream};
use http::{Method, Request, StatusCode, Uri};
use rustls::pki_types::ServerName;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::config::{ClientConfig, RetryConfig};
use crate::proto::{
    CHANNEL_HEADER, CONTROL_PATH, Frame, FrameDecoder, H2Io, format_authority, recv_chunk,
};

/// 单会话客户端侧最大并发通道数，超出立即上报失败
const MAX_CHANNELS: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn run(cfg: &ClientConfig, connector: &TlsConnector) -> Result<()> {
    run_session(cfg, connect_server(cfg, connector)).await
}

async fn run_session<S>(cfg: &ClientConfig, connect: impl Future<Output = Result<S>>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 所有任务均由会话持有；即使 run 被外部取消，JoinSet 的 Drop 也会取消子任务。
    let mut tasks = JoinSet::new();
    let mut channels = JoinSet::new();
    let mut probe_tasks = JoinSet::new();
    let ipv6_ok = Arc::new(AtomicBool::new(false));
    let probe_state = ipv6_ok.clone();
    let probe_addrs = cfg.ipv6_probe_addrs.clone();
    let probe_timeout_secs = cfg.ipv6_probe_timeout_secs;
    probe_tasks.spawn(async move {
        let ok = super::ipv6::probe(&probe_addrs, probe_timeout_secs).await;
        probe_state.store(ok, Ordering::Relaxed);
        if ok {
            info!("ipv6 connectivity: ok");
        } else {
            warn!("ipv6 connectivity: unavailable (IPv4 addresses will be tried first)");
        }
    });

    let outcome = async {
        // TCP（含 DNS）、TLS、H2、ready 和 /session 响应共用一个截止时间。
        let (send_request, ctrl_body, ctrl_stream, ping) =
            tokio::time::timeout(CONNECT_TIMEOUT, async {
                let io = connect.await?;
                let (send_request, mut conn) = client::Builder::new()
                    .initial_window_size(1 << 20)
                    .initial_connection_window_size(4 << 20)
                    .max_frame_size(1 << 20)
                    .enable_push(false)
                    .handshake(io)
                    .await?;
                let ping = conn
                    .ping_pong()
                    .ok_or_else(|| anyhow!("ping already in use"))?;
                // 连接必须持续驱动；建立失败时也由下面的统一清理回收。
                tasks.spawn(async move {
                    conn.await
                        .map_err(|e| anyhow!("h2 connection error: {e}"))?;
                    bail!("h2 connection closed by server")
                });
                let mut send = send_request.clone().ready().await?;
                let req = Request::builder()
                    .method(Method::POST)
                    .uri(CONTROL_PATH)
                    .header("x-rep-budget-ms", target_budget_ms(&cfg.retry).to_string())
                    .body(())?;
                let (resp_fut, ctrl_stream) = send.send_request(req, false)?;
                let resp = resp_fut.await?;
                if resp.status() != StatusCode::OK {
                    bail!("control stream rejected: {}", resp.status());
                }
                Ok::<_, anyhow::Error>((send_request, resp.into_body(), ctrl_stream, ping))
            })
            .await
            .map_err(|_| {
                anyhow!(
                    "control stream establishment timed out after {}s",
                    CONNECT_TIMEOUT.as_secs()
                )
            })??;
        debug!("control stream established");

        let (frame_tx, frame_rx) = mpsc::channel::<Frame>(64);
        tasks.spawn(async move {
            control_writer(frame_rx, ctrl_stream).await;
            bail!("control writer ended")
        });
        let keepalive = Duration::from_secs(cfg.retry.keepalive_secs.max(1));
        tasks.spawn(ping_loop(ping, keepalive));

        tokio::select! {
            res = tasks.join_next() => match res {
                Some(Ok(Err(e))) => Err(e),
                Some(Err(e)) => Err(anyhow!("session task panicked: {e}")),
                _ => Err(anyhow!("session task ended unexpectedly")),
            },
            res = control_reader(
                ctrl_body, frame_tx, send_request, cfg.retry.clone(), ipv6_ok, &mut channels,
            ) => res,
        }
    }
    .await;

    // 先取消所有任务，再等待退出，确保重连开始前旧通道已释放。
    channels.abort_all();
    tasks.abort_all();
    probe_tasks.abort_all();
    channels.shutdown().await;
    tasks.shutdown().await;
    probe_tasks.shutdown().await;
    outcome
}

/// 目标连接最坏耗时：attempts × 超时 + 退避间隔之和（200ms × 1..attempts-1），
/// 用 u128 中间量并钳制到 10 分钟，防 absurd 配置溢出。
fn target_budget_ms(cfg: &RetryConfig) -> u64 {
    let a = cfg.target_attempts.max(1) as u128;
    let t = cfg.connect_timeout_secs.max(1) as u128 * 1000;
    let total = a * t + 200 * a * (a - 1) / 2;
    total.min(600_000) as u64
}

async fn connect_server(
    cfg: &ClientConfig,
    connector: &TlsConnector,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    // 保留解析顺序，250ms 后尝试下一地址；DNS/TCP/TLS 仍受会话的 15s 总期限约束。
    let tcp = super::outbound::connect_tcp(cfg.server_addr.as_str(), true).await?;
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(cfg.server_name.clone())
        .map_err(|e| anyhow!("bad server_name {:?}: {e}", cfg.server_name))?;
    let tls_stream = connector.connect(name, tcp).await?;
    if tls_stream.get_ref().1.alpn_protocol() != Some(b"h2") {
        bail!("server did not negotiate h2");
    }
    info!("connected to {} (mTLS, alpn h2)", cfg.server_addr);
    Ok(tls_stream)
}

/// 周期 h2 PING；超过 2 个周期没收到 PONG 判定连接已死（半开检测）。
async fn ping_loop(mut ping: h2::PingPong, interval: Duration) -> Result<()> {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // interval 首个 tick 立即到期，跳过
    loop {
        ticker.tick().await;
        match tokio::time::timeout(interval * 2, ping.ping(Ping::opaque())).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => bail!("h2 ping failed: {e}"),
            Err(_) => bail!("keepalive timeout after {}s", interval.as_secs() * 2),
        }
    }
}

async fn control_writer(mut rx: mpsc::Receiver<Frame>, mut stream: SendStream<Bytes>) {
    while let Some(frame) = rx.recv().await {
        if stream
            .send_data(crate::proto::encode_frame(&frame), false)
            .is_err()
        {
            break;
        }
    }
    let _ = stream.send_data(Bytes::new(), true);
}

struct SessionCaps {
    retry: RetryConfig,
    ipv6_ok: Arc<AtomicBool>,
    channel_slots: Arc<Semaphore>,
}

async fn control_reader(
    mut body: RecvStream,
    frame_tx: mpsc::Sender<Frame>,
    send_request: h2::client::SendRequest<Bytes>,
    retry: RetryConfig,
    ipv6_ok: Arc<AtomicBool>,
    channels: &mut JoinSet<()>,
) -> Result<()> {
    let caps = Arc::new(SessionCaps {
        retry,
        ipv6_ok,
        channel_slots: Arc::new(Semaphore::new(MAX_CHANNELS)),
    });
    let mut dec = FrameDecoder::new();
    loop {
        let received = tokio::select! {
            chunk = recv_chunk(&mut body) => chunk,
            completed = channels.join_next(), if !channels.is_empty() => {
                if let Some(Err(e)) = completed {
                    warn!("channel task panicked: {e}");
                }
                continue;
            }
        };
        let chunk = match received {
            Some(Ok(c)) => c,
            Some(Err(e)) => bail!("control stream read: {e:#}"),
            None => bail!("control stream closed by server"),
        };
        let _ = body.flow_control().release_capacity(chunk.len());
        dec.push(&chunk);
        while let Some(frame) = dec.next_frame()? {
            if let Frame::ChannelOpen { id, host, port } = frame {
                info!("channel {id} -> {host}:{port}");
                match caps.channel_slots.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let tx = frame_tx.clone();
                        let sr = send_request.clone();
                        let caps = caps.clone();
                        channels.spawn(handle_channel(id, host, port, sr, tx, caps, permit));
                    }
                    Err(_) => {
                        warn!("channel {id} rejected: too many concurrent channels");
                        let _ = frame_tx
                            .send(Frame::ChannelResult {
                                id,
                                ok: false,
                                err: Some("client busy (too many concurrent channels)".into()),
                            })
                            .await;
                    }
                }
            }
        }
    }
}

async fn handle_channel(
    id: u64,
    host: String,
    port: u16,
    send_request: h2::client::SendRequest<Bytes>,
    frame_tx: mpsc::Sender<Frame>,
    caps: Arc<SessionCaps>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let result: Result<()> = async {
        let mut tcp = super::outbound::connect_target(
            &host,
            port,
            &caps.retry,
            caps.ipv6_ok.load(Ordering::Relaxed),
        )
        .await?;

        let uri = Uri::builder()
            .authority(format_authority(&host, port))
            .build()?;
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header(CHANNEL_HEADER, id.to_string())
            .body(())?;
        let mut send = send_request.ready().await?;
        let (resp_fut, body_tx) = send.send_request(req, false)?;

        // 先上报结果再等服务端响应；两种到达顺序服务端都能处理
        if frame_tx
            .send(Frame::ChannelResult {
                id,
                ok: true,
                err: None,
            })
            .await
            .is_err()
        {
            bail!("control channel gone");
        }

        let resp = resp_fut.await?;
        if resp.status() != StatusCode::OK {
            bail!("server rejected channel {}: {}", id, resp.status());
        }
        let mut h2io = H2Io::new(resp.into_body(), body_tx);
        let (up, down) = tokio::io::copy_bidirectional(&mut tcp, &mut h2io).await?;
        debug!("channel {id} closed ({up}B up, {down}B down)");
        Ok(())
    }
    .await;

    if let Err(e) = result {
        debug!("channel {id} failed: {e:#}");
        let _ = frame_tx
            .send(Frame::ChannelResult {
                id,
                ok: false,
                err: Some(format!("{e:#}")),
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, DuplexStream, ReadBuf};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::{Instant, timeout};

    struct TrackedIo {
        io: DuplexStream,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for TrackedIo {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
    impl AsyncRead for TrackedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for TrackedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    fn config() -> ClientConfig {
        ClientConfig {
            ipv6_probe_addrs: vec![],
            ..ClientConfig::default()
        }
    }

    struct MockSession {
        client: JoinHandle<Result<()>>,
        request: Request<RecvStream>,
        response: h2::server::SendResponse<Bytes>,
        dropped: Arc<AtomicBool>,
        server_tasks: JoinSet<()>,
    }

    async fn mock_session(connect_delay: Duration) -> MockSession {
        let (io, server_io) = tokio::io::duplex(64 * 1024);
        let dropped = Arc::new(AtomicBool::new(false));
        let io = TrackedIo {
            io,
            dropped: dropped.clone(),
        };
        let (tx, rx) = oneshot::channel();
        let mut server_tasks = JoinSet::new();
        server_tasks.spawn(async move {
            let mut server = h2::server::handshake(server_io).await.unwrap();
            let control = server.accept().await.unwrap().unwrap();
            tx.send(control).ok().unwrap();
            let mut channels = Vec::new();
            while let Some(Ok((req, mut response))) = server.accept().await {
                let body = response.send_response(Response::new(()), false).unwrap();
                channels.push((req, body));
            }
        });
        let client = tokio::spawn(async move {
            run_session(&config(), async {
                tokio::time::sleep(connect_delay).await;
                Ok(io)
            })
            .await
        });
        let (request, response) = rx.await.unwrap();
        assert_eq!(request.uri().path(), CONTROL_PATH);
        MockSession {
            client,
            request,
            response,
            dropped,
            server_tasks,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn establishment_timeout_includes_transport_connect() {
        let started = Instant::now();
        let error = run_session(&config(), std::future::pending::<Result<DuplexStream>>())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("establishment timed out"));
        assert_eq!(started.elapsed(), CONNECT_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_h2_peer_times_out_and_transport_is_dropped() {
        let (io, _peer) = tokio::io::duplex(64 * 1024);
        let dropped = Arc::new(AtomicBool::new(false));
        let io = TrackedIo {
            io,
            dropped: dropped.clone(),
        };
        let error = run_session(&config(), async { Ok(io) }).await.unwrap_err();
        assert!(error.to_string().contains("establishment timed out"));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn missing_control_response_uses_remaining_budget_and_cleans_driver() {
        let started = Instant::now();
        let session = mock_session(Duration::from_secs(10)).await;
        let error = timeout(CONNECT_TIMEOUT + Duration::from_secs(1), session.client)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("establishment timed out"));
        assert_eq!(started.elapsed(), CONNECT_TIMEOUT);
        assert!(session.dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_control_response_cleans_driver() {
        let mut session = mock_session(Duration::ZERO).await;
        session
            .response
            .send_response(Response::builder().status(403).body(()).unwrap(), true)
            .unwrap();
        let error = timeout(CONNECT_TIMEOUT + Duration::from_secs(1), session.client)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("control stream rejected: 403"));
        assert!(session.dropped.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_session_during_establishment_cleans_driver() {
        let session = mock_session(Duration::ZERO).await;
        session.client.abort();
        assert!(session.client.await.unwrap_err().is_cancelled());
        tokio::task::yield_now().await;
        assert!(session.dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn control_eof_closes_active_target_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut session = mock_session(Duration::ZERO).await;
        let mut control = session
            .response
            .send_response(Response::new(()), false)
            .unwrap();
        control
            .send_data(
                crate::proto::encode_frame(&Frame::ChannelOpen {
                    id: 1,
                    host: "127.0.0.1".into(),
                    port: listener.local_addr().unwrap().port(),
                }),
                false,
            )
            .unwrap();
        let (mut target, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        control.send_data(Bytes::new(), true).unwrap();
        assert!(
            timeout(Duration::from_secs(2), session.client)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(session.dropped.load(Ordering::SeqCst));
        let n = timeout(Duration::from_secs(1), target.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "target connection must close before reconnect");
    }

    #[tokio::test]
    async fn disconnected_session_does_not_retry_old_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // First connection is refused; a detached task would retry after 200ms.
        let mut session = mock_session(Duration::ZERO).await;
        let mut control = session
            .response
            .send_response(Response::new(()), false)
            .unwrap();
        control
            .send_data(
                crate::proto::encode_frame(&Frame::ChannelOpen {
                    id: 1,
                    host: "127.0.0.1".into(),
                    port: addr.port(),
                }),
                false,
            )
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        session.server_tasks.shutdown().await;
        drop(control);
        drop(session.request);
        drop(session.response);
        assert!(
            timeout(Duration::from_secs(2), session.client)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let listener = TcpListener::bind(addr).await.unwrap();
        assert!(
            timeout(Duration::from_millis(800), listener.accept())
                .await
                .is_err(),
            "old session retried its target after disconnect"
        );
    }
}
