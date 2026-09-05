use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

/// 真实 IPv6 连通性探测：对探测地址做实际 TCP 连接（而非只看本机是否有 v6 地址），
/// 任一成功即认为 v6 可用。
pub async fn probe(addrs: &[String], timeout_secs: u64) -> bool {
    if addrs.is_empty() {
        return false;
    }
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut set = JoinSet::new();
    for a in addrs {
        let a = a.clone();
        set.spawn(async move {
            match a.parse::<SocketAddr>() {
                // 只有全局单播地址的探测才有意义
                Ok(sa) if sa.is_ipv6() => tokio::time::timeout(timeout, TcpStream::connect(sa))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false),
                _ => {
                    tracing::warn!("invalid ipv6 probe address: {a}");
                    false
                }
            }
        });
    }
    while let Some(r) = set.join_next().await {
        if r.unwrap_or(false) {
            set.abort_all();
            return true;
        }
    }
    false
}
