mod ipv6;
mod outbound;
mod session;

use anyhow::Result;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::config::ClientConfig;

pub async fn run(cfg: ClientConfig) -> Result<()> {
    let tls = crate::tls::client_config(cfg.ca.as_ref(), cfg.cert.as_ref(), cfg.key.as_ref())?;
    let connector = tokio_rustls::TlsConnector::from(tls);

    let initial = cfg.retry.reconnect_initial_ms.max(100);
    let max = cfg.retry.reconnect_max_ms.max(initial);
    let mut delay = initial;
    loop {
        let started = Instant::now();
        match session::run(&cfg, &connector).await {
            Ok(()) => info!("session closed"),
            Err(e) => warn!("session error: {e:#}"),
        }
        // 会话存活超过 30 秒说明网络基本健康，重连退避复位
        if started.elapsed() >= Duration::from_secs(30) {
            delay = initial;
        }
        let jitter = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u64
            % (delay / 4 + 1);
        info!("reconnecting in {} ms", delay + jitter);
        tokio::time::sleep(Duration::from_millis(delay + jitter)).await;
        delay = (delay * 2).min(max);
    }
}
