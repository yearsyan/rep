pub mod proxy;
mod request_body;
pub mod tunnel;

use anyhow::Result;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::config::ServerConfig;
use tunnel::SessionState;

/// 会话级关闭信号，基于 watch 实现：值被持久保存，先 signal 后 wait
/// 不会丢唤醒（修复 notify_waiters 只能唤醒已注册 waiter 的竞态）。
#[derive(Clone)]
pub struct Shutdown {
    tx: watch::Sender<bool>,
}

impl Default for Shutdown {
    fn default() -> Self {
        let (tx, _) = watch::channel(false);
        Self { tx }
    }
}

impl Shutdown {
    pub fn signal(&self) {
        self.tx.send_replace(true);
    }

    pub fn is_signaled(&self) -> bool {
        *self.tx.borrow()
    }

    pub async fn wait(&self) {
        let mut rx = self.tx.subscribe();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            // sender 由 Shutdown 自身持有，changed 不会因发送端析构而失败
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

/// 持有当前隧道会话；新会话接入时替换并向旧会话发关闭信号（而非 abort，
/// 保证旧 driver 能走完尾部清理）。
#[derive(Default)]
pub struct Registry {
    current: Mutex<Option<Arc<SessionState>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current(&self) -> Option<Arc<SessionState>> {
        self.current.lock().unwrap().clone()
    }

    /// 注册会话：在锁内原子地"检查存活 + 标记已注册 + 替换"，
    /// 已死（shutdown 已置位）的会话不会被注册，杜绝 driver 先退、
    /// 死 state 后注册的竞态。
    pub fn register(&self, state: Arc<SessionState>) {
        let mut g = self.current.lock().unwrap();
        if state.shutdown().is_signaled() {
            return;
        }
        state.mark_registered();
        if let Some(old) = g.replace(state) {
            info!("replacing previous tunnel session");
            old.shutdown().signal();
        }
    }

    /// 会话自然结束时摘除注册；只在该会话仍是当前会话时生效。
    pub fn clear_if_current(&self, state: &Arc<SessionState>) {
        let mut g = self.current.lock().unwrap();
        if g.as_ref().is_some_and(|s| Arc::ptr_eq(s, state)) {
            *g = None;
        }
    }
}

pub async fn run(cfg: ServerConfig) -> Result<()> {
    let tunnel_tls = crate::tls::server_config(
        cfg.tunnel.tls.ca.as_ref(),
        cfg.tunnel.tls.cert.as_ref(),
        cfg.tunnel.tls.key.as_ref(),
    )?;

    let registry = Arc::new(Registry::new());

    let tunnel_listener = TcpListener::bind(&cfg.tunnel.listen).await?;
    info!("tunnel listening on {} (mTLS + h2)", cfg.tunnel.listen);

    let proxy_tls = if cfg.proxy.tls {
        Some(TlsAcceptor::from(crate::tls::proxy_tls_config(
            cfg.tunnel.tls.cert.as_ref(),
            cfg.tunnel.tls.key.as_ref(),
        )?))
    } else {
        None
    };
    let proxy_listener = TcpListener::bind(&cfg.proxy.listen).await?;
    info!(
        "proxy listening on {} (tls={}, max_connections={})",
        cfg.proxy.listen, cfg.proxy.tls, cfg.proxy.max_connections,
    );

    let a = tunnel::accept_loop(
        tunnel_listener,
        TlsAcceptor::from(tunnel_tls),
        registry.clone(),
    );
    let b = proxy::run(proxy_listener, proxy_tls, registry, cfg.proxy);
    tokio::try_join!(a, b)?;
    Ok(())
}
