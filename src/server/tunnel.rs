use anyhow::Result;
use bytes::Bytes;
use h2::server;
use h2::{Reason, RecvStream, SendStream};
use http::{Method, Request, Response};
use std::collections::HashMap;
use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_util::time::{DelayQueue, delay_queue::Key};
use tracing::{debug, info, warn};

use super::{Registry, Shutdown};
use crate::proto::{
    CHANNEL_HEADER, CONTROL_PATH, Frame, FrameDecoder, H2Io, encode_frame, recv_chunk, socket_host,
};

/// 用户侧连接（可能是裸 TCP 或 TLS 套接字）。
pub trait UserIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> UserIo for T {}

pub enum ChannelMode {
    /// CONNECT：成功后先向用户回 200 Connection established，
    /// 再把 first（与请求头一起到达的早期隧道数据）发往目标
    Connect { first: Bytes },
    /// 普通 HTTP：成功后先向目标写入这些字节（改写后的请求头）
    Relay { first: Bytes },
}

struct PendingChannel {
    user: Option<Box<dyn UserIo>>,
    mode: ChannelMode,
    verdict: Option<Result<(), String>>,
    notify: Arc<Notify>,
    /// 代理并发配额，随通道存活持有到桥接结束
    permit: Option<OwnedSemaphorePermit>,
}

enum DeadlineCommand {
    Schedule {
        id: u64,
        deadline: tokio::time::Instant,
    },
    Cancel {
        id: u64,
    },
}

const MAX_PENDING: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_DEADLINE: Duration = Duration::from_secs(15);
const MAX_TUNNEL_HANDSHAKES: usize = 16;
/// 客户端上报预算与服务端自身预算的共同上限（10 分钟）
const MAX_BUDGET_MS: u64 = 600_000;

pub struct SessionState {
    control_tx: mpsc::Sender<Frame>,
    control_rx: Mutex<Option<mpsc::Receiver<Frame>>>,
    deadline_tx: mpsc::Sender<DeadlineCommand>,
    pending: Arc<Mutex<HashMap<u64, PendingChannel>>>,
    next_id: AtomicU64,
    has_control: AtomicBool,
    registered: AtomicBool,
    shutdown: Shutdown,
    /// 客户端上报：目标连接最坏耗时预算（毫秒），用于服务端超时对齐
    budget_ms: AtomicU64,
}

impl SessionState {
    fn new(
        control_tx: mpsc::Sender<Frame>,
        control_rx: mpsc::Receiver<Frame>,
    ) -> (Self, mpsc::Receiver<DeadlineCommand>) {
        let (deadline_tx, deadline_rx) = mpsc::channel(MAX_PENDING * 2);
        (
            Self {
                control_tx,
                control_rx: Mutex::new(Some(control_rx)),
                deadline_tx,
                pending: Arc::new(Mutex::new(HashMap::new())),
                next_id: AtomicU64::new(0),
                has_control: AtomicBool::new(false),
                registered: AtomicBool::new(false),
                shutdown: Shutdown::default(),
                budget_ms: AtomicU64::new(30_000),
            },
            deadline_rx,
        )
    }

    pub fn shutdown(&self) -> &Shutdown {
        &self.shutdown
    }

    pub fn mark_registered(&self) {
        self.registered.store(true, Ordering::SeqCst);
    }

    pub fn was_registered(&self) -> bool {
        self.registered.load(Ordering::SeqCst)
    }

    pub fn has_control(&self) -> bool {
        self.has_control.load(Ordering::SeqCst)
    }

    fn control_rx_take(&self) -> mpsc::Receiver<Frame> {
        self.control_rx
            .lock()
            .unwrap()
            .take()
            .expect("control rx taken twice")
    }

    fn sweep_delay(&self) -> Duration {
        let budget = self.budget_ms.load(Ordering::Relaxed);
        Duration::from_millis(budget.saturating_add(5000).max(10_000))
    }

    async fn cancel_deadline(&self, id: u64) {
        let _ = self.deadline_tx.send(DeadlineCommand::Cancel { id }).await;
    }

    /// 把用户连接挂到当前会话，等客户端开数据流来接。成功返回后 io 归会话所有，
    /// permit 随通道持有直到桥接结束。
    pub async fn open_channel(
        self: &Arc<Self>,
        host: String,
        port: u16,
        user: Box<dyn UserIo>,
        mode: ChannelMode,
        permit: OwnedSemaphorePermit,
    ) -> Result<()> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = PendingChannel {
            user: Some(user),
            mode,
            verdict: None,
            notify: Arc::new(Notify::new()),
            permit: Some(permit),
        };
        let rejected = {
            let mut pending = self.pending.lock().unwrap();
            if pending.len() >= MAX_PENDING {
                Some(entry)
            } else {
                pending.insert(id, entry);
                None
            }
        };
        if let Some(mut entry) = rejected {
            if let Some(user) = entry.user.take() {
                write_502(user).await;
            }
            return Err(anyhow::anyhow!("too many pending channels"));
        }

        // 由会话级 DelayQueue 统一管理超时，不为每个通道创建睡眠任务。
        if self
            .deadline_tx
            .send(DeadlineCommand::Schedule {
                id,
                deadline: tokio::time::Instant::now() + self.sweep_delay(),
            })
            .await
            .is_err()
        {
            let removed = self
                .pending
                .lock()
                .unwrap()
                .remove(&id)
                .and_then(|mut p| p.user.take());
            if let Some(u) = removed {
                write_502(u).await;
            }
            return Err(anyhow::anyhow!("channel deadline manager is not reachable"));
        }

        if self
            .control_tx
            .send(Frame::ChannelOpen {
                id,
                host: host.clone(),
                port,
            })
            .await
            .is_err()
        {
            let removed = self
                .pending
                .lock()
                .unwrap()
                .remove(&id)
                .and_then(|mut p| p.user.take());
            self.cancel_deadline(id).await;
            if let Some(u) = removed {
                write_502(u).await;
            }
            return Err(anyhow::anyhow!("tunnel client is not reachable"));
        }
        debug!("channel {id} -> {host}:{port}");
        Ok(())
    }

    /// 会话已死：向所有还在等数据流的用户连接立即回 502。
    async fn fail_pending(self: &Arc<Self>) {
        let users: Vec<Box<dyn UserIo>> = {
            let mut g = self.pending.lock().unwrap();
            g.drain().filter_map(|(_, mut p)| p.user.take()).collect()
        };
        for u in users {
            write_502(u).await;
        }
    }
}

/// 单个会话只运行一个 deadline 管理器。Schedule/Cancel 命令有界排队，
/// 通道完成后会立即从 DelayQueue 移除，不再遗留逐通道睡眠任务。
async fn channel_deadline_manager(
    mut commands: mpsc::Receiver<DeadlineCommand>,
    pending: Arc<Mutex<HashMap<u64, PendingChannel>>>,
    shutdown: Shutdown,
) {
    let mut deadlines = DelayQueue::new();
    let mut keys: HashMap<u64, Key> = HashMap::new();

    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            command = commands.recv() => match command {
                Some(DeadlineCommand::Schedule { id, deadline }) => {
                    if let Some(old) = keys.remove(&id) {
                        let _ = deadlines.try_remove(&old);
                    }
                    let key = deadlines.insert_at(id, deadline);
                    keys.insert(id, key);
                }
                Some(DeadlineCommand::Cancel { id }) => {
                    if let Some(key) = keys.remove(&id) {
                        let _ = deadlines.try_remove(&key);
                    }
                }
                None => break,
            },
            expired = poll_fn(|cx| deadlines.poll_expired(cx)), if !deadlines.is_empty() => {
                let Some(expired) = expired else {
                    continue;
                };
                let id = expired.into_inner();
                keys.remove(&id);
                let removed = pending
                    .lock()
                    .unwrap()
                    .remove(&id)
                    .and_then(|mut p| p.user.take());
                if let Some(user) = removed {
                    tokio::spawn(write_502(user));
                    warn!("channel {id} timed out waiting for tunnel client");
                }
            }
        }
    }
}

pub async fn accept_loop(
    listener: TcpListener,
    tls: TlsAcceptor,
    routes: Arc<HashMap<String, Arc<Registry>>>,
) -> Result<()> {
    let handshakes = Arc::new(Semaphore::new(MAX_TUNNEL_HANDSHAKES));
    loop {
        let (tcp, peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        // permit 在创建任务前获取；满载连接立即关闭，不在进程内排队。
        let hs_permit = match handshakes.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!(
                    ?peer,
                    "rejecting tunnel connection: handshake limit reached"
                );
                continue;
            }
        };
        let tls = tls.clone();
        let routes = routes.clone();
        tokio::spawn(async move {
            let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    warn!(?peer, "tunnel tls handshake failed: {e:#}");
                    return;
                }
                Err(_) => {
                    debug!(?peer, "tunnel tls handshake timed out");
                    return;
                }
            };
            let alpn = stream.get_ref().1.alpn_protocol();
            if alpn != Some(b"h2") {
                warn!(?peer, "rejecting tunnel connection with alpn {alpn:?}");
                return;
            }
            let identity = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .ok_or_else(|| anyhow::anyhow!("missing client certificate"))
                .and_then(crate::tls::client_identity);
            let identity = match identity {
                Ok(identity) => identity,
                Err(e) => {
                    warn!(?peer, "rejecting tunnel client identity: {e:#}");
                    return;
                }
            };
            let Some(registry) = routes.get(&identity).cloned() else {
                warn!(?peer, client_name = %identity, "rejecting unconfigured tunnel client");
                return;
            };
            info!(?peer, client_name = %identity, "tunnel client authenticated");
            if let Err(e) = start_session(stream, registry).await {
                warn!(?peer, "tunnel session setup failed: {e:#}");
            }
            drop(hs_permit);
        });
    }
}

async fn start_session<T>(io: T, registry: Arc<Registry>) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        server::Builder::new()
            .initial_window_size(1 << 20)
            .initial_connection_window_size(4 << 20)
            .max_frame_size(1 << 20)
            .max_concurrent_streams(1024)
            .handshake(io),
    )
    .await??;

    let (tx, rx) = mpsc::channel(64);
    let (state, deadline_rx) = SessionState::new(tx, rx);
    let state = Arc::new(state);
    tokio::spawn(channel_deadline_manager(
        deadline_rx,
        state.pending.clone(),
        state.shutdown().clone(),
    ));
    info!("tunnel client connected");

    // 控制流必须在期限内建立，否则下线会话（防"假在线"）；
    // 会话在控制流建立并注册进 Registry 前不对外可见
    let watchdog_state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(CONTROL_DEADLINE).await;
        if !watchdog_state.has_control() {
            warn!(
                "no control stream within {}s, dropping session",
                CONTROL_DEADLINE.as_secs()
            );
            watchdog_state.shutdown().signal();
        }
    });

    let s = state.clone();
    let registry_cleanup = registry.clone();
    let registry_loop = registry.clone();
    tokio::spawn(async move {
        let result: Result<()> = loop {
            tokio::select! {
                _ = s.shutdown.wait() => break Ok(()),
                stream = conn.accept() => match stream {
                    Some(Ok((req, respond))) => {
                        let s = s.clone();
                        let r = registry_loop.clone();
                        tokio::spawn(handle_stream(req, respond, s, r));
                    }
                    Some(Err(e)) => break Err(e.into()),
                    None => break Ok(()),
                },
            }
        };
        match &result {
            Ok(()) => info!("tunnel client disconnected"),
            Err(e) => warn!("tunnel session error: {e:#}"),
        }
        // 先置位再清理：任何迟到的 register 都会被拒，杜绝死会话注册竞态
        s.shutdown().signal();
        s.fail_pending().await;
        if s.was_registered() {
            registry_cleanup.clear_if_current(&s);
        }
    });
    // 不在此处注册：由控制流建立成功时在 Registry 锁内原子注册
    Ok(())
}

async fn handle_stream(
    req: Request<RecvStream>,
    mut respond: server::SendResponse<Bytes>,
    state: Arc<SessionState>,
    registry: Arc<Registry>,
) {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if method == Method::POST && path == CONTROL_PATH {
        if state.has_control.swap(true, Ordering::SeqCst) {
            let _ = respond.send_response(Response::builder().status(409).body(()).unwrap(), true);
            state.shutdown().signal();
            return;
        }
        // 读取客户端上报的目标连接预算（钳制到安全范围）
        if let Some(v) = req
            .headers()
            .get("x-rep-budget-ms")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            state
                .budget_ms
                .store(v.clamp(1_000, MAX_BUDGET_MS), Ordering::Relaxed);
        }
        info!(
            "control stream established (target budget={}ms)",
            state.budget_ms.load(Ordering::Relaxed)
        );

        let body = req.into_body();
        let resp = Response::builder().status(200).body(()).unwrap();
        match respond.send_response(resp, false) {
            Ok(send_stream) => {
                // 控制流就绪，此刻才让会话对外可见
                registry.register(state.clone());
                let shutdown = state.shutdown().clone();
                tokio::spawn(control_writer(
                    state.control_rx_take(),
                    send_stream,
                    shutdown,
                ));
                tokio::spawn(control_reader(body, state.clone()));
            }
            Err(e) => {
                warn!("control stream respond failed: {e:#}");
                state.shutdown().signal();
            }
        }
    } else if method == Method::CONNECT {
        let id = req
            .headers()
            .get(CHANNEL_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        match id {
            Some(id) => handle_data_stream(req, respond, state, id).await,
            None => respond.send_reset(Reason::PROTOCOL_ERROR),
        }
    } else {
        respond.send_reset(Reason::PROTOCOL_ERROR);
    }
}

/// 控制流写出任务：只持有 Shutdown 与通道，不持有 SessionState，
/// 避免形成 "writer → state → sender → writer" 的自引用泄漏；
/// 会话关闭或发送失败都会退出。
async fn control_writer(
    mut rx: mpsc::Receiver<Frame>,
    mut stream: SendStream<Bytes>,
    shutdown: Shutdown,
) {
    loop {
        tokio::select! {
            frame = rx.recv() => match frame {
                Some(frame) => {
                    if stream.send_data(encode_frame(&frame), false).is_err() {
                        warn!("control stream write failed, shutting down session");
                        shutdown.signal();
                        break;
                    }
                }
                None => break,
            },
            _ = shutdown.wait() => break,
        }
    }
    let _ = stream.send_data(Bytes::new(), true);
}

async fn control_reader(mut body: RecvStream, state: Arc<SessionState>) {
    let mut dec = FrameDecoder::new();
    loop {
        let chunk = match recv_chunk(&mut body).await {
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                warn!("control stream read error: {e:#}");
                break;
            }
            None => {
                debug!("control stream closed by client");
                break;
            }
        };
        let _ = body.flow_control().release_capacity(chunk.len());
        dec.push(&chunk);
        let mut decode_failed = false;
        loop {
            match dec.next_frame() {
                Ok(Some(Frame::ChannelResult { id, ok, err })) => {
                    handle_channel_result(&state, id, ok, err).await
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => {
                    warn!("bad control frame, dropping session: {e:#}");
                    decode_failed = true;
                    break;
                }
            }
        }
        if decode_failed {
            break;
        }
    }
    // 控制流断开即整个会话失效，立即触发清理，避免"假在线"
    state.shutdown().signal();
}

async fn handle_channel_result(state: &Arc<SessionState>, id: u64, ok: bool, err: Option<String>) {
    let mut cancel_deadline = false;
    let user = {
        let mut g = state.pending.lock().unwrap();
        match g.get_mut(&id) {
            None => {
                warn!("channel result for unknown id {id}");
                None
            }
            Some(p) => {
                p.verdict = Some(if ok {
                    Ok(())
                } else {
                    Err(err.unwrap_or_else(|| "client connect failed".into()))
                });
                p.notify.notify_one();
                if !ok {
                    // 失败的通道客户端不会再开数据流，直接清理
                    cancel_deadline = true;
                    g.remove(&id).and_then(|mut p| p.user.take())
                } else {
                    None
                }
            }
        }
    };
    if cancel_deadline {
        state.cancel_deadline(id).await;
    }
    if let Some(user) = user {
        tokio::spawn(write_502(user));
    }
}

async fn handle_data_stream(
    req: Request<RecvStream>,
    mut respond: server::SendResponse<Bytes>,
    state: Arc<SessionState>,
    id: u64,
) {
    let notify = {
        let g = state.pending.lock().unwrap();
        match g.get(&id) {
            Some(p) => p.notify.clone(),
            None => {
                respond.send_reset(Reason::REFUSED_STREAM);
                return;
            }
        }
    };

    // 等控制流上的 ChannelResult；超时对齐客户端上报的目标连接预算
    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(10).max(state.sweep_delay() - Duration::from_secs(2));
    let verdict = loop {
        if state.shutdown().is_signaled() {
            break Err("session closed".into());
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break Err("timeout waiting for channel result".into());
        }
        let found = {
            let g = state.pending.lock().unwrap();
            match g.get(&id) {
                Some(p) => p.verdict.clone(),
                None => break Err("channel cancelled".into()),
            }
        };
        if let Some(v) = found {
            break v;
        }
        // pending 被会话清理后不会再收到 ChannelResult；关闭信号必须直接唤醒等待。
        tokio::select! {
            biased;
            _ = state.shutdown().wait() => break Err("session closed".into()),
            _ = tokio::time::sleep_until(deadline) => {
                break Err("timeout waiting for channel result".into());
            }
            _ = notify.notified() => {}
        }
    };

    match verdict {
        Err(e) => {
            let user = {
                let mut g = state.pending.lock().unwrap();
                match g.get_mut(&id) {
                    Some(p) => p.user.take(),
                    None => None,
                }
            };
            if let Some(u) = user {
                write_502(u).await;
            }
            state.pending.lock().unwrap().remove(&id);
            state.cancel_deadline(id).await;
            respond.send_reset(Reason::CANCEL);
            debug!("channel {id} failed: {e}");
        }
        Ok(()) => {
            let entry = state.pending.lock().unwrap().remove(&id);
            state.cancel_deadline(id).await;
            let Some(mut p) = entry else {
                respond.send_reset(Reason::CANCEL);
                return;
            };
            let Some(mut user) = p.user.take() else {
                respond.send_reset(Reason::CANCEL);
                return;
            };
            let body = req.into_body();
            let resp = Response::builder().status(200).body(()).unwrap();
            let Ok(send_stream) = respond.send_response(resp, false) else {
                return;
            };
            let mut h2io = H2Io::new(body, send_stream);
            match p.mode {
                ChannelMode::Connect { first } => {
                    if user
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    // 与 CONNECT 头同包到达的早期隧道数据在此补发
                    if !first.is_empty() && h2io.write_all(&first).await.is_err() {
                        return;
                    }
                }
                ChannelMode::Relay { first } => {
                    if h2io.write_all(&first).await.is_err() {
                        return;
                    }
                }
            }
            info!("channel {id} bridged");
            // permit 随桥接任务存活：限制的是活跃隧道数而非解析阶段
            let permit = p.permit.take();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tokio::io::copy_bidirectional(&mut *user, &mut h2io).await;
                debug!("channel {id} closed");
            });
        }
    }
}

async fn write_502(mut io: Box<dyn UserIo>) {
    let _ = io
        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
    let _ = io.shutdown().await;
}

/// 目标 host 统一为 socket 形式（无方括号）后再下发给客户端。
pub fn normalize_target_host(host: &str) -> String {
    socket_host(host).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, duplex};

    #[test]
    fn identity_registries_isolate_replacement_and_stale_cleanup() {
        let session = || {
            let (tx, rx) = mpsc::channel(64);
            Arc::new(SessionState::new(tx, rx).0)
        };
        let a = Registry::new();
        let b = Registry::new();
        let old_a = session();
        let current_b = session();
        a.register(old_a.clone());
        b.register(current_b.clone());
        let new_a = session();
        a.register(new_a.clone());
        assert!(old_a.shutdown().is_signaled());
        assert!(!current_b.shutdown().is_signaled());
        a.clear_if_current(&old_a);
        assert!(Arc::ptr_eq(&a.current().unwrap(), &new_a));
        assert!(Arc::ptr_eq(&b.current().unwrap(), &current_b));
        let dead_a = session();
        dead_a.shutdown().signal();
        a.register(dead_a);
        assert!(Arc::ptr_eq(&a.current().unwrap(), &new_a));
        a.clear_if_current(&new_a);
        assert!(a.current().is_none());
        assert!(b.current().is_some());
    }

    #[tokio::test]
    async fn deadline_manager_expires_and_cancels_entries() {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let permits = Arc::new(Semaphore::new(2));
        let (cancelled_io, _cancelled_peer) = duplex(1024);
        let (expired_io, mut expired_peer) = duplex(1024);
        let cancelled_permit = permits.clone().acquire_owned().await.unwrap();
        let expired_permit = permits.acquire_owned().await.unwrap();

        pending.lock().unwrap().insert(
            1,
            PendingChannel {
                user: Some(Box::new(cancelled_io)),
                mode: ChannelMode::Relay {
                    first: Bytes::new(),
                },
                verdict: None,
                notify: Arc::new(Notify::new()),
                permit: Some(cancelled_permit),
            },
        );
        pending.lock().unwrap().insert(
            2,
            PendingChannel {
                user: Some(Box::new(expired_io)),
                mode: ChannelMode::Relay {
                    first: Bytes::new(),
                },
                verdict: None,
                notify: Arc::new(Notify::new()),
                permit: Some(expired_permit),
            },
        );

        let (tx, rx) = mpsc::channel(8);
        let shutdown = Shutdown::default();
        let manager = tokio::spawn(channel_deadline_manager(
            rx,
            pending.clone(),
            shutdown.clone(),
        ));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        tx.send(DeadlineCommand::Schedule { id: 1, deadline })
            .await
            .unwrap();
        tx.send(DeadlineCommand::Cancel { id: 1 }).await.unwrap();
        tx.send(DeadlineCommand::Schedule { id: 2, deadline })
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(pending.lock().unwrap().contains_key(&1));
        assert!(!pending.lock().unwrap().contains_key(&2));

        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            expired_peer.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));

        pending.lock().unwrap().remove(&1);
        shutdown.signal();
        manager.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn channel_result_wait_exits_on_session_shutdown() {
        // 覆盖开始等待前已关闭，以及等待中关闭并清空 pending 的两种时序。
        for shutdown_before_start in [false, true] {
            let (client_io, server_io) = duplex(64 * 1024);
            let (request_tx, request_rx) = tokio::sync::oneshot::channel();
            let mut drivers = tokio::task::JoinSet::new();
            drivers.spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                request_tx
                    .send(conn.accept().await.unwrap().unwrap())
                    .ok()
                    .unwrap();
                while conn.accept().await.is_some() {}
            });
            let (send, conn) = h2::client::handshake(client_io).await.unwrap();
            drivers.spawn(async move {
                let _ = conn.await;
            });
            let mut send = send.ready().await.unwrap();
            let (response, _body) = send
                .send_request(
                    Request::builder()
                        .method(Method::CONNECT)
                        .uri("example.com:80")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let (request, respond) = request_rx.await.unwrap();

            let (control_tx, control_rx) = mpsc::channel(64);
            let (state, _deadlines) = SessionState::new(control_tx, control_rx);
            let state = Arc::new(state);
            state.budget_ms.store(MAX_BUDGET_MS, Ordering::Relaxed);
            let permits = Arc::new(Semaphore::new(1));
            let permit = permits.clone().acquire_owned().await.unwrap();
            let (user, mut user_peer) = duplex(1024);
            state.pending.lock().unwrap().insert(
                1,
                PendingChannel {
                    user: Some(Box::new(user)),
                    mode: ChannelMode::Relay {
                        first: Bytes::new(),
                    },
                    verdict: None,
                    notify: Arc::new(Notify::new()),
                    permit: Some(permit),
                },
            );

            if shutdown_before_start {
                state.shutdown().signal();
            }
            let waiter = tokio::spawn(handle_data_stream(request, respond, state.clone(), 1));
            if !shutdown_before_start {
                tokio::task::yield_now().await;
                assert!(!waiter.is_finished());
                state.shutdown().signal();
                state.fail_pending().await;
            }
            let started = tokio::time::Instant::now();
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("verdict waiter did not exit on session shutdown")
                .unwrap();
            assert_eq!(started.elapsed(), Duration::ZERO);
            assert!(state.pending.lock().unwrap().is_empty());
            assert_eq!(permits.available_permits(), 1);
            assert_eq!(Arc::strong_count(&state), 1, "waiter retained its session");

            let error = tokio::time::timeout(Duration::from_secs(1), response)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.reason(), Some(Reason::CANCEL));
            let mut reply = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), user_peer.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert!(reply.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
            drivers.shutdown().await;
        }
    }
}
