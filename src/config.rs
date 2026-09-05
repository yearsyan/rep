use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub tunnel: TunnelConfig,
    pub proxy: ProxyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TunnelConfig {
    pub listen: String,
    pub tls: TunnelTls,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:7000".into(),
            tls: TunnelTls::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TunnelTls {
    pub ca: String,
    pub cert: String,
    pub key: String,
}

impl Default for TunnelTls {
    fn default() -> Self {
        Self {
            ca: "certs/ca.pem".into(),
            cert: "certs/server.pem".into(),
            key: "certs/server.key".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub listen: String,
    pub tls: bool,
    /// 代理侧最大并发用户连接，超出立即回 503
    pub max_connections: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
            tls: false,
            max_connections: 256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    pub server_addr: String,
    pub server_name: String,
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub retry: RetryConfig,
    /// IPv6 真实连通性探测地址（TCP 连接级探测，任一成功即认为 v6 可用）
    pub ipv6_probe_addrs: Vec<String>,
    pub ipv6_probe_timeout_secs: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "localhost:7000".into(),
            server_name: "localhost".into(),
            ca: "certs/ca.pem".into(),
            cert: "certs/client.pem".into(),
            key: "certs/client.key".into(),
            retry: RetryConfig::default(),
            ipv6_probe_addrs: vec![
                "[2606:4700:4700::1111]:443".into(),
                "[2001:4860:4860::8888]:443".into(),
            ],
            ipv6_probe_timeout_secs: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryConfig {
    pub target_attempts: u32,
    pub connect_timeout_secs: u64,
    pub keepalive_secs: u64,
    pub reconnect_initial_ms: u64,
    pub reconnect_max_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            target_attempts: 3,
            connect_timeout_secs: 10,
            keepalive_secs: 15,
            reconnect_initial_ms: 1000,
            reconnect_max_ms: 30000,
        }
    }
}

pub fn load_server_config(path: &Path) -> Result<ServerConfig> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut cfg: ServerConfig =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let base = config_dir(path);
    resolve_path(&base, &mut cfg.tunnel.tls.ca);
    resolve_path(&base, &mut cfg.tunnel.tls.cert);
    resolve_path(&base, &mut cfg.tunnel.tls.key);
    Ok(cfg)
}

pub fn load_client_config(path: &Path) -> Result<ClientConfig> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut cfg: ClientConfig =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if cfg.server_name.is_empty() {
        cfg.server_name = host_of(&cfg.server_addr).into();
    }
    let base = config_dir(path);
    resolve_path(&base, &mut cfg.ca);
    resolve_path(&base, &mut cfg.cert);
    resolve_path(&base, &mut cfg.key);
    Ok(cfg)
}

fn config_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

// 配置里的相对路径按配置文件所在目录解析
fn resolve_path(base: &Path, p: &mut String) {
    if !Path::new(p).is_absolute() {
        *p = base.join(&*p).to_string_lossy().into_owned();
    }
}

fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(addr);
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host,
        _ => addr,
    }
}
