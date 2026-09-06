use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub tunnel: TunnelConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<ProxyConfig>,
}

impl ServerConfig {
    pub fn proxy_configs(&self) -> Result<Vec<ProxyConfig>> {
        if self.proxy.is_some() && !self.proxies.is_empty() {
            bail!("use either [proxy] or [[proxies]], not both");
        }
        let proxies = if self.proxies.is_empty() {
            vec![self.proxy.clone().unwrap_or_default()]
        } else {
            self.proxies.clone()
        };
        let mut names = HashSet::new();
        let mut listeners = HashSet::new();
        for proxy in &proxies {
            validate_client_name(&proxy.client_name)?;
            if !names.insert(&proxy.client_name) {
                bail!("duplicate proxy client_name {:?}", proxy.client_name);
            }
            if !listeners.insert(&proxy.listen) {
                bail!("duplicate proxy listen address {:?}", proxy.listen);
            }
        }
        Ok(proxies)
    }
}

pub fn validate_client_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        bail!("invalid client name {name:?}: use 1-64 chars of [A-Za-z0-9-_]");
    }
    Ok(())
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
    /// mTLS 客户端叶证书的唯一 CN，区分大小写。
    pub client_name: String,
    pub listen: String,
    pub tls: bool,
    /// 代理侧最大并发用户连接，超出立即回 503
    pub max_connections: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            client_name: "rep-client".into(),
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
    cfg.proxy_configs()?;
    let base = config_dir(path);
    resolve_path(&base, &mut cfg.tunnel.tls.ca);
    resolve_path(&base, &mut cfg.tunnel.tls.cert);
    resolve_path(&base, &mut cfg.tunnel.tls.key);
    Ok(cfg)
}

pub fn load_client_config(path: &Path) -> Result<ClientConfig> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut cfg = parse_client_config(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    let base = config_dir(path);
    resolve_path(&base, &mut cfg.ca);
    resolve_path(&base, &mut cfg.cert);
    resolve_path(&base, &mut cfg.key);
    Ok(cfg)
}

/// 解析客户端配置文本(server_name 缺省取 server_addr 的主机部分);内嵌配置也走这里。
pub fn parse_client_config(text: &str) -> Result<ClientConfig> {
    let mut cfg: ClientConfig = toml::from_str(text).context("parsing client config")?;
    if cfg.server_name.is_empty() {
        cfg.server_name = host_of(&cfg.server_addr).into();
    }
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
    // 内嵌 PEM 原样保留,优先于按路径解析
    if is_inline_pem(p) {
        return;
    }
    if !Path::new(p).is_absolute() {
        *p = base.join(&*p).to_string_lossy().into_owned();
    }
}

/// 证书配置值以 -----BEGIN 开头视为内嵌 PEM 内容,否则视为文件路径。
pub fn is_inline_pem(value: &str) -> bool {
    value.trim_start().starts_with("-----BEGIN ")
}

pub(crate) fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(addr);
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host,
        _ => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_config_supports_legacy_and_multiple_identities() {
        let legacy: ServerConfig = toml::from_str("[proxy]\nlisten = '127.0.0.1:9000'").unwrap();
        let proxies = legacy.proxy_configs().unwrap();
        assert_eq!(proxies[0].client_name, "rep-client");
        assert_eq!(proxies[0].listen, "127.0.0.1:9000");
        let multiple: ServerConfig = toml::from_str(
            "[[proxies]]\nclient_name = 'a'\nlisten = '127.0.0.1:9001'\n\
             [[proxies]]\nclient_name = 'b'\nlisten = '127.0.0.1:9002'",
        )
        .unwrap();
        assert!(multiple.proxy.is_none());
        assert_eq!(multiple.proxy_configs().unwrap().len(), 2);
    }

    #[test]
    fn proxy_config_rejects_ambiguous_routes() {
        for config in [
            "[proxy]\n[[proxies]]\nclient_name = 'a'",
            "[[proxies]]\nclient_name = 'a'\nlisten = '127.0.0.1:9001'\n\
             [[proxies]]\nclient_name = 'a'\nlisten = '127.0.0.1:9002'",
            "[[proxies]]\nclient_name = 'a'\n[[proxies]]\nclient_name = 'b'",
            "[[proxies]]\nclient_name = ''",
            "[[proxies]]\nclient_name = '../a'",
        ] {
            let cfg: ServerConfig = toml::from_str(config).unwrap();
            assert!(cfg.proxy_configs().is_err(), "accepted: {config}");
        }
    }

    #[test]
    fn inline_pem_values_skip_path_resolution() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
        assert!(is_inline_pem(pem));
        assert!(is_inline_pem(" \n -----BEGIN PRIVATE KEY-----"));
        assert!(!is_inline_pem("certs/ca.pem"));
        assert!(!is_inline_pem(""));
        let base = Path::new("/etc/rep");
        let mut inline = pem.to_string();
        resolve_path(base, &mut inline);
        assert_eq!(inline, pem);
        let mut path = String::from("certs/ca.pem");
        resolve_path(base, &mut path);
        assert_eq!(path, "/etc/rep/certs/ca.pem");
    }
}
