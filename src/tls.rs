use anyhow::{bail, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

pub fn server_config(ca: &Path, cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    let mut roots = RootCertStore::empty();
    for c in load_certs(ca)? {
        roots.add(c).with_context(|| format!("adding CA cert from {}", ca.display()))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("building client cert verifier")?;
    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_certs(cert)?, load_key(key)?)
        .context("loading server identity")?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// 代理端口可选的 TLS：只出示服务端证书，不要求客户端证书（用户侧不是 mTLS）。
pub fn proxy_tls_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(cert)?, load_key(key)?)
        .context("loading proxy tls identity")?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub fn client_config(ca: &Path, cert: &Path, key: &Path) -> Result<Arc<ClientConfig>> {    let mut roots = RootCertStore::empty();
    for c in load_certs(ca)? {
        roots.add(c).with_context(|| format!("adding CA cert from {}", ca.display()))?;
    }
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(load_certs(cert)?, load_key(key)?)
        .context("loading client identity")?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut rd = BufReader::new(f);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("parsing certs in {}", path.display()))?;
    if certs.is_empty() {
        bail!("{} contains no certificates", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut rd = BufReader::new(f);
    rustls_pemfile::private_key(&mut rd)
        .with_context(|| format!("parsing key in {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("{} contains no private key", path.display()))
}
