use anyhow::{Context, Result, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// 仅在 rustls 已完成 mTLS 校验后，用叶证书 CN 做路由授权。
pub fn client_identity(cert: &CertificateDer<'_>) -> Result<String> {
    let (remaining, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| anyhow::anyhow!("parsing client certificate: {e}"))?;
    if !remaining.is_empty() {
        bail!("trailing data in client certificate");
    }
    let mut names = parsed.subject().iter_common_name();
    let name = names
        .next()
        .context("client certificate has no CN")?
        .as_str()
        .context("client certificate CN is not a string")?;
    if names.next().is_some() {
        bail!("client certificate must have exactly one CN");
    }
    crate::config::validate_client_name(name)?;
    Ok(name.to_owned())
}

pub fn server_config(ca: &Path, cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    let mut roots = RootCertStore::empty();
    for c in load_certs(ca)? {
        roots
            .add(c)
            .with_context(|| format!("adding CA cert from {}", ca.display()))?;
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

pub fn client_config(ca: &Path, cert: &Path, key: &Path) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for c in load_certs(ca)? {
        roots
            .add(c)
            .with_context(|| format!("adding CA cert from {}", ca.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    #[test]
    fn client_identity_requires_a_valid_cn() {
        let key = KeyPair::generate().unwrap();
        for name in [
            Some("office-a"),
            None,
            Some(""),
            Some("../office"),
            Some("办公室"),
        ] {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name = DistinguishedName::new();
            if let Some(name) = name {
                params.distinguished_name.push(DnType::CommonName, name);
            }
            let cert = params.self_signed(&key).unwrap();
            let identity = client_identity(cert.der());
            if name == Some("office-a") {
                assert_eq!(identity.unwrap(), "office-a");
            } else {
                assert!(identity.is_err(), "accepted: {name:?}");
            }
        }
        assert!(client_identity(&CertificateDer::from(vec![0, 1, 2])).is_err());
    }
}
