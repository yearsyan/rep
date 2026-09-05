use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::config::{ClientConfig, ProxyConfig, ServerConfig, validate_client_name};

const CA_VALIDITY_DAYS: i64 = 3650;
const LEAF_VALIDITY_DAYS: i64 = 1095;

fn set_validity(params: &mut CertificateParams, days: i64) {
    let now = OffsetDateTime::now_utc();
    let begin = now - TimeDuration::days(1);
    let end = now + TimeDuration::days(days);
    params.not_before = rcgen::date_time_ymd(begin.year(), u8::from(begin.month()), begin.day());
    params.not_after = rcgen::date_time_ymd(end.year(), u8::from(end.month()), end.day());
}

pub fn run_init(domain: &str, ips: &[String], out: &Path, force: bool) -> Result<()> {
    let cert_dir = out.join("certs");
    fs::create_dir_all(&cert_dir)?;
    let files = [
        "ca.pem",
        "ca.key",
        "server.pem",
        "server.key",
        "client.pem",
        "client.key",
    ]
    .map(|n| cert_dir.join(n));
    if !force {
        for f in &files {
            if f.exists() {
                bail!("{} already exists, use --force to overwrite", f.display());
            }
        }
    }

    // 回环地址始终写入 SAN，本机联调可直接连
    let mut san_ips = vec![
        IpAddr::from([127, 0, 0, 1]),
        IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
    ];
    for ip in ips {
        san_ips.push(ip.parse().with_context(|| format!("parsing ip {ip}"))?);
    }

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rep CA");
    set_validity(&mut ca_params, CA_VALIDITY_DAYS);
    let ca = ca_params.self_signed(&ca_key)?;

    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::new(vec![domain.to_string()])?;
    for ip in &san_ips {
        server_params
            .subject_alt_names
            .push(SanType::IpAddress(*ip));
    }
    server_params
        .distinguished_name
        .push(DnType::CommonName, domain);
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    set_validity(&mut server_params, LEAF_VALIDITY_DAYS);
    server_params.use_authority_key_identifier_extension = true;
    let server_cert = server_params.signed_by(&server_key, &ca, &ca_key)?;

    let client_key = KeyPair::generate()?;
    let mut client_params = CertificateParams::new(vec![])?;
    client_params
        .distinguished_name
        .push(DnType::CommonName, "rep-client");
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    set_validity(&mut client_params, LEAF_VALIDITY_DAYS);
    client_params.use_authority_key_identifier_extension = true;
    let client_cert = client_params.signed_by(&client_key, &ca, &ca_key)?;

    write_cert(&files[0], &ca.pem())?;
    write_key(&files[1], &ca_key.serialize_pem())?;
    write_cert(&files[2], &server_cert.pem())?;
    write_key(&files[3], &server_key.serialize_pem())?;
    write_cert(&files[4], &client_cert.pem())?;
    write_key(&files[5], &client_key.serialize_pem())?;

    let server_toml = out.join("server.toml");
    if force || !server_toml.exists() {
        fs::write(
            &server_toml,
            toml::to_string_pretty(&ServerConfig {
                proxies: vec![ProxyConfig::default()],
                ..Default::default()
            })?,
        )?;
        println!("wrote {}", server_toml.display());
    } else {
        println!("{} exists, skipped", server_toml.display());
    }

    let client_toml = out.join("client.toml");
    if force || !client_toml.exists() {
        let cfg = ClientConfig {
            server_addr: format!("{domain}:7000"),
            server_name: domain.to_string(),
            ca: "certs/ca.pem".into(),
            cert: "certs/client.pem".into(),
            key: "certs/client.key".into(),
            ..Default::default()
        };
        fs::write(&client_toml, toml::to_string_pretty(&cfg)?)?;
        println!("wrote {}", client_toml.display());
    } else {
        println!("{} exists, skipped", client_toml.display());
    }

    println!();
    println!("server: rep server --config {}", server_toml.display());
    println!("client: rep client --config {}", client_toml.display());
    println!("client uses certs/client.pem; issue more with `rep cert issue-client`");
    Ok(())
}

pub fn run_issue_client(name: &str, config: &Path, force: bool) -> Result<()> {
    validate_client_name(name)?;
    let cfg = crate::config::load_server_config(config)?;
    let ca_path = PathBuf::from(&cfg.tunnel.tls.ca);
    let ca_key_path = ca_path.with_extension("key");
    let dir = ca_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let cert_path = dir.join(format!("{name}.pem"));
    let key_path = dir.join(format!("{name}.key"));
    if !force && (cert_path.exists() || key_path.exists()) {
        bail!(
            "{} already exists, use --force to overwrite",
            cert_path.display()
        );
    }
    let ca_pem =
        fs::read_to_string(&ca_path).with_context(|| format!("reading {}", ca_path.display()))?;
    let ca_key = KeyPair::from_pem(
        &fs::read_to_string(&ca_key_path)
            .with_context(|| format!("reading {} (CA private key)", ca_key_path.display()))?,
    )?;
    let ca_params =
        CertificateParams::from_ca_cert_pem(&ca_pem).context("parsing existing CA cert")?;
    // 用原 CA 的私钥与 subject 重建签名主体；签名与磁盘上的 ca.pem 使用同一公钥，链校验一致
    let ca = ca_params.self_signed(&ca_key)?;

    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![])?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    set_validity(&mut params, LEAF_VALIDITY_DAYS);
    params.use_authority_key_identifier_extension = true;
    let cert = params.signed_by(&key, &ca, &ca_key)?;

    let cert_path = dir.join(format!("{name}.pem"));
    let key_path = dir.join(format!("{name}.key"));
    write_cert(&cert_path, &cert.pem())?;
    write_key(&key_path, &key.serialize_pem())?;
    println!("wrote {} and {}", cert_path.display(), key_path.display());
    Ok(())
}

fn write_cert(path: &Path, pem: &str) -> Result<()> {
    fs::write(path, pem).with_context(|| format!("writing {}", path.display()))
}

fn write_key(path: &Path, pem: &str) -> Result<()> {
    fs::write(path, pem).with_context(|| format!("writing {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", path.display()))
}
