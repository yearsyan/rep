// 客户端内嵌(embed)生成:把含内嵌 PEM 的 client.toml 追加到二进制末尾,
// 客户端机器上单个可执行文件、零参数即可接入。
// 布局:[原二进制][payload UTF-8][payload 长度 u64 LE][魔数 "REPEMBD1"]
use anyhow::{Context, Result, bail};
use sha2::Digest;
use std::fs;
use std::io::{IsTerminal, BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::cert;
use crate::config::{self, ClientConfig, ProxyConfig};

const MAGIC: &[u8; 8] = b"REPEMBD1";
const TRAILER_LEN: usize = 8 + 8; // payload 长度 + 魔数
const DOWNLOAD_LIMIT: u64 = 64 * 1024 * 1024;
const RELEASE_REPO: &str = "yearsyan/rep";

// ---------------- 载荷读写 ----------------

/// 读取二进制末尾的内嵌配置;无标记或损坏返回 Ok(None)。
pub fn embedded_config(binary: &Path) -> Result<Option<String>> {
    let mut f = fs::File::open(binary).with_context(|| format!("opening {}", binary.display()))?;
    let size = f.metadata()?.len();
    if (size as usize) < TRAILER_LEN {
        return Ok(None);
    }
    f.seek(SeekFrom::End(-(TRAILER_LEN as i64)))?;
    let mut trailer = [0u8; TRAILER_LEN];
    f.read_exact(&mut trailer)?;
    if &trailer[8..] != MAGIC {
        return Ok(None);
    }
    let payload_len = u64::from_le_bytes(trailer[..8].try_into().unwrap()) as usize;
    if payload_len == 0 || payload_len + TRAILER_LEN > size as usize {
        return Ok(None); // 标记撞车或长度异常,当作无内嵌
    }
    f.seek(SeekFrom::End(-((payload_len + TRAILER_LEN) as i64)))?;
    let mut payload = vec![0u8; payload_len];
    f.read_exact(&mut payload)?;
    String::from_utf8(payload)
        .map(Some)
        .with_context(|| format!("embedded config in {} is not UTF-8", binary.display()))
}

/// 当前进程可执行文件的内嵌配置(无参启动路径用)。
pub fn embedded_config_of_current_exe() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    embedded_config(&exe).ok().flatten()
}

/// 把配置追加到 base 二进制,写出为 out。base 自带旧内嵌时先剥离,重复生成不嵌套。
pub fn append_config(base: &Path, config_text: &str, out: &Path) -> Result<()> {
    let mut data = fs::read(base).with_context(|| format!("reading {}", base.display()))?;
    if embedded_config(base)?.is_some() {
        let end = data.len() - TRAILER_LEN - config_len(&data);
        data.truncate(end);
    }
    data.extend_from_slice(config_text.as_bytes());
    data.extend_from_slice(&(config_text.len() as u64).to_le_bytes());
    data.extend_from_slice(MAGIC);
    fs::write(out, &data).with_context(|| format!("writing {}", out.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod {}", out.display()))?;
    }
    // macOS 上追加会破坏原有 codesign 签名,尽力做 ad-hoc 重签
    #[cfg(target_os = "macos")]
    {
        let st = std::process::Command::new("codesign")
            .args(["--force", "-s", "-"])
            .arg(out)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if !matches!(st, Ok(s) if s.success()) {
            tracing::warn!("codesign 重签失败,{} 可能无法在本机运行", out.display());
        }
    }
    Ok(())
}

// 从带尾部标记的数据里取 payload 长度(调用方已确认存在内嵌)
fn config_len(data: &[u8]) -> usize {
    u64::from_le_bytes(data[data.len() - TRAILER_LEN..data.len() - 8].try_into().unwrap()) as usize
}

// ---------------- Release 二进制获取 ----------------

/// 架构别名归一化为 release 产物名里的段:x86_64/amd64 → amd64,aarch64/arm64 → arm64。
fn normalize_arch(arch: &str) -> Result<&'static str> {
    match arch.to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" | "x64" => Ok("amd64"),
        "aarch64" | "arm64" => Ok("arm64"),
        _ => bail!("不支持的目标架构 {arch:?}(可选: amd64/x86_64, aarch64/arm64)"),
    }
}

fn current_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// 架构与当前进程相同时直接复制当前二进制,否则从 GitHub Release 下载对应产物。
fn obtain_binary(arch: &str, out: &Path) -> Result<()> {
    if arch == current_arch() {
        let exe = std::env::current_exe().context("定位当前可执行文件失败")?;
        fs::copy(&exe, out).with_context(|| format!("copying {}", exe.display()))?;
        println!("使用当前二进制({})", exe.display());
        return Ok(());
    }
    let ver = env!("CARGO_PKG_VERSION");
    let tag = format!("v{ver}");
    let pkg = format!("rep-{tag}-linux-{arch}.tar.gz");
    let base = format!("https://github.com/{RELEASE_REPO}/releases/download/{tag}");
    println!("从 Release {tag} 下载 {pkg} ...");
    let tarball = http_get(&format!("{base}/{pkg}"))
        .with_context(|| format!("下载 {pkg} 失败(确认 Release {tag} 已发布该架构产物)"))?;
    let sha_text = http_get(&format!("{base}/{pkg}.sha256")).context("下载 sha256 校验文件失败")?;
    verify_sha256(&tarball, &String::from_utf8_lossy(&sha_text))?;
    unpack_rep(&tarball, out)?;
    println!("已下载并校验 {pkg}");
    Ok(())
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(300))
        .build();
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(DOWNLOAD_LIMIT)
        .read_to_end(&mut buf)
        .context("读取响应体失败")?;
    Ok(buf)
}

fn verify_sha256(data: &[u8], expected_file: &str) -> Result<()> {
    let expect = expected_file.split_whitespace().next().unwrap_or("");
    let digest = sha2::Sha256::digest(data);
    let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if !expect.eq_ignore_ascii_case(&actual) {
        bail!("sha256 校验失败:期望 {expect},实际 {actual}");
    }
    Ok(())
}

// tar.gz 里取名为 rep 的成员;手动读字节写出,不走 unpack 避免路径穿越面
fn unpack_rep(tarball: &[u8], out: &Path) -> Result<()> {
    let gz = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(gz);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.to_string_lossy() != "rep" {
            continue;
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        fs::write(out, &buf).with_context(|| format!("writing {}", out.display()))?;
        return Ok(());
    }
    bail!("压缩包内没有 rep 可执行文件");
}

// ---------------- embed create 命令 ----------------

pub struct CreateArgs {
    pub name: Option<String>,
    pub config: PathBuf,
    pub arch: Option<String>,
    pub server_addr: Option<String>,
    pub listen: Option<String>,
    pub out: Option<PathBuf>,
    pub force: bool,
}

pub fn run_create(args: CreateArgs) -> Result<()> {
    // 1. 客户端名称:参数优先,缺省交互提示
    let name = match args.name.as_deref() {
        Some(n) => n.to_owned(),
        None => prompt_required("客户端名称 (如 office-b): ")?,
    };
    config::validate_client_name(&name)?;

    // 2. 服务端配置:校验 + 需要文件形态的 CA(issue-client 依赖同目录 ca.key)
    let cfg = config::load_server_config(&args.config)?;
    if config::is_inline_pem(&cfg.tunnel.tls.ca) {
        bail!("[tunnel.tls] ca 为内嵌 PEM;embed create 依赖 CA 文件路径定位 CA 私钥");
    }

    // 3. 签发客户端证书(复用 issue-client,含覆盖保护)
    cert::run_issue_client(&name, &args.config, args.force)?;

    // 4. 服务端地址:参数 > 同目录 client.toml > 交互提示
    let server_addr = match args.server_addr.as_deref() {
        Some(a) => a.to_owned(),
        None => sibling_client_server_addr(&args.config)
            .or_else(|| prompt_ok("服务端地址 (host:port): "))
            .context("需要 --server-addr(非交互且未找到可参考的 client.toml)")?,
    };
    let server_name = config::host_of(&server_addr).to_owned();

    // 5. 注册到服务端 [[proxies]]:重名复用既有端口,否则自动取下一个端口
    let raw = fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let (proxies_text, listen) = register_proxy(&raw, &name, args.listen.as_deref())?;
    if proxies_text != raw {
        fs::write(&args.config, &proxies_text)
            .with_context(|| format!("updating {}", args.config.display()))?;
        println!("已把 client_name={name} 加入 {listen}(重启 rep server 生效)");
    } else {
        println!("client_name={name} 已存在于配置,复用 {listen}");
    }

    // 6. 组装全内嵌 client.toml
    let cert_dir = PathBuf::from(&cfg.tunnel.tls.ca)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let ca_pem = read_pem(&cert_dir.join("ca.pem"))?;
    let cert_pem = read_pem(&cert_dir.join(format!("{name}.pem")))?;
    let key_pem = read_pem(&cert_dir.join(format!("{name}.key")))?;
    let client_toml = render_client_toml(&server_addr, &server_name, &ca_pem, &cert_pem, &key_pem);
    config::parse_client_config(&client_toml)?; // 落盘前先验证可解析

    // 7. 二进制来源 + 追加内嵌
    let arch = normalize_arch(args.arch.as_deref().unwrap_or(current_arch()))?;
    let out = args.out.clone().unwrap_or_else(|| format!("rep-client-{name}").into());
    let base_tmp = out.with_extension("base");
    obtain_binary(arch, &base_tmp)?;
    append_config(&base_tmp, &client_toml, &out)?;
    let _ = fs::remove_file(&base_tmp);

    println!();
    println!("完成:{}", out.display());
    println!("客户端机器上直接运行 ./{},无需任何参数或证书文件", out.file_name().and_then(|s| s.to_str()).unwrap_or("rep-client"));
    println!("代理端口 {listen} 将在服务端重启后对该客户端生效");
    Ok(())
}

fn read_pem(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if !text.contains("-----BEGIN") {
        bail!("{} 不是 PEM 格式", path.display());
    }
    Ok(text)
}

/// 在 server.toml 文本里注册新的 [[proxies]] 条目;重名时原样返回复用。
/// 返回 (新文本, 该客户端的监听地址)。用 toml::Value 往返,注释会丢失。
fn register_proxy(raw: &str, name: &str, listen_override: Option<&str>) -> Result<(String, String)> {
    let mut table: toml::Table =
        toml::from_str(raw).context("解析 server.toml 失败")?;
    // 旧式 [proxy] 先迁移为 [[proxies]] 首条目;否则会出现新旧格式混用,
    // 写回后 server 启动即被"proxy 与 proxies 不能混用"校验拒绝
    if let Some(legacy) = table.remove("proxy") {
        let mut legacy = match legacy {
            toml::Value::Table(t) => t,
            other => bail!("旧式 [proxy] 段格式异常({})", other.type_str()),
        };
        // 迁移条目补上缺省身份名,与 ProxyConfig::default 一致
        legacy
            .entry("client_name".to_owned())
            .or_insert_with(|| toml::Value::from("rep-client"));
        let arr = table
            .entry("proxies".to_owned())
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .context("\"proxies\" 必须是 [[proxies]] 数组")?;
        arr.insert(0, toml::Value::Table(legacy));
    }
    let proxies = table
        .entry("proxies".to_owned())
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let arr = proxies
        .as_array_mut()
        .context("\"proxies\" 必须是 [[proxies]] 数组")?;
    for entry in arr.iter() {
        if entry.get("client_name").and_then(|v| v.as_str()) == Some(name) {
            let listen = entry
                .get("listen")
                .and_then(|v| v.as_str())
                .context("既有 proxies 条目缺少 listen")?
                .to_owned();
            return Ok((raw.to_owned(), listen));
        }
    }
    let listen = match listen_override {
        Some(l) => l.to_owned(),
        None => next_listen(arr)?,
    };
    // 用 ProxyConfig 序列化保证字段齐全
    let proxy = ProxyConfig {
        client_name: name.to_owned(),
        listen: listen.clone(),
        ..Default::default()
    };
    arr.push(toml::Value::try_from(&proxy).context("序列化 proxies 条目失败")?);
    Ok((toml::to_string(&table)?, listen))
}

/// 取数组里最大的监听端口 +1 作为下一个端口,主机部分沿用最后一个条目。
fn next_listen(arr: &[toml::Value]) -> Result<String> {
    let mut best: Option<(String, u16)> = None;
    for entry in arr {
        let Some(listen) = entry.get("listen").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some((host, port)) = listen.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        if best.as_ref().map(|(_, p)| port >= *p).unwrap_or(true) {
            best = Some((host.to_owned(), port));
        }
    }
    match best {
        Some((host, port)) => Ok(format!("{host}:{}", port.saturating_add(1))),
        None => Ok("127.0.0.1:8080".to_owned()),
    }
}

fn sibling_client_server_addr(server_config: &Path) -> Option<String> {
    let client_toml = server_config.parent()?.join("client.toml");
    let text = fs::read_to_string(client_toml).ok()?;
    let cfg = config::parse_client_config(&text).ok()?;
    Some(cfg.server_addr)
}

fn render_client_toml(
    server_addr: &str,
    server_name: &str,
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
) -> String {
    let default = ClientConfig::default();
    let probe = default
        .ipv6_probe_addrs
        .iter()
        .map(|a| format!("  {a:?},"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"server_addr = "{server_addr}"
server_name = "{server_name}"
ca = """{ca_pem}"""
cert = """{cert_pem}"""
key = """{key_pem}"""

ipv6_probe_timeout_secs = {t}
ipv6_probe_addrs = [
{probe}
]

[retry]
target_attempts = {ta}
connect_timeout_secs = {ct}
keepalive_secs = {ka}
reconnect_initial_ms = {ri}
reconnect_max_ms = {rm}
"#,
        t = default.ipv6_probe_timeout_secs,
        ta = default.retry.target_attempts,
        ct = default.retry.connect_timeout_secs,
        ka = default.retry.keepalive_secs,
        ri = default.retry.reconnect_initial_ms,
        rm = default.retry.reconnect_max_ms,
    )
}

// ---------------- 交互输入 ----------------

fn prompt(print: &str) -> Result<String> {
    let mut out = std::io::stdout().lock();
    out.write_all(print.as_bytes())?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

/// 必填项:有终端就交互询问,无终端直接报错
fn prompt_required(label: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("非交互环境缺少必填参数:{label}");
    }
    loop {
        let v = prompt(label)?;
        if !v.is_empty() {
            return Ok(v);
        }
    }
}

fn prompt_ok(label: &str) -> Option<String> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let v = prompt(label).ok()?;
    (!v.is_empty()).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("rep-embed-test-{tag}-{}", std::process::id()));
        p
    }

    #[test]
    fn append_and_read_roundtrip() {
        let base = tmp_file("base");
        let out = tmp_file("out");
        fs::write(&base, b"fake-binary-bytes-0000").unwrap();
        let cfg = "server_addr = \"x:1\"\n";
        append_config(&base, cfg, &out).unwrap();
        assert_eq!(embedded_config(&out).unwrap().unwrap(), cfg);
        // 原始二进制不受影响
        assert_eq!(embedded_config(&base).unwrap(), None);

        // 重复生成:以带内嵌的二进制为源再生成,应剥离旧的而不是嵌套
        let cfg2 = "server_addr = \"y:2\"\n";
        let out2 = tmp_file("out2");
        append_config(&out, cfg2, &out2).unwrap();
        assert_eq!(embedded_config(&out2).unwrap().unwrap(), cfg2);
        assert_eq!(out2.metadata().unwrap().len() as usize, 22 + cfg2.len() + TRAILER_LEN);

        // 损坏尾部按无内嵌处理
        let mut broken = fs::read(&out).unwrap();
        let n = broken.len();
        broken[n - 1] ^= 0xff;
        fs::write(&out, &broken).unwrap();
        assert_eq!(embedded_config(&out).unwrap(), None);

        let _ = fs::remove_file(&base);
        let _ = fs::remove_file(&out);
        let _ = fs::remove_file(&out2);
    }

    #[test]
    fn registers_proxy_and_picks_next_port() {
        let raw = "[tunnel]\nlisten = \"0.0.0.0:7000\"\n\n[[proxies]]\nclient_name = \"rep-client\"\nlisten = \"0.0.0.0:8080\"\n";
        let (text, listen) = register_proxy(raw, "office-b", None).unwrap();
        assert_eq!(listen, "0.0.0.0:8081");
        assert!(text.contains("client_name = \"office-b\""));
        assert!(text.contains("listen = \"0.0.0.0:8081\""));
        // 重名复用
        let (text2, listen2) = register_proxy(&text, "office-b", None).unwrap();
        assert_eq!(text2, text);
        assert_eq!(listen2, "0.0.0.0:8081");
        // 显式指定
        let (_, listen3) = register_proxy(raw, "office-c", Some("127.0.0.1:9000")).unwrap();
        assert_eq!(listen3, "127.0.0.1:9000");
        // 空配置默认
        let (_, listen4) = register_proxy("", "a", None).unwrap();
        assert_eq!(listen4, "127.0.0.1:8080");
    }

    #[test]
    fn migrates_legacy_proxy_section_instead_of_mixing_formats() {
        let raw = "[proxy]\nlisten = \"127.0.0.1:17808\"\n\n[tunnel]\nlisten = \"0.0.0.0:17400\"\n";
        let (text, listen) = register_proxy(raw, "office-b", None).unwrap();
        // 新条目端口沿用迁移后旧监听 +1,而不是回退到默认 8080
        assert_eq!(listen, "127.0.0.1:17809");
        // 不允许新旧格式混用:旧段必须被移除
        assert!(!text.contains("[proxy]"));
        assert_eq!(text.matches("[[proxies]]").count(), 2);
        assert!(text.contains("client_name = \"rep-client\""));
        assert!(text.contains("client_name = \"office-b\""));
        // 写回结果必须仍能通过服务端配置校验
        let cfg: crate::config::ServerConfig = toml::from_str(&text).unwrap();
        assert_eq!(cfg.proxy_configs().unwrap().len(), 2);
    }
}
