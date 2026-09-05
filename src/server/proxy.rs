use anyhow::{Context, Result, anyhow, bail};
use bytes::BytesMut;
use http::Uri;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use super::Registry;
use super::request_body::{BodyKind, RequestIo};
use super::tunnel::{ChannelMode, normalize_target_host};
use crate::config::ProxyConfig;

const MAX_HEAD: usize = 32 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    registry: Arc<Registry>,
    cfg: ProxyConfig,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(cfg.max_connections.max(1)));
    loop {
        let (mut tcp, peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        let tls = tls.clone();
        let registry = registry.clone();
        let permits = permits.clone();
        tokio::spawn(async move {
            // 并发达到上限直接拒绝；permit 由通道持有到桥接结束，
            // 限制的是活跃隧道数
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                let _ = write_simple(&mut tcp, 503, "Service Unavailable").await;
                return;
            };
            let res = match tls {
                Some(acc) => match tokio::time::timeout(HANDSHAKE_TIMEOUT, acc.accept(tcp)).await {
                    Ok(Ok(s)) => handle_conn(s, registry, permit).await,
                    Ok(Err(e)) => Err(anyhow!("proxy tls handshake: {e:#}")),
                    Err(_) => Err(anyhow!("proxy tls handshake timed out")),
                },
                None => handle_conn(tcp, registry, permit).await,
            };
            if let Err(e) = res {
                debug!(?peer, "proxy connection ended: {e:#}");
            }
        });
    }
}

async fn handle_conn<S>(
    mut io: S,
    registry: Arc<Registry>,
    permit: OwnedSemaphorePermit,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let head = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut io)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return Err(e),
        Err(_) => bail!("timed out reading request head"),
    };
    let parsed = match parse_head(head.as_bytes()) {
        Ok(p) => p,
        Err(e) => {
            // 解析失败按客户端错误回 400，而不是悄悄断开
            write_simple(&mut io, 400, "Bad Request").await?;
            bail!("malformed request head: {e:#}");
        }
    };
    let ParsedHead {
        method,
        target,
        headers,
        body,
    } = parsed;

    let state = match registry.current() {
        Some(s) => s,
        None => {
            write_simple(&mut io, 502, "Bad Gateway").await?;
            bail!("no tunnel client connected");
        }
    };

    if method == "CONNECT" {
        let (host, port) = parse_authority(&target);
        // 与 CONNECT 头同包到达的早期隧道数据必须保留
        let first = BytesMut::from(head.leftover()).freeze();
        state
            .open_channel(
                normalize_target_host(&host),
                port,
                Box::new(io),
                ChannelMode::Connect { first },
                permit,
            )
            .await?;
        Ok(())
    } else {
        let uri: Uri = target
            .parse()
            .with_context(|| format!("bad request target {target}"))?;
        if uri.scheme_str() != Some("http") {
            write_simple(&mut io, 400, "Bad Request").await?;
            bail!("non-http scheme through plain proxy: {target}");
        }
        let host = normalize_target_host(
            uri.host()
                .ok_or_else(|| anyhow!("request target has no host: {target}"))?,
        );
        let port = uri.port_u16().unwrap_or(80);
        let out = forward_head(&method, &uri, &headers)?;

        let io = RequestIo::new(io, BytesMut::from(head.leftover()).freeze(), body);
        state
            .open_channel(
                host,
                port,
                Box::new(io),
                ChannelMode::Relay { first: out.into() },
                permit,
            )
            .await?;
        Ok(())
    }
}

fn forward_head(method: &str, uri: &Uri, headers: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut origin = uri.path().to_string();
    if origin.is_empty() {
        origin.push('/');
    }
    if let Some(q) = uri.query() {
        origin.push('?');
        origin.push_str(q);
    }

    // Connection 值里点名的头 + 固定逐跳头一律剥除；
    // Content-Length / Transfer-Encoding 保留；parse_head 已拒绝 Connection 点名这些字段。
    let mut strip: Vec<Vec<u8>> = vec![
        b"host".to_vec(),
        b"connection".to_vec(),
        b"proxy-connection".to_vec(),
        b"proxy-authorization".to_vec(),
        b"keep-alive".to_vec(),
        b"upgrade".to_vec(),
    ];
    for (name, value) in headers {
        if name == "connection" {
            for tok in value.split(|&b| b == b',') {
                let t = tok.trim_ascii().to_ascii_lowercase();
                if !t.is_empty() && !strip.contains(&t) {
                    strip.push(t);
                }
            }
        }
    }
    // RFC 9112 §3.2.2：用 absolute-form 的 authority 重建 Host，保留端口和 IPv6 方括号。
    let authority = uri.authority().context("request target has no authority")?;
    let mut out = format!("{method} {origin} HTTP/1.1\r\nHost: {authority}\r\n").into_bytes();
    for (name, value) in headers {
        if strip.iter().any(|s| s == name.as_bytes()) {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    // 每条代理连接只处理第一个请求，避免后续 absolute-form 请求被透传到源站
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(out)
}

/// 读到 \r\n\r\n 为止，返回请求头与已随之读入的剩余字节。
struct Head {
    buf: BytesMut,
    head_len: usize,
}

impl Head {
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.head_len]
    }

    fn leftover(&self) -> &[u8] {
        &self.buf[self.head_len..]
    }
}

async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> Result<Head> {
    let mut buf = BytesMut::with_capacity(4096);
    loop {
        let n = io.read_buf(&mut buf).await?;
        if n == 0 {
            bail!("eof before request head finished");
        }
        if let Some(pos) = find_head_end(&buf) {
            // 无论终止符是否到达，超限一律拒绝
            if pos + 4 > MAX_HEAD {
                bail!("request head exceeds {MAX_HEAD} bytes");
            }
            return Ok(Head {
                buf,
                head_len: pos + 4,
            });
        }
        if buf.len() > MAX_HEAD {
            bail!("request head exceeds {MAX_HEAD} bytes");
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

struct ParsedHead {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
    body: BodyKind,
}

/// 用 httparse 做严格解析：非法头行直接报错；校验版本；
/// 拒绝重复 Content-Length、CL 与 TE 并存、非法 TE 序列及 Connection 点名报文分帧字段。
fn parse_head(head_bytes: &[u8]) -> Result<ParsedHead> {
    let mut raw_headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut raw_headers);
    match req.parse(head_bytes) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => bail!("malformed request head"),
    }
    let version = req.version.context("missing http version")?;
    if version > 1 {
        bail!("unsupported http version 1.{version}");
    }
    let method = req.method.context("missing method")?.to_string();
    let target = req.path.context("missing request target")?.to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    let mut has_te = false;
    let mut body_length = 0;
    for h in req.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        // 字段值允许 obs-text；按原始字节保留，不做有损 UTF-8 转换。
        let mut value = h.value.to_vec();
        match name.as_str() {
            "content-length" => {
                content_length += 1;
                let mut length = None;
                for part in value.split(|&b| b == b',').map(<[u8]>::trim_ascii) {
                    if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
                        bail!("invalid content-length");
                    }
                    let parsed: u64 = std::str::from_utf8(part)?
                        .parse()
                        .context("content-length overflow")?;
                    if length.is_some_and(|previous| previous != parsed) {
                        bail!("conflicting content-length values");
                    }
                    length = Some(parsed);
                }
                body_length = length.context("missing content-length")?;
                // 合法的相同值列表归一化，确保本地与源站使用完全相同的长度。
                value = body_length.to_string().into_bytes();
            }
            "transfer-encoding" => has_te = true,
            "connection" => {
                for token in value.split(|&b| b == b',').map(<[u8]>::trim_ascii) {
                    if token.eq_ignore_ascii_case(b"content-length")
                        || token.eq_ignore_ascii_case(b"transfer-encoding")
                    {
                        bail!("connection option names body framing field");
                    }
                }
            }
            _ => {}
        }
        headers.push((name, value));
    }
    if content_length > 1 {
        bail!("duplicate content-length");
    }
    if content_length == 1 && has_te {
        bail!("both content-length and transfer-encoding present");
    }
    if has_te {
        if version == 0 {
            bail!("transfer-encoding is not allowed in HTTP/1.0");
        }
        // 同名字段按出现顺序合并，避免后一个字段绕过 chunked 必须最后出现的校验。
        let value = headers
            .iter()
            .filter(|(name, _)| name == "transfer-encoding")
            .map(|(_, value)| value.as_slice())
            .collect::<Vec<_>>()
            .join(b",".as_slice());
        validate_transfer_encoding(&value)?;
    }
    Ok(ParsedHead {
        method,
        target,
        headers,
        body: if has_te {
            BodyKind::Chunked
        } else {
            BodyKind::Length(body_length)
        },
    })
}

/// RFC 9112 §6.1/6.3：请求必须以 chunked 收尾，且不能重复应用 chunked。
/// 仅校验头部并透传编码；扩展编码参数中的逗号可能位于 quoted-string 内。
fn validate_transfer_encoding(value: &[u8]) -> Result<()> {
    fn trim_ows(input: &[u8]) -> &[u8] {
        let len = input
            .iter()
            .take_while(|&&b| matches!(b, b' ' | b'\t'))
            .count();
        &input[len..]
    }

    fn token<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
        let len = input
            .iter()
            .take_while(|&&b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            .count();
        if len == 0 {
            bail!("invalid token in transfer-encoding");
        }
        let (value, rest) = input.split_at(len);
        *input = rest;
        Ok(value)
    }

    fn parameter_value(input: &mut &[u8]) -> Result<()> {
        if !input.starts_with(b"\"") {
            token(input)?;
            return Ok(());
        }
        *input = &input[1..];
        while let Some((&byte, rest)) = input.split_first() {
            *input = rest;
            let byte = match byte {
                b'"' => return Ok(()),
                b'\\' => {
                    let (&escaped, rest) = input
                        .split_first()
                        .context("unterminated escape in transfer-encoding")?;
                    *input = rest;
                    escaped
                }
                other => other,
            };
            if byte != b'\t' && (byte < b' ' || byte == 0x7f) {
                bail!("invalid quoted parameter in transfer-encoding");
            }
        }
        bail!("unterminated quoted parameter in transfer-encoding")
    }

    let mut rest = value;
    let mut chunked = false;
    loop {
        rest = trim_ows(rest);
        if rest.is_empty() {
            break;
        }
        // HTTP 列表允许接收方忽略空元素；头部总大小已受 MAX_HEAD 限制。
        if rest.starts_with(b",") {
            rest = &rest[1..];
            continue;
        }
        if chunked {
            bail!("chunked must occur exactly once and be the final transfer coding");
        }
        let coding = token(&mut rest)?;
        chunked = coding.eq_ignore_ascii_case(b"chunked");
        let forbids_parameters = [
            b"chunked".as_slice(),
            b"gzip",
            b"x-gzip",
            b"deflate",
            b"compress",
            b"x-compress",
        ]
        .iter()
        .any(|name| coding.eq_ignore_ascii_case(name));
        rest = trim_ows(rest);
        while rest.starts_with(b";") {
            if forbids_parameters {
                bail!("parameters are not allowed for this transfer coding");
            }
            rest = trim_ows(&rest[1..]);
            token(&mut rest)?;
            rest = trim_ows(rest);
            rest = trim_ows(
                rest.strip_prefix(b"=")
                    .context("missing '=' in transfer-encoding parameter")?,
            );
            parameter_value(&mut rest)?;
            rest = trim_ows(rest);
        }
        if !rest.is_empty() && !rest.starts_with(b",") {
            bail!("invalid separator in transfer-encoding");
        }
    }
    if !chunked {
        bail!("request transfer-encoding must end in chunked");
    }
    Ok(())
}

fn parse_authority(s: &str) -> (String, u16) {
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        return (host.to_string(), port);
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.parse::<u16>().is_ok() => {
            (h.to_string(), p.parse().unwrap())
        }
        _ => (s.to_string(), 443),
    }
}

async fn write_simple<S: AsyncWrite + Unpin>(io: &mut S, code: u16, reason: &str) -> Result<()> {
    io.write_all(
        format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await?;
    io.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obs_text_header_values_are_forwarded_byte_for_byte() {
        // 覆盖全部 obs-text 字节、重复字段、条件请求字段和 TE quoted-string。
        let value: Vec<u8> = (0x80..=0xff).collect();
        let mut raw =
            b"POST http://example.com/ HTTP/1.1\r\nHost: wrong.example\r\nX-Label: ".to_vec();
        raw.extend_from_slice(&value);
        raw.extend_from_slice(b"\r\nX-Label: caf\xe9\r\nIf-Match: \"\xff\"\r\nTransfer-Encoding: custom;label=\"\xe9\", chunked\r\nConnection: X-Hop\r\nX-Hop: \xff\r\n\r\n");
        let head = parse_head(&raw).unwrap();
        assert_eq!(head.body, BodyKind::Chunked);
        let wire =
            forward_head(&head.method, &head.target.parse().unwrap(), &head.headers).unwrap();
        let mut expected = b"POST / HTTP/1.1\r\nHost: example.com\r\nx-label: ".to_vec();
        expected.extend_from_slice(&value);
        expected.extend_from_slice(b"\r\nx-label: caf\xe9\r\nif-match: \"\xff\"\r\ntransfer-encoding: custom;label=\"\xe9\", chunked\r\nConnection: close\r\n\r\n");
        assert_eq!(wire, expected);
    }

    #[test]
    fn forwarded_host_comes_from_url_authority() {
        for (target, authority, origin) in [
            ("http://example.com/a?q=1", "example.com", "/a?q=1"),
            ("http://example.com:8080/", "example.com:8080", "/"),
            ("http://127.0.0.1:80", "127.0.0.1:80", "/"),
            ("http://[::1]/", "[::1]", "/"),
            ("http://[::1]:8080/a", "[::1]:8080", "/a"),
        ] {
            for incoming in [
                "Host: wrong.example\r\n",
                "",
                "Host: wrong.example\r\nhOsT: another.example\r\nConnection: Host, X-Hop\r\nX-Hop: secret\r\n",
            ] {
                let raw = format!("GET {target} HTTP/1.1\r\n{incoming}Accept: */*\r\n\r\n");
                let head = parse_head(raw.as_bytes()).unwrap();
                let wire = forward_head(&head.method, &head.target.parse().unwrap(), &head.headers)
                    .unwrap();
                let forwarded = parse_head(&wire).unwrap();
                assert_eq!(forwarded.target, origin);
                let hosts: Vec<_> = forwarded
                    .headers
                    .iter()
                    .filter(|(name, _)| name == "host")
                    .collect();
                assert_eq!(hosts.len(), 1);
                assert_eq!(hosts[0].1, authority.as_bytes());
                assert!(!forwarded.headers.iter().any(|(name, _)| name == "x-hop"));
                assert!(
                    forwarded
                        .headers
                        .contains(&("accept".into(), b"*/*".to_vec()))
                );
            }
        }
    }

    #[tokio::test]
    async fn connection_naming_body_framing_returns_400_and_closes() {
        for (field, mixed_case, value, body) in [
            ("Content-Length", "cOnTeNt-LeNgTh", "4", "test"),
            (
                "Transfer-Encoding",
                "tRaNsFeR-EnCoDiNg",
                "chunked",
                "4\r\ntest\r\n0\r\n\r\n",
            ),
        ] {
            for connection in [
                format!("Connection: {field}\r\n"),
                format!("cOnNeCtIoN:\tkeep-alive, {mixed_case}\t, X-Hop\r\n"),
                format!("Connection: keep-alive\r\nConnection: {field}\r\n"),
            ] {
                // 长度头位于 Connection 前后都必须拒绝；即便尚无隧道也应返回 400。
                for headers in [
                    format!("{field}: {value}\r\n{connection}"),
                    format!("{connection}{field}: {value}\r\n"),
                ] {
                    let (io, mut peer) = tokio::io::duplex(4096);
                    let request = format!(
                        "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\n{headers}\r\n{body}"
                    );
                    peer.write_all(request.as_bytes()).await.unwrap();
                    let permits = Arc::new(Semaphore::new(1));
                    let permit = permits.clone().acquire_owned().await.unwrap();
                    let result = handle_conn(io, Arc::new(Registry::new()), permit).await;
                    assert!(result.is_err());
                    let mut response = Vec::new();
                    tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut response))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(response, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "request: {request:?}");
                    assert_eq!(permits.available_permits(), 1);
                }
            }
        }
    }

    #[test]
    fn ordinary_connection_tokens_preserve_body_framing() {
        for (field, value) in [("content-length", "4"), ("transfer-encoding", "chunked")] {
            let request = format!(
                "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\n{field}: {value}\r\nConnection: keep-alive, X-Hop, X-Content-Length\r\nX-Hop: remove\r\nX-Content-Length: metadata\r\n\r\n"
            );
            let head = parse_head(request.as_bytes()).unwrap();
            let forwarded =
                forward_head(&head.method, &head.target.parse().unwrap(), &head.headers).unwrap();
            let forwarded = parse_head(&forwarded).unwrap();
            assert!(
                forwarded
                    .headers
                    .contains(&(field.into(), value.as_bytes().to_vec()))
            );
            assert!(
                !forwarded
                    .headers
                    .iter()
                    .any(|(name, _)| name == "x-hop" || name == "x-content-length")
            );
            assert!(
                forwarded
                    .headers
                    .contains(&("connection".into(), b"close".to_vec()))
            );
        }
    }

    #[tokio::test]
    async fn invalid_transfer_encoding_returns_400_and_closes() {
        for (version, headers) in [
            ("1.1", "Transfer-Encoding: gzip\r\n"),
            ("1.1", "Transfer-Encoding: chunked, gzip\r\n"),
            ("1.1", "Transfer-Encoding: chunked, CHUNKED\r\n"),
            (
                "1.1",
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n",
            ),
            (
                "1.1",
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            ),
            ("1.1", "Transfer-Encoding: \r\n"),
            ("1.1", "Transfer-Encoding: , ,\r\n"),
            ("1.1", "Transfer-Encoding: chunked;foo=bar\r\n"),
            ("1.1", "Transfer-Encoding: gzip;foo=bar, chunked\r\n"),
            ("1.1", "Transfer-Encoding: g zip, chunked\r\n"),
            ("1.1", "Transfer-Encoding: custom;foo, chunked\r\n"),
            ("1.1", "Transfer-Encoding: custom;foo=, chunked\r\n"),
            (
                "1.1",
                "Transfer-Encoding: custom;foo=\"unclosed, chunked\r\n",
            ),
            (
                "1.1",
                "Transfer-Encoding: custom;foo=\"closed\"junk, chunked\r\n",
            ),
            ("1.1", "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n"),
            ("1.0", "Transfer-Encoding: chunked\r\n"),
        ] {
            let (io, mut peer) = tokio::io::duplex(4096);
            let request = format!(
                "POST http://example.com/upload HTTP/{version}\r\nHost: example.com\r\n{headers}\r\n0\r\n\r\n"
            );
            peer.write_all(request.as_bytes()).await.unwrap();
            let permits = Arc::new(Semaphore::new(1));
            let permit = permits.clone().acquire_owned().await.unwrap();
            assert!(
                handle_conn(io, Arc::new(Registry::new()), permit)
                    .await
                    .is_err()
            );
            let mut response = String::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_string(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                response,
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "request: {request:?}"
            );
            assert_eq!(permits.available_permits(), 1);
        }
    }

    #[test]
    fn valid_transfer_encoding_is_preserved_when_forwarding() {
        for headers in [
            "Transfer-Encoding: chunked\r\n",
            "tRaNsFeR-EnCoDiNg:\tChUnKeD\t\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
            "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: deflate, gzip, chunked\r\n",
            "Transfer-Encoding: custom;foo=bar;quoted=\"a,b\\\"c\", chunked\r\n",
            "Transfer-Encoding: ,gzip, ,chunked,\r\n",
        ] {
            let raw = format!(
                "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\n{headers}\r\n"
            );
            let head = parse_head(raw.as_bytes()).unwrap();
            let forwarded =
                forward_head(&head.method, &head.target.parse().unwrap(), &head.headers).unwrap();
            let forwarded = parse_head(&forwarded).unwrap();
            let original: Vec<_> = head
                .headers
                .iter()
                .filter(|(name, _)| name == "transfer-encoding")
                .collect();
            let actual: Vec<_> = forwarded
                .headers
                .iter()
                .filter(|(name, _)| name == "transfer-encoding")
                .collect();
            assert_eq!(actual, original);
        }
    }

    #[test]
    fn content_length_is_validated_and_normalized_for_framing() {
        for value in ["", "+4", "-1", "four", "4,5", "4,", "18446744073709551616"] {
            let raw = format!(
                "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: {value}\r\n\r\n"
            );
            assert!(
                parse_head(raw.as_bytes()).is_err(),
                "accepted length {value:?}"
            );
        }
        for value in ["4", "004", "4, 4"] {
            let raw = format!(
                "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: {value}\r\n\r\n"
            );
            let head = parse_head(raw.as_bytes()).unwrap();
            assert_eq!(head.body, BodyKind::Length(4));
            let forwarded =
                forward_head(&head.method, &head.target.parse().unwrap(), &head.headers).unwrap();
            assert!(
                forwarded
                    .windows(b"content-length: 4\r\n".len())
                    .any(|line| line == b"content-length: 4\r\n")
            );
        }
        let head =
            parse_head(b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(head.body, BodyKind::Length(0));
    }
}
