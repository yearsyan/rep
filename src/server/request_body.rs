use bytes::{Buf, Bytes};
use std::future::Future;
use std::io::{self, Cursor};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, BufReader, Chain, ReadBuf};

const MAX_METADATA: usize = 32 * 1024;
const MAX_DISCARD: usize = 64 * 1024;
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyKind {
    Length(u64),
    Chunked,
}

#[derive(Clone, Copy)]
enum State {
    Fixed(u64),
    Size,
    Data(u64),
    DataEnd,
    Trailers,
    Done,
}

/// 读方向只暴露当前 HTTP 请求体，写方向仍直接回传响应。
/// 预读字节与后续 socket 数据走同一个解析器，后续请求永远不会成为隧道数据。
pub(super) struct RequestIo<S> {
    input: Chain<Cursor<Bytes>, BufReader<S>>,
    state: State,
    line: Vec<u8>,
    ready: Bytes,
    trailer_bytes: usize,
    body_started: bool,
    write_closed: bool,
    close_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    discarded: usize,
    close_done: bool,
}

impl<S: AsyncRead + Unpin> RequestIo<S> {
    pub fn new(io: S, prefix: Bytes, kind: BodyKind) -> Self {
        Self {
            input: AsyncReadExt::chain(Cursor::new(prefix), BufReader::new(io)),
            state: match kind {
                BodyKind::Length(n) => State::Fixed(n),
                BodyKind::Chunked => State::Size,
            },
            line: Vec::new(),
            ready: Bytes::new(),
            trailer_bytes: 0,
            body_started: false,
            write_closed: false,
            close_timer: None,
            discarded: 0,
            close_done: false,
        }
    }

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
        remaining: u64,
    ) -> Poll<io::Result<usize>> {
        let data = ready!(Pin::new(&mut self.input).poll_fill_buf(cx))?;
        if data.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete HTTP request body",
            )));
        }
        let n = remaining.min(data.len().min(out.remaining()) as u64) as usize;
        out.put_slice(&data[..n]);
        Pin::new(&mut self.input).consume(n);
        Poll::Ready(Ok(n))
    }

    // 元数据整行验证后才向目标暴露；数据部分按剩余长度直接流式转发。
    fn poll_line(&mut self, cx: &mut Context<'_>, limit: usize) -> Poll<io::Result<Bytes>> {
        loop {
            let data = ready!(Pin::new(&mut self.input).poll_fill_buf(cx))?;
            if data.is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete chunked metadata",
                )));
            }
            let newline = data.iter().position(|&b| b == b'\n');
            let n = newline.map_or(data.len(), |i| i + 1);
            if self.line.len() + n > limit {
                return Poll::Ready(Err(invalid("chunked metadata too large")));
            }
            self.line.extend_from_slice(&data[..n]);
            Pin::new(&mut self.input).consume(n);
            if newline.is_some() {
                if !self.line.ends_with(b"\r\n")
                    || self.line[..self.line.len() - 2].contains(&b'\r')
                {
                    return Poll::Ready(Err(invalid("chunked metadata requires CRLF")));
                }
                return Poll::Ready(Ok(std::mem::take(&mut self.line).into()));
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RequestIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.body_started = true;
        loop {
            if !this.ready.is_empty() {
                let n = this.ready.len().min(out.remaining());
                out.put_slice(&this.ready[..n]);
                this.ready.advance(n);
                return Poll::Ready(Ok(()));
            }
            match this.state {
                State::Done | State::Fixed(0) => return Poll::Ready(Ok(())),
                State::Fixed(remaining) => {
                    let n = ready!(this.poll_data(cx, out, remaining))?;
                    this.state = State::Fixed(remaining - n as u64);
                    return Poll::Ready(Ok(()));
                }
                State::Size => {
                    let line = ready!(this.poll_line(cx, MAX_METADATA))?;
                    // httparse 允许缺少十六进制数字的宽松形式，这里显式要求 1*HEXDIG。
                    if !line.first().is_some_and(u8::is_ascii_hexdigit) {
                        return Poll::Ready(Err(invalid("missing chunk size")));
                    }
                    let size = match httparse::parse_chunk_size(&line) {
                        Ok(httparse::Status::Complete((n, size))) if n == line.len() => size,
                        _ => return Poll::Ready(Err(invalid("invalid chunk size"))),
                    };
                    this.state = if size == 0 {
                        State::Trailers
                    } else {
                        State::Data(size)
                    };
                    this.ready = line;
                }
                State::Data(remaining) => {
                    let n = ready!(this.poll_data(cx, out, remaining))?;
                    let remaining = remaining - n as u64;
                    this.state = if remaining == 0 {
                        State::DataEnd
                    } else {
                        State::Data(remaining)
                    };
                    return Poll::Ready(Ok(()));
                }
                State::DataEnd => {
                    let line = ready!(this.poll_line(cx, 2))?;
                    if line.as_ref() != b"\r\n" {
                        return Poll::Ready(Err(invalid("missing CRLF after chunk data")));
                    }
                    this.ready = line;
                    this.state = State::Size;
                }
                State::Trailers => {
                    let line = ready!(this.poll_line(cx, MAX_METADATA - this.trailer_bytes))?;
                    this.trailer_bytes += line.len();
                    if line.as_ref() == b"\r\n" {
                        this.state = State::Done;
                    } else {
                        let mut head = line.to_vec();
                        head.extend_from_slice(b"\r\n");
                        let mut headers = [httparse::EMPTY_HEADER; 1];
                        if !matches!(
                            httparse::parse_headers(&head, &mut headers),
                            Ok(httparse::Status::Complete((_, [_])))
                        ) {
                            return Poll::Ready(Err(invalid("invalid chunked trailer")));
                        }
                    }
                    this.ready = line;
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RequestIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().input.get_mut().1).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().input.get_mut().1).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            // 源站提前结束响应时也停止上传，避免上传与关闭清理同时消费输入。
            this.state = State::Done;
            this.ready = Bytes::new();
            this.line.clear();
            // 先送出响应末尾和 FIN/close_notify，让用户读完当前响应。
            ready!(Pin::new(&mut this.input.get_mut().1).poll_shutdown(cx))?;
            this.write_closed = true;
            this.close_timer = Some(Box::pin(tokio::time::sleep(CLOSE_TIMEOUT)));
            // 目标建立失败时的 502 不进入 linger，避免拖慢会话的 pending 清理。
            this.close_done = !this.body_started;
        }
        // 普通 HTTP 的后续请求就地丢弃，避免带未读数据关闭 TCP 引发 RST。
        // 等待与丢弃量均有上限，持续发送或不关闭的用户不能无限占用任务。
        while !this.close_done {
            if this.discarded >= MAX_DISCARD
                || this
                    .close_timer
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .poll(cx)
                    .is_ready()
            {
                this.close_done = true;
                break;
            }
            match Pin::new(&mut this.input).poll_fill_buf(cx) {
                Poll::Ready(Ok(data)) if !data.is_empty() => {
                    let n = data.len().min(MAX_DISCARD - this.discarded);
                    Pin::new(&mut this.input).consume(n);
                    this.discarded += n;
                }
                Poll::Ready(_) => this.close_done = true,
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    const NEXT: &[u8] =
        b"GET http://second.example/private HTTP/1.1\r\nHost: second.example\r\n\r\n";

    #[tokio::test]
    async fn stops_at_first_body_for_every_prefetch_boundary() {
        let cases: &[(BodyKind, &[u8])] = &[
            (BodyKind::Length(0), b""),
            (BodyKind::Length(4), b"test"),
            (BodyKind::Chunked, b"0\r\n\r\n"),
            (
                BodyKind::Chunked,
                b"4;note=\"a;b\"\r\ntest\r\n3\r\nend\r\n0\r\nChecksum: value\r\n\r\n",
            ),
        ];
        for &(kind, body) in cases {
            let wire = [body, NEXT].concat();
            for split in 0..=wire.len() {
                for read_size in [1, 7, 8192] {
                    let mut io = RequestIo::new(
                        Cursor::new(wire[split..].to_vec()),
                        Bytes::copy_from_slice(&wire[..split]),
                        kind,
                    );
                    let mut output = Vec::new();
                    let mut buffer = vec![0; read_size];
                    loop {
                        let n = io.read(&mut buffer).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        output.extend_from_slice(&buffer[..n]);
                    }
                    assert_eq!(
                        output, body,
                        "kind={kind:?}, split={split}, read_size={read_size}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn large_body_and_request_like_payload_are_preserved() {
        let body = NEXT.repeat(16384);
        for chunked in [false, true] {
            let (kind, encoded) = if chunked {
                let mut encoded = format!("{:x}\r\n", body.len()).into_bytes();
                encoded.extend_from_slice(&body);
                encoded.extend_from_slice(b"\r\n0\r\n\r\n");
                (BodyKind::Chunked, encoded)
            } else {
                (BodyKind::Length(body.len() as u64), body.clone())
            };
            let mut io = RequestIo::new(
                Cursor::new([encoded.as_slice(), NEXT].concat()),
                Bytes::new(),
                kind,
            );
            let mut received = Vec::new();
            io.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, encoded);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn response_can_be_written_while_upload_is_pending() {
        for kind in [BodyKind::Length(4), BodyKind::Chunked] {
            let (socket, mut peer) = tokio::io::duplex(256);
            let mut io = RequestIo::new(socket, Bytes::new(), kind);
            assert!(
                tokio::time::timeout(Duration::from_millis(1), io.read(&mut [0; 1]))
                    .await
                    .is_err()
            );
            io.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();
            let mut interim = vec![0; 25];
            peer.read_exact(&mut interim).await.unwrap();
            assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n");
            let body: &[u8] = if kind == BodyKind::Chunked {
                b"4\r\ntest\r\n0\r\n\r\n"
            } else {
                b"test"
            };
            peer.write_all(&[body, NEXT].concat()).await.unwrap();
            let mut output = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), io.read_to_end(&mut output))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(output, body);
        }
    }

    #[tokio::test]
    async fn malformed_or_truncated_bodies_fail() {
        let cases: &[(BodyKind, &[u8])] = &[
            (BodyKind::Length(4), b"tes"),
            (BodyKind::Chunked, b"4\r\ntes"),
            (BodyKind::Chunked, b"4\r\ntest"),
            (BodyKind::Chunked, b"0\r\nChecksum: unfinished"),
            (BodyKind::Chunked, b"Z\r\n"),
            (BodyKind::Chunked, b"\r\n"),
            (BodyKind::Chunked, b";extension\r\n"),
            (BodyKind::Chunked, b"10000000000000000\r\n"),
            (BodyKind::Chunked, b"1\na\r\n0\r\n\r\n"),
            (BodyKind::Chunked, b"1\r\naXX\r\n0\r\n\r\n"),
            (BodyKind::Chunked, b"0\r\nnot-a-trailer\r\n\r\n"),
        ];
        for &(kind, body) in cases {
            let mut io = RequestIo::new(Cursor::new(body), Bytes::new(), kind);
            assert!(
                io.read_to_end(&mut Vec::new()).await.is_err(),
                "accepted {body:?}"
            );
        }
    }

    #[tokio::test]
    async fn chunked_metadata_is_bounded() {
        let long_size = format!("1;{}\r\na\r\n0\r\n\r\n", "x".repeat(MAX_METADATA));
        let long_trailers = format!(
            "0\r\n{}\r\n",
            format!("X: {}\r\n", "x".repeat(1024)).repeat(33)
        );
        for body in [long_size, long_trailers] {
            let mut io = RequestIo::new(
                Cursor::new(body.into_bytes()),
                Bytes::new(),
                BodyKind::Chunked,
            );
            let error = io.read_to_end(&mut Vec::new()).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn chunked_body_handles_bytewise_delivery() {
        let body = b"4;note=value\r\ntest\r\n0\r\nChecksum: value\r\n\r\n";
        let wire = [body.as_slice(), NEXT].concat();
        let (socket, mut peer) = tokio::io::duplex(wire.len());
        let mut io = RequestIo::new(socket, Bytes::new(), BodyKind::Chunked);
        let send = async {
            for byte in wire {
                peer.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        };
        let receive = async {
            let mut output = Vec::new();
            io.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, body);
        };
        tokio::join!(send, receive);
    }

    #[tokio::test(start_paused = true)]
    async fn response_shutdown_discards_extra_input_with_limits() {
        for byte_limit in [false, true] {
            let (socket, mut peer) = tokio::io::duplex(MAX_DISCARD * 2);
            let mut io = RequestIo::new(socket, Bytes::new(), BodyKind::Length(0));
            assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0);
            if byte_limit {
                peer.write_all(&vec![b'x'; MAX_DISCARD + 1]).await.unwrap();
            }
            let start = tokio::time::Instant::now();
            io.shutdown().await.unwrap();
            assert_eq!(io.discarded, if byte_limit { MAX_DISCARD } else { 0 });
            assert_eq!(
                start.elapsed(),
                if byte_limit {
                    Duration::ZERO
                } else {
                    CLOSE_TIMEOUT
                }
            );
            assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn setup_failure_shutdown_does_not_delay_pending_cleanup() {
        let (socket, _peer) = tokio::io::duplex(256);
        let mut io = RequestIo::new(socket, Bytes::new(), BodyKind::Length(0));
        let start = tokio::time::Instant::now();
        io.shutdown().await.unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn response_ending_early_stops_the_incomplete_upload() {
        let (socket, mut peer) = tokio::io::duplex(256);
        let mut io = RequestIo::new(socket, Bytes::new(), BodyKind::Length(100));
        peer.write_all(b"x").await.unwrap();
        assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 1);
        io.shutdown().await.unwrap();
        assert_eq!(io.read(&mut [0; 1]).await.unwrap(), 0);
    }
}
