use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

pub const CHANNEL_HEADER: &str = "x-rep-channel";
pub const CONTROL_PATH: &str = "/session";

const MAX_FRAME: usize = 1 << 20;

/// 去掉 host 两侧的 IPv6 方括号，得到 socket 形式（ "::1" 而非 "[::1]"）。
pub fn socket_host(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

/// 由 socket 形式 host 构造合法的 HTTP authority（IPv6 自动补方括号）。
pub fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Frame {
    ChannelOpen { id: u64, host: String, port: u16 },
    ChannelResult { id: u64, ok: bool, err: Option<String> },
}

pub fn encode_frame(frame: &Frame) -> Bytes {
    let payload = serde_json::to_vec(frame).expect("serialize control frame");
    let mut buf = BytesMut::with_capacity(5 + payload.len());
    buf.put_u32(payload.len() as u32 + 1);
    match frame {
        Frame::ChannelOpen { .. } => buf.put_u8(1),
        Frame::ChannelResult { .. } => buf.put_u8(2),
    }
    buf.put_slice(&payload);
    buf.freeze()
}

pub struct FrameDecoder {
    buf: BytesMut,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let len = (&self.buf[..4]).get_u32() as usize;
        if !(1..=MAX_FRAME).contains(&len) {
            // 坏帧就地丢弃，避免残留在缓冲里对后续数据反复报错
            self.buf.clear();
            bail!("invalid control frame length {len}");
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        self.buf.advance(4);
        let kind = self.buf.get_u8();
        let payload = self.buf.split_to(len - 1).freeze();
        match kind {
            1 | 2 => Ok(Some(serde_json::from_slice(&payload)?)),
            other => bail!("unknown control frame type {other}"),
        }
    }
}

/// 把一条 h2 流包装成 AsyncRead + AsyncWrite，双向都遵守 h2 流控。
pub struct H2Io {
    recv: RecvStream,
    send: SendStream<Bytes>,
    leftover: Bytes,
    send_closed: bool,
}

impl H2Io {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            leftover: Bytes::new(),
            send_closed: false,
        }
    }
}

impl AsyncRead for H2Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.leftover.is_empty() {
            let n = self.leftover.len().min(buf.remaining());
            buf.put_slice(&self.leftover[..n]);
            self.leftover.advance(n);
            return Poll::Ready(Ok(()));
        }
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let _ = self.recv.flow_control().release_capacity(chunk.len());
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                self.leftover = chunk.slice(n..);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(h2_io_err(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.send_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "h2 stream already closed",
            )));
        }
        let want = buf.len().min(64 * 1024);
        self.send.reserve_capacity(want);
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(avail))) => {
                let n = avail.min(want);
                let data = Bytes::copy_from_slice(&buf[..n]);
                self.send
                    .send_data(data, false)
                    .map_err(h2_io_err)?;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(h2_io_err(e))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "h2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.send_closed {
            let _ = self.send.send_data(Bytes::new(), true);
            self.send_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

fn h2_io_err(e: h2::Error) -> io::Error {
    if e.is_reset() {
        io::Error::new(io::ErrorKind::ConnectionReset, e)
    } else {
        io::Error::other(e)
    }
}

/// 从 h2 RecvStream 读出下一个 chunk（poll_data 的 async 形式）。
pub async fn recv_chunk(body: &mut RecvStream) -> Option<io::Result<Bytes>> {
    match poll_fn(|cx| body.poll_data(cx)).await {
        Some(Ok(b)) => Some(Ok(b)),
        Some(Err(e)) => Some(Err(h2_io_err(e))),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frames = vec![
            Frame::ChannelOpen {
                id: 7,
                host: "example.com".into(),
                port: 443,
            },
            Frame::ChannelResult {
                id: 8,
                ok: false,
                err: Some("boom".into()),
            },
        ];
        let mut wire = BytesMut::new();
        for f in &frames {
            wire.extend_from_slice(&encode_frame(f));
        }
        // 拆成任意大小喂给解码器
        let mut dec = FrameDecoder::new();
        let all = wire.freeze();
        for chunk in all.chunks(3) {
            dec.push(chunk);
            while let Some(f) = dec.next_frame().unwrap() {
                assert!(frames.contains(&f));
            }
        }
        assert!(dec.next_frame().unwrap().is_none());
    }

    #[test]
    fn host_normalization() {
        assert_eq!(socket_host("[::1]"), "::1");
        assert_eq!(socket_host("example.com"), "example.com");
        assert_eq!(format_authority("::1", 80), "[::1]:80");
        assert_eq!(format_authority("example.com", 80), "example.com:80");
    }
}
