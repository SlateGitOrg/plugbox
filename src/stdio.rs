//! Guest stdout/stderr capture.
//!
//! A guest that floods stdout must neither exhaust host memory nor crash
//! itself, so writes beyond the per-request cap are accepted and discarded
//! (and counted) instead of returning an error — WASI's in-memory pipe would
//! report the stream as closed, which makes Rust's `println!` panic.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};

#[derive(Debug, Default)]
struct Buffer {
    data: Vec<u8>,
    dropped: usize,
}

/// A shared, size-capped output buffer usable as guest stdout and stderr.
#[derive(Clone, Debug)]
pub struct CappedPipe {
    cap: usize,
    buf: Arc<Mutex<Buffer>>,
}

impl CappedPipe {
    /// A pipe keeping at most `cap` bytes.
    pub fn new(cap: usize) -> CappedPipe {
        CappedPipe {
            cap,
            buf: Arc::new(Mutex::new(Buffer::default())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Buffer> {
        self.buf.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Append, keeping only what fits under the cap.
    pub fn write(&self, bytes: &[u8]) {
        let mut b = self.lock();
        let room = self.cap.saturating_sub(b.data.len());
        let keep = room.min(bytes.len());
        b.data.extend_from_slice(&bytes[..keep]);
        b.dropped += bytes.len() - keep;
    }

    /// Captured bytes so far (lossy UTF-8).
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.lock().data).into_owned()
    }

    /// Bytes discarded because the cap was reached.
    pub fn dropped(&self) -> usize {
        self.lock().dropped
    }
}

impl IsTerminal for CappedPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for CappedPipe {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }
}

impl AsyncWrite for CappedPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_and_counts() {
        let p = CappedPipe::new(5);
        let q = p.clone();
        p.write(b"abc");
        q.write(b"defg");
        assert_eq!(p.contents(), "abcde");
        assert_eq!(p.dropped(), 2);
        assert!(!p.is_terminal());
        let _ = p.async_stream();
    }

    #[test]
    fn async_write_never_errors() {
        let mut p = CappedPipe::new(2);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let r = Pin::new(&mut p).poll_write(&mut cx, b"hello");
        assert!(matches!(r, Poll::Ready(Ok(5))));
        assert!(matches!(
            Pin::new(&mut p).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut p).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(p.contents(), "he");
    }
}
