use futures::{AsyncRead, AsyncWrite};
use log::error;
use std::io::{self, Read, Write};
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct ClonableStream<T: Read + Write>(Arc<Mutex<T>>);

impl<T: Read + Write> Read for ClonableStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| {
                error!("Unable to acquire lock on ClonableStream read operation");
                io::Error::from(io::ErrorKind::BrokenPipe)
            })?
            .read(buf)
    }
}

impl<T: Read + Write> Write for ClonableStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| {
                error!("Unable to acquire lock on ClonableStream write operation");
                io::Error::from(io::ErrorKind::BrokenPipe)
            })?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| {
                error!("Unable to acquire lock on ClonableStream flush operation");
                io::Error::from(io::ErrorKind::BrokenPipe)
            })?
            .flush()
    }
}

impl<T: Read + Write> From<T> for ClonableStream<T> {
    fn from(stream: T) -> Self {
        Self(Arc::new(Mutex::new(stream)))
    }
}

impl<T: Read + Write> Clone for ClonableStream<T> {
    fn clone(&self) -> Self {
        ClonableStream(Arc::clone(&self.0))
    }
}

#[derive(Debug)]
pub struct ClonableAsyncStream<T: AsyncRead + AsyncWrite + Unpin>(Arc<Mutex<T>>);

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClonableAsyncStream<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut stream = self.0.lock().map_err(|_| {
            error!("Unable to acquire lock on ClonableAsyncStream read operation");
            io::Error::from(io::ErrorKind::BrokenPipe)
        })?;
        Pin::new(stream.deref_mut()).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClonableAsyncStream<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut stream = self.0.lock().map_err(|_| {
            error!("Unable to acquire lock on ClonableAsyncStream write operation");
            io::Error::from(io::ErrorKind::BrokenPipe)
        })?;
        Pin::new(stream.deref_mut()).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut stream = self.0.lock().map_err(|_| {
            error!("Unable to acquire lock on ClonableAsyncStream flush operation");
            io::Error::from(io::ErrorKind::BrokenPipe)
        })?;
        Pin::new(stream.deref_mut()).poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut stream = self.0.lock().map_err(|_| {
            error!("Unable to acquire lock on ClonableAsyncStream close operation");
            io::Error::from(io::ErrorKind::BrokenPipe)
        })?;
        Pin::new(stream.deref_mut()).poll_close(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> From<T> for ClonableAsyncStream<T> {
    fn from(stream: T) -> Self {
        Self(Arc::new(Mutex::new(stream)))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Clone for ClonableAsyncStream<T> {
    fn clone(&self) -> Self {
        ClonableAsyncStream(Arc::clone(&self.0))
    }
}
