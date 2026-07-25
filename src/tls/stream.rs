use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::Error;

pub struct TlsStream {
    inner: TcpStream,
}

impl TlsStream {
    pub fn handshake(stream: TcpStream, hostname: &str) -> Result<Self, Error> {
        todo!();
        Ok(Self { inner: stream })
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
