use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::Error;

const LEGACY_RECORD_VERSION: u16 = 0x0303;

pub struct TlsStream {
    inner: TcpStream,
}

impl TlsStream {
    pub fn handshake(stream: TcpStream, hostname: &str) -> Result<Self, Error> {
        let handshake = Record {
            content_type: ContentType::HANDSHAKE,
            version: ProtocolVersion::TLS1_2,
            length: 0,
            fragment: vec![],
        };

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

struct Record {
    content_type: ContentType,
    version: ProtocolVersion,
    length: u16,
    fragment: Vec<u8>,
}

enum ContentType {
    HANDSHAKE,
}

impl ContentType {
    fn encode(&self) -> u8 {
        match self {
            Self::HANDSHAKE => 0x16,
        }
    }
}

enum ProtocolVersion {
    TLS1_2,
}

impl ProtocolVersion {
    fn encode(&self) -> u16 {
        match self {
            Self::TLS1_2 => 0x0303,
        }
    }
}
