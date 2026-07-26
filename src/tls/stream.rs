use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::{Error, anyhow};

const LEGACY_RECORD_VERSION: u16 = 0x0303;

pub fn handshake(mut stream: TcpStream, _hostname: &str) -> Result<TlsStream, Error> {
    let mut buf = [0u8; 512];
    let req = TlsWriter::new(&mut buf).encode_record(Record {
        content_type: ContentType::Handshake,
        length: 0,
        fragment: vec![],
    })?;

    println!("handshake req: {:?}", req);
    stream.write_all(req)?;

    // wip...
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp)?;
    println!("handshake resp: {:?}", resp);
    // ...

    Ok(TlsStream { inner: stream })
}

pub struct TlsStream {
    inner: TcpStream,
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
    length: u16,
    fragment: Vec<u8>,
}

enum ContentType {
    Handshake,
}

impl ContentType {
    fn encode(&self) -> [u8; 1] {
        match self {
            Self::Handshake => 0x16u8.to_be_bytes(),
        }
    }
}

struct TlsWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> TlsWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn encode_record(mut self, record: Record) -> Result<&'a [u8], Error> {
        self.set_bytes(&record.content_type.encode())?;
        self.set_bytes(&LEGACY_RECORD_VERSION.to_be_bytes())?;
        self.set_bytes(&record.length.to_be_bytes())?;
        self.set_bytes(&record.fragment.as_slice())?;
        Ok(&self.buf[0..self.pos])
    }

    fn set_bytes(&mut self, data: &[u8]) -> Result<(), Error> {
        let slot = self
            .buf
            .get_mut(self.pos..self.pos + data.len())
            .ok_or_else(|| anyhow!("unexpected end of buf"))?;
        slot.copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }
}
