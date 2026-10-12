use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::{Error, anyhow, bail};

const LEGACY_RECORD_VERSION: u16 = 0x0303;
const MAX_RECORD_SIZE: usize = 16384;

pub fn handshake(mut stream: TcpStream, _hostname: &str) -> Result<TlsStream, Error> {
    let mut buf = [0u8; MAX_RECORD_SIZE];

    let req = Record::Handshake(vec![]);

    println!("handshake req: {:?}", req);

    stream.write_all(TlsWriter::new(&mut buf).encode(req)?)?;

    stream.read_exact(&mut buf[0..5])?;
    let ctype = *buf
        .get(0)
        .ok_or_else(|| anyhow!("missing content type in response"))?;
    let len = u16::from_be_bytes(buf[3..5].try_into()?);
    stream.read_exact(&mut buf[..usize::from(len)])?;

    let resp = TlsReader::new(&buf).decode(ctype, len)?;

    println!("handshake resp: {:?}", resp);

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

struct TlsWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> TlsWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn encode(mut self, record: Record) -> Result<&'a [u8], Error> {
        self.set_bytes(&record.encode_content_type().to_be_bytes())?;
        self.set_bytes(&LEGACY_RECORD_VERSION.to_be_bytes())?;
        let fragment = record.encode_fragment();
        self.set_bytes(&fragment.len().to_be_bytes())?;
        self.set_bytes(&fragment.as_slice())?;
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

struct TlsReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TlsReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn decode(&self, ctype: u8, len: u16) -> Result<Record, Error> {
        Ok(Record::decode(ctype, &self.buf[..usize::from(len)])?)
    }
}

#[derive(Debug)]
enum Record {
    Invalid,
    ChangeCipherSpec,
    Alert(AlertType, AlertDescription),
    Handshake(Vec<u8>), // TODO
    ApplicationData,
}

impl Record {
    fn encode_content_type(&self) -> u8 {
        match self {
            Self::Invalid => 0x00,
            Self::ChangeCipherSpec => 0x14,
            Self::Alert(..) => 0x15,
            Self::Handshake(..) => 0x16,
            Self::ApplicationData => 0x17,
        }
    }

    fn encode_fragment(self) -> Vec<u8> {
        match self {
            Self::Handshake(fragment) => fragment,
            Self::Alert(atype, desc) => vec![atype.encode(), desc.encode()],
            _ => vec![],
        }
    }

    fn decode(ctype: u8, fragment: &[u8]) -> Result<Self, Error> {
        let res = match ctype {
            0x00 => Self::Invalid,
            0x14 => Self::ChangeCipherSpec,
            0x15 => Self::Alert(
                AlertType::decode(fragment[0]),
                AlertDescription::decode(fragment[1]),
            ),
            0x16 => Self::Handshake(fragment.to_vec()),
            0x17 => Self::ApplicationData,
            other => bail!("unexpected response content type: {}", other),
        };
        Ok(res)
    }
}

#[derive(Debug)]
enum AlertType {
    Warning,
    Fatal,
    Unknown(u8),
}

impl AlertType {
    fn encode(&self) -> u8 {
        match self {
            Self::Warning => 0x01,
            Self::Fatal => 0x02,
            Self::Unknown(val) => *val,
        }
    }

    fn decode(val: u8) -> Self {
        match val {
            0x01 => Self::Warning,
            0x02 => Self::Fatal,
            _ => Self::Unknown(val),
        }
    }
}

#[derive(Debug)]
enum AlertDescription {
    HandshakeFailure,
    IllegalParameter,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    MissingExtension,
    Unknown(u8),
}

impl AlertDescription {
    fn encode(&self) -> u8 {
        match self {
            Self::HandshakeFailure => 0x28,
            Self::IllegalParameter => 0x2f,
            Self::DecodeError => 0x32,
            Self::DecryptError => 0x33,
            Self::ProtocolVersion => 0x46,
            Self::MissingExtension => 0x6d,
            Self::Unknown(val) => *val,
        }
    }

    fn decode(val: u8) -> Self {
        match val {
            0x28 => Self::HandshakeFailure,
            0x2f => Self::IllegalParameter,
            0x32 => Self::DecodeError,
            0x33 => Self::DecryptError,
            0x46 => Self::ProtocolVersion,
            0x6d => Self::MissingExtension,
            _ => Self::Unknown(val),
        }
    }
}
