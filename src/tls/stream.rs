use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::{Context, Error, anyhow, bail};

use crate::tls::stream::HandshakeMsg::ClientHello;

type TlsVersion = u16;
type CipherSuite = u16;
type KeyGroup = u16;
type SignatureAlgorithm = u16;

const LEGACY_RECORD_VERSION: TlsVersion = 0x0303;
const TLS1_3: TlsVersion = 0x0304;
const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = 0x1303;
const ECDSA_SECP256R1_SHA256: SignatureAlgorithm = 0x0403;
const X25519: KeyGroup = 0x001d;
const COMPRESSION_DISABLED: u8 = 0x00;
const MAX_RECORD_SIZE: usize = 16384;
const MAX_HANDSHAKE_RESPONSE_RECORDS: usize = 3;

pub fn handshake(mut stream: TcpStream, hostname: &str) -> Result<TlsStream, Error> {
    let mut buf = [0u8; MAX_RECORD_SIZE];

    // TODO ---
    let mut pub_key = vec![0u8; 32];
    rand::fill(&mut pub_key);
    // ---

    let exts = vec![
        HandshakeExtension::SupportedVersions(vec![TLS1_3]),
        HandshakeExtension::SupportedGroups(vec![X25519]),
        HandshakeExtension::KeyShare(X25519, pub_key),
        HandshakeExtension::SignatureAlgorithms(vec![ECDSA_SECP256R1_SHA256]),
        HandshakeExtension::ServerName(hostname.to_string()),
    ];
    let hello = HandshakeMsg::ClientHello(TLS_CHACHA20_POLY1305_SHA256, exts);
    let req = Record::Handshake(hello);

    println!("sending handshake req: {:?}", req);

    stream.write_all(TlsWriter::new(&mut buf).encode(req)?)?;

    for _ in 0..MAX_HANDSHAKE_RESPONSE_RECORDS {
        stream.read_exact(&mut buf[0..5])?;
        let ctype = *buf.get(0).context("missing content type in response")?;
        let len = u16::from_be_bytes(buf[3..5].try_into()?);
        stream.read_exact(&mut buf[..usize::from(len)])?;

        let resp = TlsReader::new(&buf).decode(ctype, len)?;

        match resp {
            Record::Alert(atype, adesc) => bail!("unexpected alert: {:?} {:?}", atype, adesc),
            Record::Handshake(fragment) => {
                println!("received handshake resp: {:?}", fragment);
                return Ok(TlsStream { inner: stream });
            }
            Record::ChangeCipherSpec => {
                println!("received change cipher spec resp");
            }
            other => println!("unexpected record type during handshake: {:?}", other),
        }
    }

    Err(anyhow!("did not receive handshake response"))
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
        let fragment = record.encode_fragment()?;
        self.set_bytes(&fragment.len().to_be_bytes())?;
        self.set_bytes(&fragment.as_slice())?;
        Ok(&self.buf[0..self.pos])
    }

    fn set_bytes(&mut self, data: &[u8]) -> Result<(), Error> {
        let slot = self
            .buf
            .get_mut(self.pos..self.pos + data.len())
            .context("unexpected end of buff")?;
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
    Handshake(HandshakeMsg),
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

    fn encode_fragment(self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Handshake(msg) => msg.encode(),
            Self::Alert(atype, desc) => Ok(vec![atype.encode(), desc.encode()]),
            Self::ChangeCipherSpec => Ok(vec![0x01, 0x01]),
            _ => todo!(),
        }
    }

    fn decode(ctype: u8, fragment: &[u8]) -> Result<Self, Error> {
        let res = match ctype {
            0x00 => Self::Invalid,
            0x14 => {
                let [0x01, 0x01] = fragment else {
                    bail!("unexpected change cipher spec format")
                };
                Self::ChangeCipherSpec
            }
            0x15 => {
                let [atype, adesc, ..] = fragment else {
                    bail!("alert response too short");
                };
                Self::Alert(AlertType::decode(*atype), AlertDescription::decode(*adesc))
            }
            0x16 => {
                let msg = HandshakeMsg::decode(fragment)?;
                Self::Handshake(msg)
            }
            0x17 => Self::ApplicationData,
            other => bail!("unexpected response content type: {}", other),
        };
        Ok(res)
    }
}

#[derive(Debug)]
enum HandshakeMsg {
    ClientHello(CipherSuite, Vec<HandshakeExtension>),
    ServerHello,
    NewSessionTicket,
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
    KeyUpdated,
}

impl HandshakeMsg {
    fn encode(self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = vec![];

        match self {
            ClientHello(cipher_suite, extensions) => {
                buf.write_all(&LEGACY_RECORD_VERSION.to_be_bytes())?;

                let random: u32 = rand::random();
                buf.write_all(&random.to_be_bytes())?;

                // sending empty session id for simplicity
                // in future we can send random 32 octets
                // and validate echoed value from ServerHello
                let legacy_session_id = 0x00u8.to_be_bytes();
                Self::encode_data(&mut buf, &legacy_session_id)?;

                Self::encode_data(&mut buf, &cipher_suite.to_be_bytes())?;

                // TLS1.3 does not allow compression
                let compression = COMPRESSION_DISABLED.to_be_bytes();
                Self::encode_data(&mut buf, &compression)?;

                let extensions = Self::encode_extensions(extensions)?;
                Self::encode_data(&mut buf, &extensions)?;
            }
            other => bail!("encoding {:?} is not supported.", other),
        }

        Ok(buf)
    }

    fn encode_extensions(extensions: Vec<HandshakeExtension>) -> Result<Vec<u8>, Error> {
        Ok(vec![])
    }

    fn encode_data(buf: &mut Vec<u8>, data: &[u8]) -> Result<(), Error> {
        buf.write_all(&data.len().to_be_bytes())?;
        buf.write_all(data)?;
        Ok(())
    }

    fn decode(fragment: &[u8]) -> Result<Self, Error> {
        Ok(HandshakeMsg::ServerHello)
    }
}

#[derive(Debug)]
enum HandshakeExtension {
    SupportedVersions(Vec<TlsVersion>),
    SupportedGroups(Vec<KeyGroup>),
    KeyShare(KeyGroup, Vec<u8>),
    SignatureAlgorithms(Vec<SignatureAlgorithm>),
    ServerName(String),
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
