use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream},
    str::FromStr,
};

use anyhow::{Context, Error, anyhow, bail};

type TlsVersion = u16;
type CipherSuite = u16;
type KeyGroup = u16;
type SignatureAlgorithm = u16;
type ServerNameType = u8;
type HandshakeType = u8;

const LEGACY_RECORD_VERSION: TlsVersion = 0x0303;
const TLS1_3: TlsVersion = 0x0304;
const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = 0x1303;
const ECDSA_SECP256R1_SHA256: SignatureAlgorithm = 0x0403;
const X25519: KeyGroup = 0x001d;
const HOST_NAME: ServerNameType = 0x00;
const CLIENT_HELLO: HandshakeType = 0x01;
const COMPRESSION_DISABLED: u8 = 0x00;
const MAX_RECORD_SIZE: usize = 16384;
const MAX_HANDSHAKE_RESPONSE_RECORDS: usize = 3;

pub fn handshake(mut stream: TcpStream, hostname: &str) -> Result<TlsStream, Error> {
    let mut buf = [0u8; MAX_RECORD_SIZE];

    // TODO ---
    let mut pub_key = vec![0u8; 32];
    rand::fill(&mut pub_key);
    // ---

    let mut exts = vec![
        HandshakeExtension::SupportedVersions(vec![TLS1_3]),
        HandshakeExtension::SupportedGroups(vec![X25519]),
        HandshakeExtension::KeyShare(X25519, pub_key),
        HandshakeExtension::SignatureAlgorithms(vec![ECDSA_SECP256R1_SHA256]),
    ];

    // don't pass server name if we have a user supplied ip address
    if let Err(..) = IpAddr::from_str(hostname) {
        exts.push(HandshakeExtension::ServerName(hostname.to_string()))
    }
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
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn encode(mut self, record: Record) -> Result<&'a [u8], Error> {
        self.set_bytes(&Self::encode_content_type(&record).to_be_bytes())?;
        self.set_bytes(&LEGACY_RECORD_VERSION.to_be_bytes())?;
        let fragment = self.encode_fragment(record)?;
        let len: u16 = fragment
            .len()
            .try_into()
            .context("fragment len is too large")?;
        self.set_bytes(&len.to_be_bytes())?;
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

    fn encode_content_type(record: &Record) -> u8 {
        match record {
            Record::Invalid => 0x00,
            Record::ChangeCipherSpec => 0x14,
            Record::Alert(..) => 0x15,
            Record::Handshake(..) => 0x16,
            Record::ApplicationData => 0x17,
        }
    }

    fn encode_fragment(&mut self, record: Record) -> Result<Vec<u8>, Error> {
        match record {
            Record::Handshake(msg) => self.encode_msg(msg),
            Record::Alert(atype, adesc) => Ok(vec![
                Self::encode_alert_type(&atype),
                Self::encode_alert_desc(&adesc),
            ]),
            Record::ChangeCipherSpec => Ok(vec![0x01, 0x01]),
            _ => todo!(),
        }
    }

    fn encode_alert_type(atype: &AlertType) -> u8 {
        match atype {
            AlertType::Warning => 0x01,
            AlertType::Fatal => 0x02,
            AlertType::Unknown(val) => *val,
        }
    }

    fn encode_alert_desc(adesc: &AlertDescription) -> u8 {
        match adesc {
            AlertDescription::HandshakeFailure => 0x28,
            AlertDescription::IllegalParameter => 0x2f,
            AlertDescription::DecodeError => 0x32,
            AlertDescription::DecryptError => 0x33,
            AlertDescription::ProtocolVersion => 0x46,
            AlertDescription::MissingExtension => 0x6d,
            AlertDescription::Unknown(val) => *val,
        }
    }

    fn encode_msg(&mut self, msg: HandshakeMsg) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = vec![];

        let htype: HandshakeType = match msg {
            HandshakeMsg::ClientHello(cipher_suite, extensions) => {
                buf.write_all(&LEGACY_RECORD_VERSION.to_be_bytes())?;

                let mut random = vec![0u8; 32];
                rand::fill(&mut random);
                buf.write_all(&random)?;

                // sending empty session id for simplicity
                // in future we can send random 32 octets
                // and validate echoed value from ServerHello
                let legacy_session_id = 0x00u8.to_be_bytes();
                Self::encode_data_u8(&mut buf, &legacy_session_id)?;

                Self::encode_data_u16(&mut buf, &cipher_suite.to_be_bytes())?;

                // TLS1.3 does not allow compression
                let compression = COMPRESSION_DISABLED.to_be_bytes();
                Self::encode_data_u8(&mut buf, &compression)?;

                let extensions = Self::encode_extensions(extensions)?;
                Self::encode_data_u16(&mut buf, &extensions)?;

                CLIENT_HELLO
            }
            other => bail!("encoding {:?} is not supported.", other),
        };

        // There is no native u24 type in rust, so parse as u32.
        // We then replace the first byte with the handshake type since it's not used
        let len: u32 = buf.len().try_into()?;
        let mut data = len.to_be_bytes().to_vec();
        data[0] = htype;
        data.extend_from_slice(&buf);

        Ok(data)
    }

    fn encode_extensions(extensions: Vec<HandshakeExtension>) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = vec![];

        for ext in extensions {
            buf.write_all(&Self::encode_extension_type(&ext).to_be_bytes())?;
            let data = Self::encode_data(ext)?;
            let len: u16 = data
                .len()
                .try_into()
                .context("extension data len is too large")?;
            buf.write_all(&len.to_be_bytes())?;
            buf.write_all(&data)?;
        }

        Ok(buf)
    }

    fn encode_extension_type(ext: &HandshakeExtension) -> u16 {
        match ext {
            HandshakeExtension::SupportedVersions(..) => 0x002b,
            HandshakeExtension::SupportedGroups(..) => 0x000a,
            HandshakeExtension::KeyShare(..) => 0x0033,
            HandshakeExtension::SignatureAlgorithms(..) => 0x000d,
            HandshakeExtension::ServerName(..) => 0x0000,
        }
    }

    fn encode_data(ext: HandshakeExtension) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = vec![];
        match ext {
            HandshakeExtension::SupportedVersions(versions) => {
                for v in versions {
                    buf.write_all(&v.to_be_bytes())?;
                }
                Self::encode_len_u8(&mut buf)
            }
            HandshakeExtension::SupportedGroups(groups) => {
                for g in groups {
                    buf.write_all(&g.to_be_bytes())?;
                }
                Self::encode_len_u16(&mut buf)
            }
            HandshakeExtension::KeyShare(group, pub_key) => {
                buf.write_all(&group.to_be_bytes())?;
                let len: u16 = pub_key.len().try_into().context("pub key too long")?;
                buf.write_all(&len.to_be_bytes())?;
                buf.write_all(&pub_key)?;
                Self::encode_len_u16(&mut buf)
            }
            HandshakeExtension::SignatureAlgorithms(algs) => {
                for a in algs {
                    buf.write_all(&a.to_be_bytes())?;
                }
                Self::encode_len_u16(&mut buf)
            }
            HandshakeExtension::ServerName(name) => {
                buf.push(HOST_NAME);
                let len: u16 = name.len().try_into().context("hostname too long")?;
                buf.write_all(&len.to_be_bytes())?;
                buf.write_all(name.as_bytes())?;
                Self::encode_len_u16(&mut buf)
            }
        }
    }

    fn encode_len_u8(buf: &mut Vec<u8>) -> Result<Vec<u8>, Error> {
        let len: u8 = buf.len().try_into()?;
        let mut data = len.to_be_bytes().to_vec();
        data.extend_from_slice(&buf);
        Ok(data)
    }

    fn encode_len_u16(buf: &mut Vec<u8>) -> Result<Vec<u8>, Error> {
        let len: u16 = buf.len().try_into()?;
        let mut data = len.to_be_bytes().to_vec();
        data.extend_from_slice(&buf);
        Ok(data)
    }

    fn encode_data_u8(buf: &mut Vec<u8>, data: &[u8]) -> Result<(), Error> {
        let len: u8 = data.len().try_into()?;
        buf.write_all(&len.to_be_bytes())?;
        buf.write_all(data)?;
        Ok(())
    }

    fn encode_data_u16(buf: &mut Vec<u8>, data: &[u8]) -> Result<(), Error> {
        let len: u16 = data.len().try_into()?;
        buf.write_all(&len.to_be_bytes())?;
        buf.write_all(data)?;
        Ok(())
    }
}

struct TlsReader<'a> {
    buf: &'a [u8],
    _pos: usize,
}

impl<'a> TlsReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, _pos: 0 }
    }

    fn decode(&self, ctype: u8, len: u16) -> Result<Record, Error> {
        let fragment = &self.buf[..usize::from(len)];
        let res = match ctype {
            0x00 => Record::Invalid,
            0x14 => {
                let [0x01, 0x01] = fragment else {
                    bail!("unexpected change cipher spec format")
                };
                Record::ChangeCipherSpec
            }
            0x15 => {
                let [atype, adesc, ..] = fragment else {
                    bail!("alert response too short");
                };
                Record::Alert(
                    Self::decode_alert_type(*atype),
                    Self::decode_alert_desc(*adesc),
                )
            }
            0x16 => {
                let msg = Self::decode_handshake_msg(fragment)?;
                Record::Handshake(msg)
            }
            0x17 => Record::ApplicationData,
            other => bail!("unexpected response content type: {}", other),
        };
        Ok(res)
    }

    fn decode_alert_type(val: u8) -> AlertType {
        match val {
            0x01 => AlertType::Warning,
            0x02 => AlertType::Fatal,
            _ => AlertType::Unknown(val),
        }
    }

    fn decode_alert_desc(val: u8) -> AlertDescription {
        match val {
            0x28 => AlertDescription::HandshakeFailure,
            0x2f => AlertDescription::IllegalParameter,
            0x32 => AlertDescription::DecodeError,
            0x33 => AlertDescription::DecryptError,
            0x46 => AlertDescription::ProtocolVersion,
            0x6d => AlertDescription::MissingExtension,
            _ => AlertDescription::Unknown(val),
        }
    }

    fn decode_handshake_msg(fragment: &[u8]) -> Result<HandshakeMsg, Error> {
        // TODO
        println!("received server hello: {:?}", fragment);
        Ok(HandshakeMsg::ServerHello)
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

#[derive(Debug)]
enum HandshakeMsg {
    ClientHello(CipherSuite, Vec<HandshakeExtension>),
    ServerHello,
    _NewSessionTicket,
    _EncryptedExtensions,
    _Certificate,
    _CertificateVerify,
    _Finished,
    _KeyUpdated,
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
