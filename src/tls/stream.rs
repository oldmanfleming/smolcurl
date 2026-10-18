use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream},
};

use anyhow::{Context, Error, anyhow, bail};

type TlsVersion = u16;
type CipherSuite = u16;
type KeyGroup = u16;
type SignatureAlgorithm = u16;
type ServerNameType = u8;
type HandshakeType = u8;
type ExtensionType = u16;

const LEGACY_RECORD_VERSION: TlsVersion = 0x0303;
const TLS1_3: TlsVersion = 0x0304;
const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = 0x1303;
const ECDSA_SECP256R1_SHA256: SignatureAlgorithm = 0x0403;
const X25519: KeyGroup = 0x001d;
const HOST_NAME: ServerNameType = 0x00;

const CLIENT_HELLO_MSG: HandshakeType = 0x01;
const SERVER_HELLO_MSG: HandshakeType = 0x02;

const SUPPORTED_VERSIONS_EXT: ExtensionType = 0x002b;
const KEY_SHARE_EXT: ExtensionType = 0x0033;

const COMPRESSION_DISABLED: u8 = 0x00;
const LEGACY_SESSION_ID: u8 = 0x00;
const MAX_RECORD_SIZE: usize = 16384;
const MAX_HANDSHAKE_RESPONSE_RECORDS: usize = 3;
const HELLO_RETRY_REQUEST: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

pub fn handshake(mut stream: TcpStream, hostname: &str) -> Result<TlsStream, Error> {
    let mut buf = [0u8; MAX_RECORD_SIZE];

    // TODO ---
    let mut client_pub_key = [0u8; 32];
    rand::fill(&mut client_pub_key);
    // ---

    let mut exts = vec![
        HandshakeExtension::SupportedVersions(vec![TLS1_3]),
        HandshakeExtension::SupportedGroups(vec![X25519]),
        HandshakeExtension::KeyShare(X25519, client_pub_key),
        HandshakeExtension::SignatureAlgorithms(vec![ECDSA_SECP256R1_SHA256]),
    ];

    // don't pass server name if we have a user supplied ip address
    if hostname.parse::<IpAddr>().is_err() {
        exts.push(HandshakeExtension::ServerName(hostname.to_string()));
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

        let resp = TlsReader::new(&buf).decode(ctype)?;

        match resp {
            Record::Alert(atype, adesc) => bail!("unexpected alert: {:?} {:?}", atype, adesc),
            Record::Handshake(msg) => match msg {
                HandshakeMsg::ServerHello(server_pub_key) => {
                    println!("received server hello with pub key: {:?}", server_pub_key);
                    return Ok(TlsStream {
                        inner: stream,
                        _client_pub_key: client_pub_key,
                        _server_pub_key: server_pub_key,
                    });
                }
                _ => todo!(),
            },
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
    _client_pub_key: [u8; 32],
    _server_pub_key: [u8; 32],
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
        self.set_bytes(&[Self::encode_content_type(&record)])?;
        self.set_bytes(&LEGACY_RECORD_VERSION.to_be_bytes())?;
        self.encode_fragment(record)?;
        Ok(&self.buf[0..self.pos])
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

    fn encode_fragment(&mut self, record: Record) -> Result<(), Error> {
        self.encode_dyn_len_data::<u16>(|writer| {
            match record {
                Record::Handshake(msg) => writer.encode_msg(msg),
                Record::Alert(atype, adesc) => writer.set_bytes(&[
                    Self::encode_alert_type(&atype),
                    Self::encode_alert_desc(&adesc),
                ]),
                Record::ChangeCipherSpec => writer.set_bytes(&[0x01, 0x01]),
                _ => todo!(),
            }?;
            Ok(None)
        })
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

    fn encode_msg(&mut self, msg: HandshakeMsg) -> Result<(), Error> {
        // NOTE: There is an implicit assumption here that what
        // we encode in the match will never be more than 2^24 bytes,
        // as the lead byte is used by the byte returned by the match
        // as the header type
        self.encode_dyn_len_data::<u32>(|writer| {
            match msg {
                HandshakeMsg::ClientHello(cipher_suite, extensions) => {
                    writer.set_bytes(&LEGACY_RECORD_VERSION.to_be_bytes())?;

                    let mut random = [0u8; 32];
                    rand::fill(&mut random);
                    writer.set_bytes(&random)?;

                    // sending hard-coded session id for simplicity
                    // in future we can send random 1-32 octets
                    // and validate echoed value from ServerHello
                    writer.encode_data::<u8>(&[LEGACY_SESSION_ID])?;

                    writer.encode_data::<u16>(&cipher_suite.to_be_bytes())?;

                    // TLS1.3 does not allow compression
                    writer.encode_data::<u8>(&[COMPRESSION_DISABLED])?;

                    writer.encode_extensions(extensions)?;

                    Ok(Some(CLIENT_HELLO_MSG))
                }
                other => bail!("encoding {:?} is not supported.", other),
            }
        })
    }

    fn encode_extensions(&mut self, extensions: Vec<HandshakeExtension>) -> Result<(), Error> {
        self.encode_dyn_len_data::<u16>(|writer| {
            for ext in extensions {
                writer.set_bytes(&Self::encode_extension_type(&ext).to_be_bytes())?;
                writer.encode_extension_data(ext)?;
            }
            Ok(None)
        })
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

    fn encode_extension_data(&mut self, ext: HandshakeExtension) -> Result<(), Error> {
        self.encode_dyn_len_data::<u16>(|writer| {
            match ext {
                HandshakeExtension::SupportedVersions(versions) => writer
                    .encode_dyn_len_data::<u8>(|w| {
                        for v in versions {
                            w.set_bytes(&v.to_be_bytes())?;
                        }
                        Ok(None)
                    }),
                HandshakeExtension::SupportedGroups(groups) => {
                    writer.encode_dyn_len_data::<u16>(|w| {
                        for g in groups {
                            w.set_bytes(&g.to_be_bytes())?;
                        }
                        Ok(None)
                    })
                }
                HandshakeExtension::KeyShare(group, pub_key) => {
                    writer.encode_dyn_len_data::<u16>(|w| {
                        w.set_bytes(&group.to_be_bytes())?;
                        w.encode_data::<u16>(&pub_key)?;
                        Ok(None)
                    })
                }
                HandshakeExtension::SignatureAlgorithms(algs) => {
                    writer.encode_dyn_len_data::<u16>(|w| {
                        for a in algs {
                            w.set_bytes(&a.to_be_bytes())?;
                        }
                        Ok(None)
                    })
                }
                HandshakeExtension::ServerName(name) => writer.encode_dyn_len_data::<u16>(|w| {
                    w.set_bytes(&[HOST_NAME])?;
                    let len: u16 = name.len().try_into().context("hostname too long")?;
                    w.set_bytes(&len.to_be_bytes())?;
                    w.set_bytes(name.as_bytes())?;
                    Ok(None)
                }),
            }?;
            Ok(None)
        })
    }

    fn encode_dyn_len_data<T: ByteLen>(
        &mut self,
        encode_data_fn: impl FnOnce(&mut TlsWriter) -> Result<Option<u8>, Error>,
    ) -> Result<(), Error> {
        // reserve len slots with saved positions
        let len_pos = self.pos;
        self.pos += T::byte_len();
        let start_pos = self.pos;

        // invoke closure that writes data
        // optionally a lead byte can be returned (handshake msg frame is 1 octet type + 3 octet length)
        let some_lead_byte = encode_data_fn(self)?;

        // measure written data len and update reserved len slots
        let len: T = T::from_len(self.pos - start_pos)?;
        let len_bytes = len.into_be_bytes();
        let slot = self
            .buf
            .get_mut(len_pos..len_pos + T::byte_len())
            .context("unexpected end of buff")?;
        slot.copy_from_slice(len_bytes.as_ref());

        if let Some(lead_byte) = some_lead_byte {
            self.buf[len_pos] = lead_byte;
        }

        Ok(())
    }

    fn encode_data<T: ByteLen>(&mut self, data: &[u8]) -> Result<(), Error> {
        let len: T = T::from_len(data.len())?;
        self.set_bytes(len.into_be_bytes().as_ref())?;
        self.set_bytes(data)?;
        Ok(())
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

    fn decode(&mut self, ctype: u8) -> Result<Record, Error> {
        let res = match ctype {
            0x00 => Record::Invalid,
            0x14 => {
                let [0x01, 0x01] = self.buf else {
                    bail!("unexpected change cipher spec format")
                };
                Record::ChangeCipherSpec
            }
            0x15 => {
                let [atype, adesc, ..] = self.buf else {
                    bail!("alert response too short");
                };
                Record::Alert(
                    Self::decode_alert_type(*atype),
                    Self::decode_alert_desc(*adesc),
                )
            }
            0x16 => {
                let msg = self.decode_handshake_msg()?;
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

    fn decode_handshake_msg(&mut self) -> Result<HandshakeMsg, Error> {
        // msg header is 1 byte type + 3 byte length
        // we parse the type in-place and then mask it out of the 32bit parsed length
        let msg_type = self.buf.get(self.pos).context("missing msg type")?;
        let _len = self.decode_data::<u32>()? & 0x00FFFFFF; // do we need to use len?
        match *msg_type {
            SERVER_HELLO_MSG => {
                // legacy version is ignored, but still needs to be read
                self.decode_data::<u16>()?;

                let random = self.get_bytes(32)?;
                if random.eq(&HELLO_RETRY_REQUEST) {
                    // we only support a single key group
                    // if the server does not support it, this is a failure.
                    bail!("server responded with HelloRetryRequest")
                }

                let legacy_session_id_len = self.decode_data::<u8>()?;
                if legacy_session_id_len != 1 {
                    bail!("unexpected legacy session id len")
                }
                let legacy_session_id = self.decode_data::<u8>()?;
                if legacy_session_id != LEGACY_SESSION_ID {
                    bail!("unexpected legacy session id")
                }

                let cipher_suite = self.decode_data::<u16>()?;
                if cipher_suite != TLS_CHACHA20_POLY1305_SHA256 {
                    bail!("unsupported cipher suite returned");
                }

                let legacy_compression_method = self.decode_data::<u8>()?;
                if legacy_compression_method != COMPRESSION_DISABLED {
                    bail!("server compression not disabled")
                }

                let ext_len = usize::from(self.decode_data::<u16>()?);
                let ext_end = self.pos + ext_len;
                let mut version: Option<u16> = None;
                let mut key_share: Option<(u16, [u8; 32])> = None;
                while self.pos < ext_end {
                    let ext_type = self.decode_data::<u16>()?;
                    let ext_data_len = usize::from(self.decode_data::<u16>()?);
                    match ext_type {
                        SUPPORTED_VERSIONS_EXT => {
                            version = Some(self.decode_data::<u16>()?);
                        }
                        KEY_SHARE_EXT => {
                            let key_group = self.decode_data::<u16>()?;
                            let key_len = self.decode_data::<u16>()?;
                            if key_len != 32 {
                                bail!("unexpected key len")
                            }
                            let pub_key: [u8; 32] = self.get_bytes(32)?.try_into()?;
                            key_share = Some((key_group, pub_key));
                        }
                        _ => {
                            println!("unsupported extension type in server hello: {}", ext_type);
                            self.pos += ext_data_len;
                        }
                    }
                }

                if version != Some(TLS1_3) {
                    bail!("server does not support TLS1.3: {:?}", version);
                }

                match key_share {
                    Some((X25519, pub_key)) => Ok(HandshakeMsg::ServerHello(pub_key)),
                    Some((key_group, _)) => {
                        bail!("unexpected key group received from server: {}", key_group)
                    }
                    None => bail!("did not receive key share from server"),
                }
            }
            _ => todo!(),
        }
    }

    fn decode_data<T: ByteLen>(&mut self) -> Result<T, Error> {
        Ok(T::from_be_bytes(self.get_bytes(T::byte_len())?)?)
    }

    fn get_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let bytes = self
            .buf
            .get(self.pos..self.pos + len)
            .ok_or_else(|| anyhow!("unexpected end of data"))?;
        self.pos += len;
        Ok(bytes)
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
    ServerHello([u8; 32]),
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
    KeyShare(KeyGroup, [u8; 32]),
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

trait ByteLen: Sized {
    type Bytes: AsRef<[u8]>;
    fn from_len(n: usize) -> Result<Self, Error>;
    fn into_be_bytes(self) -> Self::Bytes;
    fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error>;
    fn byte_len() -> usize;
}

impl ByteLen for u8 {
    type Bytes = [u8; 1];
    fn from_len(n: usize) -> Result<Self, Error> {
        n.try_into().context("length too large for u8")
    }

    fn into_be_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(u8::from_be_bytes(bytes.try_into()?))
    }

    fn byte_len() -> usize {
        1
    }
}

impl ByteLen for u16 {
    type Bytes = [u8; 2];
    fn from_len(n: usize) -> Result<Self, Error> {
        n.try_into().context("length too large for u16")
    }

    fn into_be_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(u16::from_be_bytes(bytes.try_into()?))
    }

    fn byte_len() -> usize {
        2
    }
}

impl ByteLen for u32 {
    type Bytes = [u8; 4];
    fn from_len(n: usize) -> Result<Self, Error> {
        n.try_into().context("length too large for u32")
    }

    fn into_be_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(u32::from_be_bytes(bytes.try_into()?))
    }

    fn byte_len() -> usize {
        4
    }
}
