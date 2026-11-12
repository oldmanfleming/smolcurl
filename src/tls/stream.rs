use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream},
};

use anyhow::{Context, Error, anyhow, bail};

use crate::{
    bytes::{ByteLen, U24},
    crypto::{self, aead, hkdf, hmac, sha256::Sha256, x25519},
};

type TlsVersion = u16;
type CipherSuite = u16;
type KeyGroup = u16;
type SignatureAlgorithm = u16;
type ServerNameType = u8;
type HandshakeType = u8;
type ExtensionType = u16;
type Signature = Vec<u8>;

const LEGACY_RECORD_VERSION: TlsVersion = 0x0303;
const TLS1_3: TlsVersion = 0x0304;
const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = 0x1303;
const ECDSA_SECP256R1_SHA256: SignatureAlgorithm = 0x0403;
const X25519: KeyGroup = 0x001d;
const HOST_NAME: ServerNameType = 0x00;

const CLIENT_HELLO_MSG: HandshakeType = 1;
const SERVER_HELLO_MSG: HandshakeType = 2;
const ENCRYPTED_EXTENSIONS_MSG: HandshakeType = 8;
const CERTIFICATE_MSG: HandshakeType = 11;
const CERTIFICATE_VERIFY_MSG: HandshakeType = 15;
const FINISHED_MSG: HandshakeType = 20;

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
const CLIENT_HS_TRAFFIC_LABEL: &'static [u8] = b"c hs traffic";
const SERVER_HS_TRAFFIC_LABEL: &'static [u8] = b"s hs traffic";
const CLIENT_AP_TRAFFIC_LABEL: &'static [u8] = b"c ap traffic";
const SERVER_AP_TRAFFIC_LABEL: &'static [u8] = b"s ap traffic";

pub struct TlsStream {
    inner: TcpStream,
    buf: [u8; MAX_RECORD_SIZE],
    pos: usize,
    len: usize,
    hasher: Sha256,
    handshake_secret: [u8; 32],
    master_secret: [u8; 32],
    client_traffic_secret: TrafficSecret,
    server_traffic_secert: TrafficSecret,
}

impl TlsStream {
    pub(crate) fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            buf: [0u8; MAX_RECORD_SIZE],
            pos: 0,
            len: 0,
            hasher: Sha256::new(),
            handshake_secret: [0u8; 32],
            master_secret: [0u8; 32],
            client_traffic_secret: TrafficSecret {
                secret: vec![],
                key: vec![],
                iv: vec![],
                seq_number: 0,
            },
            server_traffic_secert: TrafficSecret {
                secret: vec![],
                key: vec![],
                iv: vec![],
                seq_number: 0,
            },
        }
    }

    pub(crate) fn handshake(&mut self, hostname: &str) -> Result<(), Error> {
        let mut client_priv_key = [0u8; 32];
        rand::fill(&mut client_priv_key);
        let mut u = [0u8; 32];
        u[0..4].copy_from_slice(&9u32.to_le_bytes());
        let client_pub_key = x25519::x25519(client_priv_key, u);

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

        println!("sending client hello: {:?}", req);
        self.write_record(req)?;

        // update the transcript hash with client hello
        // skip the record framing when hashing the transcript
        self.hasher.update(&self.buf[5..self.pos]);

        match self.recv_handshake_msg()? {
            HandshakeMsg::ServerHello(server_pub_key) => {
                println!("received server hello with pub key: {:?}", server_pub_key);

                // update the transcript hash with server hello
                // buffer is already the inner msg part only
                self.hasher.update(&self.buf[..self.pos]);
                let transcript_hash = self.hasher.finalize();

                let early_secret = hkdf::extract(Some(&[0u8; 32]), &[0u8; 32]);
                let ecdhe = x25519::x25519(client_priv_key, server_pub_key);

                let (handshake_secret, client_hs_traffic_secret, server_hs_traffic_secret) =
                    Self::extract_secrets(
                        &early_secret,
                        &ecdhe,
                        CLIENT_HS_TRAFFIC_LABEL,
                        SERVER_HS_TRAFFIC_LABEL,
                        transcript_hash,
                    )?;
                self.handshake_secret = handshake_secret;
                self.client_traffic_secret = client_hs_traffic_secret;
                self.server_traffic_secert = server_hs_traffic_secret;
            }
            r => bail!(
                "received unexpected record when expecting server hello: {:?}",
                r
            ),
        };

        match self.recv_handshake_msg()? {
            HandshakeMsg::EncryptedExtensions(exts) => {
                println!("received encrypted extensions message: {:?}", exts);
                self.hasher.update(&self.buf[..self.pos]);
            }
            r => bail!(
                "received unexpected record when expecting encrypted extensions: {:?}",
                r
            ),
        }

        match self.recv_handshake_msg()? {
            HandshakeMsg::Certificate(certificate_entries) => {
                println!(
                    "received certificate message with entries: {:?}",
                    certificate_entries
                );

                self.hasher.update(&self.buf[..self.pos]);

                match self.recv_handshake_msg()? {
                    HandshakeMsg::CertificateVerify(signature) => {
                        println!(
                            "received certificate verify message with signature: {:?}",
                            signature
                        );

                        let transcript_hash = self.hasher.finalize();

                        // TODO: verify certificate

                        self.hasher.update(&self.buf[..self.pos]);
                    }
                    r => bail!(
                        "received unexpected record when expecting certificate verify: {:?}",
                        r
                    ),
                }
            }
            r => bail!(
                "received unexpected record when expecting certificate: {:?}",
                r
            ),
        }

        match self.recv_handshake_msg()? {
            HandshakeMsg::Finished(server_verify_data) => {
                println!(
                    "received finished message with verification data: {:?}",
                    server_verify_data
                );

                let transcript_hash = self.hasher.finalize();
                let finished_key = crypto::hkdf_expand_label(
                    &self.server_traffic_secert.secret,
                    b"finished",
                    b"",
                    32,
                )?;
                let client_verify_data = hmac::hmac_sha256(&finished_key, &transcript_hash);

                // validation must be a constant time comparison
                let mut valid = true;
                for i in 0..32 {
                    if server_verify_data[i] != client_verify_data[i] {
                        valid = false;
                    }
                }
                if !valid {
                    bail!(
                        "server and client do not agree on verification data: {:?} {:?}",
                        server_verify_data,
                        client_verify_data
                    )
                }

                self.hasher.update(&self.buf[..self.pos]);
            }
            r => bail!(
                "received unexpected record when expecting finished: {:?}",
                r
            ),
        }

        let transcript_hash = self.hasher.finalize();
        let (master_secret, client_ap_traffic_secret, server_ap_traffic_secret) =
            Self::extract_secrets(
                &self.handshake_secret,
                &[0u8; 32],
                CLIENT_AP_TRAFFIC_LABEL,
                SERVER_AP_TRAFFIC_LABEL,
                transcript_hash,
            )?;
        self.master_secret = master_secret;
        self.client_traffic_secret = client_ap_traffic_secret;
        self.server_traffic_secert = server_ap_traffic_secret;

        let finished_key =
            crypto::hkdf_expand_label(&self.client_traffic_secret.secret, b"finished", b"", 32)?;
        let verify_data = hmac::hmac_sha256(&finished_key, &transcript_hash);

        let finished = HandshakeMsg::Finished(verify_data);
        self.write_record(Record::Handshake(finished))?;

        Ok(())
    }

    fn write_record(&mut self, record: Record) -> Result<(), Error> {
        self.pos = 0;
        self.set_bytes(&[Self::encode_content_type(&record)])?;
        self.set_bytes(&LEGACY_RECORD_VERSION.to_be_bytes())?;
        self.encode_fragment(record)?;
        let stream = &mut self.inner;
        stream.write_all(&self.buf[0..self.pos])?;
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
        encode_data_fn: impl FnOnce(&mut TlsStream) -> Result<Option<u8>, Error>,
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

    fn recv_handshake_msg(&mut self) -> Result<HandshakeMsg, Error> {
        // Receive a record while handling potential alert and change cipher messages
        for _ in 0..MAX_HANDSHAKE_RESPONSE_RECORDS {
            let record = self.read_record()?;

            match record {
                Record::Alert(atype, adesc) => bail!("unexpected alert: {:?} {:?}", atype, adesc),
                Record::ChangeCipherSpec => {
                    println!("received change cipher spec");
                }
                Record::Handshake(msg) => return Ok(msg),
                other => println!("unexpected record type during handshake: {:?}", other),
            }
        }
        Err(anyhow!("didn't receive handshake message"))
    }

    fn read_record(&mut self) -> Result<Record, Error> {
        self.inner.read_exact(&mut self.buf[0..5])?;
        let ctype = *self
            .buf
            .get(0)
            .context("missing content type in response")?;
        let len = u16::from_be_bytes(self.buf[3..5].try_into()?);
        self.inner.read_exact(&mut self.buf[..usize::from(len)])?;
        self.pos = 0;
        self.len = len.into();
        self.decode_record(ctype, &len.to_be_bytes())
    }

    fn decode_record(&mut self, ctype: u8, len: &[u8; 2]) -> Result<Record, Error> {
        let res = match ctype {
            0x00 => Record::Invalid,
            0x14 => {
                if self.buf[0] != 0x01 {
                    bail!("unexpected change cipher spec format: {}", self.buf[0])
                };
                Record::ChangeCipherSpec
            }
            0x15 => {
                let [atype, adesc, ..] = self.buf;
                Record::Alert(
                    Self::decode_alert_type(atype),
                    Self::decode_alert_desc(adesc),
                )
            }
            0x16 => {
                let msg = self.decode_handshake_msg()?;
                Record::Handshake(msg)
            }
            0x17 => {
                self.decrypt_data(ctype, len)?;
                let msg = self.decode_handshake_msg()?;
                Record::Handshake(msg)
            }
            other => bail!("unexpected response content type: {}", other),
        };
        Ok(res)
    }

    fn decrypt_data(&mut self, ctype: u8, len: &[u8; 2]) -> Result<(), Error> {
        let key: &[u8; 32] = &self.server_traffic_secert.key.as_slice().try_into()?;
        let seq_number = self.server_traffic_secert.seq_number.to_be_bytes();
        let iv = &self.server_traffic_secert.iv;
        let mut nonce = [0u8; 12];
        for i in 0..12 {
            if i < 4 {
                nonce[i] = 0x0 ^ iv[i];
            } else {
                nonce[i] = seq_number[i - 4] ^ iv[i];
            }
        }
        let aad = [ctype, 0x03, 0x03, len[0], len[1]];
        let encrypted_record = &self.buf[0..self.len];
        let split = encrypted_record.len() - 16;
        let ciphertext = &encrypted_record[..split];
        let tag: &[u8; 16] = &encrypted_record[split..].try_into()?;
        let decrypted_record = aead::chacha20_aead_decrypt(&key, &nonce, &aad, ciphertext, tag)?;
        self.server_traffic_secert.seq_number += 1;
        self.buf[0..decrypted_record.len()].copy_from_slice(&decrypted_record);
        Ok(())
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
        let msg_type = self.decode_data::<u8>()?;
        let len = self.decode_data::<U24>()?.0;
        match msg_type {
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
            ENCRYPTED_EXTENSIONS_MSG => {
                let ext_len = self.decode_data::<u16>()?;
                let mut extensions: Vec<HandshakeExtension> = vec![];
                for _ in 0..ext_len {
                    let ext = self.decode_data::<u8>()?;
                    extensions.push(Self::decode_handshake_extension(ext))
                }
                Ok(HandshakeMsg::EncryptedExtensions(extensions))
            }
            CERTIFICATE_MSG => {
                let _certificate_request_context = self.decode_data::<u8>()?;
                let certificate_list_len = self.decode_data::<U24>()?.0 as usize;
                let mut certificate_entries: Vec<CertificateEntry> = vec![];
                let mut pos = 0;
                while pos < certificate_list_len {
                    let cert_data_len = self.decode_data::<U24>()?.0 as usize;
                    let cert_data = self.get_bytes(cert_data_len)?.to_vec();
                    let extensions_len = self.decode_data::<u16>()? as usize;
                    let extensions = self.get_bytes(extensions_len)?.to_vec();
                    certificate_entries.push(CertificateEntry {
                        data: cert_data,
                        extensions: extensions,
                    });
                    pos += 3 + cert_data_len + 2 + extensions_len;
                }
                Ok(HandshakeMsg::Certificate(certificate_entries))
            }
            CERTIFICATE_VERIFY_MSG => {
                let algorithm = self.decode_data::<u16>()?;
                if algorithm != ECDSA_SECP256R1_SHA256 {
                    bail!("unexpected signature algorithm: {}", algorithm)
                }
                let signature_len = self.decode_data::<u16>()?;
                let signature = self.get_bytes(signature_len as usize)?.to_vec();
                Ok(HandshakeMsg::CertificateVerify(signature))
            }
            FINISHED_MSG => {
                let verify_data: [u8; 32] = self.get_bytes(len as usize)?.try_into()?;
                Ok(HandshakeMsg::Finished(verify_data))
            }
            m => bail!("received unsupported handshake message response: {}", m),
        }
    }

    fn decode_handshake_extension(ext: u8) -> HandshakeExtension {
        match ext {
            _ => todo!(),
        }
    }

    fn decode_data<T: ByteLen>(&mut self) -> Result<T, Error> {
        Ok(T::from_be_bytes(self.get_bytes(T::byte_len())?)?)
    }

    fn get_bytes(&mut self, len: usize) -> Result<&[u8], Error> {
        let bytes = self
            .buf
            .get(self.pos..self.pos + len)
            .ok_or_else(|| anyhow!("unexpected end of data"))?;
        self.pos += len;
        Ok(bytes)
    }

    fn extract_secrets(
        secret: &[u8],
        ikm: &[u8],
        client_label: &[u8],
        server_label: &[u8],
        transcript_hash: [u8; 32],
    ) -> Result<([u8; 32], TrafficSecret, TrafficSecret), Error> {
        let derived_early = Self::derive_secret(secret, b"derived", Sha256::hash(b""))?;
        let hs_secret = hkdf::extract(Some(&derived_early), ikm);
        let client_secret = Self::derive_secret(&hs_secret, client_label, transcript_hash)?;
        let server_secret = Self::derive_secret(&hs_secret, server_label, transcript_hash)?;
        let client_traffic_secret = TrafficSecret::new(client_secret)?;
        let server_traffic_secret = TrafficSecret::new(server_secret)?;
        Ok((hs_secret, client_traffic_secret, server_traffic_secret))
    }

    fn derive_secret(
        secret: &[u8],
        label: &[u8],
        transcript_hash: [u8; 32],
    ) -> Result<Vec<u8>, Error> {
        crypto::hkdf_expand_label(secret, label, &transcript_hash, transcript_hash.len())
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

#[derive(Debug)]
struct TrafficSecret {
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    seq_number: u64,
}

impl TrafficSecret {
    pub fn new(secret: Vec<u8>) -> Result<Self, Error> {
        Ok(Self {
            secret: secret.clone(),
            key: crypto::hkdf_expand_label(&secret, b"key", b"", 32)?,
            iv: crypto::hkdf_expand_label(&secret, b"iv", b"", 12)?,
            seq_number: 0,
        })
    }
}

#[derive(Debug)]
struct CertificateEntry {
    data: Vec<u8>,
    extensions: Vec<u8>,
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
    EncryptedExtensions(Vec<HandshakeExtension>),
    Certificate(Vec<CertificateEntry>),
    CertificateVerify(Signature),
    Finished([u8; 32]),
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
