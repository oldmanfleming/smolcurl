use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use anyhow::{Error, anyhow, bail};

const MAX_DEPTH: u8 = 10;
const MAX_DELEGATIONS: u8 = 10;
const ROOT_NAME_SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4));

#[derive(Debug, Clone, Copy)]
pub enum RecordKind {
    A,
    NS,
    Txt,
    Other(u16), // A catch-all for yet-to-be supported record types; holds its raw value
}

impl RecordKind {
    fn encode(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::NS => 2,
            Self::Txt => 16,
            Self::Other(val) => *val,
        }
    }

    fn decode(val: u16) -> Self {
        match val {
            1 => Self::A,
            2 => Self::NS,
            16 => Self::Txt,
            i => Self::Other(i),
        }
    }
}

#[derive(Debug, Clone)]
pub enum RecordClass {
    IN,
    Other(u16), // A catch-all for yet-to-be suppported record classes; holds its raw value
}

impl RecordClass {
    fn encode(&self) -> u16 {
        match self {
            Self::IN => 1,
            Self::Other(val) => *val,
        }
    }

    fn decode(val: u16) -> Self {
        match val {
            1 => Self::IN,
            val => Self::Other(val),
        }
    }
}

#[derive(Debug, Clone)]
pub enum RecordData {
    A(Ipv4Addr),
    NS(String),
    Txt(String),
    Other(Vec<u8>), // A catch-all for yet-to-be supported record types; holds its raw data
}

struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
}

struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

struct DNSQuestion {
    name: String,
    kind: RecordKind,
    class: RecordClass,
}

struct DNSRecord {
    name: String,
    class: RecordClass,
    ttl: u32,
    data: RecordData,
}

pub fn resolve(name: &str, kind: RecordKind) -> Result<IpAddr, Error> {
    resolve_inner(name, kind, 0)
}

fn resolve_inner(name: &str, kind: RecordKind, depth: u8) -> Result<IpAddr, Error> {
    if depth > MAX_DEPTH {
        return Err(anyhow!("reached max recurrsion depth"));
    }

    let mut nameserver: IpAddr = ROOT_NAME_SERVER;

    for _ in 0..MAX_DELEGATIONS {
        println!("querying: {nameserver}");
        let packet = query(nameserver, name, kind)?;
        if let Some(ip) = get_first_ip(packet.answers) {
            return Ok(ip);
        }
        if let Some(ip) = get_first_ip(packet.additionals) {
            nameserver = ip;
            continue;
        }
        if let Some(ns) = get_first_nameserver(packet.authorities) {
            nameserver = resolve_inner(ns.as_str(), RecordKind::A, depth + 1)?;
            continue;
        }
        // Once we check authorities, we expect to find something.
        return Err(anyhow!("could not resolve name"));
    }

    Err(anyhow!("reached max delegation depth"))
}

fn query(addr: IpAddr, name: &str, kind: RecordKind) -> Result<DNSPacket, Error> {
    let id = rand::random();

    let mut buf = [0u8; 512];

    let query = DNSWriter::new(&mut buf).build_query(id, name, kind)?;

    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let dest = SocketAddr::new(addr, 53);
    socket.send_to(&query, dest)?;

    let (n, src) = socket.recv_from(&mut buf)?;

    if src != dest {
        return Err(anyhow!("received unexpected response from: {src}"));
    }

    let packet = DNSReader::new(&buf[..n]).decode_packet()?;

    if id != packet.header.id {
        return Err(anyhow!(
            "received unexpected id: {} - {}",
            id,
            packet.header.id
        ));
    }

    Ok(packet)
}

fn get_first_ip(records: Vec<DNSRecord>) -> Option<IpAddr> {
    records.into_iter().find_map(|r| match r.data {
        RecordData::A(ip) => Some(IpAddr::from(ip)),
        _ => None,
    })
}

fn get_first_nameserver(records: Vec<DNSRecord>) -> Option<String> {
    records.into_iter().find_map(|r| match r.data {
        RecordData::NS(ns) => Some(ns),
        _ => None,
    })
}

struct DNSWriter<'a> {
    data: &'a mut [u8],
    pos: usize,
}

impl<'a> DNSWriter<'a> {
    fn new(data: &'a mut [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn build_query(mut self, id: u16, name: &str, kind: RecordKind) -> Result<&'a [u8], Error> {
        let flags: u16 = 0; // recurrsion not desired
        let num_questions: u16 = 1;
        let num_additionals: u16 = 0;
        let num_answers: u16 = 0;
        let num_authorities: u16 = 0;
        let class = RecordClass::IN;

        self.set_bytes(&id.to_be_bytes())?;
        self.set_bytes(&flags.to_be_bytes())?;
        self.set_bytes(&num_questions.to_be_bytes())?;
        self.set_bytes(&num_answers.to_be_bytes())?;
        self.set_bytes(&num_authorities.to_be_bytes())?;
        self.set_bytes(&num_additionals.to_be_bytes())?;

        for part in name.split('.').filter(|p| !p.is_empty()) {
            if part.len() > 63 {
                return Err(anyhow!("invalid part length for provided name"));
            }
            self.set_bytes(&[part.len() as u8])?;
            self.set_bytes(part.as_bytes())?;
        }
        self.set_bytes(&[0])?;
        self.set_bytes(&kind.encode().to_be_bytes())?;
        self.set_bytes(&class.encode().to_be_bytes())?;

        Ok(&self.data[0..self.pos])
    }

    fn set_bytes(&mut self, val: &[u8]) -> Result<(), Error> {
        let slot = self
            .data
            .get_mut(self.pos..self.pos + val.len())
            .ok_or_else(|| anyhow!("unexpected end of data"))?;
        slot.copy_from_slice(val);
        self.pos += val.len();
        Ok(())
    }
}

struct DNSReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DNSReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn decode_packet(mut self) -> Result<DNSPacket, Error> {
        let header = self.decode_header()?;
        let questions = self.decode_questions(header.num_questions)?;
        let answers = self.decode_records(header.num_answers)?;
        let authorities = self.decode_records(header.num_authorities)?;
        let additionals = self.decode_records(header.num_additionals)?;

        Ok(DNSPacket {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    fn decode_header(&mut self) -> Result<DNSHeader, Error> {
        Ok(DNSHeader {
            id: self.decode_u16()?,
            flags: self.decode_u16()?,
            num_questions: self.decode_u16()?,
            num_answers: self.decode_u16()?,
            num_authorities: self.decode_u16()?,
            num_additionals: self.decode_u16()?,
        })
    }

    fn decode_questions(&mut self, n: u16) -> Result<Vec<DNSQuestion>, Error> {
        (0..n).map(|_| self.decode_question()).collect()
    }

    fn decode_question(&mut self) -> Result<DNSQuestion, Error> {
        Ok(DNSQuestion {
            name: self.decode_name()?,
            kind: RecordKind::decode(self.decode_u16()?),
            class: RecordClass::decode(self.decode_u16()?),
        })
    }

    fn decode_records(&mut self, n: u16) -> Result<Vec<DNSRecord>, Error> {
        (0..n).map(|_| self.decode_record()).collect()
    }

    fn decode_record(&mut self) -> Result<DNSRecord, Error> {
        let name = self.decode_name()?;
        let kind = RecordKind::decode(self.decode_u16()?);
        let class = RecordClass::decode(self.decode_u16()?);
        let ttl = self.decode_u32()?;
        let data = self.decode_data(kind)?;

        Ok(DNSRecord {
            name,
            class,
            ttl,
            data,
        })
    }

    fn decode_name(&mut self) -> Result<String, Error> {
        let mut labels: Vec<String> = Vec::new();

        loop {
            let len = self.decode_u8()?;
            match len & 0xC0 {
                0x00 => {
                    if len == 0 {
                        break;
                    }
                    labels.push(String::from_utf8(self.get_bytes(len as usize)?.to_vec())?);
                }
                // Last two bits of the length being 1s indicate a compression pointer
                0xC0 => {
                    let rest = self.decode_u8()?;
                    // chop off the two leading bits and add it to the
                    // next 8 bits to form the pointer.
                    let pointer = (((len & 0x3F) as u16) << 8) | (rest as u16);
                    // we save the current position before recurrsing
                    // with the pointer.
                    let pos = self.pos;
                    self.pos = pointer as usize;
                    let label = self.decode_name()?;
                    self.pos = pos;
                    labels.push(label);
                    break;
                }
                instr => bail!("invalid instruction decoding name: {instr}"),
            }
        }

        Ok(labels.join("."))
    }

    fn decode_data(&mut self, kind: RecordKind) -> Result<RecordData, Error> {
        let len: usize = self.decode_u16()?.into();
        match kind {
            RecordKind::A => {
                if len != 4 {
                    bail!("invalid A record len {len}")
                }
                let octets: &[u8; 4] = self.get_bytes(len)?.try_into()?;
                let addr = Ipv4Addr::from_octets(octets.clone());
                Ok(RecordData::A(addr))
            }
            RecordKind::NS => Ok(RecordData::NS(self.decode_name()?)),
            RecordKind::Txt => {
                let data = self.get_bytes(len)?.to_vec();
                Ok(RecordData::Txt(String::from_utf8(data)?))
            }
            _ => {
                let data = self.get_bytes(len)?.to_vec();
                Ok(RecordData::Other(data))
            }
        }
    }

    fn decode_u8(&mut self) -> Result<u8, Error> {
        let val = self
            .data
            .get(self.pos)
            .ok_or_else(|| anyhow!("unexpected end of data"))?;
        self.pos += 1;
        Ok(*val)
    }

    fn decode_u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.get_bytes(2)?.try_into()?))
    }

    fn decode_u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.get_bytes(4)?.try_into()?))
    }

    fn get_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let bytes = self
            .data
            .get(self.pos..self.pos + len)
            .ok_or_else(|| anyhow!("unexpected end of data"))?;
        self.pos += len;
        Ok(bytes)
    }
}
