use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    str::FromStr,
};

use anyhow::{Error, anyhow};

use crate::{
    resolver::{RecordKind, resolve},
    tls::stream::{TlsStream, handshake},
    url::{Scheme, URL},
};

pub fn connect(url: &URL) -> Result<impl Read + Write + use<>, Error> {
    let ip = resolve_ip(&url.host)?;
    println!("resolved {} to {}", &url.host, ip);
    let addr = SocketAddr::new(ip, url.port);

    let stream = TcpStream::connect(addr).map_err(|e| anyhow!("could not connect: {e}"))?;

    println!(
        "opened connection {} - {}",
        stream.local_addr()?,
        stream.peer_addr()?
    );

    match url.scheme {
        Scheme::Http => Ok(Transport::Plain(stream)),
        Scheme::Https => Ok(Transport::Tls(handshake(stream, &url.host)?)),
    }
}

fn resolve_ip(host: &str) -> Result<IpAddr, Error> {
    match IpAddr::from_str(host) {
        Ok(ip) => Ok(ip),
        Err(_) => {
            let addr = resolve(host, RecordKind::A)?;
            Ok(IpAddr::from(addr))
        }
    }
}

enum Transport {
    Plain(TcpStream),
    Tls(TlsStream),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}
