use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    str::FromStr,
};

use anyhow::{Error, anyhow};

use crate::{
    resolver::{RecordKind, resolve},
    tls::stream::TlsStream,
    url::{Scheme, URL},
};

enum Transport {
    Plain(TcpStream),
    TLS(TlsStream),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::TLS(stream) => stream.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::TLS(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::TLS(stream) => stream.flush(),
        }
    }
}

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
        Scheme::HTTP => Ok(Transport::Plain(stream)),
        Scheme::HTTPS => Ok(Transport::TLS(TlsStream::handshake(stream, &url.host)?)),
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
