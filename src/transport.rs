use std::{
    net::{IpAddr, SocketAddr, TcpStream},
    str::FromStr,
};

use anyhow::{Error, anyhow};

use crate::resolver::{RecordKind, resolve};

pub fn connect(host: &str, port: u16) -> Result<TcpStream, Error> {
    let ip = resolve_ip(host)?;
    println!("resolved {host} to {ip}");
    let addr = SocketAddr::new(ip, port);
    TcpStream::connect(addr).map_err(|e| anyhow!("could not connect: {e}"))
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
