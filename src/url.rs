use std::fmt;

use anyhow::{Error, anyhow, bail};

#[derive(Debug)]
pub struct URL {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path: String,
}

#[derive(Debug)]
pub enum Scheme {
    HTTP,
    HTTPS,
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Scheme::HTTP => write!(f, "http"),
            Scheme::HTTPS => write!(f, "https"),
        }
    }
}

pub fn parse_url(url: &str) -> Result<URL, Error> {
    if url.is_empty() {
        bail!("url can not be empty");
    }

    let (scheme, rest) = match parse_scheme(url)? {
        ("http", rest) => (Scheme::HTTP, rest),
        ("https", rest) => (Scheme::HTTPS, rest),
        _ => bail!("Unsupported scheme"),
    };

    if !rest.starts_with("//") {
        bail!("missing // delimiter");
    }

    let (hostport, path) = split_hostport(&rest[2..])?;

    let (host, port) = parse_hostport(&scheme, hostport)?;

    Ok(URL {
        scheme: scheme,
        host: host.into(),
        port: port,
        path: path.into(),
    })
}

fn parse_scheme(url: &str) -> Result<(&str, &str), Error> {
    for (i, c) in url.char_indices() {
        match c {
            'a'..='z' | 'A'..='Z' => continue,
            '0'..='9' | '+' | '-' | '.' => match i {
                0 => bail!("scheme must start with a letter"),
                _ => continue,
            },
            ':' => match i {
                0 => bail!("sheme must not be empty"),
                _ => return Ok((&url[0..i], &url[i + 1..])),
            },
            _ => bail!("invalid character in scheme"),
        }
    }
    Err(anyhow!("missing colon delimiter"))
}

fn split_hostport(rest: &str) -> Result<(&str, &str), Error> {
    let (hostport, path) = match rest.rfind("/") {
        Some(0) => bail!("host must be specified"),
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    Ok((hostport, path))
}

fn parse_hostport<'a>(scheme: &Scheme, hostport: &'a str) -> Result<(&'a str, u16), Error> {
    match hostport.rfind(":") {
        Some(0) => Err(anyhow!("missing host before colon")),
        Some(i) if i == hostport.len() - 1 => Err(anyhow!("missing port after colon")),
        Some(i) => Ok((&hostport[..i], parse_port(&hostport[i + 1..])?)),
        None => Ok((hostport, resolve_port(scheme))),
    }
}

fn resolve_port(scheme: &Scheme) -> u16 {
    match scheme {
        Scheme::HTTP => 80,
        Scheme::HTTPS => 553,
    }
}

fn parse_port(port_str: &str) -> Result<u16, Error> {
    match port_str.parse::<u16>() {
        Ok(port) => Ok(port),
        Err(e) => Err(anyhow!("bad port: {} {}", port_str, e)),
    }
}
