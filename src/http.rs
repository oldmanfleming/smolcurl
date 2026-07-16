use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::Error;

use crate::{transport::connect, url::parse_url};

const HTTP_VERSION: &str = "HTTP/1.1";

pub fn send(method: &str, url: &str) -> Result<String, Error> {
    let url = parse_url(url)?;

    println!(
        "parsed method: {}, scheme: {}, host: {}, port: {}, path: {}",
        method, url.scheme, url.host, url.port, url.path
    );

    let mut stream = connect(&url.host, url.port)?;

    println!(
        "oppened connection: {} - {}",
        stream.local_addr()?,
        stream.peer_addr()?
    );

    let resp = exec(&mut stream, method, url.host, url.port, url.path)?;

    Ok(resp)
}

fn exec(
    stream: &mut TcpStream,
    method: &str,
    host: String,
    port: u16,
    path: String,
) -> Result<String, Error> {
    let mut req = format!("{method} {path} {HTTP_VERSION}\r\n");
    push_header(&mut req, "Host", format!("{host}:{port}"));
    push_header(&mut req, "Connection", "close".to_string());

    req.push_str("\r\n");

    println!("sending request: \n\n{req}");

    stream.write_all(req.as_bytes())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let resp = String::from_utf8_lossy(&buf).to_string();

    println!("received response: \n\n{resp}");

    Ok(resp)
}

fn push_header(req: &mut String, key: &str, value: String) {
    req.push_str(format!("{key}: {value} \r\n").as_str());
}
