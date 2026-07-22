use std::{
    collections::HashMap,
    io::{BufRead, BufReader, BufWriter, Write},
    net::TcpStream,
    string::String,
};

use anyhow::{Error, anyhow, bail};

use crate::{
    transport::connect,
    url::{URL, parse_url},
};

const HTTP_V1_1: &str = "HTTP/1.1";
const HTTP_V1_0: &str = "HTTP/1.0";

#[derive(Debug)]
pub enum Method {
    GET,
}

impl Method {
    fn as_str(&self) -> &'static str {
        match self {
            Self::GET => "GET",
        }
    }
}

#[derive(Debug)]
pub struct Request {
    method: Method,
    url: URL,
    headers: HashMap<String, String>,
}

impl Request {
    pub fn new(
        method: Method,
        url: &str,
        headers: Option<HashMap<String, String>>,
    ) -> Result<Self, Error> {
        let u = parse_url(url)?;

        let mut h = headers.unwrap_or(HashMap::new());

        h.insert("Host".to_string(), format!("{}:{}", u.host, u.port));
        h.insert("Connection".to_string(), "close".to_string());

        Ok(Self {
            method: method,
            url: u,
            headers: h,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        write!(
            writer,
            "{} {} {}\r\n",
            self.method.as_str(),
            self.url.path,
            HTTP_V1_1
        )?;
        for (key, val) in self.headers.iter() {
            write!(writer, "{}: {}\r\n", key, val)?;
        }
        write!(writer, "\r\n")?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Response {
    version: String,
    status: u16,
    msg: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Response {
    fn read_from<R: BufRead>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = String::new();
        reader.read_line(&mut buf)?;
        let parts = buf.trim_end().splitn(3, " ").collect::<Vec<&str>>();
        let version = match parts.get(0) {
            Some(&HTTP_V1_1) => HTTP_V1_1,
            Some(&HTTP_V1_0) => HTTP_V1_0,
            Some(v) => bail!("unsupported http version in response: {v}"),
            None => bail!("unspecified http version in response"),
        };
        let status = match parts.get(1) {
            Some(s) => s.parse::<u16>()?,
            None => bail!("unspecified status cose in response"),
        };
        let msg = parts.get(2);

        let mut headers: HashMap<String, String> = HashMap::new();
        loop {
            let mut buf = String::new();
            reader.read_line(&mut buf)?;
            if buf.trim().is_empty() {
                break;
            }
            let (k, v) = buf
                .split_once(":")
                .ok_or_else(|| anyhow!("bad header format encountered"))?;
            headers.insert(k.to_ascii_lowercase(), v.trim().to_string());
        }

        let body = match headers.get("content-length") {
            Some(cl) => {
                let len = cl.parse::<usize>()?;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                buf
            }
            None => {
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf)?;
                buf
            }
        };

        Ok(Self {
            version: version.to_string(),
            status,
            msg: msg.map(|m| m.to_string()),
            headers,
            body,
        })
    }
}

pub fn send(req: Request) -> Result<Response, Error> {
    println!(
        "parsed method: {}, scheme: {}, host: {}, port: {}, path: {}",
        req.method.as_str(),
        req.url.scheme,
        req.url.host,
        req.url.port,
        req.url.path
    );

    let mut stream = connect(&req.url.host, req.url.port)?;

    println!(
        "oppened connection: {} - {}",
        stream.local_addr()?,
        stream.peer_addr()?
    );

    println!("sending request: \n{:?}", req);

    let resp = exec(&mut stream, req)?;

    println!("received response: \n{:?}", resp);
    println!("with body: {}", str::from_utf8(resp.body.as_slice())?);

    Ok(resp)
}

fn exec(mut stream: &mut TcpStream, req: Request) -> Result<Response, Error> {
    let mut writer = BufWriter::new(&mut stream);
    req.write_to(&mut writer)?;
    writer.flush()?;
    drop(writer);

    let mut reader = BufReader::new(&mut stream);
    let resp = Response::read_from(&mut reader)?;

    Ok(resp)
}
