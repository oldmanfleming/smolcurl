use anyhow::Error;

use crate::{transport::connect, url::parse_url};

pub fn send(method: &str, url: &str) -> Result<String, Error> {
    let url = parse_url(url)?;

    println!(
        "parsed method: {}, scheme: {}, host: {}, port: {}, path: {}",
        method, url.scheme, url.host, url.port, url.path
    );

    let stream = connect(&url.host, url.port)?;

    println!(
        "oppened connection: {} - {}",
        stream.local_addr()?,
        stream.peer_addr()?
    );

    todo!()
}
