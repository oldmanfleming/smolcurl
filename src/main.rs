mod http;
mod resolver;
mod transport;
mod url;

use std::env;

use anyhow::{Error, anyhow};

use crate::http::send;

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    let url = args.get(1).ok_or(anyhow!("missing url"))?;
    let resp = send("GET", url)?;
    println!("response: {}", resp);
    Ok(())
}
