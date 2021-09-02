use std::io;
use std::io::{Read, Write};
use std::sync::Arc;

use rustls::{self, ServerConnection};

pub fn create_stream<T: Read + Write + Sized>(
    sock: T,
    config: &rustls::ServerConfig,
) -> Result<rustls::StreamOwned<ServerConnection, T>, io::Error> {
    let conn = ServerConnection::new(Arc::new(config.clone())).unwrap();
    let stream = rustls::StreamOwned { conn, sock };
    Ok(stream)
}
