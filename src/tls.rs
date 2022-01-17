use std::io;
use std::io::{Read, Write};
use std::sync::Arc;

use rustls::{self, ServerConfig, ServerConnection};

pub fn create_stream<T: Read + Write + Sized>(
    sock: T,
    config: Arc<ServerConfig>,
) -> Result<rustls::StreamOwned<ServerConnection, T>, io::Error> {
    let conn = ServerConnection::new(config).unwrap();
    let stream = rustls::StreamOwned { conn, sock };
    Ok(stream)
}

pub(crate) struct SwitchableConn<T: Read + Write>(Option<EitherConn<T>>);

pub(crate) enum EitherConn<T: Read + Write> {
    Plain(T),
    Tls(rustls::StreamOwned<ServerConnection, T>),
}

impl<T: Read + Write> Read for SwitchableConn<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.0.as_mut().unwrap() {
            EitherConn::Plain(p) => p.read(buf),
            EitherConn::Tls(t) => t.read(buf),
        }
    }
}

impl<T: Read + Write> Write for SwitchableConn<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.0.as_mut().unwrap() {
            EitherConn::Plain(p) => p.write(buf),
            EitherConn::Tls(t) => t.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0.as_mut().unwrap() {
            EitherConn::Plain(p) => p.flush(),
            EitherConn::Tls(t) => t.flush(),
        }
    }
}

impl<T: Read + Write> SwitchableConn<T> {
    pub fn new(rw: T) -> SwitchableConn<T> {
        SwitchableConn(Some(EitherConn::Plain(rw)))
    }

    pub fn switch_to_tls(&mut self, config: Arc<ServerConfig>) -> io::Result<()> {
        let replacement = match self.0.take() {
            Some(EitherConn::Plain(plain)) => Ok(EitherConn::Tls(create_stream(plain, config)?)),
            Some(EitherConn::Tls(_)) => Err(io::Error::new(
                io::ErrorKind::Other,
                "tls variant found when plain was expected",
            )),
            None => unreachable!(),
        }?;

        self.0 = Some(replacement);
        Ok(())
    }
}
