use std::io::{self, Chain, Cursor};
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

pub(crate) struct SwitchableConn<T: Read + Write>(pub(crate) Option<EitherConn<T>>);

pub(crate) enum EitherConn<T: Read + Write> {
    Plain(T),
    Tls(Box<rustls::StreamOwned<ServerConnection, PrependedReader<T>>>),
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

    pub fn switch_to_tls(
        &mut self,
        config: Arc<ServerConfig>,
        to_prepend: &[u8],
    ) -> io::Result<()> {
        let replacement = match self.0.take() {
            Some(EitherConn::Plain(plain)) => Ok(EitherConn::Tls(Box::new(create_stream(
                PrependedReader::new(to_prepend, plain),
                config,
            )?))),
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

pub(crate) struct PrependedReader<RW: Read + Write> {
    inner: Chain<Cursor<Vec<u8>>, RW>,
}

impl<RW: Read + Write> PrependedReader<RW> {
    fn new(prepended: &[u8], rw: RW) -> PrependedReader<RW> {
        PrependedReader {
            inner: Cursor::new(prepended.to_vec()).chain(rw),
        }
    }
}

impl<RW: Read + Write> Read for PrependedReader<RW> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<RW: Read + Write> Write for PrependedReader<RW> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.get_mut().1.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.get_mut().1.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::PrependedReader;

    #[test]
    fn test_bufreader_replace() {
        let mut rw = Cursor::new(vec![1, 2, 3]);
        let mut br = PrependedReader::new(&[0, 1, 2], &mut rw);
        let mut out = Vec::new();
        br.read_to_end(&mut out).unwrap();

        assert_eq!(&out, &[0, 1, 2, 1, 2, 3]);
    }
}
