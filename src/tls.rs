use std::io::{BufReader, Read, Write};
use std::sync::Arc;
use std::{fs, io};

use rustls::{self, NoClientAuth, ServerConfig, ServerConnection};

/// TLS configuration
#[derive(Clone)]
pub struct TlsConfig {
    /// Full path to the server certificate file.
    pub server_cert: String,
    /// Full path to the server key file.
    pub server_cert_key: String,
}

fn make_config(config: &TlsConfig) -> Result<Arc<rustls::ServerConfig>, io::Error> {
    let builder = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "inconsistent cipher-suites/versions specified",
            )
        })?
        .with_client_cert_verifier(NoClientAuth::new());

    let mut server_config = {
        let certs = load_cert(&config.server_cert)?;
        let privkey = load_private_key(&config.server_cert_key)?;

        builder
            .with_single_cert(certs, privkey)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "bad certificates/private key"))?
    };

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    Ok(Arc::new(server_config))
}

fn load_cert(filename: &str) -> Result<Vec<rustls::Certificate>, io::Error> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    Ok(rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect())
}

fn load_private_key(filename: &str) -> Result<rustls::PrivateKey, io::Error> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot parse private key .pem file",
            )
        })? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    Err(io::Error::new(
        io::ErrorKind::Other,
        format!(
            "no keys found in {:?} (encrypted keys not supported)",
            filename
        ),
    ))
}

pub fn create_stream<T: Read + Write + Sized>(
    sock: T,
    config: &TlsConfig,
) -> Result<rustls::StreamOwned<ServerConnection, T>, io::Error> {
    let config = make_config(config)?;
    let conn = ServerConnection::new(config).unwrap();
    let stream = rustls::StreamOwned { conn, sock };
    Ok(stream)
}
