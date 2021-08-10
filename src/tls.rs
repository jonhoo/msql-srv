use std::io::{BufReader, Read, Write};
use std::sync::{Arc, Mutex};
use std::{fs, io};

use rustls::{
    self, AllowAnyAuthenticatedClient, Connection, NoClientAuth, RootCertStore, ServerConfig,
    ServerConnection,
};

/// TLS configuration
pub struct TlsConfig {
    /// Full path to the server certificate file.
    pub server_cert: String,
    /// Full path to the server key file.
    pub server_cert_key: String,
    /// Optional full path to a folder of client certificates to validate against.
    pub client_cert_dir: Option<String>,
}

fn make_config(config: &TlsConfig) -> Arc<rustls::ServerConfig> {
    let client_auth = if config.client_cert_dir.is_some() {
        let mut client_auth_roots = RootCertStore::empty();

        let paths = fs::read_dir(config.client_cert_dir.as_ref().unwrap()).unwrap();

        for path in paths {
            let path = path.unwrap();
            if !path.path().is_file() {
                continue;
            }

            let roots = load_certs(path.path().to_str().unwrap());

            for root in roots {
                client_auth_roots.add(&root).unwrap();
            }
        }

        AllowAnyAuthenticatedClient::new(client_auth_roots)
    } else {
        NoClientAuth::new()
    };

    let builder = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .expect("inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(client_auth);

    let mut server_config = {
        let certs = load_certs(&config.server_cert);
        let privkey = load_private_key(&config.server_cert_key);

        builder
            .with_single_cert(certs, privkey)
            .expect("bad certificates/private key")
    };

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    Arc::new(server_config)
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

pub struct TlsStream<C: Connection + Sized, T: Read + Write + Sized> {
    stream: Arc<Mutex<rustls::StreamOwned<C, T>>>,
}

impl<C, T> Clone for TlsStream<C, T>
where
    C: Connection,
    T: Read + Write,
{
    fn clone(&self) -> Self {
        TlsStream {
            stream: Arc::clone(&self.stream),
        }
    }
}

impl<C, T> Write for TlsStream<C, T>
where
    C: Connection,
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let stream = &mut self.stream.lock().unwrap();

        stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let stream = &mut self.stream.lock().unwrap();

        stream.flush()?;

        Ok(())
    }
}

impl<C, T> Read for TlsStream<C, T>
where
    C: Connection,
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let stream = &mut self.stream.lock().unwrap();

        stream.read(buf)
    }
}

pub fn create_stream<S: Read + Write>(
    sock: S,
    config: &TlsConfig,
) -> TlsStream<ServerConnection, S> {
    let config = make_config(config);

    let conn = ServerConnection::new(config).unwrap();

    let stream = Arc::new(Mutex::new(rustls::StreamOwned { conn, sock }));

    TlsStream { stream }
}
