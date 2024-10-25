extern crate chrono;
extern crate msql_srv;
extern crate mysql;
extern crate mysql_common as myc;
extern crate nom;

use msql_srv::AuthenticationContext;
use msql_srv::PluginAuth;
use msql_srv::{MysqlIntermediary, MysqlShim, QueryResultWriter, StatementMetaWriter};
#[cfg(all(feature = "tls", unix))]
use rcgen::generate_simple_self_signed;
#[cfg(all(feature = "tls", unix))]
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use std::io;
use std::io::Error;
use std::net;
use std::sync::Arc;
use std::thread;

fn main() {
    let mut threads = Vec::new();
    let listener = net::TcpListener::bind("127.0.0.1:3306").unwrap();

    while let Ok((s, _)) = listener.accept() {
        threads.push(thread::spawn(move || {
            MysqlIntermediary::run_on_tcp(ProxyServerSession, s).unwrap();
        }));
    }

    for t in threads {
        t.join().unwrap();
    }
}

#[derive(Debug)]
pub struct ProxyServerSession;

impl<W: std::io::Write + std::io::Read> MysqlShim<W> for ProxyServerSession {
    type Error = io::Error;
    fn on_prepare(&mut self, _: &str, info: StatementMetaWriter<W>) -> io::Result<()> {
        info.reply(42, &[], &[])
    }
    fn on_execute(
        &mut self,
        _: u32,
        _: msql_srv::ParamParser,
        results: QueryResultWriter<W>,
    ) -> io::Result<()> {
        results.completed(0, 0)
    }
    fn on_close(&mut self, _: u32) {}

    fn on_query(&mut self, _: &str, results: QueryResultWriter<W>) -> io::Result<()> {
        results.start(&[])?.finish()
    }

    fn after_authentication(
        &mut self,
        context: &AuthenticationContext<'_>,
    ) -> Result<(), Self::Error> {
        if let Some(auth) = context.plugin_auth.as_ref() {
            let PluginAuth {
                salt: _,
                auth_data: _,
                ..
            } = auth;
            // use salt and auth data to verify password.
            // see the client implementation for more detail:
            // https://github.com/blackbeam/rust_mysql_common/blob/ba64cc2605cb64e9973bb084cbcab1d6b0697ef9/src/scramble.rs#L115
        } else {
            return Err(Error::new(
                io::ErrorKind::Unsupported,
                "Ensure ssl is enabled in jdbc and verify server Certificate is off.",
            ));
        }

        Ok(())
    }

    fn tls_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();

        let builder = ServerConfig::builder();

        let builder = builder
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.serialize_der().unwrap())],
                PrivateKeyDer::Pkcs8(cert.get_key_pair().serialize_der().into()),
            )
            .unwrap();

        Some(std::sync::Arc::new(builder))
    }
}
