extern crate chrono;
extern crate msql_srv;
extern crate mysql;
extern crate mysql_common as myc;
extern crate nom;

use msql_srv::AuthenticationContext;
use msql_srv::{
    Column, ErrorKind, InitWriter, MysqlIntermediary, MysqlShim, ParamParser, QueryResultWriter,
    StatementMetaWriter,
};
use mysql::prelude::*;
use mysql::MySqlError;
use mysql::OptsBuilder;
use mysql::SslOpts;
#[cfg(all(feature = "tls", unix))]
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    error::ErrorStack,
    hash::MessageDigest,
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{extension::SubjectKeyIdentifier, X509},
};
#[cfg(all(feature = "tls", unix))]
use rcgen::generate_simple_self_signed;
#[cfg(all(feature = "tls", unix))]
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    RootCertStore, ServerConfig,
};
use std::error::Error;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

struct TestingShim<Q, P, E, I, A> {
    columns: Vec<Column>,
    params: Vec<Column>,
    on_q: Q,
    on_p: P,
    on_e: E,
    on_i: I,
    after_auth: A,
    #[cfg(feature = "tls")]
    server_tls: Option<std::sync::Arc<rustls::ServerConfig>>,
    client_tls: Option<SslOpts>,
    #[cfg(all(feature = "tls", unix))]
    client_cert_pkcs12_file: Option<Arc<tempfile::NamedTempFile>>,
}

impl<Q, P, E, I, A> MysqlShim<net::TcpStream> for TestingShim<Q, P, E, I, A>
where
    Q: FnMut(&str, QueryResultWriter<net::TcpStream>) -> io::Result<()>,
    P: FnMut(&str) -> u32,
    E: FnMut(u32, Vec<msql_srv::ParamValue>, QueryResultWriter<net::TcpStream>) -> io::Result<()>,
    I: FnMut(&str, InitWriter<net::TcpStream>) -> io::Result<()>,
    A: FnMut(&AuthenticationContext) -> io::Result<()>,
{
    type Error = io::Error;

    fn on_prepare(
        &mut self,
        query: &str,
        info: StatementMetaWriter<net::TcpStream>,
    ) -> io::Result<()> {
        let id = (self.on_p)(query);
        info.reply(id, &self.params, &self.columns)
    }

    fn on_execute(
        &mut self,
        id: u32,
        params: ParamParser,
        results: QueryResultWriter<net::TcpStream>,
    ) -> io::Result<()> {
        (self.on_e)(id, params.into_iter().collect(), results)
    }

    fn on_close(&mut self, _: u32) {}

    fn on_init(&mut self, schema: &str, writer: InitWriter<net::TcpStream>) -> io::Result<()> {
        (self.on_i)(schema, writer)
    }

    fn on_query(
        &mut self,
        query: &str,
        results: QueryResultWriter<net::TcpStream>,
    ) -> io::Result<()> {
        (self.on_q)(query, results)
    }

    #[cfg(feature = "tls")]
    fn tls_config(&self) -> Option<std::sync::Arc<rustls::ServerConfig>> {
        self.server_tls.as_ref().map(std::sync::Arc::clone)
    }

    fn after_authentication(&mut self, auth_context: &AuthenticationContext) -> io::Result<()> {
        (self.after_auth)(auth_context)
    }
}

impl<Q, P, E, I, T> TestingShim<Q, P, E, I, T>
where
    Q: 'static + Send + FnMut(&str, QueryResultWriter<net::TcpStream>) -> io::Result<()>,
    P: 'static + Send + FnMut(&str) -> u32,
    E: 'static
        + Send
        + FnMut(u32, Vec<msql_srv::ParamValue>, QueryResultWriter<net::TcpStream>) -> io::Result<()>,
    I: 'static + Send + FnMut(&str, InitWriter<net::TcpStream>) -> io::Result<()>,
    T: 'static + Send + FnMut(&AuthenticationContext) -> io::Result<()>,
{
    fn new(on_q: Q, on_p: P, on_e: E, on_i: I, after_auth: T) -> Self {
        TestingShim {
            columns: Vec::new(),
            params: Vec::new(),
            on_q,
            on_p,
            on_e,
            on_i,
            after_auth,
            #[cfg(feature = "tls")]
            server_tls: None,
            client_tls: None,
            #[cfg(all(feature = "tls", unix))]
            client_cert_pkcs12_file: None,
        }
    }

    fn with_params(mut self, p: Vec<Column>) -> Self {
        self.params = p;
        self
    }

    fn with_columns(mut self, c: Vec<Column>) -> Self {
        self.columns = c;
        self
    }

    #[cfg(all(feature = "tls", unix))]
    fn with_tls(mut self, client: bool, server: bool, use_client_certs: bool) -> Self {
        use std::fs::File;

        use mysql::ClientIdentity;
        use rustls::server::WebPkiClientVerifier;

        let mut client_cert_der = None;

        if use_client_certs {
            let (client_cert, client_pkey) = mk_client_cert().unwrap();

            client_cert_der = Some(CertificateDer::from(client_cert.to_der().unwrap()));

            // Set up client cert der12 file.
            let client_cert_pkcs12_file = Arc::new(tempfile::NamedTempFile::new().unwrap());
            self.client_cert_pkcs12_file = Some(Arc::clone(&client_cert_pkcs12_file));

            let pkcs12 = Pkcs12::builder()
                .name("friendly_name")
                .cert(&client_cert)
                .pkey(&client_pkey)
                .build2("password")
                .unwrap();
            let der = pkcs12.to_der().unwrap();

            let mut f = File::create(&*client_cert_pkcs12_file).unwrap();
            f.write(&der).unwrap();
            f.flush().unwrap();
        }

        if server {
            let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();

            let builder = ServerConfig::builder();

            let builder = if let Some(client_cert_der) = client_cert_der {
                let mut client_auth_roots = RootCertStore::empty();

                client_auth_roots.add(client_cert_der).unwrap();

                let client_auth = WebPkiClientVerifier::builder(client_auth_roots.into())
                    .build()
                    .unwrap();

                builder.with_client_cert_verifier(client_auth)
            } else {
                builder.with_no_client_auth()
            }
            .with_single_cert(
                vec![CertificateDer::from(cert.serialize_der().unwrap())],
                PrivateKeyDer::Pkcs8(cert.get_key_pair().serialize_der().into()),
            )
            .unwrap();

            self.server_tls = Some(std::sync::Arc::new(builder));
        }

        if client {
            self.client_tls = Some(
                SslOpts::default()
                    .with_danger_accept_invalid_certs(true)
                    .with_client_identity(self.client_cert_pkcs12_file.as_ref().map(|x| {
                        ClientIdentity::new(x.path().to_owned()).with_password("password")
                    })),
            );
        }

        self
    }

    fn test<C>(self, c: C)
    where
        C: FnOnce(&mut mysql::Conn),
    {
        self.test_with_result(c).unwrap()
    }

    fn test_with_result<C>(self, c: C) -> Result<(), Box<dyn Error + 'static>>
    where
        C: FnOnce(&mut mysql::Conn) -> (),
    {
        let client_tls = self.client_tls.clone();

        let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let jh = thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            MysqlIntermediary::run_on_tcp(self, s)
        });

        let opts = OptsBuilder::default()
            .ip_or_hostname(Some("localhost"))
            .user(Some("username"))
            .tcp_port(port)
            .ssl_opts(client_tls);

        let mut db = mysql::Conn::new(opts)?;

        c(&mut db);
        drop(db);
        jh.join().unwrap().unwrap();

        Ok(())
    }
}

#[cfg(all(feature = "tls", unix))]
fn mk_client_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    let key_pair = PKey::from_rsa(Rsa::generate(2048)?)?;

    let mut cert_builder = X509::builder()?;

    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

#[test]
fn it_connects() {
    let username = Arc::new(Mutex::new(None));
    let username1 = Arc::clone(&username);
    TestingShim::new(
        |_, _| unreachable!(),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        move |a| {
            let mut ac = username1.lock().unwrap();
            assert_eq!(*ac, None);
            *ac = a.username.clone();
            Ok(())
        },
    )
    .test(|_| {});

    let username = username.lock().unwrap();
    assert_eq!(*username, Some(b"username".to_vec()));
}

#[cfg(all(feature = "tls", unix))]
fn tls_test_common(
    enable_client_tls: bool,
    enable_server_tls: bool,
    use_client_certs: bool,
) -> Result<(Option<Vec<u8>>, Option<Vec<CertificateDer<'static>>>), Box<dyn Error + 'static>> {
    let auth_context = Arc::new(Mutex::new((None, None)));
    let auth_context1 = Arc::clone(&auth_context);
    TestingShim::new(
        |_, _| unreachable!(),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        move |a| {
            let mut ac = auth_context1.lock().unwrap();
            assert_eq!(*ac, (None, None));
            *ac = (
                a.username.clone(),
                a.tls_client_certs
                    .map(|x| x.iter().map(|c| c.clone().into_owned()).collect()),
            );
            Ok(())
        },
    )
    .with_tls(enable_client_tls, enable_server_tls, use_client_certs)
    .test_with_result(|_| {})?;

    Ok(Arc::try_unwrap(auth_context).unwrap().into_inner().unwrap())
}

#[test]
#[cfg(all(feature = "tls", unix))]
fn it_connects_tls_server_only() {
    // Client can connect ok without SSL when SSL is enabled on the server.
    let (username, certs) = tls_test_common(false, true, false).unwrap();
    assert_eq!(username, Some(b"username".to_vec()));
    assert_eq!(certs, None);
}

#[test]
#[cfg(all(feature = "tls", unix))]
fn it_connects_tls_both_no_client_certs() {
    // SSL connection when ssl enabled on server and used by client, client not passing certs to the server.
    let (username, certs) = tls_test_common(true, true, false).unwrap();
    assert_eq!(username, Some(b"username".to_vec()));
    assert_eq!(certs, None);
}

#[test]
#[cfg(all(feature = "tls", unix))]
fn it_connects_tls_both_with_client_certs() {
    // SSL connection when ssl enabled on server and used by client, with the client passing certs to the server.
    let (username, certs) = tls_test_common(true, true, true).unwrap();
    assert_eq!(username, Some(b"username".to_vec()));
    assert!(!certs.expect("expected client certs").is_empty());
}

#[test]
#[cfg(all(feature = "tls", unix))]
fn it_connects_tls_both_with_delayed_server_read() {
    // This test is to ensure correctly handle the case when we read both the pre-TLS data as well
    // as (at least part of) the TLS handshake into our the buffer.  When that happens, we need to
    // ensure we correctly pass that TLS part of the data to rustls so that is can handle the TLS
    // handshake properly.
    use std::{marker::PhantomData, sync::Arc};

    struct MyShim<RW> {
        ph: PhantomData<RW>,
    }

    impl<RW: Read + Write> MysqlShim<RW> for MyShim<RW> {
        type Error = io::Error;

        fn on_prepare(
            &mut self,
            _: &str,
            _: StatementMetaWriter<'_, RW>,
        ) -> Result<(), Self::Error> {
            unreachable!()
        }

        fn on_execute(
            &mut self,
            _: u32,
            _: ParamParser<'_>,
            _: QueryResultWriter<'_, RW>,
        ) -> Result<(), Self::Error> {
            unreachable!()
        }

        fn on_close(&mut self, _: u32) {
            unreachable!()
        }

        fn on_query(&mut self, _: &str, _: QueryResultWriter<'_, RW>) -> Result<(), Self::Error> {
            unreachable!()
        }

        fn tls_config(&self) -> Option<Arc<ServerConfig>> {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();

            Some(std::sync::Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![CertificateDer::from(cert.serialize_der().unwrap())],
                        PrivateKeyDer::Pkcs8(cert.get_key_pair().serialize_der().into()),
                    )
                    .unwrap(),
            ))
        }
    }

    let shim = MyShim {
        ph: PhantomData::default(),
    };

    let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let jh = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let s = DelayedReadRW {
            s,
            read_delay: Duration::from_millis(200),
        };
        MysqlIntermediary::run_on(shim, s)
    });

    let db = mysql::Conn::new(
        OptsBuilder::default()
            .ip_or_hostname(Some("localhost"))
            .tcp_port(port)
            .ssl_opts(Some(
                SslOpts::default().with_danger_accept_invalid_certs(true),
            )),
    )
    .unwrap();
    drop(db);
    jh.join().unwrap().unwrap();
}

struct DelayedReadRW<RW: Read + Write> {
    s: RW,
    read_delay: Duration,
}

impl<RW: Read + Write> Read for DelayedReadRW<RW> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        thread::sleep(self.read_delay);
        self.s.read(buf)
    }
}

impl<RW: Read + Write> Write for DelayedReadRW<RW> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.s.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.s.flush()
    }
}

#[test]
#[cfg(all(feature = "tls", unix))]
fn it_does_not_connect_tls_client_only() {
    // Client requesting tls fails as expected when server does not support it.
    let e = tls_test_common(true, false, false).expect_err("client should not have connected");
    assert!(
        matches!(
            e.downcast_ref::<mysql::Error>(),
            Some(mysql::Error::DriverError(
                mysql::DriverError::TlsNotSupported
            ))
        ),
        "unexpected error {:?}",
        e
    );
}

#[test]
fn it_fails_correctly_on_after_auth_error() {
    let e = TestingShim::new(
        |_, _| unreachable!(),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        move |_| Err(io::Error::new(io::ErrorKind::Other, "")),
    )
    .test_with_result(|_| {})
    .expect_err("client should not have connected");

    let expected = MySqlError {
        state: "28000".to_owned(),
        message: "client authentication failed".to_owned(),
        code: 1045,
    };

    assert!(
        matches!(
            e.downcast_ref::<mysql::Error>(),
            Some(mysql::Error::MySqlError(m)) if m == &expected,
        ),
        "unexpected error {:?}",
        e
    );
}

#[test]
fn it_inits_ok() {
    TestingShim::new(
        |_, _| unreachable!(),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |schema, writer| {
            assert_eq!(schema, "test");
            writer.ok()
        },
        |_| Ok(()),
    )
    .test(|db| assert_eq!(true, db.select_db("test")));
}

#[test]
fn it_inits_error() {
    TestingShim::new(
        |_, _| unreachable!(),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |schema, writer| {
            assert_eq!(schema, "test");
            writer.error(
                ErrorKind::ER_BAD_DB_ERROR,
                format!("Database {} not found", schema).as_bytes(),
            )
        },
        |_| Ok(()),
    )
    .test(|db| assert_eq!(false, db.select_db("test")));
}

#[test]
fn it_inits_on_use_query_ok() {
    TestingShim::new(
        |_, _| unreachable!(),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |schema, writer| {
            assert_eq!(schema, "test");
            writer.ok()
        },
        |_| Ok(()),
    )
    .test(|db| match db.query_drop("USE `test`;") {
        Ok(_) => assert!(true),
        Err(_) => assert!(false),
    });
}

#[test]
fn it_pings() {
    TestingShim::new(
        |_, _| unreachable!(),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| assert_eq!(db.ping(), true))
}

#[test]
fn empty_response() {
    TestingShim::new(
        |_, w| w.completed(0, 0),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        assert_eq!(db.query_iter("SELECT a, b FROM foo").unwrap().count(), 0);
    })
}

#[test]
fn no_rows() {
    let cols = [Column {
        table: String::new(),
        column: "a".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
        colflags: myc::constants::ColumnFlags::empty(),
    }];
    TestingShim::new(
        move |_, w| w.start(&cols[..])?.finish(),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        assert_eq!(db.query_iter("SELECT a, b FROM foo").unwrap().count(), 0);
    })
}

#[test]
fn no_columns() {
    TestingShim::new(
        move |_, w| w.start(&[])?.finish(),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        assert_eq!(db.query_iter("SELECT a, b FROM foo").unwrap().count(), 0);
    })
}

#[test]
fn no_columns_but_rows() {
    TestingShim::new(
        move |_, w| w.start(&[])?.write_col(42).map(|_| ()),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        assert_eq!(db.query_iter("SELECT a, b FROM foo").unwrap().count(), 0);
    })
}

#[test]
fn error_response() {
    let err = (ErrorKind::ER_NO, "clearly not");
    TestingShim::new(
        move |_, w| w.error(err.0, err.1.as_bytes()),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        if let mysql::Error::MySqlError(e) = db.query_iter("SELECT a, b FROM foo").unwrap_err() {
            assert_eq!(
                e,
                mysql::error::MySqlError {
                    state: String::from_utf8(err.0.sqlstate().to_vec()).unwrap(),
                    message: err.1.to_owned(),
                    code: err.0 as u16,
                }
            );
        } else {
            unreachable!();
        }
    })
}

#[test]
fn error_in_result_set_response() {
    let err = (ErrorKind::ER_NO, "clearly not");
    TestingShim::new(
        move |_, w| {
            let cols = &[Column {
                table: String::new(),
                column: "a".to_owned(),
                coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
                colflags: myc::constants::ColumnFlags::empty(),
            }];
            let mut w = w.start(cols)?;
            w.write_col(1024)?;
            w.finish_error(err.0, &err.1.as_bytes())
        },
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        let mut result = db.query_iter("SELECT a FROM foo").unwrap();
        let row1 = result.next().unwrap().unwrap().get::<i16, _>(0).unwrap();
        assert_eq!(row1, 1024);
        if let mysql::Error::MySqlError(e) = result.by_ref().next().unwrap().unwrap_err() {
            assert_eq!(
                e,
                mysql::error::MySqlError {
                    state: String::from_utf8(err.0.sqlstate().to_vec()).unwrap(),
                    message: err.1.to_owned(),
                    code: err.0 as u16,
                }
            );
        } else {
            unreachable!()
        }
    })
}

#[test]
fn empty_on_drop() {
    let cols = [Column {
        table: String::new(),
        column: "a".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
        colflags: myc::constants::ColumnFlags::empty(),
    }];
    TestingShim::new(
        move |_, w| w.start(&cols[..]).map(|_| ()),
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        assert_eq!(db.query_iter("SELECT a, b FROM foo").unwrap().count(), 0);
    })
}

#[test]
fn it_queries_nulls() {
    TestingShim::new(
        |_, w| {
            let cols = &[Column {
                table: String::new(),
                column: "a".to_owned(),
                coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
                colflags: myc::constants::ColumnFlags::empty(),
            }];
            let mut w = w.start(cols)?;
            w.write_col(None::<i16>)?;
            w.finish()
        },
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        let row = db
            .query_iter("SELECT a, b FROM foo")
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(row.as_ref(0), Some(&mysql::Value::NULL));
    })
}

#[test]
fn it_queries() {
    TestingShim::new(
        |_, w| {
            let cols = &[Column {
                table: String::new(),
                column: "a".to_owned(),
                coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
                colflags: myc::constants::ColumnFlags::empty(),
            }];
            let mut w = w.start(cols)?;
            w.write_col(1024i16)?;
            w.finish()
        },
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        let row = db
            .query_iter("SELECT a, b FROM foo")
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(row.get::<i16, _>(0), Some(1024));
    })
}

#[test]
fn multi_result() {
    TestingShim::new(
        |_, w| {
            let cols = &[Column {
                table: String::new(),
                column: "a".to_owned(),
                coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
                colflags: myc::constants::ColumnFlags::empty(),
            }];
            let mut row = w.start(cols)?;
            row.write_col(1024i16)?;
            let w = row.finish_one()?;
            let mut row = w.start(cols)?;
            row.write_col(1025i16)?;
            row.finish()
        },
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        let mut result = db
            .query_iter("SELECT a FROM foo; SELECT a FROM foo")
            .unwrap();
        let mut set = result.iter().unwrap();
        let row1: Vec<_> = set
            .by_ref()
            .filter_map(|row| row.unwrap().get::<i16, _>(0))
            .collect();
        assert_eq!(row1, vec![1024]);
        drop(set);
        let mut set = result.iter().unwrap();
        let row2: Vec<_> = set
            .by_ref()
            .filter_map(|row| row.unwrap().get::<i16, _>(0))
            .collect();
        assert_eq!(row2, vec![1025]);
        drop(set);
        assert!(result.iter().is_none());
    })
}

#[test]
fn it_queries_many_rows() {
    TestingShim::new(
        |_, w| {
            let cols = &[
                Column {
                    table: String::new(),
                    column: "a".to_owned(),
                    coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
                    colflags: myc::constants::ColumnFlags::empty(),
                },
                Column {
                    table: String::new(),
                    column: "b".to_owned(),
                    coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
                    colflags: myc::constants::ColumnFlags::empty(),
                },
            ];
            let mut w = w.start(cols)?;
            w.write_col(1024i16)?;
            w.write_col(1025i16)?;
            w.end_row()?;
            w.write_row(&[1024i16, 1025i16])?;
            w.finish()
        },
        |_| unreachable!(),
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        let mut rows = 0;
        for row in db.query_iter("SELECT a, b FROM foo").unwrap() {
            let row = row.unwrap();
            assert_eq!(row.get::<i16, _>(0), Some(1024));
            assert_eq!(row.get::<i16, _>(1), Some(1025));
            rows += 1;
        }
        assert_eq!(rows, 2);
    })
}

#[test]
fn it_prepares() {
    let cols = vec![Column {
        table: String::new(),
        column: "a".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
        colflags: myc::constants::ColumnFlags::empty(),
    }];
    let cols2 = cols.clone();
    let params = vec![Column {
        table: String::new(),
        column: "c".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
        colflags: myc::constants::ColumnFlags::empty(),
    }];

    TestingShim::new(
        |_, _| unreachable!(),
        |q| {
            assert_eq!(q, "SELECT a FROM b WHERE c = ?");
            41
        },
        move |stmt, params, w| {
            assert_eq!(stmt, 41);
            assert_eq!(params.len(), 1);
            // rust-mysql sends all numbers as LONGLONG
            assert_eq!(
                params[0].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_LONGLONG
            );
            assert_eq!(Into::<i8>::into(params[0].value), 42i8);

            let mut w = w.start(&cols)?;
            w.write_col(1024i16)?;
            w.finish()
        },
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .with_params(params)
    .with_columns(cols2)
    .test(|db| {
        let row = db
            .exec_iter("SELECT a FROM b WHERE c = ?", (42i16,))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(row.get::<i16, _>(0), Some(1024i16));
    })
}

#[test]
fn insert_exec() {
    let params = vec![
        Column {
            table: String::new(),
            column: "username".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_VARCHAR,
            colflags: myc::constants::ColumnFlags::empty(),
        },
        Column {
            table: String::new(),
            column: "email".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_VARCHAR,
            colflags: myc::constants::ColumnFlags::empty(),
        },
        Column {
            table: String::new(),
            column: "pw".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_VARCHAR,
            colflags: myc::constants::ColumnFlags::empty(),
        },
        Column {
            table: String::new(),
            column: "created".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_DATETIME,
            colflags: myc::constants::ColumnFlags::empty(),
        },
        Column {
            table: String::new(),
            column: "session".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_VARCHAR,
            colflags: myc::constants::ColumnFlags::empty(),
        },
        Column {
            table: String::new(),
            column: "rss".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_VARCHAR,
            colflags: myc::constants::ColumnFlags::empty(),
        },
        Column {
            table: String::new(),
            column: "mail".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_VARCHAR,
            colflags: myc::constants::ColumnFlags::empty(),
        },
    ];

    TestingShim::new(
        |_, _| unreachable!(),
        |_| 1,
        move |_, params, w| {
            assert_eq!(params.len(), 7);
            assert_eq!(
                params[0].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_VAR_STRING
            );
            assert_eq!(
                params[1].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_VAR_STRING
            );
            assert_eq!(
                params[2].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_VAR_STRING
            );
            assert_eq!(
                params[3].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_DATETIME
            );
            assert_eq!(
                params[4].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_VAR_STRING
            );
            assert_eq!(
                params[5].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_VAR_STRING
            );
            assert_eq!(
                params[6].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_VAR_STRING
            );
            assert_eq!(Into::<&str>::into(params[0].value), "user199");
            assert_eq!(Into::<&str>::into(params[1].value), "user199@example.com");
            assert_eq!(
                Into::<&str>::into(params[2].value),
                "$2a$10$Tq3wrGeC0xtgzuxqOlc3v.07VTUvxvwI70kuoVihoO2cE5qj7ooka"
            );
            assert_eq!(
                Into::<chrono::NaiveDateTime>::into(params[3].value),
                chrono::NaiveDate::from_ymd_opt(2018, 4, 6)
                    .unwrap()
                    .and_hms_opt(13, 0, 56)
                    .unwrap()
            );
            assert_eq!(Into::<&str>::into(params[4].value), "token199");
            assert_eq!(Into::<&str>::into(params[5].value), "rsstoken199");
            assert_eq!(Into::<&str>::into(params[6].value), "mtok199");

            w.completed(42, 1)
        },
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .with_params(params)
    .test(|db| {
        let res = db
            .exec_iter(
                "INSERT INTO `users` \
                 (`username`, `email`, `password_digest`, `created_at`, \
                 `session_token`, `rss_token`, `mailing_list_token`) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "user199",
                    "user199@example.com",
                    "$2a$10$Tq3wrGeC0xtgzuxqOlc3v.07VTUvxvwI70kuoVihoO2cE5qj7ooka",
                    mysql::Value::Date(2018, 4, 6, 13, 0, 56, 0),
                    "token199",
                    "rsstoken199",
                    "mtok199",
                ),
            )
            .unwrap();
        assert_eq!(res.affected_rows(), 42);
        assert_eq!(res.last_insert_id(), Some(1));
    })
}

#[test]
fn send_long() {
    let cols = vec![Column {
        table: String::new(),
        column: "a".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
        colflags: myc::constants::ColumnFlags::empty(),
    }];
    let cols2 = cols.clone();
    let params = vec![Column {
        table: String::new(),
        column: "c".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_BLOB,
        colflags: myc::constants::ColumnFlags::empty(),
    }];

    TestingShim::new(
        |_, _| unreachable!(),
        |q| {
            assert_eq!(q, "SELECT a FROM b WHERE c = ?");
            41
        },
        move |stmt, params, w| {
            assert_eq!(stmt, 41);
            assert_eq!(params.len(), 1);
            // rust-mysql sends all strings as VAR_STRING
            assert_eq!(
                params[0].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_VAR_STRING
            );
            assert_eq!(Into::<&[u8]>::into(params[0].value), b"Hello world");

            let mut w = w.start(&cols)?;
            w.write_col(1024i16)?;
            w.finish()
        },
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .with_params(params)
    .with_columns(cols2)
    .test(|db| {
        let row = db
            .exec_iter("SELECT a FROM b WHERE c = ?", (b"Hello world",))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(row.get::<i16, _>(0), Some(1024i16));
    })
}

#[test]
fn it_prepares_many() {
    let cols = vec![
        Column {
            table: String::new(),
            column: "a".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
            colflags: myc::constants::ColumnFlags::empty(),
        },
        Column {
            table: String::new(),
            column: "b".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
            colflags: myc::constants::ColumnFlags::empty(),
        },
    ];
    let cols2 = cols.clone();

    TestingShim::new(
        |_, _| unreachable!(),
        |q| {
            assert_eq!(q, "SELECT a, b FROM x");
            41
        },
        move |stmt, params, w| {
            assert_eq!(stmt, 41);
            assert_eq!(params.len(), 0);

            let mut w = w.start(&cols)?;
            w.write_col(1024i16)?;
            w.write_col(1025i16)?;
            w.end_row()?;
            w.write_row(&[1024i16, 1025i16])?;
            w.finish()
        },
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .with_params(Vec::new())
    .with_columns(cols2)
    .test(|db| {
        let mut rows = 0;
        for row in db.exec_iter("SELECT a, b FROM x", ()).unwrap() {
            let row = row.unwrap();
            assert_eq!(row.get::<i16, _>(0), Some(1024));
            assert_eq!(row.get::<i16, _>(1), Some(1025));
            rows += 1;
        }
        assert_eq!(rows, 2);
    })
}

#[test]
fn prepared_empty() {
    let cols = vec![Column {
        table: String::new(),
        column: "a".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
        colflags: myc::constants::ColumnFlags::empty(),
    }];
    let cols2 = cols;
    let params = vec![Column {
        table: String::new(),
        column: "c".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
        colflags: myc::constants::ColumnFlags::empty(),
    }];

    TestingShim::new(
        |_, _| unreachable!(),
        |_| 0,
        move |_, params, w| {
            assert!(!params.is_empty());
            w.completed(0, 0)
        },
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .with_params(params)
    .with_columns(cols2)
    .test(|db| {
        assert_eq!(
            db.exec_iter("SELECT a FROM b WHERE c = ?", (42i16,))
                .unwrap()
                .count(),
            0
        );
    })
}

#[test]
fn prepared_no_params() {
    let cols = vec![Column {
        table: String::new(),
        column: "a".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
        colflags: myc::constants::ColumnFlags::empty(),
    }];
    let cols2 = cols.clone();
    let params = vec![];

    TestingShim::new(
        |_, _| unreachable!(),
        |_| 0,
        move |_, params, w| {
            assert!(params.is_empty());
            let mut w = w.start(&cols)?;
            w.write_col(1024i16)?;
            w.finish()
        },
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .with_params(params)
    .with_columns(cols2)
    .test(|db| {
        let row = db.exec_iter("foo", ()).unwrap().next().unwrap().unwrap();
        assert_eq!(row.get::<i16, _>(0), Some(1024i16));
    })
}

#[test]
fn prepared_nulls() {
    let cols = vec![
        Column {
            table: String::new(),
            column: "a".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
            colflags: myc::constants::ColumnFlags::empty(),
        },
        Column {
            table: String::new(),
            column: "b".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
            colflags: myc::constants::ColumnFlags::empty(),
        },
    ];
    let cols2 = cols.clone();
    let params = vec![
        Column {
            table: String::new(),
            column: "c".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
            colflags: myc::constants::ColumnFlags::empty(),
        },
        Column {
            table: String::new(),
            column: "d".to_owned(),
            coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
            colflags: myc::constants::ColumnFlags::empty(),
        },
    ];

    TestingShim::new(
        |_, _| unreachable!(),
        |_| 0,
        move |_, params, w| {
            assert_eq!(params.len(), 2);
            assert!(params[0].value.is_null());
            assert!(!params[1].value.is_null());
            assert_eq!(
                params[0].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_NULL
            );
            // rust-mysql sends all numbers as LONGLONG :'(
            assert_eq!(
                params[1].coltype,
                myc::constants::ColumnType::MYSQL_TYPE_LONGLONG
            );
            assert_eq!(Into::<i8>::into(params[1].value), 42i8);

            let mut w = w.start(&cols)?;
            w.write_row(vec![None::<i16>, Some(42)])?;
            w.finish()
        },
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .with_params(params)
    .with_columns(cols2)
    .test(|db| {
        let row = db
            .exec_iter(
                "SELECT a, b FROM x WHERE c = ? AND d = ?",
                (mysql::Value::NULL, 42),
            )
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(row.as_ref(0), Some(&mysql::Value::NULL));
        assert_eq!(row.get::<i16, _>(1), Some(42));
    })
}

#[test]
fn prepared_no_rows() {
    let cols = vec![Column {
        table: String::new(),
        column: "a".to_owned(),
        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
        colflags: myc::constants::ColumnFlags::empty(),
    }];
    let cols2 = cols.clone();
    TestingShim::new(
        |_, _| unreachable!(),
        |_| 0,
        move |_, _, w| w.start(&cols[..])?.finish(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .with_columns(cols2)
    .test(|db| {
        assert_eq!(db.exec_iter("SELECT a, b FROM foo", ()).unwrap().count(), 0);
    })
}

#[test]
fn prepared_no_cols_but_rows() {
    TestingShim::new(
        |_, _| unreachable!(),
        |_| 0,
        move |_, _, w| w.start(&[])?.write_col(42).map(|_| ()),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        assert_eq!(db.exec_iter("SELECT a, b FROM foo", ()).unwrap().count(), 0);
    })
}

#[test]
fn prepared_no_cols() {
    TestingShim::new(
        |_, _| unreachable!(),
        |_| 0,
        move |_, _, w| w.start(&[])?.finish(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(|db| {
        assert_eq!(db.exec_iter("SELECT a, b FROM foo", ()).unwrap().count(), 0);
    })
}

#[test]
fn really_long_query() {
    let long = "CREATE TABLE `stories` (`id` int unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, `always_null` int, `created_at` datetime, `user_id` int unsigned, `url` varchar(250) DEFAULT '', `title` varchar(150) DEFAULT '' NOT NULL, `description` mediumtext, `short_id` varchar(6) DEFAULT '' NOT NULL, `is_expired` tinyint(1) DEFAULT 0 NOT NULL, `is_moderated` tinyint(1) DEFAULT 0 NOT NULL, `markeddown_description` mediumtext, `story_cache` mediumtext, `merged_story_id` int, `unavailable_at` datetime, `twitter_id` varchar(20), `user_is_author` tinyint(1) DEFAULT 0,  INDEX `index_stories_on_created_at`  (`created_at`), fulltext INDEX `index_stories_on_description`  (`description`),   INDEX `is_idxes`  (`is_expired`, `is_moderated`),  INDEX `index_stories_on_is_expired`  (`is_expired`),  INDEX `index_stories_on_is_moderated`  (`is_moderated`),  INDEX `index_stories_on_merged_story_id`  (`merged_story_id`), UNIQUE INDEX `unique_short_id`  (`short_id`), fulltext INDEX `index_stories_on_story_cache`  (`story_cache`), fulltext INDEX `index_stories_on_title`  (`title`),  INDEX `index_stories_on_twitter_id`  (`twitter_id`),  INDEX `url`  (`url`(191)),  INDEX `index_stories_on_user_id`  (`user_id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    TestingShim::new(
        move |q, w| {
            assert_eq!(q, long);
            w.start(&[])?.finish()
        },
        |_| 0,
        |_, _, _| unreachable!(),
        |_, _| unreachable!(),
        |_| Ok(()),
    )
    .test(move |db| {
        db.query_iter(long).unwrap();
    })
}
