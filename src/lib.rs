//! Bindings for emulating a MySQL/MariaDB server.
//!
//! When developing new databases or caching layers, it can be immensely useful to test your system
//! using existing applications. However, this often requires significant work modifying
//! applications to use your database over the existing ones. This crate solves that problem by
//! acting as a MySQL server, and delegating operations such as querying and query execution to
//! user-defined logic.
//!
//! To start, implement `MysqlShim` for your backend, and create a `MysqlIntermediary` over an
//! instance of your backend and a connection stream. The appropriate methods will be called on
//! your backend whenever a client issues a `QUERY`, `PREPARE`, or `EXECUTE` command, and you will
//! have a chance to respond appropriately. For example, to write a shim that always responds to
//! all commands with a "no results" reply:
//!
//! ```
//! # extern crate msql_srv;
//! extern crate mysql;
//! # use std::io;
//! # use std::net;
//! # use std::thread;
//! use msql_srv::*;
//! use mysql::prelude::*;
//! use mysql::Opts;
//!
//! struct Backend;
//! impl<W: io::Read + io::Write> MysqlShim<W> for Backend {
//!     type Error = io::Error;
//!
//!     fn on_prepare(&mut self, _: &str, info: StatementMetaWriter<W>) -> io::Result<()> {
//!         info.reply(42, &[], &[])
//!     }
//!     fn on_execute(
//!         &mut self,
//!         _: u32,
//!         _: ParamParser,
//!         results: QueryResultWriter<W>,
//!     ) -> io::Result<()> {
//!         results.completed(0, 0)
//!     }
//!     fn on_close(&mut self, _: u32) {}
//!
//!     fn on_init(&mut self, _: &str, writer: InitWriter<W>) -> io::Result<()> { Ok(()) }
//!
//!     fn on_query(&mut self, _: &str, results: QueryResultWriter<W>) -> io::Result<()> {
//!         let cols = [
//!             Column {
//!                 table: "foo".to_string(),
//!                 column: "a".to_string(),
//!                 coltype: ColumnType::MYSQL_TYPE_LONGLONG,
//!                 colflags: ColumnFlags::empty(),
//!             },
//!             Column {
//!                 table: "foo".to_string(),
//!                 column: "b".to_string(),
//!                 coltype: ColumnType::MYSQL_TYPE_STRING,
//!                 colflags: ColumnFlags::empty(),
//!             },
//!         ];
//!
//!         let mut rw = results.start(&cols)?;
//!         rw.write_col(42)?;
//!         rw.write_col("b's value")?;
//!         rw.finish()
//!     }
//! }
//!
//! fn main() {
//!     let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
//!     let port = listener.local_addr().unwrap().port();
//!
//!     let jh = thread::spawn(move || {
//!         if let Ok((s, _)) = listener.accept() {
//!             MysqlIntermediary::run_on_tcp(Backend, s).unwrap();
//!         }
//!     });
//!
//!     let mut db = mysql::Conn::new(Opts::from_url(&format!("mysql://127.0.0.1:{}", port)).unwrap()).unwrap();
//!     assert_eq!(db.ping(), true);
//!     assert_eq!(db.query_iter("SELECT a, b FROM foo").unwrap().count(), 1);
//!     drop(db);
//!     jh.join().unwrap();
//! }
//! ```
#![deny(missing_docs)]
#![deny(rust_2018_idioms)]

// Note to developers: you can find decent overviews of the protocol at
//
//   https://github.com/cwarden/mysql-proxy/blob/master/doc/protocol.rst
//
// and
//
//   https://mariadb.com/kb/en/library/clientserver-protocol/
//
// Wireshark also does a pretty good job at parsing the MySQL protocol.

extern crate mysql_common as myc;

use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::iter;
use std::net;

use commands::ClientHandshake;
use myc::constants::CapabilityFlags;

pub use crate::myc::constants::{ColumnFlags, ColumnType, StatusFlags};

mod commands;
mod errorcodes;
mod packet;
mod params;
mod resultset;
#[cfg(feature = "tls")]
mod tls;
mod value;
mod writers;

/// Meta-information abot a single column, used either to describe a prepared statement parameter
/// or an output column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// This column's associated table.
    ///
    /// Note that this is *technically* the table's alias.
    pub table: String,
    /// This column's name.
    ///
    /// Note that this is *technically* the column's alias.
    pub column: String,
    /// This column's type>
    pub coltype: ColumnType,
    /// Any flags associated with this column.
    ///
    /// Of particular interest are `ColumnFlags::UNSIGNED_FLAG` and `ColumnFlags::NOT_NULL_FLAG`.
    pub colflags: ColumnFlags,
}

pub use crate::errorcodes::ErrorKind;
pub use crate::params::{ParamParser, ParamValue, Params};
pub use crate::resultset::{InitWriter, QueryResultWriter, RowWriter, StatementMetaWriter};
pub use crate::value::{ToMysqlValue, Value, ValueInner};

/// Salt length, we set the salt as fixed 20 bytes.
pub const SALT_SIZE: usize = 20;

const AUTH_PLUGIN_DATA_PART_1_LENGTH: usize = 8;
const DEFAULT_PLUGIN_AUTH: &str = "mysql_native_password";

/// Implementors of this trait can be used to drive a MySQL-compatible database backend.
pub trait MysqlShim<W: Read + Write> {
    /// The error type produced by operations on this shim.
    ///
    /// Must implement `From<io::Error>` so that transport-level errors can be lifted.
    type Error: From<io::Error>;

    /// Server version, defaults to `5.1.10-alpha-msql-proxy`
    fn version(&self) -> &str {
        // 5.1.10 because that's what Ruby's ActiveRecord requires
        "5.1.10-alpha-msql-proxy"
    }

    /// Called when the client issues a request to prepare `query` for later execution.
    ///
    /// The provided [`StatementMetaWriter`](struct.StatementMetaWriter.html) should be used to
    /// notify the client of the statement id assigned to the prepared statement, as well as to
    /// give metadata about the types of parameters and returned columns.
    fn on_prepare(
        &mut self,
        query: &str,
        info: StatementMetaWriter<'_, W>,
    ) -> Result<(), Self::Error>;

    /// Called when the client executes a previously prepared statement.
    ///
    /// Any parameters included with the client's command is given in `params`.
    /// A response to the query should be given using the provided
    /// [`QueryResultWriter`](struct.QueryResultWriter.html).
    fn on_execute(
        &mut self,
        id: u32,
        params: ParamParser<'_>,
        results: QueryResultWriter<'_, W>,
    ) -> Result<(), Self::Error>;

    /// Called when the client wishes to deallocate resources associated with a previously prepared
    /// statement.
    fn on_close(&mut self, stmt: u32);

    /// Called when the client issues a query for immediate execution.
    ///
    /// Results should be returned using the given
    /// [`QueryResultWriter`](struct.QueryResultWriter.html).
    fn on_query(
        &mut self,
        query: &str,
        results: QueryResultWriter<'_, W>,
    ) -> Result<(), Self::Error>;

    /// Called when client switches database.
    fn on_init(&mut self, _: &str, _: InitWriter<'_, W>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Provides the TLS configuration, if we want to support TLS.
    #[cfg(feature = "tls")]
    fn tls_config(&self) -> Option<std::sync::Arc<rustls::ServerConfig>> {
        None
    }

    /// Called after successful authentication (including TLS if applicable) passing relevant
    /// information to allow additional logic in the MySqlShim implementation.
    fn after_authentication(
        &mut self,
        _context: &AuthenticationContext<'_>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Sent to the client to be included in the password hashing algorithm on the client.
    /// This is from: https://github.com/mysql/mysql-server/blob/8.0/mysys/crypt_genhash_impl.cc#L425-L436
    fn salt(&self) -> [u8; SALT_SIZE] {
        // Provide a fixed salt for now (avoid introducing a dependency on rand)
        let bs = ";X,po_k}>o6^Wz!/kM}N".as_bytes();
        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
        for i in 0..SALT_SIZE {
            salt[i] = bs[i];
            if salt[i] == b'\0' || salt[i] == b'$' {
                salt[i] += 1;
            }
        }
        salt
    }

    /// Default plugin for authentication
    /// Plugin methods: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_authentication_methods.html
    fn default_auth_plugin(&self) -> &str {
        DEFAULT_PLUGIN_AUTH
    }

    /// Called when reading the handshake response by client's auth_plugin
    /// See: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html#sect_protocol_connection_phase_auth_method_mismatch
    fn auth_plugin_for_user(&self, _user: &[u8]) -> &str {
        DEFAULT_PLUGIN_AUTH
    }
}

/// Information about an authenticated user
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, Clone, PartialEq)]
pub struct AuthenticationContext<'a> {
    /// The username exactly as passed by the client,
    pub username: Option<Vec<u8>>,
    #[cfg(feature = "tls")]
    /// The TLS certificate chain presented by the client.
    pub tls_client_certs: Option<&'a [rustls::pki_types::CertificateDer<'a>]>,
    /// Data collected from CLIENT_PLUGIN_AUTH
    pub plugin_auth: Option<PluginAuth<'a>>,
}

/// Contains authentication information sent from the client based on the authentication plugin
/// See: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html#sect_protocol_connection_phase_initial_handshake_auth_method
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PluginAuth<'a> {
    /// Name of the plugin used to create this data.
    pub plugin_name: Cow<'a, [u8]>,
    /// The salt used by the client to hash the password.
    pub salt: [u8; SALT_SIZE],
    /// The authentication data. In most cases this is the password with a hashing algorithm applied.
    pub auth_data: Cow<'a, [u8]>,
}

impl<'a> PluginAuth<'a> {
    /// Convenience function to clone the data to owned values
    pub fn to_owned(&self) -> PluginAuth<'static> {
        let Self {
            plugin_name,
            salt,
            auth_data,
        } = self;
        PluginAuth {
            plugin_name: Cow::Owned(plugin_name.to_vec()),
            salt: *salt,
            auth_data: Cow::Owned(auth_data.to_vec()),
        }
    }
}

/// A server that speaks the MySQL/MariaDB protocol, and can delegate client commands to a backend
/// that implements [`MysqlShim`](trait.MysqlShim.html).
pub struct MysqlIntermediary<B, RW: Read + Write> {
    shim: B,
    rw: packet::PacketConn<RW>,
}

impl<B: MysqlShim<net::TcpStream>> MysqlIntermediary<B, net::TcpStream> {
    /// Create a new server over a TCP stream and process client commands until the client
    /// disconnects or an error occurs. See also
    /// [`MysqlIntermediary::run_on`](struct.MysqlIntermediary.html#method.run_on).
    pub fn run_on_tcp(shim: B, stream: net::TcpStream) -> Result<(), B::Error> {
        MysqlIntermediary::run_on(shim, stream)
    }
}

impl<B: MysqlShim<S>, S: Read + Write + Clone> MysqlIntermediary<B, S> {
    /// Create a new server over a two-way stream and process client commands until the client
    /// disconnects or an error occurs. See also
    /// [`MysqlIntermediary::run_on`](struct.MysqlIntermediary.html#method.run_on).
    pub fn run_on_stream(shim: B, stream: S) -> Result<(), B::Error> {
        MysqlIntermediary::run_on(shim, stream)
    }
}

#[derive(Default)]
struct StatementData {
    long_data: HashMap<u16, Vec<u8>>,
    bound_types: Vec<(myc::constants::ColumnType, bool)>,
    params: u16,
}

impl<B: MysqlShim<RW>, RW: Read + Write> MysqlIntermediary<B, RW> {
    /// Create a new server over a two-way channel and process client commands until the client
    /// disconnects or an error occurs.
    pub fn run_on(shim: B, rw: RW) -> Result<(), B::Error> {
        let rw = packet::PacketConn::new(rw);
        let mut mi = MysqlIntermediary { shim, rw };
        mi.init()?;
        mi.run()
    }

    fn init(&mut self) -> Result<(), B::Error> {
        #[cfg(feature = "tls")]
        let tls_conf = self.shim.tls_config();

        let mut capabilities = CapabilityFlags::empty();
        capabilities.insert(CapabilityFlags::CLIENT_PROTOCOL_41);
        #[cfg(feature = "tls")]
        {
            if tls_conf.is_some() {
                capabilities.insert(CapabilityFlags::CLIENT_SSL);
                capabilities.insert(CapabilityFlags::CLIENT_SECURE_CONNECTION);

                capabilities.insert(CapabilityFlags::CLIENT_PLUGIN_AUTH);
                capabilities.insert(CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA);
            }
        }

        let server_capabilities = capabilities.bits().to_le_bytes();

        let salt = self.shim.salt();
        let default_auth_plugin = self.shim.default_auth_plugin();

        self.rw.write_all(&[10])?; // protocol 10

        self.rw.write_all(self.shim.version().as_bytes())?;
        self.rw.write_all(&[0x00])?; //null terminate version

        self.rw.write_all(&[0x08, 0x00, 0x00, 0x00])?; // TODO: connection ID
        self.rw
            .write_all(&salt[0..AUTH_PLUGIN_DATA_PART_1_LENGTH])?; // auth-plugin-data-part-1, 8 bytes
        self.rw.write_all(&[0x00])?; //fillter

        self.rw.write_all(&server_capabilities[..2])?;
        self.rw.write_all(&[0x21])?; // UTF8_GENERAL_CI
        self.rw.write_all(&[0x00, 0x00])?; // status flags
        self.rw.write_all(&server_capabilities[2..4])?; // extended capabilities
        self.rw.write_all(&((salt.len() + 1) as u8).to_le_bytes())?; // length of the combined auth_plugin_data(SALT)
        self.rw.write_all(&[0x00; 6][..])?; // filler
        self.rw.write_all(&[0x00; 4][..])?; // filler

        self.rw.write_all(&salt[AUTH_PLUGIN_DATA_PART_1_LENGTH..])?; // Part2 of the auth_plugin_data. 13 bytes
        self.rw.write_all(&[0x00])?; // Null terminate salt, as 12 bytes less than 13. See: https://dev.mysql.com/doc/dev/mysql-server/latest//page_protocol_connection_phase_packets_protocol_handshake_v10.html
        self.rw.write_all(default_auth_plugin.as_bytes())?;
        self.rw.write_all(&[0x00])?; // Null terminate plugin string
        self.rw.flush()?;

        let mut auth_context = AuthenticationContext::default();

        {
            let (seq, handshake) = self.rw.next()?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "peer terminated connection",
                )
            })?;
            let handshake = commands::client_handshake(&handshake, false)
                .map_err(|e| match e {
                    nom::Err::Incomplete(_) => io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "client sent incomplete handshake",
                    ),
                    nom::Err::Failure(nom_error) | nom::Err::Error(nom_error) => {
                        if let nom::error::ErrorKind::Eof = nom_error.code {
                            io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "client did not complete handshake; got {:?}",
                                    nom_error.input
                                ),
                            )
                        } else {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "bad client handshake; got {:?} ({:?})",
                                    nom_error.input, nom_error.code
                                ),
                            )
                        }
                    }
                })?
                .1;

            auth_context.username = handshake.username.map(|x| x.to_vec());

            self.rw.set_seq(seq + 1);

            #[cfg(not(feature = "tls"))]
            if handshake.capabilities.contains(CapabilityFlags::CLIENT_SSL) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "client requested SSL despite us not advertising support for it",
                )
                .into());
            }

            #[cfg(feature = "tls")]
            if handshake.capabilities.contains(CapabilityFlags::CLIENT_SSL) {
                let mut auth_context = AuthenticationContext::default();
                let config = tls_conf.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "client requested SSL despite us not advertising support for it",
                    )
                })?;
                self.rw.switch_to_tls(config)?;

                let (seq, handshake) = self.rw.next()?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "peer terminated connection",
                    )
                })?;

                let handshake = commands::client_handshake(&handshake, true)
                    .map_err(|e| match e {
                        nom::Err::Incomplete(_) => io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "client sent incomplete handshake",
                        ),
                        nom::Err::Failure(nom_error) | nom::Err::Error(nom_error) => {
                            if let nom::error::ErrorKind::Eof = nom_error.code {
                                io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    format!(
                                        "client did not complete handshake; got {:?}",
                                        nom_error.input
                                    ),
                                )
                            } else {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "bad client handshake; got {:?} ({:?})",
                                        nom_error.input, nom_error.code
                                    ),
                                )
                            }
                        }
                    })?
                    .1;

                auth_context.username = handshake.username.map(|x| x.to_vec());

                self.rw.set_seq(seq + 1);

                let ClientHandshake {
                    auth_response,
                    auth_plugin: received_client_plugin,
                    capabilities: client_capabilities,
                    ..
                } = handshake;

                if !client_capabilities.contains(CapabilityFlags::CLIENT_PLUGIN_AUTH) {
                    if let Err(e) = self.shim.after_authentication(&auth_context) {
                        writers::write_err(
                            ErrorKind::ER_ACCESS_DENIED_ERROR,
                            "client authentication failed".as_ref(),
                            &mut self.rw,
                        )?;
                        self.rw.flush()?;
                        return Err(e);
                    }
                    writers::write_ok_packet(&mut self.rw, 0, 0, StatusFlags::empty())?;
                    self.rw.flush()?;
                    return Ok(());
                }

                let user_auth_plugin = auth_context
                    .username
                    .as_ref()
                    .map(|user| self.shim.auth_plugin_for_user(user))
                    .unwrap_or_else(|| self.shim.default_auth_plugin());

                let auth_plugin = received_client_plugin.unwrap_or(b"");

                // Start SwitchAuthRequest
                let auth_switch_response = if user_auth_plugin.as_bytes() != auth_plugin {
                    self.rw.write_all(&[0xfe])?;
                    self.rw.write_all(user_auth_plugin.as_bytes())?;
                    self.rw.write_all(&[0x00])?;
                    self.rw.write_all(&salt)?;
                    self.rw.write_all(&[0x00])?;

                    self.rw.flush()?;
                    {
                        let (seq, auth_response_data) = self.rw.next()?.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "peer terminated connection",
                            )
                        })?;
                        self.rw.set_seq(seq + 1);

                        Some(auth_response_data.to_vec())
                    }
                } else {
                    None
                };

                auth_context.tls_client_certs = self.rw.tls_certs().map(Into::into);

                let plugin_auth = self.handle_plugin_auth(
                    auth_switch_response,
                    auth_response,
                    received_client_plugin,
                    salt,
                )?;
                auth_context.plugin_auth = plugin_auth;
                if let Err(e) = self.shim.after_authentication(&auth_context) {
                    writers::write_err(
                        ErrorKind::ER_ACCESS_DENIED_ERROR,
                        "client authentication failed".as_ref(),
                        &mut self.rw,
                    )?;
                    self.rw.flush()?;
                    return Err(e);
                }
                writers::write_ok_packet(&mut self.rw, 0, 0, StatusFlags::empty())?;
                self.rw.flush()?;
                return Ok(());
            }

            if let Err(e) = self.shim.after_authentication(&auth_context) {
                writers::write_err(
                    ErrorKind::ER_ACCESS_DENIED_ERROR,
                    "client authentication failed".as_ref(),
                    &mut self.rw,
                )?;
                self.rw.flush()?;
                return Err(e);
            }
        }

        writers::write_ok_packet(&mut self.rw, 0, 0, StatusFlags::empty())?;
        self.rw.flush()?;

        Ok(())
    }

    fn handle_plugin_auth<'a>(
        &self,
        auth_switch_response: Option<Vec<u8>>,
        auth_response: Option<&'a [u8]>,
        received_client_plugin: Option<&'a [u8]>,
        salt: [u8; SALT_SIZE],
    ) -> Result<Option<PluginAuth<'a>>, B::Error> {
        let plugin_auth = match (auth_switch_response, auth_response, received_client_plugin) {
            (None, Some(auth_data), Some(auth_plugin)) => Some(PluginAuth {
                plugin_name: auth_plugin.into(),
                salt,
                auth_data: auth_data.into(),
            }),
            (Some(switch_data), _, Some(auth_plugin)) => Some(PluginAuth {
                plugin_name: auth_plugin.into(),
                salt,
                auth_data: switch_data.into(),
            }),
            // No auth data
            (None, None, _) => None,
            // Client supports plugin auth, but did not send any plugin, only auth data
            (Some(_), _, None) => None,
            // Client supports plugin auth, but did not send any plugin or auth data
            (None, Some(_), None) => None,
        };

        Ok(plugin_auth)
    }

    fn run(mut self) -> Result<(), B::Error> {
        use crate::commands::Command;

        let mut stmts: HashMap<u32, _> = HashMap::new();
        while let Some((seq, packet)) = self.rw.next()? {
            self.rw.set_seq(seq + 1);
            let cmd = commands::parse(&packet).unwrap().1;
            match cmd {
                Command::Query(q) => {
                    if q.starts_with(b"SELECT @@") || q.starts_with(b"select @@") {
                        let w = QueryResultWriter::new(&mut self.rw, false);
                        let var = &q[b"SELECT @@".len()..];
                        match var {
                            b"max_allowed_packet" => {
                                let cols = &[Column {
                                    table: String::new(),
                                    column: "@@max_allowed_packet".to_owned(),
                                    coltype: myc::constants::ColumnType::MYSQL_TYPE_LONG,
                                    colflags: myc::constants::ColumnFlags::UNSIGNED_FLAG,
                                }];
                                let mut w = w.start(cols)?;
                                w.write_row(iter::once(67108864u32))?;
                                w.finish()?;
                            }
                            _ => {
                                w.completed(0, 0)?;
                            }
                        }
                    } else if q.starts_with(b"USE ") || q.starts_with(b"use ") {
                        let w = InitWriter {
                            writer: &mut self.rw,
                        };
                        let schema = ::std::str::from_utf8(&q[b"USE ".len()..])
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                        let schema = schema.trim().trim_end_matches(';').trim_matches('`');
                        self.shim.on_init(schema, w)?;
                    } else {
                        let w = QueryResultWriter::new(&mut self.rw, false);
                        self.shim.on_query(
                            ::std::str::from_utf8(q)
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                            w,
                        )?;
                    }
                }
                Command::Prepare(q) => {
                    let w = StatementMetaWriter {
                        writer: &mut self.rw,
                        stmts: &mut stmts,
                    };

                    self.shim.on_prepare(
                        ::std::str::from_utf8(q)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                        w,
                    )?;
                }
                Command::Execute { stmt, params } => {
                    let state = stmts.get_mut(&stmt).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("asked to execute unknown statement {}", stmt),
                        )
                    })?;
                    {
                        let params = params::ParamParser::new(params, state);
                        let w = QueryResultWriter::new(&mut self.rw, true);
                        self.shim.on_execute(stmt, params, w)?;
                    }
                    state.long_data.clear();
                }
                Command::SendLongData { stmt, param, data } => {
                    stmts
                        .get_mut(&stmt)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("got long data packet for unknown statement {}", stmt),
                            )
                        })?
                        .long_data
                        .entry(param)
                        .or_insert_with(Vec::new)
                        .extend(data);
                }
                Command::Close(stmt) => {
                    self.shim.on_close(stmt);
                    stmts.remove(&stmt);
                    // NOTE: spec dictates no response from server
                }
                Command::ListFields(_) => {
                    let cols = &[Column {
                        table: String::new(),
                        column: "not implemented".to_owned(),
                        coltype: myc::constants::ColumnType::MYSQL_TYPE_SHORT,
                        colflags: myc::constants::ColumnFlags::UNSIGNED_FLAG,
                    }];
                    writers::write_column_definitions(cols, &mut self.rw, true, true)?;
                }
                Command::Init(schema) => {
                    let w = InitWriter {
                        writer: &mut self.rw,
                    };
                    self.shim.on_init(
                        ::std::str::from_utf8(schema)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                        w,
                    )?;
                }
                Command::Ping => {
                    writers::write_ok_packet(&mut self.rw, 0, 0, StatusFlags::empty())?;
                }
                Command::Quit => {
                    break;
                }
            }
            self.rw.flush()?;
        }
        Ok(())
    }
}
