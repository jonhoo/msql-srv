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
//!
//! struct Backend;
//! impl<W: io::Write> MysqlShim<W> for Backend {
//!     type Error = io::Error;
//!
//!     fn on_prepare(&mut self, _: &str, info: StatementMetaWriter<W>) -> io::Result<()> {
//!         info.reply(42, &[], &[])
//!     }
//!     fn on_execute(
//!         &mut self,
//!         _: u32,
//!         _: Params,
//!         results: QueryResultWriter<W>,
//!     ) -> io::Result<()> {
//!         results.completed(0, 0)
//!     }
//!     fn on_close(&mut self, _: u32) {}
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
//!     let mut db = mysql::Conn::new(&format!("mysql://127.0.0.1:{}", port)).unwrap();
//!     assert_eq!(db.ping(), true);
//!     assert_eq!(db.query("SELECT a, b FROM foo").unwrap().count(), 1);
//!     drop(db);
//!     jh.join().unwrap();
//! }
//! ```
#![deny(missing_docs)]
#![feature(nll)]

// Note to developers: you can find decent overviews of the protocol at
//
//   https://github.com/cwarden/mysql-proxy/blob/master/doc/protocol.rst
//
// and
//
//   https://mariadb.com/kb/en/library/clientserver-protocol/
//
// Wireshark also does a pretty good job at parsing the MySQL protocol.

extern crate byteorder;
extern crate chrono;
extern crate mysql_common as myc;
#[macro_use]
extern crate nom;
extern crate tokio;
#[macro_use]
extern crate futures;

use std::collections::HashMap;
use std::io;
use std::net;
use tokio::prelude::*;

pub use errorcodes::ErrorKind;
pub use myc::constants::{ColumnFlags, ColumnType, StatusFlags};
pub use params::{ParamValue, Params};
pub use resultset::{QueryResultWriter, RowWriter, StatementMetaWriter};
pub use value::{ToMysqlValue, Value, ValueInner};

mod commands;
mod errorcodes;
mod packet;
mod params;
mod resultset;
mod value;
mod writers;

/// Bind a new server to a TCP port and process client requests until the client disconnects or an
/// error occurs. See also
/// [`MysqlIntermediary::run_on`](struct.MysqlIntermediary.html#method.run_on).
pub fn bind(
    addr: &net::SocketAddr,
) -> Result<
    ConnectionStream<
        impl Stream<
            Item = (
                tokio::io::ReadHalf<tokio::net::tcp::TcpStream>,
                tokio::io::WriteHalf<tokio::net::tcp::TcpStream>,
            ),
            Error = tokio::io::Error,
        >,
    >,
    tokio::io::Error,
> {
    Ok(manage(
        tokio::net::tcp::TcpListener::bind(addr)?
            .incoming()
            .map(|s| s.split()),
    ))
}

/// Create a new server over a two-way stream and process client commands until the client
/// disconnects or an error occurs. See also
/// [`MysqlIntermediary::run_on`](struct.MysqlIntermediary.html#method.run_on).
pub fn manage<S, R, W>(connections: S) -> ConnectionStream<S>
where
    S: Stream<Item = (R, W), Error = io::Error>,
    R: AsyncRead,
    W: AsyncWrite,
{
    ConnectionStream(connections)
}

/// A stream of incoming MySQL client connections.
///
/// Use [`ConnectionStream::on_request`] to set the [`Service`] to use to serve these requests.
pub struct ConnectionStream<S>(S);

impl<S> ConnectionStream<S> {
    /// Use the given factory to produce new [`Service`] instances to manage incoming
    /// [`Connection`]s.
    pub fn on_request<Svc, R, W, E, F, FF>(
        self,
        mut new_service: F,
    ) -> impl Stream<Item = Connection<R, W, Svc>>
    where
        S: Stream<Item = (R, W), Error = E>,
        Svc: Service<W>,
        R: AsyncRead,
        W: AsyncWrite,
        F: FnMut() -> FF,
        FF: IntoFuture<Item = Svc, Error = E>,
    {
        self.0.and_then(move |(r, w)| {
            new_service()
                .into_future()
                .map(move |s| Connection::new(s, r, w))
        })
    }
}

#[derive(Default)]
struct StatementData {
    long_data: HashMap<u16, Vec<u8>>,
    bound_types: Vec<(myc::constants::ColumnType, bool)>,
    params: u16,
}

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

mod connection;
pub use connection::Connection;

mod service;
pub use service::{
    MissingParams, MissingService, PartialMissing, PartialServiceState, Request, Service,
    ServiceState,
};
