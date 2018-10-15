use crate::{
    commands, packet, params, writers, Column, PartialServiceState, QueryResultWriter, Request,
    Service, ServiceState, StatementData, StatementMetaWriter,
};
use mysql_common as myc;
use mysql_common::constants::StatusFlags;
use std::collections::HashMap;
use std::io;
use std::iter;
use std::marker::PhantomData;
use std::mem;
use tokio::prelude::*;

enum ResponseState<W, S>
where
    W: AsyncWrite,
    S: Service<W>,
{
    UserFuture(<S::ResponseFut as IntoFuture>::Future),
    Flush(ServiceState<W, S>),
    Pending,
}

impl<W, S> Future for ResponseState<W, S>
where
    W: AsyncWrite,
    S: Service<W>,
{
    type Item = ServiceState<W, S>;
    type Error = S::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        loop {
            match mem::replace(self, ResponseState::Pending) {
                ResponseState::UserFuture(mut f) => match f.poll()? {
                    Async::NotReady => {
                        mem::replace(self, ResponseState::UserFuture(f));
                    }
                    Async::Ready(r) => {
                        mem::replace(self, ResponseState::Flush(r));
                    }
                },
                ResponseState::Flush(mut r) => match r.output.poll_flush()? {
                    Async::NotReady => {
                        mem::replace(self, ResponseState::Flush(r));
                    }
                    Async::Ready(()) => return Ok(Async::Ready(r)),
                },
                ResponseState::Pending => unreachable!("polled ResponseState after Async::Ready"),
            }
        }
    }
}

enum Initialization<R, W> {
    New {
        input: R,
        output: W,
    },
    Writing {
        input: R,
        output: W,
        bytes: &'static [u8],
        written: usize,
    },
    ReadHandshake {
        input: packet::PacketReader<R>,
        output: packet::PacketWriter<W>,
    },
    AckHandshake {
        input: packet::PacketReader<R>,
        output: packet::PacketWriter<W>,
    },
    Pending,
}

impl<R, W> Future for Initialization<R, W>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    type Item = (packet::PacketReader<R>, packet::PacketWriter<W>);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        loop {
            match mem::replace(self, Initialization::Pending) {
                Initialization::New { input, output } => {
                    mem::replace(
                        self,
                        Initialization::Writing {
                            input,
                            output,
                            bytes: concat!(
                                10, // protocol 10
                                // 5.1.10 because that's what Ruby's ActiveRecord requires
                                "5.1.10-alpha-msql-proxy\0",
                                0x08,             // TODO: connection ID
                                0x00,             //
                                0x00,             //
                                0x00,             //
                                ";X,po_k}\0",     // auth seed
                                0x00,             // just 4.1 proto
                                0x42,             //
                                0x21,             // UTF8_GENERAL_CI
                                0x00,             // status flags
                                0x00,             //
                                0x00,             // extended capabilities
                                0x00,             //
                                0x00,             // no plugins
                                0x00,             // filler x6
                                0x00,             //
                                0x00,             //
                                0x00,             //
                                0x00,             //
                                0x00,             //
                                0x00,             // filler x4
                                0x00,             //
                                0x00,             //
                                0x00,             //
                                ">o6^Wz!/kM}N\0"  // 4.1+ servers must extend salt
                            )
                            .as_bytes(),
                            written: 0,
                        },
                    );
                }
                Initialization::Writing {
                    input,
                    mut output,
                    bytes,
                    mut written,
                } => {
                    if written == bytes.len() {
                        try_ready!(output.poll_flush());
                        mem::replace(
                            self,
                            Initialization::ReadHandshake {
                                input: packet::PacketReader::new(input),
                                output: packet::PacketWriter::new(output),
                            },
                        );
                    } else {
                        let wrote = try_ready!(output.poll_write(&bytes[written..]));
                        written += wrote;
                        mem::replace(
                            self,
                            Initialization::Writing {
                                input,
                                output,
                                bytes,
                                written,
                            },
                        );
                    }
                }
                Initialization::ReadHandshake {
                    mut input,
                    mut output,
                } => {
                    if let Some((seq, handshake)) = try_ready!(input.poll()) {
                        if let Err(e) = commands::client_handshake(&handshake) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("bad client handshake: {:?}", e),
                            ));
                        }

                        output.set_seq(seq + 1);
                        writers::write_ok_packet(&mut output, 0, 0, StatusFlags::empty())?;
                        mem::replace(self, Initialization::AckHandshake { input, output });
                    } else {
                        // client left in the middle of handshake?
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "client disconnected during handshake",
                        ));
                    }
                }
                Initialization::AckHandshake { input, mut output } => {
                    // poll until the output is done
                    let _ = try_ready!(output.poll_flush());
                    return Ok(Async::Ready((input, output)));
                }
                Initialization::Pending => unreachable!("polled Initialization after Async::Ready"),
            }
        }
    }
}
enum ConnectionState<R, W, S>
where
    W: AsyncWrite,
    S: Service<W>,
{
    Initializing {
        state: Initialization<R, W>,
        service: S,
    },
    Reading {
        input: packet::PacketReader<R>,
        output: packet::PacketWriter<W>,
        stmts: HashMap<u32, StatementData>,
        service: S,
    },
    Writing {
        clear_long: Option<u32>,
        input: packet::PacketReader<R>,
        pending: ResponseState<W, S>,
    },
    Internal {
        input: packet::PacketReader<R>,
        pending: Box<Future<Item = ServiceState<W, S>, Error = io::Error>>,
    },
    Flush {
        input: packet::PacketReader<R>,
        output: packet::PacketWriter<W>,
        stmts: HashMap<u32, StatementData>,
        service: S,
    },
    Pending,
}

impl<R, W, S> Connection<R, W, S>
where
    W: AsyncWrite,
    S: Service<W>,
{
    pub(crate) fn new(service: S, read: R, write: W) -> Self {
        Connection {
            state: ConnectionState::Initializing {
                state: Initialization::New {
                    input: read,
                    output: write,
                },
                service: service,
            },
        }
    }
}

/// A running connection to a MySQL/MariaDB client.
pub struct Connection<R, W, S>
where
    W: AsyncWrite,
    S: Service<W>,
{
    state: ConnectionState<R, W, S>,
}

impl<R, W, S> Future for Connection<R, W, S>
where
    R: AsyncRead + 'static,
    W: AsyncWrite + 'static,
    S: Service<W> + 'static,
{
    type Item = ();
    type Error = S::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        loop {
            match mem::replace(&mut self.state, ConnectionState::Pending) {
                ConnectionState::Initializing { mut state, service } => {
                    match state.poll()? {
                        Async::Ready((r, w)) => {
                            mem::replace(
                                &mut self.state,
                                ConnectionState::Reading {
                                    input: r,
                                    output: w,
                                    stmts: HashMap::default(),
                                    service,
                                },
                            );
                        }
                        Async::NotReady => {
                            mem::replace(
                                &mut self.state,
                                ConnectionState::Initializing { state, service },
                            );
                            return Ok(Async::NotReady);
                        }
                    };
                }
                ConnectionState::Reading {
                    mut input,
                    mut output,
                    service,
                    mut stmts,
                } => {
                    use crate::commands::Command;

                    match input.poll()? {
                        Async::NotReady => {
                            mem::replace(
                                &mut self.state,
                                ConnectionState::Reading {
                                    input,
                                    output,
                                    service,
                                    stmts,
                                },
                            );
                            return Ok(Async::Ready(()));
                        }
                        Async::Ready(None) => {
                            return Ok(Async::Ready(()));
                        }
                        Async::Ready(Some((seq, packet))) => {
                            output.set_seq(seq + 1);

                            // this is not great.
                            //
                            // but without it, borrowck thinks that packet has to live for the
                            // static lifetime, even though we never move it into any future or
                            // leak it through the loop (at least as far as I'm aware).
                            //
                            // we also happen to know that nothing that's derived from this packet
                            // will ever live until the next time we read from `input`. which means
                            // that even if the developer's returned future keeps a handle to the
                            // packet, that's fine, because it'll be dropped by the time we read
                            // again!
                            //
                            // this definitely is unsafe though, because the developer will now get
                            // a Request<'static>, which means they'll also have access to
                            // `&'static str` which is most certainly not `'static`. If they leak
                            // it somewhere, they'll be all sorts of sad.
                            let packet: &'static [u8] = unsafe { mem::transmute(&*packet) };

                            let cmd = match commands::parse(packet) {
                                Ok((_, cmd)) => cmd,
                                Err(e) => {
                                    return Err(io::Error::new(io::ErrorKind::InvalidData, e).into())
                                }
                            };

                            match cmd {
                                Command::Query(q) => {
                                    let w = QueryResultWriter::new(output, stmts, false);
                                    if q.starts_with(b"SELECT @@") || q.starts_with(b"select @@") {
                                        if q == b"SELECT @@max_allowed_packet"
                                            || q == b"select @@max_allowed_packet"
                                        {
                                            let cols = &[Column {
                                                table: String::new(),
                                                column: "@@max_allowed_packet".to_owned(),
                                                coltype:
                                                    myc::constants::ColumnType::MYSQL_TYPE_SHORT,
                                                colflags:
                                                    myc::constants::ColumnFlags::UNSIGNED_FLAG,
                                            }];

                                            let mut w = w.start(cols)?;
                                            w.write_row(iter::once(1024u16))?;
                                            let fut = Box::new(
                                                w.finish().map(move |pr| pr.finish(service)),
                                            );

                                            mem::replace(
                                                &mut self.state,
                                                ConnectionState::Internal {
                                                    input,
                                                    pending: fut,
                                                },
                                            );
                                        } else {
                                            let fut = Box::new(
                                                w.completed(0, 0).map(move |pr| pr.finish(service)),
                                            );
                                            mem::replace(
                                                &mut self.state,
                                                ConnectionState::Internal {
                                                    input,
                                                    pending: fut,
                                                },
                                            );
                                        }
                                    } else {
                                        let fut = service
                                            .on_request(
                                                Request::Query {
                                                    query: ::std::str::from_utf8(q).map_err(
                                                        |e| {
                                                            io::Error::new(
                                                                io::ErrorKind::InvalidData,
                                                                e,
                                                            )
                                                        },
                                                    )?,
                                                    results: w,
                                                }
                                                .into(),
                                            )
                                            .into_future();

                                        mem::replace(
                                            &mut self.state,
                                            ConnectionState::Writing {
                                                input,
                                                clear_long: None,
                                                pending: ResponseState::UserFuture(fut),
                                            },
                                        );
                                    }
                                }
                                Command::Prepare(q) => {
                                    let fut = service
                                        .on_request(Request::Prepare {
                                            query: ::std::str::from_utf8(q).map_err(|e| {
                                                { io::Error::new(io::ErrorKind::InvalidData, e) }
                                                    .into()
                                            })?,
                                            info: StatementMetaWriter {
                                                writer: output,
                                                stmts: stmts,
                                            },
                                        })
                                        .into_future();

                                    mem::replace(
                                        &mut self.state,
                                        ConnectionState::Writing {
                                            input,
                                            pending: ResponseState::UserFuture(fut),
                                            clear_long: None,
                                        },
                                    );
                                }
                                Command::Execute { stmt, params } => {
                                    let state = stmts.remove(&stmt).ok_or_else(|| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            format!("asked to execute unknown statement {}", stmt),
                                        )
                                    })?;

                                    {
                                        let params = params::Params::new(params, (stmt, state));
                                        let w = QueryResultWriter::new(output, stmts, true);
                                        let fut = service
                                            .on_request(
                                                Request::Execute {
                                                    id: stmt,
                                                    params,
                                                    results: w,
                                                }
                                                .into(),
                                            )
                                            .into_future();

                                        mem::replace(
                                            &mut self.state,
                                            ConnectionState::Writing {
                                                input,
                                                clear_long: Some(stmt),
                                                pending: ResponseState::UserFuture(fut),
                                            },
                                        );
                                    }
                                }
                                Command::SendLongData { stmt, param, data } => {
                                    stmts
                                        .get_mut(&stmt)
                                        .ok_or_else(|| {
                                            io::Error::new(
                                                io::ErrorKind::InvalidData,
                                                format!(
                                                    "got long data packet for unknown statement {}",
                                                    stmt
                                                ),
                                            )
                                        })?
                                        .long_data
                                        .entry(param)
                                        .or_insert_with(Vec::new)
                                        .extend(data);
                                }
                                Command::Close(stmt) => {
                                    stmts.remove(&stmt);
                                    let fut = service
                                        .on_request(
                                            Request::Close {
                                                id: stmt,
                                                rest: PartialServiceState {
                                                    output,
                                                    stmts,
                                                    missing: PhantomData,
                                                },
                                            }
                                            .into(),
                                        )
                                        .into_future();

                                    mem::replace(
                                        &mut self.state,
                                        ConnectionState::Writing {
                                            input,
                                            clear_long: None,
                                            pending: ResponseState::UserFuture(fut),
                                        },
                                    );

                                    // NOTE: spec dictates no response from server
                                }
                                Command::Init(_) | Command::Ping => {
                                    writers::write_ok_packet(
                                        &mut output,
                                        0,
                                        0,
                                        StatusFlags::empty(),
                                    )?;

                                    mem::replace(
                                        &mut self.state,
                                        ConnectionState::Flush {
                                            input,
                                            output,
                                            stmts,
                                            service,
                                        },
                                    );
                                }
                                Command::Quit => {
                                    return Ok(Async::Ready(()));
                                }
                            }
                        }
                    }
                }
                ConnectionState::Internal { input, mut pending } => {
                    let ServiceState {
                        stmts,
                        service,
                        output,
                    } = match pending.poll()? {
                        Async::NotReady => {
                            mem::replace(
                                &mut self.state,
                                ConnectionState::Internal { input, pending },
                            );
                            return Ok(Async::NotReady);
                        }
                        Async::Ready(r) => r,
                    };

                    mem::replace(
                        &mut self.state,
                        ConnectionState::Flush {
                            input,
                            output,
                            service,
                            stmts,
                        },
                    );
                }
                ConnectionState::Writing {
                    input,
                    mut pending,
                    clear_long,
                } => {
                    let ServiceState {
                        mut stmts,
                        service,
                        output,
                    } = match pending.poll()? {
                        Async::NotReady => {
                            mem::replace(
                                &mut self.state,
                                ConnectionState::Writing {
                                    input,
                                    pending,
                                    clear_long,
                                },
                            );
                            return Ok(Async::NotReady);
                        }
                        Async::Ready(r) => r,
                    };

                    if let Some(stmt) = clear_long {
                        if let Some(stmt) = stmts.get_mut(&stmt) {
                            stmt.long_data.clear();
                        }
                    }

                    mem::replace(
                        &mut self.state,
                        ConnectionState::Flush {
                            input,
                            output,
                            service,
                            stmts,
                        },
                    );
                }
                ConnectionState::Flush {
                    input,
                    mut output,
                    stmts,
                    service,
                } => match output.poll_flush()? {
                    Async::NotReady => {
                        mem::replace(
                            &mut self.state,
                            ConnectionState::Flush {
                                input,
                                output,
                                stmts,
                                service,
                            },
                        );
                        return Ok(Async::NotReady);
                    }
                    Async::Ready(()) => {
                        mem::replace(
                            &mut self.state,
                            ConnectionState::Reading {
                                input,
                                output,
                                stmts,
                                service,
                            },
                        );
                    }
                },
                ConnectionState::Pending => {
                    unreachable!("polled ConnectionState after Async::Ready")
                }
            }
        }
    }
}
