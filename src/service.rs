use crate::{packet, params, QueryResultWriter, StatementData, StatementMetaWriter};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::marker::PhantomData;
use tokio::prelude::*;

/// Indicates what state is missing from a [`PartialServiceState`] to produce a [`ServiceState`].
///
/// Note that this trait is [sealed] -- it is not meant for public implementation.
///
/// [sealed]: https://rust-lang-nursery.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait PartialMissing: Clone + Copy + fmt::Debug + private::Sealed + 'static {}

mod private {
    use super::{MissingParams, MissingService};
    pub trait Sealed {}

    impl Sealed for MissingService {}
    impl Sealed for MissingParams {}
}

/// Your [`Service`] instance is needed. Add it with [`PartialServiceState::finish`].
#[derive(Clone, Copy, Debug)]
pub struct MissingService;
impl PartialMissing for MissingService {}

/// The [`Params`] you were provided with in [`Request::Execute`] is needed.
/// Add it with [`PartialServiceState::add`].
#[derive(Clone, Copy, Debug)]
pub struct MissingParams;
impl PartialMissing for MissingParams {}

/// The state a [`Service`] needs to continue processing future requests.
///
/// Usually you will be provided with a [`PartialServiceState`] which you then have to add
/// intermediate state to in order to finish handling the current request.
pub struct ServiceState<W, S> {
    pub(crate) stmts: HashMap<u32, StatementData>,
    pub(crate) output: packet::PacketWriter<W>,
    pub(crate) service: S,
}

/// A partial [`ServiceState`] that is missing state that needs to be carried forward to satisfy
/// future requests. `M` is a [`PartialMissing`], which indicates what state is missing.
pub struct PartialServiceState<W, M> {
    pub(crate) stmts: HashMap<u32, StatementData>,
    pub(crate) output: packet::PacketWriter<W>,
    pub(crate) missing: PhantomData<M>,
}

impl<W> PartialServiceState<W, MissingService> {
    /// Return the current [`Service`] instance to allow the next request to be processed.
    pub fn finish<S>(self, service: S) -> ServiceState<W, S> {
        ServiceState {
            output: self.output,
            stmts: self.stmts,
            service,
        }
    }
}

impl<W> PartialServiceState<W, MissingParams> {
    /// Return the [`Params`] statement state to allow the next request to be processed.
    pub fn add<'a>(mut self, p: params::Params<'a>) -> PartialServiceState<W, MissingService> {
        let (sid, stmt) = p.statement();
        self.stmts.insert(sid, stmt);

        PartialServiceState {
            output: self.output,
            stmts: self.stmts,
            missing: PhantomData,
        }
    }
}

/// Implementors of this trait can be used to drive a MySQL-compatible database backend.
pub trait Service<W: AsyncWrite>
where
    Self: Sized,
{
    /// Type for unrecoverable service errors.
    ///
    /// Note that this should not be used to indicate that a client operation has failed. For that,
    /// use [`QueryResultWriter::error`] instead. It will return that error to the client and keep
    /// the connection up and running.
    ///
    /// The error type must be convertable from `std::io::Error` so that protocol errors can also
    /// bubble up.
    type Error: From<io::Error>;

    /// Type of the future used to handle client request.
    type ResponseFut: IntoFuture<Item = ServiceState<W, Self>, Error = Self::Error> + 'static;

    /// Handle a single client request.
    ///
    /// The returned future must eventually resolve into a [`ServiceState`] so that all the
    /// connection state is available when processing the next request. The handles that are
    /// provided in [`Request`] all yield [`PartialServiceState`] instances which you can then turn
    /// into [`ServiceState`] by adding back the `Service` instance with
    /// [`PartialServiceState::finish`].
    fn on_request(self, req: Request<W>) -> Self::ResponseFut;
}

/// A client request that you have to promise not to use incorrectly.
///
/// You will need to call [`RawRequest::i_read_the_docs`].
pub struct RawRequest<W: Write>(Request<W>);

impl<W: Write> RawRequest<W> {
    /// You have to call this method, but read its full description first.
    ///
    /// Items marked `'static` in [`Request`] are *not* actually `'static`. They live until the
    /// produced [`Service::ResponseFut`] resolves. Unfortunately, there isn't any way currently in
    /// Rust to express that sort of dynamic lifetime as far as I can tell. Instead, we have to
    /// cheat and pretend they're `'static` so that they can be brought into the returned future.
    ///
    /// It is *very* important that you do not try to use the data from a [`Request`] outside of
    /// the scope of the returned future (e.g., spawn them onto another thread), as this *will*
    /// lead to faulty program behavior.
    pub unsafe fn i_read_the_docs(self) -> Request<W> {
        self.0
    }
}

/// A client request.
pub enum Request<W: Write> {
    /// The client issued a request to prepare `query` for later execution.
    ///
    /// The provided [`StatementMetaWriter`](struct.StatementMetaWriter.html) should be used to
    /// notify the client of the statement id assigned to the prepared statement, as well as to
    /// give metadata about the types of parameters and returned columns.
    Prepare {
        /// The SQL query issued by the client.
        query: &'static str,

        /// A handle for replying with information about the newly prepared statemetn to the
        /// client.
        info: StatementMetaWriter<W>,
    },

    /// The client executed a previously prepared statement.
    ///
    /// Any parameters included with the client's command is given in `params`.
    /// A response to the query should be given using the provided
    /// [`QueryResultWriter`](struct.QueryResultWriter.html).
    Execute {
        /// The ID previously issued to this client through [`StatementMetaWriter::reply`].
        id: u32,

        /// An iterator over parameters provided by the client for executing this statement.
        params: params::Params<'static>,

        /// A handle for writing query results back to the client.
        results: QueryResultWriter<W, MissingParams>,
    },

    /// The client wishes to deallocate resources associated with a previously prepared
    /// statement.
    Close {
        /// The ID previously issued to this client through [`StatementMetaWriter::reply`].
        id: u32,

        /// Meta information needed to produce the future's [`ServiceState`].
        rest: PartialServiceState<W, MissingService>,
    },

    /// The client issued a query for immediate execution.
    ///
    /// Results should be returned using the given
    /// [`QueryResultWriter`](struct.QueryResultWriter.html).
    Query {
        /// The SQL query issued by the client.
        query: &'static str,

        /// A handle for writing query results back to the client.
        results: QueryResultWriter<W, MissingService>,
    },
}

impl<W: Write> From<Request<W>> for RawRequest<W> {
    fn from(r: Request<W>) -> Self {
        RawRequest(r)
    }
}
