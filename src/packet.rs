use byteorder::{ByteOrder, LittleEndian};
use crate::{PartialMissing, PartialServiceState, StatementData};
use nom::{self, IResult};
use std::collections::HashMap;
use std::io;
use std::io::prelude::*;
use std::marker::PhantomData;
use std::mem;
use tokio::prelude::*;

const U24_MAX: usize = 16_777_215;

pub struct PacketWriter<W> {
    to_write: Vec<u8>,
    last_packet_start: usize,
    written: usize,
    seq: u8,
    w: W,
}

impl<W: Write> Write for PacketWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::cmp::min;
        let left = min(buf.len(), U24_MAX - self.to_write.len());
        self.to_write.extend(&buf[..left]);

        if self.to_write.len() == U24_MAX {
            self.end_packet()?;
        }
        Ok(left)
    }

    fn flush(&mut self) -> io::Result<()> {
        unimplemented!();
        // self.maybe_end_packet()?;
        // self.w.flush()
    }
}

impl<W: Write> PacketWriter<W> {
    pub fn new(w: W) -> Self {
        PacketWriter {
            to_write: vec![0, 0, 0, 0],
            last_packet_start: 0,
            written: 0,
            seq: 0,
            w,
        }
    }

    fn maybe_end_packet(&mut self) -> io::Result<()> {
        let len = self.to_write.len() - 4 - self.last_packet_start;
        if len != 0 {
            LittleEndian::write_u24(
                &mut self.to_write[self.last_packet_start..self.last_packet_start + 3],
                len as u32,
            );
            self.to_write[self.last_packet_start + 3] = self.seq;
            self.seq = self.seq.wrapping_add(1);
            self.last_packet_start = self.to_write.len();
            self.to_write.extend(&[0, 0, 0, 0]); // add next packet's header
        }
        Ok(())
    }

    pub fn end_packet(&mut self) -> io::Result<()> {
        self.maybe_end_packet()
    }
}

pub(crate) enum Flusher<W, M> {
    Flushing {
        stmts: HashMap<u32, StatementData>,
        writer: PacketWriter<W>,
        missing: PhantomData<M>,
    },
    Done,
}

impl<W, M: PartialMissing> Future for Flusher<W, M>
where
    W: AsyncWrite,
{
    type Item = PartialServiceState<W, M>;
    type Error = io::Error;
    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        if let Flusher::Flushing {
            mut writer,
            stmts,
            missing,
        } = mem::replace(self, Flusher::Done)
        {
            match writer.poll_flush()? {
                Async::NotReady => {
                    mem::replace(
                        self,
                        Flusher::Flushing {
                            writer,
                            stmts,
                            missing,
                        },
                    );
                    Ok(Async::NotReady)
                }
                Async::Ready(_) => Ok(Async::Ready(PartialServiceState {
                    output: writer,
                    stmts,
                    missing,
                })),
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "attempted to poll Flusher after flushed",
            ))
        }
    }
}

impl<W: AsyncWrite> PacketWriter<W> {
    pub(crate) fn poll_flush(&mut self) -> Result<Async<()>, io::Error> {
        self.end_packet()?;

        loop {
            if self.written == self.last_packet_start {
                try_ready!(self.w.poll_flush());
                self.to_write.truncate(4);
                self.written = 0;
                self.last_packet_start = 0;
                return Ok(Async::Ready(()));
            }

            let w = try_ready!(
                self.w
                    .poll_write(&self.to_write[self.written..self.last_packet_start])
            );
            self.written += w;
        }
    }

    pub(crate) fn flusher<M>(self, stmts: HashMap<u32, StatementData>) -> Flusher<W, M> {
        Flusher::Flushing {
            writer: self,
            stmts,
            missing: PhantomData,
        }
    }
}

impl<W> PacketWriter<W> {
    pub fn set_seq(&mut self, seq: u8) {
        self.seq = seq;
    }
}

pub struct PacketReader<R> {
    bytes: Vec<u8>,
    start: usize,
    remaining: usize,
    r: R,
}

impl<R> PacketReader<R> {
    pub fn new(r: R) -> Self {
        PacketReader {
            bytes: Vec::new(),
            start: 0,
            remaining: 0,
            r,
        }
    }
}

impl<R: AsyncRead> PacketReader<R> {
    pub(crate) fn poll<'a>(&'a mut self) -> Result<Async<Option<(u8, Packet<'a>)>>, io::Error> {
        self.start = self.bytes.len() - self.remaining;

        loop {
            {
                // borrowck isn't smart enough to realize that bytes actually does live long
                // enough. in particular, quoth @talchas:
                //
                // > because for borrows started before a branch it doesn't split it up between the
                // > branches for determining when the borrow ends > in one branch it doesn't end
                // > until after the function returns (because it is the lifetime 'a), so it does
                // > in bot
                let bytes: &'static [u8] = unsafe { mem::transmute(&self.bytes[self.start..]) };
                match packet(bytes) {
                    Ok((rest, p)) => {
                        self.remaining = rest.len();
                        return Ok(Async::Ready(Some(p)));
                    }
                    Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {}
                    Err(nom::Err::Failure(ctx)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("{:?}", ctx),
                        ))
                    }
                }
            }

            // we need to read some more
            self.bytes.drain(0..self.start);
            self.start = 0;
            let end = self.bytes.len();
            self.bytes.resize(end + 1024, 0);
            let read = {
                let mut buf = &mut self.bytes[end..];
                match self.r.poll_read(&mut buf)? {
                    Async::Ready(n) => n,
                    Async::NotReady => {
                        // no bytes read
                        self.bytes.truncate(end);
                        self.remaining = end;
                        return Ok(Async::NotReady);
                    }
                }
            };
            self.bytes.truncate(end + read);
            self.remaining = self.bytes.len();

            if read == 0 {
                if self.bytes.is_empty() {
                    return Ok(Async::Ready(None));
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{} unhandled bytes", self.bytes.len()),
                    ));
                }
            }
        }
    }
}

named!(
    fullpacket<(u8, &[u8])>,
    do_parse!(
        tag!(&[0xff, 0xff, 0xff]) >> seq: take!(1) >> bytes: take!(U24_MAX) >> (seq[0], bytes)
    )
);

named!(
    onepacket<(u8, &[u8])>,
    do_parse!(
        length: apply!(nom::le_u24,) >> seq: take!(1) >> bytes: take!(length) >> (seq[0], bytes)
    )
);

pub struct Packet<'a>(&'a [u8], Vec<u8>);

impl<'a> Packet<'a> {
    fn extend(&mut self, bytes: &'a [u8]) {
        if self.0.is_empty() {
            if self.1.is_empty() {
                // first extend
                self.0 = bytes;
            } else {
                // later extend
                self.1.extend(bytes);
            }
        } else {
            use std::mem;

            assert!(self.1.is_empty());
            let mut v = self.0.to_vec();
            v.extend(bytes);
            mem::replace(&mut self.1, v);
            self.0 = &[];
        }
    }
}

impl<'a> AsRef<[u8]> for Packet<'a> {
    fn as_ref(&self) -> &[u8] {
        if self.1.is_empty() {
            self.0
        } else {
            &*self.1
        }
    }
}

use std::ops::Deref;
impl<'a> Deref for Packet<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

fn packet<'a>(input: &'a [u8]) -> IResult<&'a [u8], (u8, Packet<'a>)> {
    do_parse!(
        input,
        full: fold_many0!(
            fullpacket,
            (0, None),
            |(seq, pkt): (_, Option<Packet<'a>>), (nseq, p)| {
                let pkt = if let Some(mut pkt) = pkt {
                    assert_eq!(nseq, seq + 1);
                    pkt.extend(p);
                    Some(pkt)
                } else {
                    Some(Packet(p, Vec::new()))
                };
                (nseq, pkt)
            }
        ) >> last: onepacket
            >> ({
                let seq = last.0;
                let pkt = if let Some(mut pkt) = full.1 {
                    assert_eq!(last.0, full.0 + 1);
                    pkt.extend(last.1);
                    pkt
                } else {
                    Packet(last.1, Vec::new())
                };
                (seq, pkt)
            })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_ping() {
        assert_eq!(
            onepacket(&[0x01, 0, 0, 0, 0x10]).unwrap().1,
            (0, &[0x10][..])
        );
    }

    #[test]
    fn test_ping() {
        let p = packet(&[0x01, 0, 0, 0, 0x10]).unwrap().1;
        assert_eq!(p.0, 0);
        assert_eq!(&*p.1, &[0x10][..]);
    }

    #[test]
    fn test_long_exact() {
        let mut data = Vec::new();
        data.push(0xff);
        data.push(0xff);
        data.push(0xff);
        data.push(0);
        data.extend(&[0; U24_MAX][..]);
        data.push(0x00);
        data.push(0x00);
        data.push(0x00);
        data.push(1);

        let (rest, p) = packet(&data[..]).unwrap();
        assert!(rest.is_empty());
        assert_eq!(p.0, 1);
        assert_eq!(p.1.len(), U24_MAX);
        assert_eq!(&*p.1, &[0; U24_MAX][..]);
    }

    #[test]
    fn test_long_more() {
        let mut data = Vec::new();
        data.push(0xff);
        data.push(0xff);
        data.push(0xff);
        data.push(0);
        data.extend(&[0; U24_MAX][..]);
        data.push(0x01);
        data.push(0x00);
        data.push(0x00);
        data.push(1);
        data.push(0x10);

        let (rest, p) = packet(&data[..]).unwrap();
        assert!(rest.is_empty());
        assert_eq!(p.0, 1);
        assert_eq!(p.1.len(), U24_MAX + 1);
        assert_eq!(&p.1[..U24_MAX], &[0; U24_MAX][..]);
        assert_eq!(&p.1[U24_MAX..], &[0x10]);
    }
}
