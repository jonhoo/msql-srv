use crate::myc::constants::{CapabilityFlags, Command as CommandByte};

#[derive(Debug)]
pub struct ClientHandshake<'a> {
    capabilities: CapabilityFlags,
    maxps: u32,
    collation: u16,
    username: &'a [u8],
    pub database: Option<&'a [u8]>,
}

fn lenenc_int<'a, E: nom::error::ParseError<&'a [u8]>>(
    i: &'a [u8],
) -> nom::IResult<&'a [u8], u64, E> {
    let (i, x) = nom::number::complete::le_u8(i)?;
    match x {
        x if x < 0xfc => Ok((i, x.into())),
        0xfc => nom::number::complete::le_u16(i).map(|(i, v)| (i, v as u64)),
        0xfd => nom::number::complete::le_u24(i).map(|(i, v)| (i, v as u64)),
        0xfe => nom::number::complete::le_u64(i).map(|(i, v)| (i, v as u64)),
        0xff => Err(nom::Err::Error(nom::error::make_error(
            i,
            nom::error::ErrorKind::Char,
        ))),
        _ => unreachable!(),
    }
}

pub fn client_handshake(i: &[u8]) -> nom::IResult<&[u8], ClientHandshake<'_>> {
    // mysql handshake protocol documentation
    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html

    let (i, cap) = nom::number::complete::le_u16(i)?;

    if CapabilityFlags::from_bits_truncate(cap as u32).contains(CapabilityFlags::CLIENT_PROTOCOL_41)
    {
        // HandshakeResponse41
        let (i, cap2) = nom::number::complete::le_u16(i)?;
        let cap = (cap2 as u32) << 16 | cap as u32;
        let capabilities = CapabilityFlags::from_bits_truncate(cap);

        let (i, maxps) = nom::number::complete::le_u32(i)?;
        let (i, collation) = nom::bytes::complete::take(1u8)(i)?;
        let (i, _) = nom::bytes::complete::take(23u8)(i)?;
        let (i, username) = nom::bytes::complete::take_until(&b"\0"[..])(i)?;
        let (mut i, _) = nom::bytes::complete::tag(b"\0")(i)?;
        if capabilities.contains(CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
            let (i2, auth_response_length) = lenenc_int(i)?;
            let (i2, _) = nom::bytes::complete::take(auth_response_length)(i2)?;
            i = i2;
        } else if capabilities.contains(CapabilityFlags::CLIENT_SECURE_CONNECTION) {
            let (i2, auth_response_length) = nom::number::complete::le_u8(i)?;
            let (i2, _) = nom::bytes::complete::take(auth_response_length)(i2)?;
            i = i2;
        } else {
            let (i2, _) = nom::bytes::complete::tag(b"\0")(i)?;
            i = i2;
        }
        let mut database = None;
        if capabilities.contains(CapabilityFlags::CLIENT_CONNECT_WITH_DB) {
            let (_, database2) = nom::bytes::complete::tag(b"\0")(i)?;
            database = Some(database2);
        }
        Ok((
            i,
            ClientHandshake {
                capabilities: capabilities,
                maxps,
                collation: u16::from(collation[0]),
                username,
                database,
            },
        ))
    } else {
        // HandshakeResponse320
        let (i, maxps1) = nom::number::complete::le_u16(i)?;
        let (i, maxps2) = nom::number::complete::le_u8(i)?;
        let maxps = (maxps2 as u32) << 16 | maxps1 as u32;
        let (i, username) = nom::bytes::complete::take_until(&b"\0"[..])(i)?;

        Ok((
            i,
            ClientHandshake {
                capabilities: CapabilityFlags::from_bits_truncate(cap as u32),
                maxps,
                collation: 0,
                username,
                database: None,
            },
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command<'a> {
    Query(&'a [u8]),
    ListFields(&'a [u8]),
    Close(u32),
    Prepare(&'a [u8]),
    Init(&'a [u8]),
    Execute {
        stmt: u32,
        params: &'a [u8],
    },
    SendLongData {
        stmt: u32,
        param: u16,
        data: &'a [u8],
    },
    Ping,
    Quit,
}

pub fn execute(i: &[u8]) -> nom::IResult<&[u8], Command<'_>> {
    let (i, stmt) = nom::number::complete::le_u32(i)?;
    let (i, _flags) = nom::bytes::complete::take(1u8)(i)?;
    let (i, _iterations) = nom::number::complete::le_u32(i)?;
    Ok((&[], Command::Execute { stmt, params: i }))
}

pub fn send_long_data(i: &[u8]) -> nom::IResult<&[u8], Command<'_>> {
    let (i, stmt) = nom::number::complete::le_u32(i)?;
    let (i, param) = nom::number::complete::le_u16(i)?;
    Ok((
        &[],
        Command::SendLongData {
            stmt,
            param,
            data: i,
        },
    ))
}

pub fn parse(i: &[u8]) -> nom::IResult<&[u8], Command<'_>> {
    use nom::bytes::complete::tag;
    use nom::combinator::{map, rest};
    use nom::sequence::preceded;
    nom::branch::alt((
        map(
            preceded(tag(&[CommandByte::COM_QUERY as u8]), rest),
            Command::Query,
        ),
        map(
            preceded(tag(&[CommandByte::COM_FIELD_LIST as u8]), rest),
            Command::ListFields,
        ),
        map(
            preceded(tag(&[CommandByte::COM_INIT_DB as u8]), rest),
            Command::Init,
        ),
        map(
            preceded(tag(&[CommandByte::COM_STMT_PREPARE as u8]), rest),
            Command::Prepare,
        ),
        preceded(tag(&[CommandByte::COM_STMT_EXECUTE as u8]), execute),
        preceded(
            tag(&[CommandByte::COM_STMT_SEND_LONG_DATA as u8]),
            send_long_data,
        ),
        map(
            preceded(
                tag(&[CommandByte::COM_STMT_CLOSE as u8]),
                nom::number::complete::le_u32,
            ),
            Command::Close,
        ),
        map(tag(&[CommandByte::COM_QUIT as u8]), |_| Command::Quit),
        map(tag(&[CommandByte::COM_PING as u8]), |_| Command::Ping),
    ))(i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::myc::constants::{CapabilityFlags, UTF8_GENERAL_CI};
    use crate::packet::PacketReader;
    use std::io::Cursor;

    #[test]
    fn it_parses_handshake() {
        let data = &[
            0x25, 0x00, 0x00, 0x01, 0x85, 0xa6, 0x3f, 0x20, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x6f, 0x6e, 0x00, 0x00,
        ];
        let r = Cursor::new(&data[..]);
        let mut pr = PacketReader::new(r);
        let (_, p) = pr.next().unwrap().unwrap();
        let (_, handshake) = client_handshake(&p).unwrap();
        println!("{:?}", handshake);
        assert!(handshake
            .capabilities
            .contains(CapabilityFlags::CLIENT_LONG_PASSWORD));
        assert!(handshake
            .capabilities
            .contains(CapabilityFlags::CLIENT_MULTI_RESULTS));
        assert!(!handshake
            .capabilities
            .contains(CapabilityFlags::CLIENT_CONNECT_WITH_DB));
        assert!(!handshake
            .capabilities
            .contains(CapabilityFlags::CLIENT_DEPRECATE_EOF));
        assert_eq!(handshake.collation, UTF8_GENERAL_CI);
        assert_eq!(handshake.username, &b"jon"[..]);
        assert_eq!(handshake.maxps, 16777216);
    }

    #[test]
    fn it_parses_request() {
        let data = &[
            0x21, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40,
            0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e,
            0x74, 0x20, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x20, 0x31,
        ];
        let r = Cursor::new(&data[..]);
        let mut pr = PacketReader::new(r);
        let (_, p) = pr.next().unwrap().unwrap();
        let (_, cmd) = parse(&p).unwrap();
        assert_eq!(
            cmd,
            Command::Query(&b"select @@version_comment limit 1"[..])
        );
    }

    #[test]
    fn it_handles_list_fields() {
        // mysql_list_fields (CommandByte::COM_FIELD_LIST / 0x04) has been deprecated in mysql 5.7 and will be removed
        // in a future version. The mysql command line tool issues one of these commands after
        // switching databases with USE <DB>.
        let data = &[
            0x21, 0x00, 0x00, 0x00, 0x04, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40,
            0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e,
            0x74, 0x20, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x20, 0x31,
        ];
        let r = Cursor::new(&data[..]);
        let mut pr = PacketReader::new(r);
        let (_, p) = pr.next().unwrap().unwrap();
        let (_, cmd) = parse(&p).unwrap();
        assert_eq!(
            cmd,
            Command::ListFields(&b"select @@version_comment limit 1"[..])
        );
    }
}
