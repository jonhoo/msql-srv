#[cfg(test)]
#[allow(unused_imports)]
pub mod tests {
    /// Non panicking Slice::split_at
    macro_rules! split_at_or_err {
        ($reader:expr, $at:expr, $msg:expr) => {
            if $reader.len() >= $at {
                Ok($reader.split_at($at))
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, $msg))
            }
        };
    }

    /// Reads MySql's length-encoded string
    #[macro_export]
    macro_rules! read_lenenc_str {
        ($reader:expr) => {{
            let reader = $reader;
            reader.read_lenenc_int().and_then(|len| {
                let (value, rest) = split_at_or_err!(
                    reader,
                    len as usize,
                    "EOF while reading length-encoded string"
                )?;
                *reader = rest;
                Ok(value)
            })
        }};
    }

    use crate::myc::constants::ColumnType;
    use crate::myc::io::ReadMysqlExt;
    use crate::myc::io::WriteMysqlExt as RawWriteMysqlExt;
    use crate::myc::value::Value;
    use crate::myc::value::Value::*;
    use byteorder::{LittleEndian as LE, ReadBytesExt, WriteBytesExt};
    use std::io;

    pub trait WriteMysqlExt: WriteBytesExt + RawWriteMysqlExt {
        /// Writes MySql's value in binary value format.
        fn write_bin_value(&mut self, value: &Value) -> io::Result<u64> {
            match *value {
                Value::NULL => Ok(0),
                Value::Bytes(ref x) => self.write_lenenc_str(&x[..]),
                Value::Int(x) => {
                    self.write_i64::<LE>(x)?;
                    Ok(8)
                }
                Value::UInt(x) => {
                    self.write_u64::<LE>(x)?;
                    Ok(8)
                }
                Value::Float(x) => {
                    self.write_f32::<LE>(x)?;
                    Ok(8)
                }
                Value::Double(x) => {
                    self.write_f64::<LE>(x)?;
                    Ok(8)
                }
                Value::Date(0u16, 0u8, 0u8, 0u8, 0u8, 0u8, 0u32) => {
                    self.write_u8(0u8)?;
                    Ok(1)
                }
                Value::Date(y, m, d, 0u8, 0u8, 0u8, 0u32) => {
                    self.write_u8(4u8)?;
                    self.write_u16::<LE>(y)?;
                    self.write_u8(m)?;
                    self.write_u8(d)?;
                    Ok(5)
                }
                Value::Date(y, m, d, h, i, s, 0u32) => {
                    self.write_u8(7u8)?;
                    self.write_u16::<LE>(y)?;
                    self.write_u8(m)?;
                    self.write_u8(d)?;
                    self.write_u8(h)?;
                    self.write_u8(i)?;
                    self.write_u8(s)?;
                    Ok(8)
                }
                Value::Date(y, m, d, h, i, s, u) => {
                    self.write_u8(11u8)?;
                    self.write_u16::<LE>(y)?;
                    self.write_u8(m)?;
                    self.write_u8(d)?;
                    self.write_u8(h)?;
                    self.write_u8(i)?;
                    self.write_u8(s)?;
                    self.write_u32::<LE>(u)?;
                    Ok(12)
                }
                Value::Time(_, 0u32, 0u8, 0u8, 0u8, 0u32) => {
                    self.write_u8(0u8)?;
                    Ok(1)
                }
                Value::Time(neg, d, h, m, s, 0u32) => {
                    self.write_u8(8u8)?;
                    self.write_u8(if neg { 1u8 } else { 0u8 })?;
                    self.write_u32::<LE>(d)?;
                    self.write_u8(h)?;
                    self.write_u8(m)?;
                    self.write_u8(s)?;
                    Ok(9)
                }
                Value::Time(neg, d, h, m, s, u) => {
                    self.write_u8(12u8)?;
                    self.write_u8(if neg { 1u8 } else { 0u8 })?;
                    self.write_u32::<LE>(d)?;
                    self.write_u8(h)?;
                    self.write_u8(m)?;
                    self.write_u8(s)?;
                    self.write_u32::<LE>(u)?;
                    Ok(13)
                }
            }
        }
    }

    impl<T> WriteMysqlExt for T where T: WriteBytesExt {}

    /// Reads value in binary format.
    pub fn read_bin_value(
        input: &mut &[u8],
        column_type: ColumnType,
        unsigned: bool,
    ) -> io::Result<Value> {
        read_bin(input, column_type, unsigned)
    }

    /// Reads value in text format.
    pub fn read_text_value(input: &mut &[u8]) -> io::Result<Value> {
        read_text(input)
    }

    fn read_text(input: &mut &[u8]) -> io::Result<Value> {
        if input.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF while reading Value",
            ))
        } else if input[0] == 0xfb {
            let _ = input.read_u8();
            Ok(Value::NULL)
        } else {
            Ok(Value::Bytes(read_lenenc_str!(input)?.into()))
        }
    }

    fn read_bin(input: &mut &[u8], column_type: ColumnType, unsigned: bool) -> io::Result<Value> {
        match column_type {
            ColumnType::MYSQL_TYPE_STRING
            | ColumnType::MYSQL_TYPE_VAR_STRING
            | ColumnType::MYSQL_TYPE_BLOB
            | ColumnType::MYSQL_TYPE_TINY_BLOB
            | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
            | ColumnType::MYSQL_TYPE_LONG_BLOB
            | ColumnType::MYSQL_TYPE_SET
            | ColumnType::MYSQL_TYPE_ENUM
            | ColumnType::MYSQL_TYPE_DECIMAL
            | ColumnType::MYSQL_TYPE_VARCHAR
            | ColumnType::MYSQL_TYPE_BIT
            | ColumnType::MYSQL_TYPE_NEWDECIMAL
            | ColumnType::MYSQL_TYPE_GEOMETRY
            | ColumnType::MYSQL_TYPE_JSON => Ok(Bytes(read_lenenc_str!(input)?.into())),
            ColumnType::MYSQL_TYPE_TINY => {
                if unsigned {
                    Ok(Int(input.read_u8()?.into()))
                } else {
                    Ok(Int(input.read_i8()?.into()))
                }
            }
            ColumnType::MYSQL_TYPE_SHORT | ColumnType::MYSQL_TYPE_YEAR => {
                if unsigned {
                    Ok(Int(input.read_u16::<LE>()?.into()))
                } else {
                    Ok(Int(input.read_i16::<LE>()?.into()))
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                if unsigned {
                    Ok(Int(input.read_u32::<LE>()?.into()))
                } else {
                    Ok(Int(input.read_i32::<LE>()?.into()))
                }
            }
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if unsigned {
                    Ok(UInt(input.read_u64::<LE>()?))
                } else {
                    Ok(Int(input.read_i64::<LE>()?))
                }
            }
            ColumnType::MYSQL_TYPE_FLOAT => Ok(Float(input.read_f32::<LE>()?)),
            ColumnType::MYSQL_TYPE_DOUBLE => Ok(Double(input.read_f64::<LE>()?)),
            ColumnType::MYSQL_TYPE_TIMESTAMP
            | ColumnType::MYSQL_TYPE_DATE
            | ColumnType::MYSQL_TYPE_DATETIME => {
                let len = input.read_u8()?;
                let mut year = 0u16;
                let mut month = 0u8;
                let mut day = 0u8;
                let mut hour = 0u8;
                let mut minute = 0u8;
                let mut second = 0u8;
                let mut micro_second = 0u32;
                if len >= 4u8 {
                    year = input.read_u16::<LE>()?;
                    month = input.read_u8()?;
                    day = input.read_u8()?;
                }
                if len >= 7u8 {
                    hour = input.read_u8()?;
                    minute = input.read_u8()?;
                    second = input.read_u8()?;
                }
                if len == 11u8 {
                    micro_second = input.read_u32::<LE>()?;
                }
                Ok(Date(year, month, day, hour, minute, second, micro_second))
            }
            ColumnType::MYSQL_TYPE_TIME => {
                let len = input.read_u8()?;
                let mut is_negative = false;
                let mut days = 0u32;
                let mut hours = 0u8;
                let mut minutes = 0u8;
                let mut seconds = 0u8;
                let mut micro_seconds = 0u32;
                if len >= 8u8 {
                    is_negative = input.read_u8()? == 1u8;
                    days = input.read_u32::<LE>()?;
                    hours = input.read_u8()?;
                    minutes = input.read_u8()?;
                    seconds = input.read_u8()?;
                }
                if len == 12u8 {
                    micro_seconds = input.read_u32::<LE>()?;
                }
                Ok(Time(
                    is_negative,
                    days,
                    hours,
                    minutes,
                    seconds,
                    micro_seconds,
                ))
            }
            ColumnType::MYSQL_TYPE_NULL => Ok(NULL),
            x => unimplemented!("Unsupported column type {:?}", x),
        }
    }
}
