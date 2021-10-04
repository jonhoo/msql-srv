use crate::myc::constants::ColumnType;
use crate::myc::io::ReadMysqlExt;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io;

/// MySQL value as provided when executing prepared statements.
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Value<'a>(ValueInner<'a>);

/// A representation of a concrete, typed MySQL value.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ValueInner<'a> {
    /// The MySQL `NULL` value.
    NULL,
    /// An untyped sequence of bytes (usually a text type or `MYSQL_TYPE_BLOB`).
    Bytes(&'a [u8]),
    /// A signed integer.
    Int(i64),
    /// An unsigned integer.
    UInt(u64),
    /// A floating point number.
    Double(f64),
    /// A [binary encoding](https://mariadb.com/kb/en/library/resultset-row/#date-binary-encoding)
    /// of a `MYSQL_TYPE_DATE`.
    Date(&'a [u8]),
    /// A [binary encoding](https://mariadb.com/kb/en/library/resultset-row/#time-binary-encoding)
    /// of a `MYSQL_TYPE_TIME`.
    Time(&'a [u8]),
    /// A [binary
    /// encoding](https://mariadb.com/kb/en/library/resultset-row/#timestamp-binary-encoding) of a
    /// `MYSQL_TYPE_TIMESTAMP` or `MYSQL_TYPE_DATETIME`.
    Datetime(&'a [u8]),
}

impl<'a> Value<'a> {
    /// Return the inner stored representation of this value.
    ///
    /// This may be useful for when you do not care about the exact data type used for a column,
    /// but instead wish to introspect a value you are given at runtime. Note that the contained
    /// value may be stored in a type that is more general than what the corresponding parameter
    /// type allows (e.g., a `u8` will be stored as an `u64`).
    pub fn into_inner(self) -> ValueInner<'a> {
        self.0
    }

    pub(crate) fn null() -> Self {
        Value(ValueInner::NULL)
    }

    /// Returns true if this is a NULL value
    pub fn is_null(&self) -> bool {
        matches!(self.0, ValueInner::NULL)
    }

    pub(crate) fn parse_from(
        input: &mut &'a [u8],
        ct: ColumnType,
        unsigned: bool,
    ) -> io::Result<Self> {
        ValueInner::parse_from(input, ct, unsigned).map(Value)
    }

    pub(crate) fn bytes(input: &'a [u8]) -> Value<'a> {
        Value(ValueInner::Bytes(input))
    }
}

macro_rules! read_bytes {
    ($input:expr, $len:expr) => {
        if $len as usize > $input.len() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF while reading length-encoded string",
            ))
        } else {
            let (bits, rest) = $input.split_at($len as usize);
            *$input = rest;
            Ok(bits)
        }
    };
}

impl<'a> ValueInner<'a> {
    fn parse_from(input: &mut &'a [u8], ct: ColumnType, unsigned: bool) -> io::Result<Self> {
        match ct {
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
            | ColumnType::MYSQL_TYPE_JSON => {
                let len = input.read_lenenc_int()?;
                Ok(ValueInner::Bytes(read_bytes!(input, len)?))
            }
            ColumnType::MYSQL_TYPE_TINY => {
                if unsigned {
                    Ok(ValueInner::UInt(u64::from(input.read_u8()?)))
                } else {
                    Ok(ValueInner::Int(i64::from(input.read_i8()?)))
                }
            }
            ColumnType::MYSQL_TYPE_SHORT | ColumnType::MYSQL_TYPE_YEAR => {
                if unsigned {
                    Ok(ValueInner::UInt(u64::from(
                        input.read_u16::<LittleEndian>()?,
                    )))
                } else {
                    Ok(ValueInner::Int(i64::from(
                        input.read_i16::<LittleEndian>()?,
                    )))
                }
            }
            ColumnType::MYSQL_TYPE_LONG | ColumnType::MYSQL_TYPE_INT24 => {
                if unsigned {
                    Ok(ValueInner::UInt(u64::from(
                        input.read_u32::<LittleEndian>()?,
                    )))
                } else {
                    Ok(ValueInner::Int(i64::from(
                        input.read_i32::<LittleEndian>()?,
                    )))
                }
            }
            ColumnType::MYSQL_TYPE_LONGLONG => {
                if unsigned {
                    Ok(ValueInner::UInt(input.read_u64::<LittleEndian>()?))
                } else {
                    Ok(ValueInner::Int(input.read_i64::<LittleEndian>()?))
                }
            }
            ColumnType::MYSQL_TYPE_FLOAT => {
                let f = input.read_f32::<LittleEndian>()?;
                println!("read {}", f);
                Ok(ValueInner::Double(f64::from(f)))
            }
            ColumnType::MYSQL_TYPE_DOUBLE => {
                Ok(ValueInner::Double(input.read_f64::<LittleEndian>()?))
            }
            ColumnType::MYSQL_TYPE_TIMESTAMP | ColumnType::MYSQL_TYPE_DATETIME => {
                let len = input.read_u8()?;
                Ok(ValueInner::Datetime(read_bytes!(input, len)?))
            }
            ColumnType::MYSQL_TYPE_DATE => {
                let len = input.read_u8()?;
                Ok(ValueInner::Date(read_bytes!(input, len)?))
            }
            ColumnType::MYSQL_TYPE_TIME => {
                let len = input.read_u8()?;
                Ok(ValueInner::Time(read_bytes!(input, len)?))
            }
            ColumnType::MYSQL_TYPE_NULL => Ok(ValueInner::NULL),
            ct => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown column type {:?}", ct),
            )),
        }
    }
}

// NOTE: these should all be TryInto
macro_rules! impl_into {
    ($t:ty, $($variant:path),*) => {
        impl<'a> Into<$t> for Value<'a> {
            fn into(self) -> $t {
                match self.0 {
                    $($variant(v) => v as $t),*,
                    v => panic!(concat!("invalid type conversion from {:?} to ", stringify!($t)), v)
                }
            }
        }
    }
}

impl_into!(u8, ValueInner::UInt, ValueInner::Int);
impl_into!(u16, ValueInner::UInt, ValueInner::Int);
impl_into!(u32, ValueInner::UInt, ValueInner::Int);
impl_into!(u64, ValueInner::UInt);
impl_into!(i8, ValueInner::UInt, ValueInner::Int);
impl_into!(i16, ValueInner::UInt, ValueInner::Int);
impl_into!(i32, ValueInner::UInt, ValueInner::Int);
impl_into!(i64, ValueInner::Int);
impl_into!(f32, ValueInner::Double);
impl_into!(f64, ValueInner::Double);
impl_into!(&'a [u8], ValueInner::Bytes);

impl<'a> Into<&'a str> for Value<'a> {
    fn into(self) -> &'a str {
        if let ValueInner::Bytes(v) = self.0 {
            ::std::str::from_utf8(v).unwrap()
        } else {
            panic!("invalid type conversion from {:?} to string", self)
        }
    }
}

use chrono::{NaiveDate, NaiveDateTime};
impl<'a> Into<NaiveDate> for Value<'a> {
    fn into(self) -> NaiveDate {
        if let ValueInner::Date(mut v) = self.0 {
            assert_eq!(v.len(), 4);
            NaiveDate::from_ymd(
                i32::from(v.read_u16::<LittleEndian>().unwrap()),
                u32::from(v.read_u8().unwrap()),
                u32::from(v.read_u8().unwrap()),
            )
        } else {
            panic!("invalid type conversion from {:?} to date", self)
        }
    }
}

impl<'a> Into<NaiveDateTime> for Value<'a> {
    fn into(self) -> NaiveDateTime {
        if let ValueInner::Datetime(mut v) = self.0 {
            assert!(v.len() == 7 || v.len() == 11);
            let d = NaiveDate::from_ymd(
                i32::from(v.read_u16::<LittleEndian>().unwrap()),
                u32::from(v.read_u8().unwrap()),
                u32::from(v.read_u8().unwrap()),
            );

            let h = u32::from(v.read_u8().unwrap());
            let m = u32::from(v.read_u8().unwrap());
            let s = u32::from(v.read_u8().unwrap());

            if v.len() == 11 {
                let us = v.read_u32::<LittleEndian>().unwrap();
                d.and_hms_micro(h, m, s, us)
            } else {
                d.and_hms(h, m, s)
            }
        } else {
            panic!("invalid type conversion from {:?} to datetime", self)
        }
    }
}

use std::time::Duration;
impl<'a> Into<Duration> for Value<'a> {
    fn into(self) -> Duration {
        if let ValueInner::Time(mut v) = self.0 {
            assert!(v.is_empty() || v.len() == 8 || v.len() == 12);

            if v.is_empty() {
                return Duration::from_secs(0);
            }

            let neg = v.read_u8().unwrap();
            if neg != 0u8 {
                unimplemented!();
            }

            let days = u64::from(v.read_u32::<LittleEndian>().unwrap());
            let hours = u64::from(v.read_u8().unwrap());
            let minutes = u64::from(v.read_u8().unwrap());
            let seconds = u64::from(v.read_u8().unwrap());
            let micros = if v.len() == 12 {
                v.read_u32::<LittleEndian>().unwrap()
            } else {
                0
            };

            Duration::new(
                days * 86_400 + hours * 3_600 + minutes * 60 + seconds,
                micros * 1_000,
            )
        } else {
            panic!("invalid type conversion from {:?} to datetime", self)
        }
    }
}
