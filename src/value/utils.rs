#[cfg(test)]
#[allow(unused_imports)]
pub mod tests {
    use crate::myc::io::WriteMysqlExt as RawWriteMysqlExt;
    use crate::myc::value::Value;
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
}
