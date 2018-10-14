use myc;
use {StatementData, Value};

/// A `ParamParser` decodes query parameters included in a client's `EXECUTE` command given
/// type information for the expected parameters.
///
/// Note that `Params` does *not* implement `Iterator`, because that would require streaming
/// iterators, which is blocked on higher-kinded lifetimes. If you're curious about this, take a
/// look at [`rust-streaming`](https://github.com/emk/rust-streaming).
///
/// Note also that you'll need to return the params to the [`QueryResultWriter`] you are provided
/// with to produce the final query [`Response`]. This is because `Params` borrows some statement
/// state that must be carried along to subsequent requests.
pub struct Params<'a> {
    stmt: (u32, StatementData),
    input: &'a [u8],
    nullmap: Option<&'a [u8]>,
    col: u16,
}

impl<'a> Params<'a> {
    pub(crate) fn new(input: &'a [u8], stmt: (u32, StatementData)) -> Self {
        Params {
            stmt: stmt,
            input: input,
            nullmap: None,
            col: 0,
        }
    }
}

/// A single parameter value provided by a client when issuing an `EXECUTE` command.
pub struct ParamValue<'a> {
    /// The value provided for this parameter.
    pub value: Value<'a>,
    /// The column type assigned to this parameter.
    pub coltype: myc::constants::ColumnType,
}

impl<'a> Params<'a> {
    pub(crate) fn statement(self) -> (u32, StatementData) {
        self.stmt
    }
}

impl<'a> Params<'a> {
    /// Retrieve the next parameter's value.
    pub fn next(&'a mut self) -> Option<ParamValue<'a>> {
        if self.nullmap.is_none() {
            let nullmap_len = (self.stmt.1.params as usize + 7) / 8;
            let (nullmap, rest) = self.input.split_at(nullmap_len);
            self.nullmap = Some(nullmap);
            self.input = rest;

            if !rest.is_empty() && rest[0] != 0x00 {
                let (typmap, rest) = rest[1..].split_at(2 * self.stmt.1.params as usize);
                self.stmt.1.bound_types.clear();
                for i in 0..self.stmt.1.params as usize {
                    self.stmt.1.bound_types.push((
                        myc::constants::ColumnType::from(typmap[2 * i as usize]),
                        (typmap[2 * i as usize + 1] & 128) != 0,
                    ));
                }
                self.input = rest;
            }
        }

        if self.col >= self.stmt.1.params {
            return None;
        }
        let pt = &self.stmt.1.bound_types[self.col as usize];

        // https://web.archive.org/web/20170404144156/https://dev.mysql.com/doc/internals/en/null-bitmap.html
        // NULL-bitmap-byte = ((field-pos + offset) / 8)
        // NULL-bitmap-bit  = ((field-pos + offset) % 8)
        if let Some(nullmap) = self.nullmap {
            let byte = self.col as usize / 8;
            if byte >= nullmap.len() {
                return None;
            }
            if (nullmap[byte] & 1u8 << (self.col % 8)) != 0 {
                self.col += 1;
                return Some(ParamValue {
                    value: Value::null(),
                    coltype: pt.0,
                });
            }
        } else {
            unreachable!();
        }

        let v = if let Some(data) = self.stmt.1.long_data.get(&self.col) {
            Value::bytes(&data[..])
        } else {
            Value::parse_from(&mut self.input, pt.0, pt.1).unwrap()
        };
        self.col += 1;
        Some(ParamValue {
            value: v,
            coltype: pt.0,
        })
    }
}
