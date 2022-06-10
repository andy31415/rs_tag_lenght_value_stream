#![no_std]

pub mod types;

use byteorder::{ByteOrder, LittleEndian};
use types::{ContainerType, ElementType, TagType};

/// Represents an actual value read from a TLV record
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Value<'a> {
    Signed(i64),
    Unsigned(u64),
    Bool(bool),
    Float(f32),
    Double(f64),
    Utf8(&'a [u8]),
    Bytes(&'a [u8]),
    Null,
    ContainerStart(ContainerType),
    ContainerEnd,
}

/// Represents a data record read from a TLV stream
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Record<'a> {
    pub tag_type: TagType,
    pub tag_value: u64, // fully expanded 8-byte value

    pub value: Value<'a>,
}

/// Represents an incremental parsing result containing
/// some data and the remaining parse buffer
#[derive(Debug, PartialEq)]
pub(crate) struct IncrementalParseResult<'a, T> {
    pub(crate) parsed: T,
    pub(crate) remaining_input: &'a [u8],
}

#[derive(Debug)]
pub struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Check if the parser was fully consumed
    ///
    /// When iterating over a parser, any parse error
    /// will result in iteration completing without the
    /// full data being consumed.
    pub fn done(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the undelying tag and rest of the data
    pub(crate) fn read_tag_value(
        tag_type: TagType,
        data: &[u8],
    ) -> Option<IncrementalParseResult<u64>> {
        let tag_length = match tag_type {
            TagType::Anonymous => 0,
            TagType::ContextSpecific1byte => 1,
            TagType::Implicit2byte | TagType::CommonProfile2byte => 2,
            TagType::Implicit4byte | TagType::CommonProfile4byte => 4,
            TagType::FullyQualified6byte => 6,
            TagType::FullyQualified8byte => 8,
        };

        if data.len() < tag_length {
            // Cannot parse, return nothing and do not consume the data
            return None;
        }

        let (buf, remaining_input) = data.split_at(tag_length);
        let parsed = match tag_length {
            0 => 0u64,
            nbytes => LittleEndian::read_uint(buf, nbytes),
        };

        Some(IncrementalParseResult {
            parsed,
            remaining_input,
        })
    }

    pub(crate) fn read_value(
        element_type: ElementType,
        data: &'a [u8],
    ) -> Option<IncrementalParseResult<'a, Value<'a>>> {
        match element_type {
            ElementType::Unsigned(n) | ElementType::Signed(n) => {
                let value_len = match n {
                    types::ElementDataLength::Bytes1 if !data.is_empty() => 1,
                    types::ElementDataLength::Bytes2 if data.len() >= 2 => 2,
                    types::ElementDataLength::Bytes4 if data.len() >= 4 => 4,
                    types::ElementDataLength::Bytes8 if data.len() >= 8 => 8,
                    _ => return None, // insufficient buffer space
                };

                let parsed = {
                    if let ElementType::Unsigned(_) = element_type {
                        Value::Unsigned(LittleEndian::read_uint(data, value_len))
                    } else {
                        Value::Signed(LittleEndian::read_int(data, value_len))
                    }
                };

                Some(IncrementalParseResult {
                    parsed,
                    remaining_input: data.split_at(value_len).1,
                })
            }
            ElementType::Boolean(v) => Some(IncrementalParseResult {
                parsed: Value::Bool(v),
                remaining_input: data,
            }),
            ElementType::Float => {
                if data.len() < 4 {
                    return None;
                }
                Some(IncrementalParseResult {
                    parsed: Value::Float(LittleEndian::read_f32(data)),
                    remaining_input: data.split_at(4).1,
                })
            }
            ElementType::Double => {
                if data.len() < 8 {
                    return None;
                }
                Some(IncrementalParseResult {
                    parsed: Value::Double(LittleEndian::read_f64(data)),
                    remaining_input: data.split_at(8).1,
                })
            }
            ElementType::Utf8String(data_len) | ElementType::ByteString(data_len) => {
                let length_parsing = Parser::read_value(ElementType::Unsigned(data_len), data)?;

                let data_len = match length_parsing.parsed {
                    Value::Unsigned(n) => n,
                    _ => return None,
                };

                if data_len > length_parsing.remaining_input.len() as u64 {
                    // String too short
                    return None;
                }

                let (value, remaining_input) =
                    length_parsing.remaining_input.split_at(data_len as usize);

                let parsed = {
                    if let ElementType::Utf8String(_) = element_type {
                        Value::Utf8(value)
                    } else {
                        Value::Bytes(value)
                    }
                };

                Some(IncrementalParseResult {
                    parsed,
                    remaining_input,
                })
            }
            ElementType::Null => Some(IncrementalParseResult {
                parsed: Value::Null,
                remaining_input: data,
            }),
            ElementType::ContainerStart(t) => Some(IncrementalParseResult {
                parsed: Value::ContainerStart(t),
                remaining_input: data,
            }),
            ElementType::ContainerEnd => Some(IncrementalParseResult {
                parsed: Value::ContainerEnd,
                remaining_input: data,
            }),
        }
    }
}

impl<'a> Iterator for Parser<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.data.split_first() {
            None => None,
            Some((control, rest)) => {
                let tag_type = TagType::for_control(*control);

                let result = Parser::read_tag_value(tag_type, rest)?;

                let tag_value = result.parsed;
                let rest = result.remaining_input;

                let value_type = ElementType::for_control(*control)?;

                let value = Parser::read_value(value_type, rest)?;

                self.data = value.remaining_input;

                Some(Self::Item {
                    tag_type,
                    tag_value,
                    value: value.parsed,
                })
            }
        }
    }
}

///
#[cfg(test)]
mod tests {
    use crate::types::ElementDataLength;

    use super::*;

    #[test]
    fn read_tag_value_works() {
        let empty = [].as_slice();
        assert_eq!(
            Parser::read_tag_value(TagType::Anonymous, empty),
            Some(IncrementalParseResult {
                parsed: 0,
                remaining_input: empty
            })
        );

        let some_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].as_slice();
        assert_eq!(
            Parser::read_tag_value(TagType::Anonymous, some_bytes),
            Some(IncrementalParseResult {
                parsed: 0,
                remaining_input: some_bytes
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::ContextSpecific1byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: 0x01,
                remaining_input: [2, 3, 4, 5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile2byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: 0x0201,
                remaining_input: [3, 4, 5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::Implicit2byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: 0x0201,
                remaining_input: [3, 4, 5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::Implicit4byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: 0x04030201,
                remaining_input: [5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile4byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: 0x04030201,
                remaining_input: [5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified6byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: 0x060504030201,
                remaining_input: [7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified8byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: 0x0807060504030201,
                remaining_input: [9, 10].as_slice()
            })
        );
    }

    #[test]
    fn read_tag_value_fails_on_short() {
        let empty = [].as_slice();
        assert_eq!(Parser::read_tag_value(TagType::Implicit2byte, empty), None);

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile2byte, empty),
            None
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified6byte, empty),
            None
        );

        let one_byte = [1].as_slice();

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile2byte, one_byte),
            None
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified6byte, one_byte),
            None
        );

        let four_bytes = [1, 2, 3, 4].as_slice();

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified6byte, four_bytes),
            None
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified8byte, four_bytes),
            None
        );
    }

    fn check_value_read(in_type: ElementType, in_data: &[u8], out_type: Value, out_data: &[u8]) {
        assert_eq!(
            Parser::read_value(in_type, in_data),
            Some(IncrementalParseResult {
                parsed: out_type,
                remaining_input: out_data
            }),
            "Expecting {:?}/{:?} to parse to {:?}/{:?}",
            in_type,
            in_data,
            out_type,
            out_data,
        );
    }

    #[test]
    fn it_reads_values() {
        let empty_element_types = [
            (ElementType::Null, Value::Null),
            (ElementType::ContainerEnd, Value::ContainerEnd),
            (
                ElementType::ContainerStart(ContainerType::Array),
                Value::ContainerStart(ContainerType::Array),
            ),
            (
                ElementType::ContainerStart(ContainerType::List),
                Value::ContainerStart(ContainerType::List),
            ),
            (
                ElementType::ContainerStart(ContainerType::Structure),
                Value::ContainerStart(ContainerType::Structure),
            ),
            (ElementType::Boolean(true), Value::Bool(true)),
            (ElementType::Boolean(false), Value::Bool(false)),
        ];

        for (in_type, out_type) in empty_element_types {
            check_value_read(in_type, &[], out_type, &[]);
            check_value_read(in_type, &[1, 2, 3], out_type, &[1, 2, 3]);
        }

        ///// Unsigned tests
        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes1),
            &[0x01],
            Value::Unsigned(0x01),
            &[],
        );

        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes1),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Unsigned(0x01),
            &[0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes2),
            &[0x01, 0x02],
            Value::Unsigned(0x0201),
            &[],
        );

        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes2),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Unsigned(0x0201),
            &[0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes4),
            &[0x01, 0x02, 0x03, 0x04],
            Value::Unsigned(0x04030201),
            &[],
        );

        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes4),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Unsigned(0x04030201),
            &[0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes8),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            Value::Unsigned(0x0807060504030201),
            &[],
        );

        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes8),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Unsigned(0x0807060504030201),
            &[0x09],
        );

        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes2),
            &[0xFF, 0xFF, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Unsigned(0xFFFF),
            &[0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Unsigned(ElementDataLength::Bytes4),
            &[0xFE, 0xFF, 0xFF, 0xFF, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Unsigned(0xFFFFFFFE),
            &[0x05, 0x06, 0x07, 0x08, 0x09],
        );

        // Signed tests
        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes1),
            &[0x01],
            Value::Signed(0x01),
            &[],
        );

        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes1),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Signed(0x01),
            &[0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes2),
            &[0x01, 0x02],
            Value::Signed(0x0201),
            &[],
        );

        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes2),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Signed(0x0201),
            &[0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes4),
            &[0x01, 0x02, 0x03, 0x04],
            Value::Signed(0x04030201),
            &[],
        );

        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes4),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Signed(0x04030201),
            &[0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes8),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            Value::Signed(0x0807060504030201),
            &[],
        );

        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes8),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Signed(0x0807060504030201),
            &[0x09],
        );

        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes2),
            &[0xFF, 0xFF, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Signed(-1),
            &[0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Signed(ElementDataLength::Bytes4),
            &[0xFE, 0xFF, 0xFF, 0xFF, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Signed(-2),
            &[0x05, 0x06, 0x07, 0x08, 0x09],
        );

        // Floating point number tests
        check_value_read(
            ElementType::Float,
            &[0x0, 0x0, 0x0, 0x0, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Float(0_f32),
            &[0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Float,
            &[0x0, 0x0, 0xf6, 0x42, 0x05, 0x06, 0x07, 0x08, 0x09],
            Value::Float(123_f32),
            &[0x05, 0x06, 0x07, 0x08, 0x09],
        );

        check_value_read(
            ElementType::Double,
            &[0x0, 0x0, 0x0, 0x0, 0x00, 0x00, 0x00, 0x00, 0x09],
            Value::Double(0_f64),
            &[0x09],
        );

        check_value_read(
            ElementType::Double,
            &[0x0, 0x0, 0x00, 0x00, 0x00, 0xc0, 0x5e, 0x40, 0x09],
            Value::Double(123_f64),
            &[0x09],
        );

        // Strings
        check_value_read(
            ElementType::Utf8String(ElementDataLength::Bytes1),
            &[0x00],
            Value::Utf8(&[]),
            &[],
        );

        check_value_read(
            ElementType::Utf8String(ElementDataLength::Bytes1),
            &[0x00, 0x01],
            Value::Utf8(&[]),
            &[0x01],
        );

        check_value_read(
            ElementType::Utf8String(ElementDataLength::Bytes2),
            &[0x00, 0x00],
            Value::Utf8(&[]),
            &[],
        );

        check_value_read(
            ElementType::Utf8String(ElementDataLength::Bytes2),
            &[0x01, 0x00, 0x41, 0x42],
            Value::Utf8(&[0x41]),
            &[0x42],
        );

        check_value_read(
            ElementType::Utf8String(ElementDataLength::Bytes1),
            &[0x02, 0x41, 0x42, 0x11, 0x22, 0x33],
            Value::Utf8(&[0x41, 0x42]),
            &[0x11, 0x22, 0x33],
        );

        // Bytes
        check_value_read(
            ElementType::ByteString(ElementDataLength::Bytes1),
            &[0x04, 0x01, 0x02, 0x00, 0xFF, 0x11, 0x22, 0x33],
            Value::Bytes(&[0x01, 0x02, 0x00, 0xFF]),
            &[0x11, 0x22, 0x33],
        );

        check_value_read(
            ElementType::ByteString(ElementDataLength::Bytes4),
            &[0x02, 0x00, 0x00, 0x00, 0xFF, 0x11, 0x22, 0x33],
            Value::Bytes(&[0xFF, 0x11]),
            &[0x22, 0x33],
        );
    }

    fn expect_short_read(in_type: ElementType, in_data: &[u8]) {
        assert_eq!(
            Parser::read_value(in_type, in_data),
            None,
            "Expecting {:?}/{:?} to be short read (value is None)",
            in_type,
            in_data,
        );
    }

    #[test]
    fn short_value_reads() {
        expect_short_read(ElementType::Unsigned(ElementDataLength::Bytes1), &[]);

        expect_short_read(ElementType::Unsigned(ElementDataLength::Bytes2), &[]);
        expect_short_read(ElementType::Unsigned(ElementDataLength::Bytes2), &[0x01]);

        expect_short_read(ElementType::Unsigned(ElementDataLength::Bytes4), &[]);
        expect_short_read(
            ElementType::Unsigned(ElementDataLength::Bytes4),
            &[0x01, 0x02],
        );
        expect_short_read(
            ElementType::Unsigned(ElementDataLength::Bytes4),
            &[0x01, 0x02, 0x03],
        );

        expect_short_read(ElementType::Unsigned(ElementDataLength::Bytes8), &[]);
        expect_short_read(
            ElementType::Unsigned(ElementDataLength::Bytes8),
            &[0x01, 0x02],
        );
        expect_short_read(
            ElementType::Unsigned(ElementDataLength::Bytes8),
            &[0x01, 0x02, 0x03],
        );
        expect_short_read(
            ElementType::Unsigned(ElementDataLength::Bytes8),
            &[1, 2, 3, 4, 5, 6, 7],
        );

        expect_short_read(ElementType::Float, &[]);
        expect_short_read(ElementType::Float, &[1]);
        expect_short_read(ElementType::Float, &[1, 2]);
        expect_short_read(ElementType::Float, &[1, 2, 3]);

        expect_short_read(ElementType::Double, &[]);
        expect_short_read(ElementType::Double, &[1]);
        expect_short_read(ElementType::Double, &[1, 2]);
        expect_short_read(ElementType::Double, &[1, 2, 3]);
        expect_short_read(ElementType::Double, &[1, 2, 3, 4]);
        expect_short_read(ElementType::Double, &[1, 2, 3, 4, 5, 6, 7]);

        expect_short_read(ElementType::Utf8String(ElementDataLength::Bytes1), &[]);
        expect_short_read(ElementType::Utf8String(ElementDataLength::Bytes1), &[1]);
        expect_short_read(ElementType::Utf8String(ElementDataLength::Bytes1), &[2, 1]);
        expect_short_read(ElementType::Utf8String(ElementDataLength::Bytes1), &[3, 1]);
        expect_short_read(
            ElementType::Utf8String(ElementDataLength::Bytes1),
            &[3, 1, 2],
        );
        expect_short_read(ElementType::Utf8String(ElementDataLength::Bytes2), &[]);
        expect_short_read(ElementType::Utf8String(ElementDataLength::Bytes2), &[0]);
        expect_short_read(ElementType::Utf8String(ElementDataLength::Bytes2), &[1, 0]);
        expect_short_read(
            ElementType::Utf8String(ElementDataLength::Bytes2),
            &[0, 1, 1],
        ); // 256 length string

        expect_short_read(ElementType::ByteString(ElementDataLength::Bytes1), &[]);
        expect_short_read(ElementType::ByteString(ElementDataLength::Bytes1), &[1]);
        expect_short_read(ElementType::ByteString(ElementDataLength::Bytes1), &[2, 1]);
        expect_short_read(ElementType::ByteString(ElementDataLength::Bytes1), &[3, 1]);
        expect_short_read(
            ElementType::ByteString(ElementDataLength::Bytes1),
            &[3, 1, 2],
        );
        expect_short_read(ElementType::ByteString(ElementDataLength::Bytes4), &[1]);
        expect_short_read(
            ElementType::ByteString(ElementDataLength::Bytes4),
            &[1, 0, 0],
        );
        expect_short_read(
            ElementType::ByteString(ElementDataLength::Bytes4),
            &[1, 0, 0, 0],
        );
        expect_short_read(
            ElementType::ByteString(ElementDataLength::Bytes4),
            &[2, 0, 0, 0, 0],
        );
    }

    #[test]
    fn parsing_from_u8_buffer() {
        let buffer = [0x00, 0x7c, 0b0000_0101, 0x11, 0x22].as_slice();

        assert_eq!(
            Parser::new(buffer).eq([
                Record {
                    tag_type: TagType::Anonymous,
                    tag_value: 0,
                    value: Value::Signed(0x7c),
                },
                Record {
                    tag_type: TagType::Anonymous,
                    tag_value: 0,
                    value: Value::Unsigned(0x2211)
                }
            ]),
            true
        );
    }
}
