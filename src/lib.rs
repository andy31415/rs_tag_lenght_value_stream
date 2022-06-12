#![no_std]

pub mod raw_types;

use core::ops::Deref;

pub use raw_types::ContainerType;

use byteorder::{ByteOrder, LittleEndian};
use raw_types::{ElementDataLength, ElementType, TagType};

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

impl<'a> Value<'a> {
    fn u64_repr_length(len: u64) -> ElementDataLength {
        if (len as u8) as u64 == len {
            return ElementDataLength::Bytes1;
        }

        if (len as u16) as u64 == len {
            return ElementDataLength::Bytes2;
        }

        if (len as u32) as u64 == len {
            return ElementDataLength::Bytes4;
        }

        return ElementDataLength::Bytes8;
    }

    fn i64_repr_length(len: i64) -> ElementDataLength {
        if (len as i8) as i64 == len {
            return ElementDataLength::Bytes1;
        }

        if (len as i16) as i64 == len {
            return ElementDataLength::Bytes2;
        }

        if (len as i32) as i64 == len {
            return ElementDataLength::Bytes4;
        }

        return ElementDataLength::Bytes8;
    }

    pub fn get_control_byte_bits(&self) -> u8 {
        match self {
            Value::Signed(n) => {
                ElementType::Signed(Value::i64_repr_length(*n)).get_control_byte_bits()
            }
            Value::Unsigned(n) => {
                ElementType::Unsigned(Value::u64_repr_length(*n)).get_control_byte_bits()
            }
            Value::Bool(v) => ElementType::Boolean(*v).get_control_byte_bits(),
            Value::Float(_) => ElementType::Float.get_control_byte_bits(),
            Value::Double(_) => ElementType::Double.get_control_byte_bits(),
            Value::Utf8(buff) => ElementType::Utf8String(Value::u64_repr_length(buff.len() as u64))
                .get_control_byte_bits(),
            Value::Bytes(buff) => {
                ElementType::ByteString(Value::u64_repr_length(buff.len() as u64))
                    .get_control_byte_bits()
            }
            Value::Null => ElementType::Null.get_control_byte_bits(),
            Value::ContainerStart(t) => ElementType::ContainerStart(*t).get_control_byte_bits(),
            Value::ContainerEnd => ElementType::ContainerEnd.get_control_byte_bits(),
        }
    }
}

/// Represents a split out tag value.
///
/// For a full representation, tags are split out as 3 items: vendor id, profile id and actual tag.
///
/// There is a separate breakdown for implicit, context specific and anonymous cases.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TagValue {
    Anonymous,
    ContextSpecific {
        tag: u32,
    },
    Implicit {
        tag: u32,
    },
    Full {
        vendor_id: u16,
        profile_id: u16,
        tag: u32,
    },
}

impl TagValue {
    /// Gets the corresponding control bits to represent this tag value
    ///
    /// ```
    /// # use tag_length_value_stream::TagValue;
    /// # use tag_length_value_stream::raw_types::TagType;
    ///
    /// assert_eq!(TagValue::Anonymous.tag_type(), TagType::Anonymous);
    /// assert_eq!(TagValue::ContextSpecific{tag: 123}.tag_type(), TagType::ContextSpecific1byte);
    /// assert_eq!(TagValue::Implicit{tag: 123}.tag_type(), TagType::Implicit2byte);
    /// assert_eq!(TagValue::Implicit{tag: 0xFFFF}.tag_type(), TagType::Implicit2byte);
    /// assert_eq!(TagValue::Implicit{tag: 0x10000}.tag_type(), TagType::Implicit4byte);
    /// assert_eq!(TagValue::Implicit{tag: 0x123456}.tag_type(), TagType::Implicit4byte);
    /// assert_eq!(TagValue::Full{vendor_id: 0, profile_id: 0, tag: 1}.tag_type(), TagType::CommonProfile2byte);
    /// assert_eq!(TagValue::Full{vendor_id: 0, profile_id: 0, tag: 0xFFFF}.tag_type(), TagType::CommonProfile2byte);
    /// assert_eq!(TagValue::Full{vendor_id: 0, profile_id: 0, tag: 0x10000}.tag_type(), TagType::CommonProfile4byte);
    /// assert_eq!(TagValue::Full{vendor_id: 0, profile_id: 1, tag: 1}.tag_type(), TagType::FullyQualified6byte);
    /// assert_eq!(TagValue::Full{vendor_id: 0, profile_id: 10, tag: 0x12345678}.tag_type(), TagType::FullyQualified6byte);
    /// assert_eq!(TagValue::Full{vendor_id: 1, profile_id: 0, tag: 0}.tag_type(), TagType::FullyQualified8byte);
    /// assert_eq!(TagValue::Full{vendor_id: 1, profile_id: 2, tag: 3}.tag_type(), TagType::FullyQualified8byte);
    /// ```
    pub fn tag_type(&self) -> TagType {
        match self {
            TagValue::Anonymous => TagType::Anonymous,
            TagValue::ContextSpecific { tag } => {
                assert!(*tag & 0xFF == *tag);
                TagType::ContextSpecific1byte
            }
            TagValue::Implicit { tag } => {
                if *tag & 0xFFFF == *tag {
                    TagType::Implicit2byte
                } else {
                    TagType::Implicit4byte
                }
            }
            TagValue::Full {
                vendor_id,
                profile_id,
                tag,
            } => match (vendor_id, profile_id, tag) {
                (0, 0, t) if ((*t & 0xFFFF) == *t) => TagType::CommonProfile2byte,
                (0, 0, _) => TagType::CommonProfile4byte,
                (0, _, _) => TagType::FullyQualified6byte,
                _ => TagType::FullyQualified8byte,
            },
        }
    }

    pub fn extract_tag_into<'a>(&self, dest: &'a mut [u8]) -> &'a [u8] {
        match self {
            TagValue::Anonymous => dest.split_at(0).0,
            TagValue::ContextSpecific { tag } | TagValue::Implicit { tag } => {
                if *tag & 0xFFFF == *tag {
                    LittleEndian::write_u16(dest, *tag as u16);
                    dest.split_at(2).0
                } else {
                    LittleEndian::write_u32(dest, *tag);
                    dest.split_at(2).0
                }
            }
            TagValue::Full {
                vendor_id: 0,
                profile_id: 0,
                tag,
            } if ((*tag & 0xFFFF) == *tag) => {
                LittleEndian::write_u16(dest, *tag as u16);
                dest.split_at(2).0
            }
            TagValue::Full {
                vendor_id: 0,
                profile_id: 0,
                tag,
            } => {
                LittleEndian::write_u32(dest, *tag);
                dest.split_at(4).0
            }
            TagValue::Full {
                vendor_id: 0,
                profile_id,
                tag,
            } => {
                {
                    LittleEndian::write_u16(dest, *profile_id);
                    let (_, rest) = dest.split_at_mut(2);
                    LittleEndian::write_u32(rest, *tag);
                }
                dest.split_at(6).0
            }
            TagValue::Full {
                vendor_id,
                profile_id,
                tag,
            } => {
                {
                    LittleEndian::write_u16(dest, *vendor_id);
                    let (_, rest) = dest.split_at_mut(2);
                    LittleEndian::write_u16(rest, *profile_id);
                    let (_, rest) = rest.split_at_mut(2);
                    LittleEndian::write_u32(rest, *tag);
                }
                dest.split_at(8).0
            }
        }
    }
}

/// Represents a data record read from a TLV stream
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Record<'a> {
    pub tag: TagValue,
    pub value: Value<'a>,
}

impl<'a> Record<'a> {
    pub fn control_byte(&self) -> u8 {
        self.tag.tag_type().get_control_byte_bits() | self.value.get_control_byte_bits()
    }
}

/// Represents an incremental parsing result containing
/// some data and the remaining parse buffer
#[derive(Debug, PartialEq)]
pub(crate) struct IncrementalParseResult<'a, T> {
    pub(crate) parsed: T,
    pub(crate) remaining_input: &'a [u8],
}

/// Provides the ability to parse TLV data into underlying types.
///
/// # Examples
///
/// Parsing a valid stream:
///
/// ```
/// use tag_length_value_stream::{Record, Parser, TagValue, Value, ContainerType};
///
/// let mut parser = Parser::new(&[
///     0xD5, 0xBB, 0xAA, 0xDD, 0xCC, 0x01, 0x00,  // tag: 0xAABB/0xCCDD/1, structure start
///     0x34, 0x01,                                // tag: context 1, null
///     0x34, 0x10,                                // tag: context 16, null
///     0x28, 0x02,                                // tag: context 2, false
///     0x29, 0x03,                                // tag: context 3, true
///     0x85, 0x22, 0x11, 0x34, 0x12,              // tag: implicit tag 0x1122, unsigned 0x1234
///     0x82, 0xcd, 0xab, 0xFE, 0xFF, 0xFF, 0xFF,  // tag: implicit tag 0xabcd, signed -2
///     0x18                                       // anonymous tag, container end
/// ]);
///
/// assert_eq!(parser.next(), Some(
///         Record {
///             tag: TagValue::Full { vendor_id: 0xAABB, profile_id: 0xCCDD, tag: 1 },
///             value: Value::ContainerStart(ContainerType::Structure)
///         },
/// ));
/// assert!(!parser.done());
///
/// assert_eq!(parser.next(), Some(Record { tag: TagValue::ContextSpecific{tag: 1}, value: Value::Null}));
/// assert_eq!(parser.next(), Some(Record { tag: TagValue::ContextSpecific{tag: 16}, value: Value::Null}));
/// assert_eq!(parser.next(), Some(Record { tag: TagValue::ContextSpecific{tag: 2}, value: Value::Bool(false)}));
/// assert_eq!(parser.next(), Some(Record { tag: TagValue::ContextSpecific{tag: 3}, value: Value::Bool(true)}));
/// assert_eq!(parser.next(), Some(Record { tag: TagValue::Implicit{tag: 0x1122}, value: Value::Unsigned(0x1234)}));
/// assert_eq!(parser.next(), Some(Record { tag: TagValue::Implicit{tag: 0xabcd}, value: Value::Signed(-2)}));
///
///
/// assert_eq!(parser.next(), Some(Record { tag: TagValue::Anonymous, value: Value::ContainerEnd}));
/// assert!(parser.done());
///
/// assert_eq!(parser.next(), None);
/// assert!(parser.done());
/// ```
///
/// Parsing an invalid stream (tag terminated early)
///
/// ```
/// use tag_length_value_stream::{Record, Parser, TagValue, Value, ContainerType};
///
/// let mut parser = Parser::new(&[
///     0xD5, 0xBB, 0xAA, 0xDD, 0xCC, 0x01, 0x00,  // tag: 0xAABB/0xCCDD/1, structure start
///     0x82, 0xcd,                                // tag: implicit tag 0x??cd<truncated> (no tag, no signed data)
/// ]);
///
/// assert_eq!(parser.next(), Some(
///         Record {
///             tag: TagValue::Full { vendor_id: 0xAABB, profile_id: 0xCCDD, tag: 1 },
///             value: Value::ContainerStart(ContainerType::Structure)
///         },
/// ));
/// assert!(!parser.done());
///
/// assert_eq!(parser.next(), None);
/// assert!(!parser.done());  // Parser NOT done as input data still available, but cannot be parsed
/// ```
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

    /// Attempts to parse the tag information for the given value array
    pub(crate) fn read_tag_value(
        tag_type: TagType,
        data: &[u8],
    ) -> Option<IncrementalParseResult<TagValue>> {
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

        let (tag_buffer, remaining_input) = data.split_at(tag_length);

        // we know we have sufficient size to parse, do the parsing
        let parsed = match tag_type {
            TagType::Anonymous => TagValue::Anonymous,
            TagType::ContextSpecific1byte => TagValue::ContextSpecific {
                tag: tag_buffer[0] as u32,
            },
            TagType::Implicit2byte | TagType::Implicit4byte => TagValue::Implicit {
                tag: LittleEndian::read_uint(tag_buffer, tag_length) as u32,
            },
            TagType::CommonProfile2byte | TagType::CommonProfile4byte => TagValue::Full {
                vendor_id: 0,
                profile_id: 0,
                tag: LittleEndian::read_uint(tag_buffer, tag_length) as u32,
            },
            TagType::FullyQualified6byte => TagValue::Full {
                vendor_id: LittleEndian::read_u16(tag_buffer),
                profile_id: LittleEndian::read_u16(&tag_buffer[2..4]),
                tag: LittleEndian::read_u16(&tag_buffer[4..6]) as u32,
            },
            TagType::FullyQualified8byte => TagValue::Full {
                vendor_id: LittleEndian::read_u16(tag_buffer),
                profile_id: LittleEndian::read_u16(&tag_buffer[2..4]),
                tag: LittleEndian::read_u32(&tag_buffer[4..8]),
            },
        };

        Some(IncrementalParseResult {
            parsed,
            remaining_input,
        })
    }

    /// Attempts to read a value from a byte array
    pub(crate) fn read_value(
        element_type: ElementType,
        data: &'a [u8],
    ) -> Option<IncrementalParseResult<'a, Value<'a>>> {
        match element_type {
            ElementType::Unsigned(n) | ElementType::Signed(n) => {
                let value_len = match n {
                    raw_types::ElementDataLength::Bytes1 if !data.is_empty() => 1,
                    raw_types::ElementDataLength::Bytes2 if data.len() >= 2 => 2,
                    raw_types::ElementDataLength::Bytes4 if data.len() >= 4 => 4,
                    raw_types::ElementDataLength::Bytes8 if data.len() >= 8 => 8,
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

/// Iterating over a Parser means getting the underlying TLV data entries
/// from the stream.
///
/// Iteration will return None if the stream is exhaused OR if the stream
/// encountered a parsing error.
///
/// If None is returned due to a parsing error, then `done` will return false
/// even though `next()` returned None.
impl<'a> Iterator for Parser<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.data.split_first() {
            None => None,
            Some((control, rest)) => {
                let tag_parse = Parser::read_tag_value(TagType::for_control(*control), rest)?;
                let value_parse = Parser::read_value(
                    ElementType::for_control(*control)?,
                    tag_parse.remaining_input,
                )?;

                // all parsing succeeded, advance input and return the parsing result
                self.data = value_parse.remaining_input;
                Some(Self::Item {
                    tag: tag_parse.parsed,
                    value: value_parse.parsed,
                })
            }
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
enum TlvBytesState {
    SendControl,
    SendTag,
    SendLength,
    SendData,

    Done,
}

/// Represents a transformation of an iterator of TLV Records
/// into the corresponding sequence of bytes.
pub struct TlvBytes<'a, Data> {
    data: Data,
    current_record: Option<Record<'a>>,
    state: TlvBytesState,

    // At most 8 byptes are needed for longest things:
    //   - 8 byte tags are the longest
    //   - 8 byte integer values are the longest
    data_buffer: [u8; 8],
}

impl<'a, Data> TlvBytes<'a, Data>
where
    Data: Iterator<Item = Record<'a>>,
{
    pub fn new(data: Data) -> Self {
        Self {
            data,
            current_record: None,
            state: TlvBytesState::SendControl,
            data_buffer: [0; 8],
        }
    }
}

impl<'a, Data> TlvBytes<'a, Data>
where
    Data: Iterator<Item = Record<'a>>,
{
    pub fn next(&'a mut self) -> Option<&'a [u8]> {
        match self.state {
            TlvBytesState::SendControl => {
                self.current_record = self.data.next();
                match self.current_record {
                    None => {
                        self.state = TlvBytesState::Done;
                        None
                    }
                    Some(record) => {
                        self.data_buffer[0] = record.control_byte();
                        self.state = TlvBytesState::SendTag;
                        Some(self.data_buffer.split_at(1).0)
                    }
                }
            }
            TlvBytesState::SendTag => {
                let record = self.current_record.unwrap();

                // decide which part to fix
                self.state = match record.value {
                    Value::Utf8(_) | Value::Bytes(_) => TlvBytesState::SendLength,
                    Value::Signed(_) | Value::Unsigned(_) | Value::Float(_) | Value::Double(_) => {
                        TlvBytesState::SendData
                    }
                    _ => TlvBytesState::SendControl,
                };

                Some(record.tag.extract_tag_into(self.data_buffer.as_mut_slice()))
            }
            TlvBytesState::SendLength => {
                // after sending length, data follows (if any)
                self.state = TlvBytesState::SendData;

                match self.current_record.unwrap().value {
                    Value::Utf8(bytes) | Value::Bytes(bytes) => {
                        let n = bytes.len() as u64;
                        match Value::u64_repr_length(n) {
                            ElementDataLength::Bytes1 => {
                                self.data_buffer[0] = n as u8;
                                if n == 0 {
                                    // No data available, can send the next item
                                    self.state = TlvBytesState::SendControl;
                                }
                                Some(self.data_buffer.split_at(1).0)
                            }
                            ElementDataLength::Bytes2 => {
                                LittleEndian::write_u16(self.data_buffer.as_mut_slice(), n as u16);
                                Some(self.data_buffer.split_at(2).0)
                            }
                            ElementDataLength::Bytes4 => {
                                LittleEndian::write_u32(self.data_buffer.as_mut_slice(), n as u32);
                                Some(self.data_buffer.split_at(4).0)
                            }
                            ElementDataLength::Bytes8 => {
                                LittleEndian::write_u64(self.data_buffer.as_mut_slice(), n);
                                Some(self.data_buffer.split_at(8).0)
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
            TlvBytesState::SendData => {
                // after sending data, move to the next record
                self.state = TlvBytesState::SendControl;

                match self.current_record.unwrap().value {
                    Value::Utf8(bytes) | Value::Bytes(bytes) => Some(bytes),
                    Value::Signed(n) => match Value::i64_repr_length(n) {
                        ElementDataLength::Bytes1 => {
                            self.data_buffer[0] = (n as i8) as u8;
                            Some(self.data_buffer.split_at(1).0)
                        }
                        ElementDataLength::Bytes2 => {
                            LittleEndian::write_i16(self.data_buffer.as_mut_slice(), n as i16);
                            Some(self.data_buffer.split_at(2).0)
                        }
                        ElementDataLength::Bytes4 => {
                            LittleEndian::write_i32(self.data_buffer.as_mut_slice(), n as i32);
                            Some(self.data_buffer.split_at(4).0)
                        }
                        ElementDataLength::Bytes8 => {
                            LittleEndian::write_i64(self.data_buffer.as_mut_slice(), n);
                            Some(self.data_buffer.split_at(8).0)
                        }
                    },
                    Value::Unsigned(n) => match Value::u64_repr_length(n) {
                        ElementDataLength::Bytes1 => {
                            self.data_buffer[0] = n as u8;
                            Some(self.data_buffer.split_at(1).0)
                        }
                        ElementDataLength::Bytes2 => {
                            LittleEndian::write_u16(self.data_buffer.as_mut_slice(), n as u16);
                            Some(self.data_buffer.split_at(2).0)
                        }
                        ElementDataLength::Bytes4 => {
                            LittleEndian::write_u32(self.data_buffer.as_mut_slice(), n as u32);
                            Some(self.data_buffer.split_at(4).0)
                        }
                        ElementDataLength::Bytes8 => {
                            LittleEndian::write_u64(self.data_buffer.as_mut_slice(), n);
                            Some(self.data_buffer.split_at(8).0)
                        }
                    },
                    Value::Float(n) => {
                        LittleEndian::write_f32(self.data_buffer.as_mut_slice(), n);
                        Some(self.data_buffer.split_at(4).0)
                    }
                    Value::Double(n) => {
                        LittleEndian::write_f64(self.data_buffer.as_mut_slice(), n);
                        Some(self.data_buffer.split_at(4).0)
                    }
                    _ => unreachable!(),
                }
            }
            TlvBytesState::Done => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::raw_types::ElementDataLength;

    use super::*;

    #[test]
    fn read_tag_value_works() {
        let empty = [].as_slice();
        assert_eq!(
            Parser::read_tag_value(TagType::Anonymous, empty),
            Some(IncrementalParseResult {
                parsed: TagValue::Anonymous,
                remaining_input: empty
            })
        );

        let some_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].as_slice();
        assert_eq!(
            Parser::read_tag_value(TagType::Anonymous, some_bytes),
            Some(IncrementalParseResult {
                parsed: TagValue::Anonymous,
                remaining_input: some_bytes
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::ContextSpecific1byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: TagValue::ContextSpecific { tag: 1 },
                remaining_input: [2, 3, 4, 5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile2byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: TagValue::Full {
                    vendor_id: 0,
                    profile_id: 0,
                    tag: 0x0201
                },
                remaining_input: [3, 4, 5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::Implicit2byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: TagValue::Implicit { tag: 0x0201 },
                remaining_input: [3, 4, 5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::Implicit4byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: TagValue::Implicit { tag: 0x04030201 },
                remaining_input: [5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile4byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: TagValue::Full {
                    vendor_id: 0,
                    profile_id: 0,
                    tag: 0x04030201
                },
                remaining_input: [5, 6, 7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified6byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: TagValue::Full {
                    vendor_id: 0x0201,
                    profile_id: 0x0403,
                    tag: 0x0605
                },
                remaining_input: [7, 8, 9, 10].as_slice()
            })
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified8byte, some_bytes),
            Some(IncrementalParseResult {
                parsed: TagValue::Full {
                    vendor_id: 0x0201,
                    profile_id: 0x0403,
                    tag: 0x08070605
                },
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

        let mut parser = Parser::new(buffer);
        let expected = [
            Record {
                tag: TagValue::Anonymous,
                value: Value::Signed(0x7c),
            },
            Record {
                tag: TagValue::Anonymous,
                value: Value::Unsigned(0x2211),
            },
        ];

        for value in expected {
            assert_eq!(parser.next(), Some(value));
        }
        assert!(parser.done());
    }

    fn anonymous(value: Value) -> Record {
        Record {
            tag: TagValue::Anonymous,
            value,
        }
    }

    #[test]
    fn complex_structue_parsing() {
        let buffer = [
            0xD5, 0xBB, 0xAA, 0xDD, 0xCC, 0x01, 0x00, 0xC9, 0xBB, 0xAA, 0xDD, 0xCC, 0x02, 0x00,
            0x88, 0x02, 0x00, 0x36, 0x00, 0x00, 0x2A, 0x00, 0xEF, 0x02, 0xF0, 0x67, 0xFD, 0xFF,
            0x07, 0x00, 0x90, 0x2F, 0x50, 0x09, 0x00, 0x00, 0x00, 0x15, 0x18, 0x17, 0xD4, 0xBB,
            0xAA, 0xDD, 0xCC, 0x11, 0x00, 0xB4, 0xA0, 0xBB, 0x0D, 0x00, 0x14, 0xB5, 0x00, 0x28,
            0x6B, 0xEE, 0x6D, 0x70, 0x11, 0x01, 0x00, 0x0E, 0x01, 0x53, 0x54, 0x41, 0x52, 0x54,
            0x2E, 0x2E, 0x2E, 0x21, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41,
            0x42, 0x43, 0x44, 0x45, 0x46, 0x40, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x23, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x24, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x25, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x5E,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x26, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x2A, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41,
            0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x28,
            0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            0x37, 0x29, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x2D, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37, 0x3D, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x5B, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x5D, 0x39, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x3B, 0x39, 0x41,
            0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x27,
            0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x2E, 0x2E, 0x2E, 0x45, 0x4E, 0x44, 0x18,
            0x18, 0x18, 0xCC, 0xBB, 0xAA, 0xDD, 0xCC, 0x05, 0x00, 0x0E, 0x54, 0x68, 0x69, 0x73,
            0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x8A, 0xFF, 0xFF, 0x00,
            0x00, 0x88, 0x41, 0xAB, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x31, 0x40, 0x18,
        ]
        .as_slice();

        let mut parser = Parser::new(buffer);
        let expected = [
            Record {
                tag: TagValue::Full { vendor_id: 0xAABB, profile_id: 0xCCDD, tag: 1 },
                value: Value::ContainerStart(ContainerType::Structure)
            },
            Record {
                tag: TagValue::Full { vendor_id: 0xAABB, profile_id: 0xCCDD, tag: 2 },
                value: Value::Bool(true)
            },
            Record {
                tag: TagValue::Implicit { tag: 2 },
                value: Value::Bool(false)
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 0 },
                value: Value::ContainerStart(ContainerType::Array)
            },
            anonymous(Value::Signed(42)),
            anonymous(Value::Signed(-17)),
            anonymous(Value::Signed(-170000)),
            anonymous(Value::Unsigned(40000000000)),
            anonymous(Value::ContainerStart(ContainerType::Structure)),
            anonymous(Value::ContainerEnd),
            anonymous(Value::ContainerStart(ContainerType::List)),
            Record {
                tag: TagValue::Full { vendor_id: 0xAABB, profile_id: 0xCCDD, tag: 17 },
                value: Value::Null,
            },
            Record {
                tag: TagValue::Implicit { tag: 900000 },
                value: Value::Null,
            },
            anonymous(Value::Null),
            Record {
                tag: TagValue::Implicit { tag: 4000000000 },
                value: Value::ContainerStart(ContainerType::Structure)
            },
            Record {
                tag: TagValue::Full { vendor_id: 0, profile_id: 0, tag: 70000},
                value: Value::Utf8(
                    "START...!123456789ABCDEF@123456789ABCDEF#123456789ABCDEF$123456789ABCDEF%123456789ABCDEF^123456789ABCDEF&123456789ABCDEF*123456789ABCDEF01234567(9ABCDEF01234567)9ABCDEF01234567-9ABCDEF01234567=9ABCDEF01234567[9ABCDEF01234567]9ABCDEF01234567;9ABCDEF01234567'9ABCDEF...END".as_bytes())
            },
            anonymous(Value::ContainerEnd),
            anonymous(Value::ContainerEnd),
            anonymous(Value::ContainerEnd),
            Record {
                tag: TagValue::Full { vendor_id: 0xAABB, profile_id: 0xCCDD, tag: 5 },
                value: Value::Utf8("This is a test".as_bytes())
            },
            Record {
                tag: TagValue::Implicit { tag: 65535 },
                value: Value::Float(17.0)
            },
            Record {
                tag: TagValue::Implicit { tag: 65536 },
                value: Value::Double(17.0)
            },
            anonymous(Value::ContainerEnd),
        ];

        for value in expected {
            assert_eq!(parser.next(), Some(value));
        }
        assert!(parser.done());
    }
}
