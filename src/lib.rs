#![no_std]

pub mod types;

use byteorder::{ByteOrder, LittleEndian};
use types::{ContainerType, TagType};

/// Represents an actual value read from a TLV record
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
pub struct Record<'a> {
    pub tag_type: TagType,
    pub tag_value: u64, // fully expanded 8-byte value

    pub value: Value<'a>,
}

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
    pub(crate) fn read_tag_value(tag_type: TagType, data: &[u8]) -> (Option<u64>, &[u8]) {
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
            return (None, data);
        }

        let (buf, rest) = data.split_at(tag_length);

        (
            Some(match tag_length {
                0 => 0u64,
                nbytes => LittleEndian::read_uint(buf, nbytes),
            }),
            rest,
        )
    }
}

impl<'a> Iterator for Parser<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.data.split_first() {
            None => None,
            Some((control, rest)) => {
                let tag_type = TagType::for_control(*control);
                let (tag_value, rest) = Parser::read_tag_value(tag_type, rest);

                if tag_value.is_none() {
                    return None;
                }
                let tag_value = tag_value.unwrap();

                // FIXME: read actual value

                // FIXME:
                //   read value (if applicable: integers or byte strings or something)

                // FIXME

                self.data = rest;

                Some(Self::Item {
                    tag_type,
                    tag_value,
                    value: Value::Null, // FIXME: implement
                })
            }
        }
    }
}

///
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_tag_value_works() {
        let empty = [].as_slice();
        assert_eq!(
            Parser::read_tag_value(TagType::Anonymous, empty),
            (Some(0), empty)
        );

        let some_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].as_slice();
        assert_eq!(
            Parser::read_tag_value(TagType::Anonymous, some_bytes),
            (Some(0), some_bytes)
        );

        assert_eq!(
            Parser::read_tag_value(TagType::ContextSpecific1byte, some_bytes),
            (Some(0x01), [2, 3, 4, 5, 6, 7, 8, 9, 10].as_slice())
        );

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile2byte, some_bytes),
            (Some(0x0201), [3, 4, 5, 6, 7, 8, 9, 10].as_slice())
        );

        assert_eq!(
            Parser::read_tag_value(TagType::Implicit2byte, some_bytes),
            (Some(0x0201), [3, 4, 5, 6, 7, 8, 9, 10].as_slice())
        );

        assert_eq!(
            Parser::read_tag_value(TagType::Implicit4byte, some_bytes),
            (Some(0x04030201), [5, 6, 7, 8, 9, 10].as_slice())
        );

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile4byte, some_bytes),
            (Some(0x04030201), [5, 6, 7, 8, 9, 10].as_slice())
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified6byte, some_bytes),
            (Some(0x060504030201), [7, 8, 9, 10].as_slice())
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified8byte, some_bytes),
            (Some(0x0807060504030201), [9, 10].as_slice())
        );
    }

    #[test]
    fn read_tag_value_fails_on_short() {
        let empty = [].as_slice();
        assert_eq!(
            Parser::read_tag_value(TagType::Implicit2byte, empty),
            (None, empty)
        );

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile2byte, empty),
            (None, empty)
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified6byte, empty),
            (None, empty)
        );

        let one_byte = [1].as_slice();

        assert_eq!(
            Parser::read_tag_value(TagType::CommonProfile2byte, one_byte),
            (None, one_byte)
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified6byte, one_byte),
            (None, one_byte)
        );
        
        let four_bytes = [1,2,3,4].as_slice();

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified6byte, four_bytes),
            (None, four_bytes)
        );

        assert_eq!(
            Parser::read_tag_value(TagType::FullyQualified8byte, four_bytes),
            (None, four_bytes)
        );
    }
}
