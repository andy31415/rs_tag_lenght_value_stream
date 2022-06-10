
/// Defines a valid data length for various length-prefixed data
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum ElementDataLength {
    /// Length encoded over 1 byte
    Bytes1,

    /// Length encoded over 2 bytes
    Bytes2,

    /// Length encoded over 4 bytes
    Bytes4,

    /// Length encoded over 8 bytes
    Bytes8,
}

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum ContainerType {
    Structure,
    List,
    Array
}

/// Defines all element types supported by the TLV encoding for control blocks
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum ElementType {
    /// Represents a signed integer
    Signed(ElementDataLength),

    /// Represents an unsigned integer
    Unsigned(ElementDataLength),

    /// Represents a boolean value
    Boolean(bool),

    /// Represents a floating point number over 4 bytes
    Float,

    /// Represents a floating point number over 8 bytes
    Double,

    /// Represents a string encoded as utf-8
    Utf8String(ElementDataLength),

    /// Represents a binary data blob
    ByteString(ElementDataLength),

    /// No value/null
    Null,

    /// Beginning of a container, ends with ContainerEnd
    ContainerStart(ContainerType),

    /// Marks the end of a structure/array/list
    ContainerEnd,
}
impl ElementType {
    const CONTROL_BITS: u8 = 0b11111;

    /// Figure out what the lower 5 bits of a control byte have to
    /// be in order for this element type to match
    fn get_control_byte_bits(&self) -> u8 {
        match self {
            ElementType::Signed(len) => match len {
                ElementDataLength::Bytes1 => 0b00000,
                ElementDataLength::Bytes2 => 0b00001,
                ElementDataLength::Bytes4 => 0b00010,
                ElementDataLength::Bytes8 => 0b00011,
            },
            ElementType::Unsigned(len) => match len {
                ElementDataLength::Bytes1 => 0b00100,
                ElementDataLength::Bytes2 => 0b00101,
                ElementDataLength::Bytes4 => 0b00110,
                ElementDataLength::Bytes8 => 0b00111,
            },
            ElementType::Boolean(value) => match value {
                false => 0b01000,
                true => 0b01001,
            },
            ElementType::Float => 0b01010,
            ElementType::Double => 0b01011,
            ElementType::Utf8String(len) => match len {
                ElementDataLength::Bytes1 => 0b01100,
                ElementDataLength::Bytes2 => 0b01101,
                ElementDataLength::Bytes4 => 0b01110,
                ElementDataLength::Bytes8 => 0b01111,
            },
            ElementType::ByteString(len) => match len {
                ElementDataLength::Bytes1 => 0b10000,
                ElementDataLength::Bytes2 => 0b10001,
                ElementDataLength::Bytes4 => 0b10010,
                ElementDataLength::Bytes8 => 0b10011,
            },
            ElementType::Null => 0b10100,
            ElementType::ContainerStart(c) =>{ 
                match c {
                    ContainerType::Structure => 0b10101,
                    ContainerType::Array => 0b10110,
                    ContainerType::List => 0b10111,
                }
            }
            ElementType::ContainerEnd => 0b11000,
        }
    }

    /// Determines if a specific control bit is matched by the current value.
    ///
    /// Looks at the lower bits of the control byte and see if those correspond
    /// to self.
    pub fn matches_control_bit(&self, control: u8) -> bool {
        (control & Self::CONTROL_BITS) == self.get_control_byte_bits()
    }

    /// Returns true if the data for this tag contains a size.
    ///
    /// Specifically utf8 and byte strings are encoded as:
    ///
    /// ```text
    /// +----------------+   +---------------+   +------------------+   +-------------------+
    /// |control (1-byte)|   |tag (0-8 bytes)|   |length (1-4 bytes)|   |data (length bytes)|
    /// +----------------+   +---------------+   +------------------+   +-------------------+
    /// ```
    /// 
    /// Note that container types (structs, lists) are not sized and instead
    /// use an 'end of container' tag to delimit them.
    /// 
    /// ```
    /// # use tag_length_value_stream::raw_types::*;
    ///
    /// assert!(ElementType::Utf8String(ElementDataLength::Bytes2).is_sized_data());
    /// assert!(ElementType::ByteString(ElementDataLength::Bytes4).is_sized_data());
    /// assert!(!ElementType::ContainerStart(ContainerType::Structure).is_sized_data());
    /// assert!(!ElementType::ContainerStart(ContainerType::Array).is_sized_data());
    /// assert!(!ElementType::ContainerStart(ContainerType::List).is_sized_data());
    /// assert!(!ElementType::Null.is_sized_data());
    /// assert!(!ElementType::ContainerEnd.is_sized_data());
    /// ```
    pub fn is_sized_data(&self) -> bool {
        matches!(self, ElementType::Utf8String(_) | ElementType::ByteString(_))
    }

    /// Extracts the element type from a control byte.
    /// Returns an option if the control type is not known.
    ///
    /// ```
    /// # use tag_length_value_stream::raw_types::*;
    ///
    /// assert_eq!(ElementType::for_control(0), Some(ElementType::Signed(ElementDataLength::Bytes1)));
    /// assert_eq!(ElementType::for_control(1), Some(ElementType::Signed(ElementDataLength::Bytes2)));
    /// assert_eq!(ElementType::for_control(2), Some(ElementType::Signed(ElementDataLength::Bytes4)));
    /// assert_eq!(ElementType::for_control(3), Some(ElementType::Signed(ElementDataLength::Bytes8)));
    /// assert_eq!(ElementType::for_control(4), Some(ElementType::Unsigned(ElementDataLength::Bytes1)));
    /// assert_eq!(ElementType::for_control(5), Some(ElementType::Unsigned(ElementDataLength::Bytes2)));
    /// assert_eq!(ElementType::for_control(6), Some(ElementType::Unsigned(ElementDataLength::Bytes4)));
    /// assert_eq!(ElementType::for_control(7), Some(ElementType::Unsigned(ElementDataLength::Bytes8)));
    /// // ...
    /// ```
    pub fn for_control(control: u8) -> Option<ElementType> {
        match control & Self::CONTROL_BITS {
            0b00000 => Some(ElementType::Signed(ElementDataLength::Bytes1)),
            0b00001 => Some(ElementType::Signed(ElementDataLength::Bytes2)),
            0b00010 => Some(ElementType::Signed(ElementDataLength::Bytes4)),
            0b00011 => Some(ElementType::Signed(ElementDataLength::Bytes8)),
            0b00100 => Some(ElementType::Unsigned(ElementDataLength::Bytes1)),
            0b00101 => Some(ElementType::Unsigned(ElementDataLength::Bytes2)),
            0b00110 => Some(ElementType::Unsigned(ElementDataLength::Bytes4)),
            0b00111 => Some(ElementType::Unsigned(ElementDataLength::Bytes8)),
            0b01000 => Some(ElementType::Boolean(false)),
            0b01001 => Some(ElementType::Boolean(true)),
            0b01010 => Some(ElementType::Float),
            0b01011 => Some(ElementType::Double),
            0b01100 => Some(ElementType::Utf8String(ElementDataLength::Bytes1)),
            0b01101 => Some(ElementType::Utf8String(ElementDataLength::Bytes2)),
            0b01110 => Some(ElementType::Utf8String(ElementDataLength::Bytes4)),
            0b01111 => Some(ElementType::Utf8String(ElementDataLength::Bytes8)),
            0b10000 => Some(ElementType::ByteString(ElementDataLength::Bytes1)),
            0b10001 => Some(ElementType::ByteString(ElementDataLength::Bytes2)),
            0b10010 => Some(ElementType::ByteString(ElementDataLength::Bytes4)),
            0b10011 => Some(ElementType::ByteString(ElementDataLength::Bytes8)),
            0b10100 => Some(ElementType::Null),
            0b10101 => Some(ElementType::ContainerStart(ContainerType::Structure)),
            0b10110 => Some(ElementType::ContainerStart(ContainerType::Array)),
            0b10111 => Some(ElementType::ContainerStart(ContainerType::List)),
            0b11000 => Some(ElementType::ContainerEnd),
            _ => None,
        }
    }
}

/// Defines various tag types supported by TLV encoding
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum TagType {
    Anonymous,
    ContextSpecific1byte,
    CommonProfile2byte,
    CommonProfile4byte,
    Implicit2byte,
    Implicit4byte,
    FullyQualified6byte,
    FullyQualified8byte,
}

impl TagType {
    const CONTROL_BITS: u8 = 0b1110_0000;
    const SHIFT: u8 = 5;

    fn get_control_byte_bits(&self) -> u8 {
        match self {
            TagType::Anonymous => 0b000 << 5,
            TagType::ContextSpecific1byte => 0b001 << 5,
            TagType::CommonProfile2byte => 0b010 << 5,
            TagType::CommonProfile4byte => 0b011 << 5,
            TagType::Implicit2byte => 0b100 << 5,
            TagType::Implicit4byte => 0b101 << 5,
            TagType::FullyQualified6byte => 0b110 << 5,
            TagType::FullyQualified8byte => 0b111 << 5,
        }
    }

    /// Determines if a specific control bit is matched by the current value.
    ///
    /// Looks at the upper bits of the control byte to see if those correspond
    /// to self.
    pub fn matches_control_bit(&self, control: u8) -> bool {
        (control & Self::CONTROL_BITS) == self.get_control_byte_bits()
    }

    /// Extracts the element type from a control byte.
    /// Returns an option if the control type is not known.
    ///
    /// ```
    /// use tag_length_value_stream::raw_types::*;
    ///
    /// assert_eq!(TagType::for_control(0), TagType::Anonymous);
    /// assert_eq!(TagType::for_control(0b0001_1111), TagType::Anonymous); // only upper bits matter
    ///
    /// assert_eq!(TagType::for_control(0b0010_0000), TagType::ContextSpecific1byte);
    /// assert_eq!(TagType::for_control(0b0100_0000), TagType::CommonProfile2byte);
    /// assert_eq!(TagType::for_control(0b0110_0000), TagType::CommonProfile4byte);
    /// assert_eq!(TagType::for_control(0b1000_0000), TagType::Implicit2byte);
    /// assert_eq!(TagType::for_control(0b1010_0000), TagType::Implicit4byte);
    /// assert_eq!(TagType::for_control(0b1100_0000), TagType::FullyQualified6byte);
    /// assert_eq!(TagType::for_control(0b1110_0000), TagType::FullyQualified8byte);
    /// ```
    pub fn for_control(control: u8) -> TagType {
        match (control & Self::CONTROL_BITS) >> Self::SHIFT {
            0b000 => TagType::Anonymous,
            0b001 => TagType::ContextSpecific1byte,
            0b010 => TagType::CommonProfile2byte,
            0b011 => TagType::CommonProfile4byte,
            0b100 => TagType::Implicit2byte,
            0b101 => TagType::Implicit4byte,
            0b110 => TagType::FullyQualified6byte,
            0b111 => TagType::FullyQualified8byte,
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_elements_types_convert_cleanly() {
        // TLV converts
        for code in 0u8..=0b11000u8 {
            let t = ElementType::for_control(code);

            assert!(t.is_some(), "Can parse control bit 0b{:b}", code);
            assert!(t.unwrap().matches_control_bit(code), "Matches 0b{:b}", code);

            // Upper bits of control should not matter
            assert!(
                t.unwrap().matches_control_bit(0b1000_0000u8 | code),
                "Lower bits match for 0b{:b}",
                code
            );
            assert!(
                t.unwrap().matches_control_bit(0b1100_0000u8 | code),
                "Lower bits match for 0b{:b}",
                code
            );
            assert!(
                t.unwrap().matches_control_bit(0b1010_0000u8 | code),
                "Lower bits match for 0b{:b}",
                code
            );
            assert!(
                t.unwrap().matches_control_bit(0b1110_0000u8 | code),
                "Lower bits match for 0b{:b}",
                code
            );
        }

        for code in 0b11001u8..=0b11111 {
            let t = ElementType::for_control(code);
            assert!(
                t.is_none(),
                "Code 0b{:b} should be reserved, not {:?}",
                code,
                t
            );
        }
    }

    #[test]
    fn all_tag_types_convert_cleanly() {
        // TLV converts
        for tag in 0u8..=0b111 {
            let code = tag << 5;
            let t = TagType::for_control(code);
            assert!(
                t.matches_control_bit(tag << 5),
                "Matches 0b{:b}: {:?}",
                code,
                t
            );

            for lo_bits in 1..=0b11111 {
                let code = (tag << 5) | lo_bits;
                let t = TagType::for_control(code);
                assert!(
                    t.matches_control_bit(tag << 5),
                    "Matches 0b{:b}: {:?}",
                    code,
                    t
                );
            }
        }
    }
}
