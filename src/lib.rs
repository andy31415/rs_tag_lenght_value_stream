/// Defines a valid data length for various length-prefixed data
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum ElementDataLength {
    Bytes1,
    Bytes2,
    Bytes4,
    Bytes8,
}

/// Defines all element types supported by the TLV encoding for control blocks
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum ElementType {
    Signed(ElementDataLength),
    Unsigned(ElementDataLength),
    Boolean(bool),
    Float, // 4-byte float
    Double, // 8-byte float
    Utf8String(ElementDataLength),
    ByteString(ElementDataLength),
    Null,
    Structure,
    Array,
    List,
    EndOfContainer,
}

/// Defines various tag types supported by TLV encoding
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum TagType {
    Anonymous,
    ContextSpecific1byte,
    ContextSpecific2byte,
    ContextSpecific4byte,
    Implicit2byte,
    Implicit4byte,
    FullyQualified6byte,
    FullyQualified8byte,
}

impl ElementType {
    
    const CONTROL_BITS: u8 = 0b11111;

    /// Figure out what the lower 5 bits of a control byte have to
    /// be in order for this element type to match
    fn get_control_byte_bits(&self) -> u8 {
        match self {
            ElementType::Signed(len) => {
                match len {
                    ElementDataLength::Bytes1 => 0b00000,
                    ElementDataLength::Bytes2 => 0b00001,
                    ElementDataLength::Bytes4 => 0b00010,
                    ElementDataLength::Bytes8 => 0b00011,
                }
            }
            ElementType::Unsigned(len) => {
                match len {
                    ElementDataLength::Bytes1 => 0b00100,
                    ElementDataLength::Bytes2 => 0b00101,
                    ElementDataLength::Bytes4 => 0b00110,
                    ElementDataLength::Bytes8 => 0b00111,
                }
            }
            ElementType::Boolean(value) => {
                match value {
                    false => 0b01000,
                    true  => 0b01001,
                }
            }
            ElementType::Float => 0b01010,
            ElementType::Double => 0b01011,
            ElementType::Utf8String(len) => {
                match len {
                    ElementDataLength::Bytes1 => 0b01100,
                    ElementDataLength::Bytes2 => 0b01101,
                    ElementDataLength::Bytes4 => 0b01110,
                    ElementDataLength::Bytes8 => 0b01111,
                }
            }
            ElementType::ByteString(len) => {
                match len {
                    ElementDataLength::Bytes1 => 0b10000,
                    ElementDataLength::Bytes2 => 0b10001,
                    ElementDataLength::Bytes4 => 0b10010,
                    ElementDataLength::Bytes8 => 0b10011,
                }
            }
            ElementType::Null => 0b10100,
            ElementType::Structure => 0b10101,
            ElementType::Array => 0b10110,
            ElementType::List => 0b10111,
            ElementType::EndOfContainer => 0b11000,
        }
    }
    
    pub fn matches_control_bit(&self, control: u8) -> bool {
        (control & ElementType::CONTROL_BITS) == self.get_control_byte_bits()
    }

    /// Extracts the element type from a control byte.
    /// Returns an option if the control type is not known.
    /// 
    /// ```
    /// # use tlv_stream::*;
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
        match control & ElementType::CONTROL_BITS {
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
            0b10101 => Some(ElementType::Structure),
            0b10110 => Some(ElementType::Array),
            0b10111 => Some(ElementType::List),
            0b11000 => Some(ElementType::EndOfContainer),
            _ => None
        }
    }

}



#[cfg(test)]
mod tests {
    use crate::ElementType;

    #[test]
    fn all_elements_convert_cleanly() {
        // TLV converts
        for code in 0u8..=0b11000u8 {
            let t = ElementType::for_control(code);
            
            assert!(t.is_some(), "Can parse control bit 0b{:b}", code);
            assert!(t.unwrap().matches_control_bit(code), "Matches 0b{:b}", code);

            // Upper bits of control should not matter
            assert!(t.unwrap().matches_control_bit(0b1000_0000u8 | code), "Lower bits match for 0b{:b}", code);
            assert!(t.unwrap().matches_control_bit(0b1100_0000u8 | code), "Lower bits match for 0b{:b}", code);
            assert!(t.unwrap().matches_control_bit(0b1010_0000u8 | code), "Lower bits match for 0b{:b}", code);
            assert!(t.unwrap().matches_control_bit(0b1110_0000u8 | code), "Lower bits match for 0b{:b}", code);
            
        }
        
        for code in 0b11001u8..=0b11111 {
            let t = ElementType::for_control(code);
            assert!(t.is_none(), "Code 0b{:b} should be reserved, not {:?}", code, t);
        }
    }
}
