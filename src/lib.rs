/// Defines a valid data length for various length-prefixed data
#[derive(Debug, PartialEq, PartialOrd)]
pub enum ElementDataLength {
    Bytes1,
    Bytes2,
    Bytes4,
    Bytes8,
}

/// Defines all element types supported by the TLV encoding for control blocks
#[derive(Debug, PartialEq, PartialOrd)]
pub enum ElementType {
    SignedInteger(ElementDataLength),
    UnsignedInteger(ElementDataLength),
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
#[derive(Debug, PartialEq, PartialOrd)]
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
            ElementType::SignedInteger(len) => {
                match len {
                    ElementDataLength::Bytes1 => 0b00000,
                    ElementDataLength::Bytes2 => 0b00001,
                    ElementDataLength::Bytes4 => 0b00010,
                    ElementDataLength::Bytes8 => 0b00011,
                }
            }
            ElementType::UnsignedInteger(len) => {
                match len {
                    ElementDataLength::Bytes1 => 0b00100,
                    ElementDataLength::Bytes2 => 0b00101,
                    ElementDataLength::Bytes4 => 0b00110,
                    ElementDataLength::Bytes8 => 0b00111,
                }
            }
            ElementType::Boolean(value) => {
                match value {
                    false => 0b01001,
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
    /// assert_eq!(ElementType::for_control(0x00), Some(ElementType::SignedInteger(ElementDataLength::Bytes1)));
    /// assert_eq!(ElementType::for_control(0x01), Some(ElementType::SignedInteger(ElementDataLength::Bytes2)));
    /// assert_eq!(ElementType::for_control(0x02), Some(ElementType::SignedInteger(ElementDataLength::Bytes4)));
    /// assert_eq!(ElementType::for_control(0x03), Some(ElementType::SignedInteger(ElementDataLength::Bytes8)));
    /// ```
    pub fn for_control(control: u8) -> Option<ElementType> {
        match control & ElementType::CONTROL_BITS {
            0b00000 => Some(ElementType::SignedInteger(ElementDataLength::Bytes1)),
            0b00001 => Some(ElementType::SignedInteger(ElementDataLength::Bytes2)),
            0b00010 => Some(ElementType::SignedInteger(ElementDataLength::Bytes4)),
            0b00011 => Some(ElementType::SignedInteger(ElementDataLength::Bytes8)),

            _ => None
        }
    }

}



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
