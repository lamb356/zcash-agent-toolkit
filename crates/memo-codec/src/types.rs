use serde::{Deserialize, Serialize};

/// Total size of a Zcash memo field in bytes.
pub const MEMO_SIZE: usize = 512;

/// Size of the structured header in bytes.
pub const HEADER_SIZE: usize = 54;

/// Maximum payload per memo chunk: MEMO_SIZE - HEADER_SIZE.
pub const PAYLOAD_SIZE: usize = MEMO_SIZE - HEADER_SIZE; // 458

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Discriminant for the kind of message carried in a memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Handshake = 0x01,
    Text = 0x02,
    Command = 0x03,
    Response = 0x04,
    Ack = 0x05,
    Close = 0x06,
    Binary = 0x07,
    TaskAssign = 0x10,
    TaskProof = 0x11,
    PaymentConfirm = 0x12,
}

impl TryFrom<u8> for MessageType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MessageType::Handshake),
            0x02 => Ok(MessageType::Text),
            0x03 => Ok(MessageType::Command),
            0x04 => Ok(MessageType::Response),
            0x05 => Ok(MessageType::Ack),
            0x06 => Ok(MessageType::Close),
            0x07 => Ok(MessageType::Binary),
            0x10 => Ok(MessageType::TaskAssign),
            0x11 => Ok(MessageType::TaskProof),
            0x12 => Ok(MessageType::PaymentConfirm),
            other => Err(other),
        }
    }
}

impl MessageType {
    /// Returns true for message types whose payload is raw binary (not text).
    pub fn is_binary(&self) -> bool {
        matches!(self, MessageType::Binary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_roundtrip_through_u8() {
        let variants = [
            MessageType::Handshake,
            MessageType::Text,
            MessageType::Command,
            MessageType::Response,
            MessageType::Ack,
            MessageType::Close,
            MessageType::Binary,
            MessageType::TaskAssign,
            MessageType::TaskProof,
            MessageType::PaymentConfirm,
        ];
        for mt in variants {
            let byte = mt as u8;
            let back = MessageType::try_from(byte).expect("should convert back");
            assert_eq!(mt, back);
        }
    }

    #[test]
    fn try_from_invalid_u8_fails() {
        assert!(MessageType::try_from(0x00).is_err());
        assert!(MessageType::try_from(0x08).is_err());
        assert!(MessageType::try_from(0xFF).is_err());
    }

    #[test]
    fn constants_are_consistent() {
        assert_eq!(PAYLOAD_SIZE, MEMO_SIZE - HEADER_SIZE);
        assert_eq!(PAYLOAD_SIZE, 458);
    }
}
