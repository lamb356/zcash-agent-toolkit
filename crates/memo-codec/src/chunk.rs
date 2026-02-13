use std::fmt;

use crate::types::{MessageType, HEADER_SIZE, MEMO_SIZE, PAYLOAD_LENGTH_OFFSET, PAYLOAD_SIZE, PROTOCOL_VERSION};

/// Errors that can occur during memo encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoError {
    /// Input byte slice is not exactly 512 bytes.
    InvalidLength { expected: usize, actual: usize },
    /// Version byte is not a recognised protocol version.
    InvalidVersion(u8),
    /// Message-type byte does not map to a known variant.
    InvalidMessageType(u8),
    /// Payload exceeds the maximum of 452 bytes.
    PayloadTooLarge { max: usize, actual: usize },
    /// Hex string could not be decoded.
    HexDecodeError(String),
    /// BLAKE3 content hash mismatch during reassembly.
    ContentHashMismatch,
    /// Missing chunks during reassembly.
    MissingChunks {
        expected: u16,
        received: u16,
    },
    /// Session ID mismatch across chunks.
    SessionIdMismatch,
    /// Payload length in header exceeds maximum.
    InvalidPayloadLength { max: usize, actual: u16 },
    /// Message too large to fit in u16 chunks.
    MessageTooLarge { max_bytes: usize, actual_bytes: usize },
    /// Chunks have inconsistent headers (msg_type, content_hash, or total_chunks mismatch).
    InconsistentChunks,
    /// Duplicate chunk index detected.
    DuplicateChunkIndex(u16),
    /// Chunk index is out of range for the declared total_chunks.
    InvalidChunkIndex { index: u16, total: u16 },
}

impl fmt::Display for MemoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoError::InvalidLength { expected, actual } => {
                write!(f, "invalid memo length: expected {expected}, got {actual}")
            }
            MemoError::InvalidVersion(v) => write!(f, "invalid protocol version: 0x{v:02X}"),
            MemoError::InvalidMessageType(v) => write!(f, "invalid message type: 0x{v:02X}"),
            MemoError::PayloadTooLarge { max, actual } => {
                write!(f, "payload too large: max {max}, got {actual}")
            }
            MemoError::HexDecodeError(e) => write!(f, "hex decode error: {e}"),
            MemoError::ContentHashMismatch => write!(f, "BLAKE3 content hash mismatch"),
            MemoError::MissingChunks { expected, received } => {
                write!(f, "missing chunks: expected {expected}, received {received}")
            }
            MemoError::SessionIdMismatch => write!(f, "session ID mismatch across chunks"),
            MemoError::InvalidPayloadLength { max, actual } => {
                write!(f, "invalid payload length: max {max}, got {actual}")
            }
            MemoError::MessageTooLarge { max_bytes, actual_bytes } => {
                write!(f, "message too large: max {max_bytes} bytes, got {actual_bytes}")
            }
            MemoError::InconsistentChunks => {
                write!(f, "inconsistent chunk headers (msg_type, content_hash, or total_chunks mismatch)")
            }
            MemoError::DuplicateChunkIndex(idx) => {
                write!(f, "duplicate chunk index: {idx}")
            }
            MemoError::InvalidChunkIndex { index, total } => {
                write!(f, "invalid chunk index {index} for total_chunks {total}")
            }
        }
    }
}

impl std::error::Error for MemoError {}

/// Structured header occupying the first 60 bytes of every memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoHeader {
    /// Protocol version (currently 0x01).
    pub version: u8,
    /// Type of the message.
    pub msg_type: MessageType,
    /// 16-byte session identifier.
    pub session_id: [u8; 16],
    /// Zero-based index of this chunk within the message.
    pub chunk_index: u16,
    /// Total number of chunks in the message.
    pub total_chunks: u16,
    /// BLAKE3 hash of the *full* original message data.
    pub content_hash: [u8; 32],
    /// Exact number of payload bytes in this chunk.
    pub payload_length: u16,
}

/// Encode a header and payload into a 512-byte memo.
///
/// The payload must be at most `PAYLOAD_SIZE` (452) bytes. Shorter payloads
/// are zero-padded to fill the memo.
pub fn encode_memo(header: &MemoHeader, payload: &[u8]) -> Result<[u8; MEMO_SIZE], MemoError> {
    if payload.len() > PAYLOAD_SIZE {
        return Err(MemoError::PayloadTooLarge {
            max: PAYLOAD_SIZE,
            actual: payload.len(),
        });
    }

    let mut buf = [0u8; MEMO_SIZE];

    // Header layout (60 bytes):
    // [0]        version
    // [1]        msg_type
    // [2..18]    session_id (16 bytes)
    // [18..20]   chunk_index (u16 big-endian)
    // [20..22]   total_chunks (u16 big-endian)
    // [22..54]   content_hash (32 bytes)
    // [54..56]   payload_length (u16 big-endian)
    // [56..60]   reserved (4 bytes, zeroed)
    buf[0] = header.version;
    buf[1] = header.msg_type as u8;
    buf[2..18].copy_from_slice(&header.session_id);
    buf[18..20].copy_from_slice(&header.chunk_index.to_be_bytes());
    buf[20..22].copy_from_slice(&header.total_chunks.to_be_bytes());
    buf[22..54].copy_from_slice(&header.content_hash);
    buf[PAYLOAD_LENGTH_OFFSET..PAYLOAD_LENGTH_OFFSET + 2]
        .copy_from_slice(&(payload.len() as u16).to_be_bytes());
    // [56..60] reserved — already zeroed.

    // Payload (remainder is already zeroed).
    buf[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);

    Ok(buf)
}

/// Decode a 512-byte memo into its header and payload.
///
/// The exact payload length is read from the header's `payload_length` field,
/// so all message types (including binary) are handled uniformly.
pub fn decode_memo(bytes: &[u8; MEMO_SIZE]) -> Result<(MemoHeader, Vec<u8>), MemoError> {
    let version = bytes[0];
    if version != PROTOCOL_VERSION {
        return Err(MemoError::InvalidVersion(version));
    }

    let msg_type =
        MessageType::try_from(bytes[1]).map_err(MemoError::InvalidMessageType)?;

    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&bytes[2..18]);

    let chunk_index = u16::from_be_bytes([bytes[18], bytes[19]]);
    let total_chunks = u16::from_be_bytes([bytes[20], bytes[21]]);

    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&bytes[22..54]);

    let payload_length = u16::from_be_bytes([
        bytes[PAYLOAD_LENGTH_OFFSET],
        bytes[PAYLOAD_LENGTH_OFFSET + 1],
    ]);

    if payload_length as usize > PAYLOAD_SIZE {
        return Err(MemoError::InvalidPayloadLength {
            max: PAYLOAD_SIZE,
            actual: payload_length,
        });
    }

    let header = MemoHeader {
        version,
        msg_type,
        session_id,
        chunk_index,
        total_chunks,
        content_hash,
        payload_length,
    };

    let payload = bytes[HEADER_SIZE..HEADER_SIZE + payload_length as usize].to_vec();

    Ok((header, payload))
}

/// Convenience: encode a memo then hex-encode the result.
pub fn encode_memo_hex(header: &MemoHeader, payload: &[u8]) -> Result<String, MemoError> {
    let memo = encode_memo(header, payload)?;
    Ok(hex::encode(memo))
}

/// Convenience: hex-decode a string then decode the memo.
pub fn decode_memo_hex(hex_str: &str) -> Result<(MemoHeader, Vec<u8>), MemoError> {
    let bytes = hex::decode(hex_str).map_err(|e| MemoError::HexDecodeError(e.to_string()))?;
    if bytes.len() != MEMO_SIZE {
        return Err(MemoError::InvalidLength {
            expected: MEMO_SIZE,
            actual: bytes.len(),
        });
    }
    let mut arr = [0u8; MEMO_SIZE];
    arr.copy_from_slice(&bytes);
    decode_memo(&arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(msg_type: MessageType) -> MemoHeader {
        MemoHeader {
            version: PROTOCOL_VERSION,
            msg_type,
            session_id: [0xAB; 16],
            chunk_index: 0,
            total_chunks: 1,
            content_hash: [0xCD; 32],
            payload_length: 0, // will be set by encode_memo via header
        }
    }

    #[test]
    fn roundtrip_encode_decode_all_types() {
        let types = [
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
        let payload = b"hello world";

        for mt in types {
            let header = make_header(mt);
            let memo = encode_memo(&header, payload).expect("encode");
            let (dec_header, dec_payload) = decode_memo(&memo).expect("decode");

            assert_eq!(dec_header.version, PROTOCOL_VERSION);
            assert_eq!(dec_header.msg_type, mt);
            assert_eq!(dec_header.session_id, [0xAB; 16]);
            assert_eq!(dec_header.chunk_index, 0);
            assert_eq!(dec_header.total_chunks, 1);
            assert_eq!(dec_header.content_hash, [0xCD; 32]);

            // All types now use exact payload_length — no special binary handling.
            assert_eq!(dec_payload, payload);
        }
    }

    #[test]
    fn encoded_memo_is_exactly_512_bytes() {
        let header = make_header(MessageType::Text);
        let memo = encode_memo(&header, b"test").expect("encode");
        assert_eq!(memo.len(), MEMO_SIZE);
    }

    #[test]
    fn payload_is_zero_padded() {
        let header = make_header(MessageType::Text);
        let payload = b"short";
        let memo = encode_memo(&header, payload).expect("encode");

        // Payload region starts at HEADER_SIZE.
        assert_eq!(&memo[HEADER_SIZE..HEADER_SIZE + payload.len()], payload);
        // Remainder should be zeros.
        for &b in &memo[HEADER_SIZE + payload.len()..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn hex_roundtrip() {
        let header = make_header(MessageType::Command);
        let payload = b"hex test payload";
        let hex_str = encode_memo_hex(&header, payload).expect("hex encode");
        let (dec_header, dec_payload) = decode_memo_hex(&hex_str).expect("hex decode");

        assert_eq!(dec_header.msg_type, MessageType::Command);
        assert_eq!(dec_payload, payload);
    }

    #[test]
    fn invalid_version_returns_error() {
        let header = make_header(MessageType::Text);
        let mut memo = encode_memo(&header, b"test").expect("encode");
        memo[0] = 0xFF; // corrupt version
        let err = decode_memo(&memo).unwrap_err();
        assert_eq!(err, MemoError::InvalidVersion(0xFF));
    }

    #[test]
    fn invalid_message_type_returns_error() {
        let header = make_header(MessageType::Text);
        let mut memo = encode_memo(&header, b"test").expect("encode");
        memo[1] = 0xEE; // invalid message type
        let err = decode_memo(&memo).unwrap_err();
        assert_eq!(err, MemoError::InvalidMessageType(0xEE));
    }

    #[test]
    fn wrong_length_hex_returns_error() {
        let short_hex = hex::encode([0u8; 100]);
        let err = decode_memo_hex(&short_hex).unwrap_err();
        assert_eq!(
            err,
            MemoError::InvalidLength {
                expected: MEMO_SIZE,
                actual: 100,
            }
        );
    }

    #[test]
    fn payload_too_large_returns_error() {
        let header = make_header(MessageType::Text);
        let big_payload = vec![0x42u8; PAYLOAD_SIZE + 1];
        let err = encode_memo(&header, &big_payload).unwrap_err();
        assert_eq!(
            err,
            MemoError::PayloadTooLarge {
                max: PAYLOAD_SIZE,
                actual: PAYLOAD_SIZE + 1,
            }
        );
    }

    #[test]
    fn chunk_index_and_total_chunks_roundtrip() {
        let header = MemoHeader {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::Text,
            session_id: [0x01; 16],
            chunk_index: 300,
            total_chunks: 500,
            content_hash: [0x02; 32],
            payload_length: 0,
        };
        let memo = encode_memo(&header, b"").expect("encode");
        let (dec, _) = decode_memo(&memo).expect("decode");
        assert_eq!(dec.chunk_index, 300);
        assert_eq!(dec.total_chunks, 500);
    }
}
