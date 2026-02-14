pub mod handshake;
pub mod task;
pub mod relay;

pub use handshake::*;
pub use task::*;
pub use relay::*;

pub use memo_codec::{MessageType, MEMO_SIZE};

use std::fmt;
use memo_codec::MemoError;

/// Errors that can occur during agent protocol operations.
#[derive(Debug)]
pub enum ProtocolError {
    /// An error from memo encoding/decoding.
    Memo(MemoError),
    /// JSON serialization/deserialization error.
    Json(serde_json::Error),
    /// Received a message type that was not expected.
    UnexpectedMessageType {
        expected: MessageType,
        actual: MessageType,
    },
    /// Protocol version is not supported.
    UnsupportedVersion(u8),
    /// Session ID is already registered.
    SessionAlreadyExists,
    /// Session ID was not found.
    UnknownSession,
    /// Replay attack detected (duplicate nonce).
    ReplayDetected,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Memo(e) => write!(f, "memo error: {e}"),
            ProtocolError::Json(e) => write!(f, "json error: {e}"),
            ProtocolError::UnexpectedMessageType { expected, actual } => {
                write!(f, "unexpected message type: expected {expected:?}, got {actual:?}")
            }
            ProtocolError::UnsupportedVersion(v) => write!(f, "unsupported protocol version: {v}"),
            ProtocolError::SessionAlreadyExists => write!(f, "session already exists"),
            ProtocolError::UnknownSession => write!(f, "unknown session"),
            ProtocolError::ReplayDetected => write!(f, "replay detected: duplicate nonce"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolError::Memo(e) => Some(e),
            ProtocolError::Json(e) => Some(e),
            _ => None,
        }
    }
}
