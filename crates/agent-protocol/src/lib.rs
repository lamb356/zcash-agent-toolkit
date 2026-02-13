pub mod handshake;
pub mod task;
pub mod relay;

pub use handshake::*;
pub use task::*;
pub use relay::*;

// Re-export key types from dependencies for convenience.
pub use crypto_primitives::{AgentKeyPair, AgentCipher};
pub use memo_codec::{MessageType, MEMO_SIZE};

use std::fmt;
use memo_codec::MemoError;
use crypto_primitives::CipherError;

/// Errors that can occur during agent protocol operations.
#[derive(Debug)]
pub enum ProtocolError {
    /// An error from memo encoding/decoding.
    Memo(MemoError),
    /// An error from cipher operations.
    Cipher(CipherError),
    /// JSON serialization/deserialization error.
    Json(serde_json::Error),
    /// Received a message type that was not expected.
    UnexpectedMessageType {
        expected: MessageType,
        actual: MessageType,
    },
    /// The public key in a handshake is not valid.
    InvalidPublicKey,
    /// No cipher registered for the given session.
    UnknownSession,
    /// Protocol version is not supported.
    UnsupportedVersion(u8),
    /// Session ID is already registered.
    SessionAlreadyExists,
    /// Replay attack detected (duplicate nonce).
    ReplayDetected,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Memo(e) => write!(f, "memo error: {e}"),
            ProtocolError::Cipher(e) => write!(f, "cipher error: {e}"),
            ProtocolError::Json(e) => write!(f, "json error: {e}"),
            ProtocolError::UnexpectedMessageType { expected, actual } => {
                write!(f, "unexpected message type: expected {expected:?}, got {actual:?}")
            }
            ProtocolError::InvalidPublicKey => write!(f, "invalid public key"),
            ProtocolError::UnknownSession => write!(f, "unknown session"),
            ProtocolError::UnsupportedVersion(v) => write!(f, "unsupported protocol version: {v}"),
            ProtocolError::SessionAlreadyExists => write!(f, "session already exists"),
            ProtocolError::ReplayDetected => write!(f, "replay detected: duplicate nonce"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolError::Memo(e) => Some(e),
            ProtocolError::Cipher(e) => Some(e),
            ProtocolError::Json(e) => Some(e),
            _ => None,
        }
    }
}
