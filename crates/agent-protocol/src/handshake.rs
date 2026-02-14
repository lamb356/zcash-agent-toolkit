use serde::{Deserialize, Serialize};

use memo_codec::{chunk_message, decode_chunked_message, MessageType, MEMO_SIZE};

use crate::ProtocolError;

/// A handshake message exchanged between agents to establish identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentHandshake {
    /// Deterministic agent identifier.
    pub agent_id: String,
    /// Capabilities advertised by this agent.
    pub capabilities: Vec<String>,
    /// Protocol version supported by this agent.
    pub protocol_version: u8,
}

/// Create a handshake payload from identity and capabilities.
pub fn create_handshake(agent_id: &str, capabilities: &[&str]) -> AgentHandshake {
    AgentHandshake {
        agent_id: agent_id.to_string(),
        capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
        protocol_version: 1,
    }
}

/// Encode a handshake as Handshake-type memos for a given session.
pub fn encode_handshake(
    handshake: &AgentHandshake,
    session_id: &[u8; 16],
) -> Result<Vec<[u8; MEMO_SIZE]>, ProtocolError> {
    let json = serde_json::to_vec(handshake).map_err(ProtocolError::Json)?;
    chunk_message(&json, MessageType::Handshake, session_id).map_err(ProtocolError::Memo)
}

/// Decode handshake memos back into an `AgentHandshake`.
pub fn decode_handshake(memos: &[[u8; MEMO_SIZE]]) -> Result<AgentHandshake, ProtocolError> {
    let msg = decode_chunked_message(memos).map_err(ProtocolError::Memo)?;
    if msg.msg_type != MessageType::Handshake {
        return Err(ProtocolError::UnexpectedMessageType {
            expected: MessageType::Handshake,
            actual: msg.msg_type,
        });
    }
    let handshake: AgentHandshake = serde_json::from_slice(&msg.data).map_err(ProtocolError::Json)?;
    if handshake.protocol_version != 1 {
        return Err(ProtocolError::UnsupportedVersion(handshake.protocol_version as u8));
    }
    Ok(handshake)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_primitives::generate_session_id;

    #[test]
    fn create_handshake_produces_identity_and_capabilities() {
        let hs = create_handshake("agent-alpha", &["text", "task", "payment"]);
        assert_eq!(hs.agent_id, "agent-alpha");
        assert_eq!(hs.protocol_version, 1);
        assert_eq!(hs.capabilities, vec!["text", "task", "payment"]);
    }

    #[test]
    fn encode_decode_handshake_roundtrip() {
        let hs = create_handshake("agent-alpha", &["text", "command"]);
        let session_id = generate_session_id().unwrap();

        let memos = encode_handshake(&hs, &session_id).unwrap();
        let decoded = decode_handshake(&memos).expect("decode should succeed");

        assert_eq!(decoded, hs);
    }

    #[test]
    fn decode_handshake_with_wrong_message_type_returns_error() {
        let hs = create_handshake("agent-alpha", &["text"]);
        let session_id = generate_session_id().unwrap();
        let json = serde_json::to_vec(&hs).unwrap();
        let memos =
            memo_codec::chunk_message(&json, MessageType::Text, &session_id).unwrap();

        let result = decode_handshake(&memos);
        assert!(result.is_err());
        match result.unwrap_err() {
            ProtocolError::UnexpectedMessageType { expected, actual } => {
                assert_eq!(expected, MessageType::Handshake);
                assert_eq!(actual, MessageType::Text);
            }
            other => panic!("expected UnexpectedMessageType, got: {other:?}"),
        }
    }

    #[test]
    fn decode_handshake_with_unsupported_version_is_rejected() {
        let mut hs = create_handshake("agent-alpha", &["text"]);
        hs.protocol_version = 99;
        let session_id = generate_session_id().unwrap();
        let json = serde_json::to_vec(&hs).unwrap();
        let memos = memo_codec::chunk_message(&json, MessageType::Handshake, &session_id).unwrap();

        let result = decode_handshake(&memos);
        assert!(result.is_err());
        match result.unwrap_err() {
            ProtocolError::UnsupportedVersion(v) => assert_eq!(v, 99),
            other => panic!("expected UnsupportedVersion, got: {other:?}"),
        }
    }

    #[test]
    fn handshake_with_empty_capabilities() {
        let hs = create_handshake("agent-beta", &[]);
        let session_id = generate_session_id().unwrap();

        let memos = encode_handshake(&hs, &session_id).unwrap();
        let decoded = decode_handshake(&memos).expect("decode should succeed");
        assert!(decoded.capabilities.is_empty());
    }
}
