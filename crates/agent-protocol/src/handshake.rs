use serde::{Deserialize, Serialize};

use address_utils::agent_id_from_pubkey;
use crypto_primitives::AgentKeyPair;
use memo_codec::{chunk_message, decode_chunked_message, MessageType, MEMO_SIZE};

use crate::ProtocolError;

/// A handshake message exchanged between agents to establish a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentHandshake {
    /// Deterministic agent identifier derived from the public key.
    pub agent_id: String,
    /// X25519 public key as a lowercase hex string.
    pub public_key: String,
    /// Capabilities advertised by this agent.
    pub capabilities: Vec<String>,
    /// Protocol version supported by this agent.
    pub protocol_version: u8,
}

/// Create a handshake payload from a keypair and a list of capabilities.
pub fn create_handshake(keypair: &AgentKeyPair, capabilities: &[&str]) -> AgentHandshake {
    AgentHandshake {
        agent_id: agent_id_from_pubkey(&keypair.public_key_bytes()),
        public_key: keypair.public_key_hex(),
        capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
        protocol_version: 1,
    }
}

/// Encode a handshake as Handshake-type memos for a given session.
pub fn encode_handshake(handshake: &AgentHandshake, session_id: &[u8; 16]) -> Result<Vec<[u8; MEMO_SIZE]>, ProtocolError> {
    let json = serde_json::to_vec(handshake).map_err(ProtocolError::Json)?;
    chunk_message(&json, MessageType::Handshake, session_id).map_err(ProtocolError::Memo)
}

/// Decode handshake memos back into an AgentHandshake.
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

/// Complete a handshake by deriving the shared secret from our keypair and their handshake.
///
/// Decodes the peer's public key from hex, performs X25519 Diffie-Hellman,
/// and returns the derived 32-byte shared secret.
pub fn complete_handshake(
    our_keypair: &AgentKeyPair,
    their_handshake: &AgentHandshake,
) -> Result<[u8; 32], ProtocolError> {
    let peer_pub_bytes =
        hex::decode(&their_handshake.public_key).map_err(|_| ProtocolError::InvalidPublicKey)?;
    if peer_pub_bytes.len() != 32 {
        return Err(ProtocolError::InvalidPublicKey);
    }
    let mut pub_array = [0u8; 32];
    pub_array.copy_from_slice(&peer_pub_bytes);
    Ok(our_keypair.diffie_hellman(&pub_array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_primitives::generate_session_id;

    #[test]
    fn create_handshake_produces_correct_agent_id_and_public_key() {
        let keypair = AgentKeyPair::generate();
        let hs = create_handshake(&keypair, &["text", "task"]);

        assert_eq!(hs.agent_id, agent_id_from_pubkey(&keypair.public_key_bytes()));
        assert_eq!(hs.public_key, keypair.public_key_hex());
        assert_eq!(hs.protocol_version, 1);
        assert_eq!(hs.capabilities, vec!["text", "task"]);
    }

    #[test]
    fn encode_decode_handshake_roundtrip() {
        let keypair = AgentKeyPair::generate();
        let hs = create_handshake(&keypair, &["text", "command"]);
        let session_id = generate_session_id().unwrap();

        let memos = encode_handshake(&hs, &session_id).unwrap();
        let decoded = decode_handshake(&memos).expect("decode should succeed");

        assert_eq!(decoded, hs);
    }

    #[test]
    fn complete_handshake_both_agents_derive_same_shared_secret() {
        let alice = AgentKeyPair::generate();
        let bob = AgentKeyPair::generate();

        let alice_hs = create_handshake(&alice, &["text"]);
        let bob_hs = create_handshake(&bob, &["text"]);

        let secret_ab = complete_handshake(&alice, &bob_hs).expect("alice completes");
        let secret_ba = complete_handshake(&bob, &alice_hs).expect("bob completes");

        assert_eq!(secret_ab, secret_ba);
    }

    #[test]
    fn decode_handshake_with_wrong_message_type_returns_error() {
        let keypair = AgentKeyPair::generate();
        let hs = create_handshake(&keypair, &["text"]);
        let session_id = generate_session_id().unwrap();

        // Encode as Text type instead of Handshake
        let json = serde_json::to_vec(&hs).unwrap();
        let memos = memo_codec::chunk_message(&json, MessageType::Text, &session_id).unwrap();

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
    fn handshake_with_empty_capabilities() {
        let keypair = AgentKeyPair::generate();
        let hs = create_handshake(&keypair, &[]);
        let session_id = generate_session_id().unwrap();

        assert!(hs.capabilities.is_empty());

        let memos = encode_handshake(&hs, &session_id).unwrap();
        let decoded = decode_handshake(&memos).expect("decode");
        assert_eq!(decoded.capabilities, Vec::<String>::new());
    }

    #[test]
    fn handshake_with_multiple_capabilities() {
        let keypair = AgentKeyPair::generate();
        let caps = &["text", "command", "task", "payment", "binary"];
        let hs = create_handshake(&keypair, caps);
        let session_id = generate_session_id().unwrap();

        let memos = encode_handshake(&hs, &session_id).unwrap();
        let decoded = decode_handshake(&memos).expect("decode");
        assert_eq!(
            decoded.capabilities,
            caps.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
    }
}
