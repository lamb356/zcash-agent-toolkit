use std::collections::HashMap;

use crypto_primitives::AgentCipher;
use memo_codec::{chunk_message, decode_chunked_message, MessageType, MEMO_SIZE};

use crate::ProtocolError;

/// Manages multiple concurrent encrypted conversations.
///
/// Each session is identified by a 16-byte session ID and has its own
/// `AgentCipher` for encryption/decryption.
pub struct ConversationManager {
    /// Map from session_id to cipher for that session.
    ciphers: HashMap<[u8; 16], AgentCipher>,
}

impl ConversationManager {
    /// Create a new empty conversation manager.
    pub fn new() -> Self {
        Self {
            ciphers: HashMap::new(),
        }
    }

    /// Register a cipher for a session (typically called after handshake completes).
    pub fn register_session(&mut self, session_id: [u8; 16], cipher: AgentCipher) {
        self.ciphers.insert(session_id, cipher);
    }

    /// Encrypt and chunk a message for sending.
    ///
    /// Returns a vector of 512-byte memos ready to be sent as Zcash memo fields.
    pub fn send_message(
        &self,
        session_id: &[u8; 16],
        msg_type: MessageType,
        plaintext: &[u8],
    ) -> Result<Vec<[u8; MEMO_SIZE]>, ProtocolError> {
        let cipher = self
            .ciphers
            .get(session_id)
            .ok_or(ProtocolError::UnknownSession)?;
        let encrypted = cipher.encrypt(plaintext);
        Ok(chunk_message(&encrypted, msg_type, session_id))
    }

    /// Decrypt and reassemble received memos.
    ///
    /// Returns the message type and decrypted plaintext.
    pub fn receive_message(
        &self,
        memos: &[[u8; MEMO_SIZE]],
    ) -> Result<(MessageType, Vec<u8>), ProtocolError> {
        let msg = decode_chunked_message(memos).map_err(ProtocolError::Memo)?;
        let cipher = self
            .ciphers
            .get(&msg.session_id)
            .ok_or(ProtocolError::UnknownSession)?;
        let plaintext = cipher.decrypt(&msg.data).map_err(ProtocolError::Cipher)?;
        Ok((msg.msg_type, plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_primitives::{AgentKeyPair, generate_session_id};

    /// Helper: create two agents, perform DH, and return (session_id, manager_a, manager_b).
    fn setup_conversation() -> ([u8; 16], ConversationManager, ConversationManager) {
        let alice = AgentKeyPair::generate();
        let bob = AgentKeyPair::generate();

        let shared_secret = alice.diffie_hellman(&bob.public_key_bytes());
        let session_id = generate_session_id();

        let mut mgr_a = ConversationManager::new();
        let mut mgr_b = ConversationManager::new();

        mgr_a.register_session(session_id, AgentCipher::new(&shared_secret));
        mgr_b.register_session(session_id, AgentCipher::new(&shared_secret));

        (session_id, mgr_a, mgr_b)
    }

    #[test]
    fn send_receive_roundtrip() {
        let (session_id, mgr_a, mgr_b) = setup_conversation();

        let plaintext = b"Hello from Alice to Bob!";
        let memos = mgr_a
            .send_message(&session_id, MessageType::Text, plaintext)
            .expect("send");

        let (msg_type, decrypted) = mgr_b.receive_message(&memos).expect("receive");
        assert_eq!(msg_type, MessageType::Text);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn two_sessions_decrypt_only_own_messages() {
        let alice = AgentKeyPair::generate();
        let bob = AgentKeyPair::generate();
        let carol = AgentKeyPair::generate();

        let secret_ab = alice.diffie_hellman(&bob.public_key_bytes());
        let secret_ac = alice.diffie_hellman(&carol.public_key_bytes());

        let session_ab = generate_session_id();
        let session_ac = generate_session_id();

        let mut mgr_alice = ConversationManager::new();
        mgr_alice.register_session(session_ab, AgentCipher::new(&secret_ab));
        mgr_alice.register_session(session_ac, AgentCipher::new(&secret_ac));

        let mut mgr_bob = ConversationManager::new();
        mgr_bob.register_session(session_ab, AgentCipher::new(&secret_ab));

        let mut mgr_carol = ConversationManager::new();
        mgr_carol.register_session(session_ac, AgentCipher::new(&secret_ac));

        // Alice sends to Bob
        let msg_to_bob = b"Secret for Bob";
        let memos_bob = mgr_alice
            .send_message(&session_ab, MessageType::Text, msg_to_bob)
            .expect("send to bob");

        // Alice sends to Carol
        let msg_to_carol = b"Secret for Carol";
        let memos_carol = mgr_alice
            .send_message(&session_ac, MessageType::Command, msg_to_carol)
            .expect("send to carol");

        // Bob can decrypt his message
        let (_, dec_bob) = mgr_bob.receive_message(&memos_bob).expect("bob receives");
        assert_eq!(dec_bob, msg_to_bob);

        // Carol can decrypt her message
        let (_, dec_carol) = mgr_carol
            .receive_message(&memos_carol)
            .expect("carol receives");
        assert_eq!(dec_carol, msg_to_carol);

        // Carol cannot decrypt Bob's message (unknown session for her)
        let result = mgr_carol.receive_message(&memos_bob);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_session_returns_error() {
        let mgr = ConversationManager::new();
        let unknown_session = generate_session_id();

        let result = mgr.send_message(&unknown_session, MessageType::Text, b"test");
        assert!(result.is_err());
        match result.unwrap_err() {
            ProtocolError::UnknownSession => {}
            other => panic!("expected UnknownSession, got: {other:?}"),
        }
    }

    #[test]
    fn large_message_roundtrip() {
        let (session_id, mgr_a, mgr_b) = setup_conversation();

        // 5 KB message -- will produce multiple chunks after encryption overhead
        let plaintext: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let memos = mgr_a
            .send_message(&session_id, MessageType::Command, &plaintext)
            .expect("send large");

        // Should require multiple memos due to encryption overhead
        assert!(memos.len() > 1);

        let (msg_type, decrypted) = mgr_b.receive_message(&memos).expect("receive large");
        assert_eq!(msg_type, MessageType::Command);
        assert_eq!(decrypted, plaintext);
    }
}
