use std::collections::HashMap;

use crate::ProtocolError;

/// Information tracked for an active peer conversation.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// The peer's deterministic agent identifier.
    pub peer_agent_id: String,
    /// Capabilities advertised by the peer in the handshake.
    pub capabilities: Vec<String>,
    /// Creation timestamp for the session.
    pub created_at: u64,
}

/// Tracks active protocol sessions by session id.
#[derive(Debug, Default)]
pub struct ConversationManager {
    sessions: HashMap<[u8; 16], SessionInfo>,
    max_sessions: usize,
}

impl ConversationManager {
    /// Create a new conversation manager with a default capacity limit.
    pub fn new() -> Self {
        Self::with_max_sessions(100)
    }

    /// Create a new conversation manager with an explicit capacity limit.
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// Register a peer session from decoded handshake information.
    pub fn register_session(
        &mut self,
        session_id: [u8; 16],
        peer_agent_id: String,
        capabilities: Vec<String>,
        created_at: u64,
    ) -> Result<(), ProtocolError> {
        if self.sessions.contains_key(&session_id) {
            return Err(ProtocolError::SessionAlreadyExists);
        }

        if self.sessions.len() >= self.max_sessions && !self.sessions.is_empty() {
            let mut oldest = None;
            for (id, info) in &self.sessions {
                match oldest {
                    Some((oldest_created_at, _)) if oldest_created_at <= info.created_at => {}
                    _ => oldest = Some((info.created_at, *id)),
                }
            }
            if let Some((_, oldest_id)) = oldest {
                self.sessions.remove(&oldest_id);
            }
        }

        self.sessions.insert(
            session_id,
            SessionInfo {
                peer_agent_id,
                capabilities,
                created_at,
            },
        );
        Ok(())
    }

    /// Read-only lookup of an active session.
    pub fn get_session(&self, session_id: &[u8; 16]) -> Option<&SessionInfo> {
        self.sessions.get(session_id)
    }

    /// Remove and return a session from tracking.
    pub fn remove_session(&mut self, session_id: &[u8; 16]) -> Option<SessionInfo> {
        self.sessions.remove(session_id)
    }

    /// Return all active session identifiers.
    pub fn list_sessions(&self) -> Vec<[u8; 16]> {
        self.sessions.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_primitives::{generate_session_id, random_bytes_array};

    #[test]
    fn register_and_get_session() {
        let mut manager = ConversationManager::new();
        let session_id = generate_session_id().unwrap();
        let created_at = 1_700_000_000u64;

        manager
            .register_session(
                session_id,
                "agent-b".to_string(),
                vec!["task".to_string()],
                created_at,
            )
            .expect("register");

        let session = manager.get_session(&session_id).expect("session should exist");
        assert_eq!(session.peer_agent_id, "agent-b");
        assert_eq!(session.capabilities, vec!["task"]);
        assert_eq!(session.created_at, created_at);
    }

    #[test]
    fn duplicate_session_is_rejected() {
        let mut manager = ConversationManager::new();
        let session_id = generate_session_id().unwrap();
        let created_at = 1_700_000_000u64;

        manager
            .register_session(
                session_id,
                "agent-b".to_string(),
                vec!["task".to_string()],
                created_at,
            )
            .expect("first");
        let err = manager.register_session(
            session_id,
            "agent-c".to_string(),
            vec!["text".to_string()],
            created_at,
        );
        assert!(matches!(err, Err(ProtocolError::SessionAlreadyExists)));
    }

    #[test]
    fn remove_session() {
        let mut manager = ConversationManager::new();
        let session_id = generate_session_id().unwrap();
        manager
            .register_session(
                session_id,
                "agent-b".to_string(),
                vec!["task".to_string()],
                1,
            )
            .expect("register");
        assert!(manager.get_session(&session_id).is_some());

        let removed = manager.remove_session(&session_id);
        assert!(removed.is_some());
        assert!(manager.get_session(&session_id).is_none());
    }

    #[test]
    fn list_sessions() {
        let mut manager = ConversationManager::with_max_sessions(4);
        let session_a = generate_session_id().unwrap();
        let session_b = generate_session_id().unwrap();
        let session_c = generate_session_id().unwrap();

        manager
            .register_session(
                session_a,
                "a".to_string(),
                vec!["text".to_string()],
                1,
            )
            .expect("session a");
        manager
            .register_session(
                session_b,
                "b".to_string(),
                vec!["text".to_string()],
                2,
            )
            .expect("session b");
        manager
            .register_session(
                session_c,
                "c".to_string(),
                vec!["text".to_string()],
                3,
            )
            .expect("session c");

        let sessions = manager.list_sessions();
        assert_eq!(sessions.len(), 3);
        assert!(sessions.contains(&session_a));
        assert!(sessions.contains(&session_b));
        assert!(sessions.contains(&session_c));
    }

    #[test]
    fn max_sessions_eviction_removes_oldest() {
        let mut manager = ConversationManager::with_max_sessions(2);
        let session_a = generate_session_id().unwrap();
        let session_b = generate_session_id().unwrap();
        let session_c = generate_session_id().unwrap();

        manager
            .register_session(
                session_a,
                "a".to_string(),
                vec!["text".to_string()],
                100,
            )
            .unwrap();
        manager
            .register_session(
                session_b,
                "b".to_string(),
                vec!["text".to_string()],
                200,
            )
            .unwrap();
        assert_eq!(manager.list_sessions().len(), 2);

        manager
            .register_session(
                session_c,
                "c".to_string(),
                vec!["text".to_string()],
                50,
            )
            .unwrap();
        assert_eq!(manager.list_sessions().len(), 2);
        assert!(manager.get_session(&session_a).is_none());
        assert!(manager.get_session(&session_b).is_some());
        assert!(manager.get_session(&session_c).is_some());
    }

    #[test]
    fn max_sessions_eviction_uses_oldest_created_at() {
        let mut manager = ConversationManager::with_max_sessions(2);
        let random = random_bytes_array::<16>().unwrap();
        let mut older = random;
        older[0] = 0;
        let mut newer = random;
        newer[0] = 1;

        manager
            .register_session(older, "a".to_string(), vec!["text".to_string()], 5)
            .unwrap();
        manager
            .register_session(newer, "b".to_string(), vec!["text".to_string()], 10)
            .unwrap();
        manager
            .register_session([1u8; 16], "c".to_string(), vec!["text".to_string()], 7)
            .unwrap();

        assert_eq!(manager.list_sessions().len(), 2);
        assert!(manager.get_session(&older).is_none());
        assert!(manager.get_session(&newer).is_some());
    }
}
