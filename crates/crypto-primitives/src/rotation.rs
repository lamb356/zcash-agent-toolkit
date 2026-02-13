use crate::key_exchange::{AgentKeyPair, KeyExchangeError};
use crate::random::RandomError;

pub struct RotatingKeyPair {
    current: AgentKeyPair,
    previous: Option<AgentKeyPair>,
    generation: u32,
    pub(crate) created_at: u64,
    message_count: u32,
}

impl RotatingKeyPair {
    pub fn new(created_at: u64) -> Result<Self, RandomError> {
        Ok(Self {
            current: AgentKeyPair::generate(),
            previous: None,
            generation: 0,
            created_at,
            message_count: 0,
        })
    }

    pub fn rotate(&mut self, now: u64) -> Result<(), RandomError> {
        let previous = std::mem::replace(&mut self.current, AgentKeyPair::generate());

        if let Some(mut old_previous) = self.previous.take() {
            old_previous.zeroize_secret();
        }

        self.previous = Some(previous);
        self.generation = self.generation.saturating_add(1);
        self.created_at = now;
        self.message_count = 0;
        Ok(())
    }

    pub fn current_public_key(&self) -> [u8; 32] {
        self.current.public_key_bytes()
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn increment_message_count(&mut self) {
        self.message_count = self.message_count.saturating_add(1);
    }

    pub fn should_rotate(&self, max_age_secs: u64, max_messages: u32) -> bool {
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => self.created_at,
        };

        now.saturating_sub(self.created_at) > max_age_secs || self.message_count > max_messages
    }

    pub fn derive_shared_secret(
        &self,
        their_public: &[u8; 32],
    ) -> Result<[u8; 32], KeyExchangeError> {
        let current_secret = self.current.diffie_hellman(their_public);

        if let Some(previous) = self.previous.as_ref() {
            if previous.public_key_bytes() == *their_public {
                let previous_secret = previous.diffie_hellman(their_public);
                if !is_zero_key(&previous_secret) {
                    return Ok(previous_secret);
                }
            }
        }

        if !is_zero_key(&current_secret) {
            return Ok(current_secret);
        }

        if let Some(previous) = self.previous.as_ref() {
            let previous_secret = previous.diffie_hellman(their_public);
            if !is_zero_key(&previous_secret) {
                return Ok(previous_secret);
            }
        }

        Err(KeyExchangeError::InvalidSharedSecret)
    }
}

fn is_zero_key(secret: &[u8; 32]) -> bool {
    secret.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pair() -> RotatingKeyPair {
        RotatingKeyPair::new(10_000).expect("create rotating pair")
    }

    #[test]
    fn rotation_produces_new_keys() {
        let mut pair = make_pair();
        let mut keys = Vec::new();

        keys.push(pair.current_public_key());
        for offset in 0..5 {
            pair.rotate(pair.created_at + offset).expect("rotate");
            keys.push(pair.current_public_key());
        }

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }

    #[test]
    fn previous_key_available() {
        let old_secret = [11u8; 32];
        let old_pair = AgentKeyPair::from_secret_bytes(old_secret).unwrap();
        let old_pub = old_pair.public_key_bytes();
        let mut pair = RotatingKeyPair {
            current: old_pair,
            previous: None,
            generation: 0,
            created_at: 10_000,
            message_count: 0,
        };

        pair.rotate(pair.created_at + 1).expect("rotate once");
        let new_pub = pair.current_public_key();
        assert_ne!(old_pub, new_pub);

        let peer = AgentKeyPair::from_secret_bytes(old_secret).unwrap();
        let expected = peer.diffie_hellman(&old_pub);
        let recovered = pair
            .derive_shared_secret(&old_pub)
            .expect("derive using previous");
        assert_eq!(recovered, expected);
    }

    #[test]
    fn two_rotations_drops_oldest() {
        let gen0 = AgentKeyPair::from_secret_bytes([1u8; 32]).unwrap();
        let gen1 = AgentKeyPair::from_secret_bytes([2u8; 32]).unwrap();
        let gen2 = AgentKeyPair::from_secret_bytes([3u8; 32]).unwrap();

        let gen0_pub = gen0.public_key_bytes();
        let gen1_pub = gen1.public_key_bytes();

        let pair = RotatingKeyPair {
            current: gen2,
            previous: Some(gen1),
            generation: 2,
            created_at: 10_000,
            message_count: 0,
        };

        assert!(pair.previous.is_some());
        let prev_pub = pair.previous.as_ref().unwrap().public_key_bytes();
        assert_eq!(prev_pub, gen1_pub);
        assert_ne!(prev_pub, gen0_pub);

        let peer_prev = AgentKeyPair::from_secret_bytes([2u8; 32]).unwrap();
        let expected_prev = peer_prev.diffie_hellman(&gen1_pub);
        let recovered_prev = pair
            .derive_shared_secret(&gen1_pub)
            .expect("derive with prev pub");
        assert_eq!(recovered_prev, expected_prev);

        let peer_curr = AgentKeyPair::from_secret_bytes([3u8; 32]).unwrap();
        let gen2_pub = pair.current_public_key();
        let expected_curr = peer_curr.diffie_hellman(&gen2_pub);
        let recovered_curr = pair
            .derive_shared_secret(&gen2_pub)
            .expect("derive with current pub");
        assert_eq!(recovered_curr, expected_curr);
    }

    #[test]
    fn should_rotate_by_age() {
        let pair = RotatingKeyPair::new(0).expect("create at epoch");
        assert!(pair.should_rotate(3600, 1000));
    }

    #[test]
    fn should_rotate_by_message_count() {
        let mut pair = RotatingKeyPair::new(10).expect("create at t");

        for _ in 0..500 {
            pair.increment_message_count();
        }

        assert!(pair.should_rotate(9_999_999, 500));
    }

    #[test]
    fn generation_increments() {
        let mut pair = make_pair();
        assert_eq!(pair.generation(), 0);

        pair.rotate(11).expect("rotate one");
        assert_eq!(pair.generation(), 1);

        pair.rotate(12).expect("rotate two");
        assert_eq!(pair.generation(), 2);
    }
}
