use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetError {
    SkipLimitExceeded { requested: u64, max: u64 },
    MessageKeyConsumed(u64),
    InvalidRootKey,
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetError::SkipLimitExceeded { requested, max } => {
                write!(f, "skip limit exceeded when requesting {requested} (max {max})")
            }
            RatchetError::MessageKeyConsumed(index) => {
                write!(f, "message key for index {index} was already consumed")
            }
            RatchetError::InvalidRootKey => write!(f, "invalid root key"),
        }
    }
}

impl std::error::Error for RatchetError {}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RatchetState {
    chain_key: [u8; 32],
    #[zeroize(skip)]
    message_index: u64,
    #[zeroize(skip)]
    skipped_keys: BTreeMap<u64, [u8; 32]>,
}

impl RatchetState {
    pub fn new(root_key: [u8; 32]) -> Self {
        Self {
            chain_key: root_key,
            message_index: 0,
            skipped_keys: BTreeMap::new(),
        }
    }

    pub fn ratchet_forward(&mut self) -> ([u8; 32], u64) {
        let old_index = self.message_index;
        let message_key =
            blake3::derive_key("zcash-agent-toolkit message key v1", &self.chain_key);
        let next_chain_key =
            blake3::derive_key("zcash-agent-toolkit chain key v1", &self.chain_key);

        self.chain_key.zeroize();
        self.chain_key = next_chain_key;
        self.message_index = self.message_index.saturating_add(1);

        (message_key, old_index)
    }

    pub fn get_message_key(&mut self, index: u64) -> Result<[u8; 32], RatchetError> {
        match index.cmp(&self.message_index) {
            std::cmp::Ordering::Less => self
                .skipped_keys
                .remove(&index)
                .map_or_else(
                    || Err(RatchetError::MessageKeyConsumed(index)),
                    Ok,
                ),
            std::cmp::Ordering::Equal => {
                let (key, _) = self.ratchet_forward();
                Ok(key)
            }
            std::cmp::Ordering::Greater => {
                let gap = index - self.message_index;
                if gap > 100 {
                    return Err(RatchetError::SkipLimitExceeded {
                        requested: index,
                        max: 100,
                    });
                }

                for _ in 0..=gap {
                    let (key, idx) = self.ratchet_forward();
                    if idx < index {
                        self.insert_skipped(idx, key);
                    } else {
                        return Ok(key);
                    }
                }

                Err(RatchetError::InvalidRootKey)
            }
        }
    }

    fn insert_skipped(&mut self, index: u64, key: [u8; 32]) {
        self.skipped_keys.insert(index, key);
        self.enforce_skip_limit();
    }

    fn enforce_skip_limit(&mut self) {
        while self.skipped_keys.len() > 100 {
            if let Some((&oldest, _)) = self.skipped_keys.iter().next() {
                if let Some(mut key) = self.skipped_keys.remove(&oldest) {
                    key.zeroize();
                }
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentCipher, CipherError};
    use std::collections::HashSet;

    fn make_root() -> [u8; 32] {
        [1u8; 32]
    }

    #[test]
    fn test_ratchet_produces_unique_keys() {
        let mut ratchet = RatchetState::new(make_root());
        let mut keys = HashSet::new();

        for _ in 0..100 {
            let (key, _) = ratchet.ratchet_forward();
            assert!(keys.insert(key));
        }

        assert_eq!(keys.len(), 100);
    }

    #[test]
    fn test_ratchet_forward_secrecy() {
        let mut ratchet = RatchetState::new(make_root());
        for _ in 0..10 {
            let _ = ratchet.ratchet_forward();
        }

        let chain_key = ratchet.chain_key;

        let mut stale = RatchetState::new(chain_key);
        stale.message_index = 10;

        let err = stale
            .get_message_key(5)
            .expect_err("index 5 should be consumed in stale state");
        assert!(matches!(err, RatchetError::MessageKeyConsumed(5)));
    }

    #[test]
    fn test_ratchet_deterministic() {
        let mut a = RatchetState::new(make_root());
        let mut b = RatchetState::new(make_root());

        for _ in 0..50 {
            let (a_key, _) = a.ratchet_forward();
            let (b_key, _) = b.ratchet_forward();
            assert_eq!(a_key, b_key);
        }
    }

    #[test]
    fn test_skipped_message_keys() {
        let mut alice = RatchetState::new(make_root());
        let _ = alice
            .get_message_key(5)
            .expect("cache skip from 0 to 5");

        let key3 = alice
            .get_message_key(3)
            .expect("consume key for index 3 from skipped");
        let key4 = alice
            .get_message_key(4)
            .expect("consume key for index 4 from skipped");

        assert!(matches!(
            alice.get_message_key(3),
            Err(RatchetError::MessageKeyConsumed(3))
        ));

        assert_ne!(key3, key4);
    }

    #[test]
    fn test_skip_limit_exceeded() {
        let mut ratchet = RatchetState::new(make_root());
        let err = ratchet
            .get_message_key(200)
            .expect_err("skipping more than 100 should fail");
        assert!(matches!(
            err,
            RatchetError::SkipLimitExceeded {
                requested,
                max
            } if requested == 200 && max == 100
        ));
    }

    #[test]
    fn test_encrypt_decrypt_with_ratchet() -> Result<(), CipherError> {
        let root = make_root();

        let mut alice = RatchetState::new(root);
        let mut bob = RatchetState::new(root);

        for i in 0..3 {
            let plaintext = format!("message {i}");

            let key_a = alice.ratchet_forward().0;
            let key_b = bob.ratchet_forward().0;
            assert_eq!(key_a, key_b);

            let cipher_a = AgentCipher::from_key(key_a);
            let cipher_b = AgentCipher::from_key(key_b);

            let encrypted = cipher_a.encrypt(plaintext.as_bytes())?;
            let decrypted = cipher_b.decrypt(&encrypted)?;
            assert_eq!(decrypted, plaintext.as_bytes());
        }

        Ok(())
    }

    #[test]
    fn test_out_of_order_decrypt() {
        let root = make_root();
        let mut sender = RatchetState::new(root);
        let mut receiver = RatchetState::new(root);

        let mut ciphertexts = Vec::new();
        for i in 0..5 {
            let plaintext = format!("message-{i}");
            let key = sender.ratchet_forward().0;
            let cipher = AgentCipher::from_key(key);
            let encrypted = cipher
                .encrypt(plaintext.as_bytes())
                .expect("encrypt message");
            ciphertexts.push(encrypted);
        }

        for i in [4u64, 1, 0, 3, 2] {
            let key = receiver.get_message_key(i).expect("get key");
            let cipher = AgentCipher::from_key(key);
            let decrypted = cipher
                .decrypt(&ciphertexts[i as usize])
                .expect("decrypt out-of-order");
            let expected = format!("message-{i}");
            assert_eq!(decrypted, expected.as_bytes());
        }
    }

    #[test]
    fn test_replay_rejected() {
        let mut receiver = RatchetState::new(make_root());
        let _ = receiver.get_message_key(3).expect("derive index 3");

        let replay = receiver.get_message_key(3);
        assert!(matches!(replay, Err(RatchetError::MessageKeyConsumed(3))));
    }
}

