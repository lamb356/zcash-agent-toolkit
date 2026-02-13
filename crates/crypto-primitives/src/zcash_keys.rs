use std::fmt;

use crate::key_exchange::AgentKeyPair;

#[derive(Debug)]
pub enum KeyDerivationError {
    InvalidSeed,
    InvalidExtendedKey,
    KeyGeneration(String),
}

impl fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyDerivationError::InvalidSeed => write!(f, "invalid seed"),
            KeyDerivationError::InvalidExtendedKey => write!(f, "invalid extended key"),
            KeyDerivationError::KeyGeneration(msg) => write!(f, "key generation failed: {msg}"),
        }
    }
}

impl std::error::Error for KeyDerivationError {}

pub struct AgentKeyDerivation;

impl AgentKeyDerivation {
    pub fn from_seed(seed: &[u8; 32], agent_index: u32) -> Result<AgentKeyPair, KeyDerivationError> {
        if seed.iter().all(|b| *b == 0) {
            return Err(KeyDerivationError::InvalidSeed);
        }

        let context = format!("zcash-agent-toolkit/v1/agent/{agent_index}");
        let derived = blake3::derive_key(&context, seed);
        AgentKeyPair::from_secret_bytes(derived).map_err(|e| KeyDerivationError::KeyGeneration(e.to_string()))
    }

    pub fn agent_id_from_seed(seed: &[u8; 32], agent_index: u32) -> Result<[u8; 32], KeyDerivationError> {
        let keypair = Self::from_seed(seed, agent_index)?;
        Ok(blake3::hash(keypair.public_key_bytes().as_ref()).into())
    }

    pub fn from_extended_key(
        key_bytes: &[u8],
        account_index: u32,
    ) -> Result<AgentKeyPair, KeyDerivationError> {
        if key_bytes.is_empty() {
            return Err(KeyDerivationError::InvalidExtendedKey);
        }

        let context = format!("zcash-agent-toolkit/v1/from-extsk/{account_index}");
        let derived = blake3::derive_key(&context, key_bytes);
        AgentKeyPair::from_secret_bytes(derived)
            .map_err(|e| KeyDerivationError::KeyGeneration(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_derivation() {
        let seed = [7u8; 32];
        let a = AgentKeyDerivation::from_seed(&seed, 0).expect("derive");
        let b = AgentKeyDerivation::from_seed(&seed, 0).expect("derive again");
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn test_different_indices_different_keys() {
        let seed = [8u8; 32];
        let a = AgentKeyDerivation::from_seed(&seed, 0).expect("derive0");
        let b = AgentKeyDerivation::from_seed(&seed, 1).expect("derive1");
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn test_agent_id_matches_keypair() {
        let seed = [9u8; 32];
        let keypair = AgentKeyDerivation::from_seed(&seed, 42).expect("derive");
        let agent_id = AgentKeyDerivation::agent_id_from_seed(&seed, 42).expect("agent id");
        let expected: [u8; 32] = blake3::hash(&keypair.public_key_bytes().as_ref()).into();
        assert_eq!(agent_id, expected);
    }

    #[test]
    fn test_from_extended_key_deterministic() {
        let ext = b"extended-spending-key-data";
        let a = AgentKeyDerivation::from_extended_key(ext, 3).expect("derive");
        let b = AgentKeyDerivation::from_extended_key(ext, 3).expect("derive again");
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn test_from_extended_key_different_accounts() {
        let ext = b"extended-spending-key-data";
        let a = AgentKeyDerivation::from_extended_key(ext, 3).expect("derive");
        let b = AgentKeyDerivation::from_extended_key(ext, 4).expect("derive");
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn test_cross_agent_dh() {
        let seed = [11u8; 32];
        let derived = AgentKeyDerivation::from_seed(&seed, 7).expect("derive");
        let peer = crate::AgentKeyPair::generate();

        let a = derived.diffie_hellman(&peer.public_key_bytes());
        let b = peer.diffie_hellman(&derived.public_key_bytes());
        assert_eq!(a, b);
    }

    #[test]
    fn test_empty_extended_key_rejected() {
        let err = AgentKeyDerivation::from_extended_key(&[], 0);
        assert!(matches!(err, Err(KeyDerivationError::InvalidExtendedKey)));
    }
}
