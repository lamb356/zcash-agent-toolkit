use std::fmt;

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
    pub fn from_seed(seed: &[u8; 32], agent_index: u32) -> Result<[u8; 32], KeyDerivationError> {
        if seed.iter().all(|b| *b == 0) {
            return Err(KeyDerivationError::InvalidSeed);
        }

        let context = format!("zcash-agent-toolkit/v1/agent/{agent_index}");
        let secret = blake3::derive_key(&context, seed);
        Ok(blake3::hash(&secret).into())
    }

    pub fn agent_id_from_seed(seed: &[u8; 32], agent_index: u32) -> Result<[u8; 32], KeyDerivationError> {
        Self::from_seed(seed, agent_index)
    }

    pub fn from_extended_key(
        key_bytes: &[u8],
        account_index: u32,
    ) -> Result<[u8; 32], KeyDerivationError> {
        if key_bytes.is_empty() {
            return Err(KeyDerivationError::InvalidExtendedKey);
        }

        let context = format!("zcash-agent-toolkit/v1/from-extsk/{account_index}");
        let secret = blake3::derive_key(&context, key_bytes);
        Ok(blake3::hash(&secret).into())
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
        assert_eq!(a, b);
    }

    #[test]
    fn test_different_indices_different_keys() {
        let seed = [8u8; 32];
        let a = AgentKeyDerivation::from_seed(&seed, 0).expect("derive0");
        let b = AgentKeyDerivation::from_seed(&seed, 1).expect("derive1");
        assert_ne!(a, b);
    }

    #[test]
    fn test_agent_id_matches_seed_derivation() {
        let seed = [9u8; 32];
        let derived = AgentKeyDerivation::from_seed(&seed, 42).expect("derive");
        let agent_id = AgentKeyDerivation::agent_id_from_seed(&seed, 42).expect("agent id");
        assert_eq!(agent_id, derived);
    }

    #[test]
    fn test_from_extended_key_deterministic() {
        let ext = b"extended-spending-key-data";
        let a = AgentKeyDerivation::from_extended_key(ext, 3).expect("derive");
        let b = AgentKeyDerivation::from_extended_key(ext, 3).expect("derive again");
        assert_eq!(a, b);
    }

    #[test]
    fn test_from_extended_key_different_accounts() {
        let ext = b"extended-spending-key-data";
        let a = AgentKeyDerivation::from_extended_key(ext, 3).expect("derive");
        let b = AgentKeyDerivation::from_extended_key(ext, 4).expect("derive");
        assert_ne!(a, b);
    }

    #[test]
    fn test_invalid_seed_rejected() {
        let seed = [0u8; 32];
        let result = AgentKeyDerivation::from_seed(&seed, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_extended_key_rejected() {
        let err = AgentKeyDerivation::from_extended_key(&[], 0);
        assert!(matches!(err, Err(KeyDerivationError::InvalidExtendedKey)));
    }
}
