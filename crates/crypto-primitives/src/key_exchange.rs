use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// An X25519 keypair for agent-to-agent key exchange.
pub struct AgentKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl AgentKeyPair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Reconstruct a keypair from raw secret key bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Return the public key as a 32-byte array.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Return the public key as a lowercase hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public.to_bytes())
    }

    /// Return the secret key as a 32-byte array.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Perform X25519 Diffie-Hellman key exchange and derive a symmetric key via BLAKE3 KDF.
    pub fn diffie_hellman(&self, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(*peer_public_bytes);
        let shared_secret = self.secret.diffie_hellman(&peer_public);
        blake3::derive_key(
            "zcash-agent-toolkit v1 shared secret",
            shared_secret.as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_32_byte_public_key() {
        let kp = AgentKeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
    }

    #[test]
    fn two_keypairs_have_different_public_keys() {
        let a = AgentKeyPair::generate();
        let b = AgentKeyPair::generate();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn from_secret_bytes_roundtrip() {
        let original = AgentKeyPair::generate();
        let secret_bytes = original.secret_key_bytes();
        let restored = AgentKeyPair::from_secret_bytes(secret_bytes);
        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn two_agents_derive_same_shared_secret() {
        let alice = AgentKeyPair::generate();
        let bob = AgentKeyPair::generate();

        let secret_ab = alice.diffie_hellman(&bob.public_key_bytes());
        let secret_ba = bob.diffie_hellman(&alice.public_key_bytes());

        assert_eq!(secret_ab, secret_ba);
    }

    #[test]
    fn different_keypair_combinations_produce_different_shared_secrets() {
        let alice = AgentKeyPair::generate();
        let bob = AgentKeyPair::generate();
        let carol = AgentKeyPair::generate();

        let secret_ab = alice.diffie_hellman(&bob.public_key_bytes());
        let secret_ac = alice.diffie_hellman(&carol.public_key_bytes());

        assert_ne!(secret_ab, secret_ac);
    }

    #[test]
    fn public_key_hex_produces_64_char_lowercase_hex() {
        let kp = AgentKeyPair::generate();
        let hex_str = kp.public_key_hex();
        assert_eq!(hex_str.len(), 64);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hex_str, hex_str.to_lowercase());
    }
}
