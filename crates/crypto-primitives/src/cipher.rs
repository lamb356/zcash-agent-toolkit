use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

/// Authenticated encryption cipher for agent communication.
pub struct AgentCipher {
    key: [u8; 32],
}

/// Errors that can occur during cipher operations.
#[derive(Debug)]
pub enum CipherError {
    /// Decryption failed (wrong key or tampered data).
    DecryptionFailed,
    /// Ciphertext is too short or malformed.
    InvalidCiphertext,
    /// Hex string could not be decoded.
    InvalidKeyHex,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::DecryptionFailed => write!(f, "decryption failed"),
            CipherError::InvalidCiphertext => write!(f, "invalid ciphertext"),
            CipherError::InvalidKeyHex => write!(f, "invalid key hex"),
        }
    }
}

impl std::error::Error for CipherError {}

impl AgentCipher {
    /// Create a cipher from a shared secret, deriving the encryption key via BLAKE3 KDF.
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let key = blake3::derive_key("zcash-agent-toolkit v1 encryption key", shared_secret);
        Self { key }
    }

    /// Create a cipher from a raw 32-byte key directly.
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Encrypt plaintext. Returns nonce (12 bytes) || ciphertext || tag (16 bytes).
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).expect("failed to generate random nonce");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Decrypt data formatted as nonce (12 bytes) || ciphertext || tag (16 bytes).
    /// Returns the plaintext or an error.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherError> {
        if data.len() < 12 + 16 {
            return Err(CipherError::InvalidCiphertext);
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).unwrap();
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CipherError::DecryptionFailed)
    }

    /// Encrypt plaintext and return the result as a hex string.
    pub fn encrypt_hex(&self, plaintext: &[u8]) -> String {
        hex::encode(self.encrypt(plaintext))
    }

    /// Decrypt from a hex-encoded string.
    pub fn decrypt_hex(&self, hex_str: &str) -> Result<Vec<u8>, CipherError> {
        let data = hex::decode(hex_str).map_err(|_| CipherError::InvalidCiphertext)?;
        self.decrypt(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher() -> AgentCipher {
        AgentCipher::from_key([42u8; 32])
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let cipher = test_cipher();
        let plaintext = b"hello, zcash agent!";
        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let cipher_a = AgentCipher::from_key([1u8; 32]);
        let cipher_b = AgentCipher::from_key([2u8; 32]);
        let ciphertext = cipher_a.encrypt(b"secret");
        let result = cipher_b.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let cipher = test_cipher();
        let mut ciphertext = cipher.encrypt(b"important data");
        // Flip a byte in the ciphertext portion (after the 12-byte nonce)
        let idx = 12 + (ciphertext.len() - 12) / 2;
        ciphertext[idx] ^= 0xFF;
        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn two_encryptions_produce_different_ciphertext() {
        let cipher = test_cipher();
        let plaintext = b"same message";
        let ct_a = cipher.encrypt(plaintext);
        let ct_b = cipher.encrypt(plaintext);
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let cipher = test_cipher();
        let ciphertext = cipher.encrypt(b"");
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let cipher = test_cipher();
        let plaintext = vec![0xABu8; 10 * 1024]; // 10 KB
        let ciphertext = cipher.encrypt(&plaintext);
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_hex_decrypt_hex_roundtrip() {
        let cipher = test_cipher();
        let plaintext = b"hex roundtrip test";
        let hex_ct = cipher.encrypt_hex(plaintext);
        let decrypted = cipher.decrypt_hex(&hex_ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_too_short_data_returns_invalid_ciphertext() {
        let cipher = test_cipher();
        // Less than 28 bytes (12 nonce + 16 tag)
        let short_data = vec![0u8; 27];
        let result = cipher.decrypt(&short_data);
        assert!(matches!(result, Err(CipherError::InvalidCiphertext)));
    }
}
