/// Compute a BLAKE3 hash of the given data, returning a 32-byte digest.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Compute a BLAKE3 hash and return it as a lowercase hex string.
pub fn blake3_hash_hex(data: &[u8]) -> String {
    hex::encode(blake3_hash(data))
}

/// Compute a BLAKE3 keyed hash (MAC) using a 32-byte key.
pub fn blake3_keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Derive a 32-byte key from context string and input key material using BLAKE3 KDF.
pub fn blake3_derive_key(context: &str, input_key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, input_key_material)
}

/// Streaming BLAKE3 hasher that allows incremental updates.
pub struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Blake3Hasher {
    /// Create a new streaming hasher.
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finalize the hash and return a 32-byte digest.
    pub fn finalize(&self) -> [u8; 32] {
        *self.inner.finalize().as_bytes()
    }

    /// Finalize the hash and return a lowercase hex string.
    pub fn finalize_hex(&self) -> String {
        hex::encode(self.finalize())
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hash_produces_32_bytes() {
        let result = blake3_hash(b"test data");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn blake3_hash_is_deterministic() {
        let a = blake3_hash(b"hello");
        let b = blake3_hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn blake3_hash_different_inputs_different_outputs() {
        let a = blake3_hash(b"hello");
        let b = blake3_hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn blake3_hash_hex_produces_64_char_lowercase_hex() {
        let hex_str = blake3_hash_hex(b"test");
        assert_eq!(hex_str.len(), 64);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hex_str, hex_str.to_lowercase());
    }

    #[test]
    fn blake3_keyed_hash_different_keys_different_outputs() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let data = b"same data";
        let hash_a = blake3_keyed_hash(&key_a, data);
        let hash_b = blake3_keyed_hash(&key_b, data);
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn blake3_derive_key_different_contexts_different_keys() {
        let ikm = b"input key material";
        let key_a = blake3_derive_key("context A", ikm);
        let key_b = blake3_derive_key("context B", ikm);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn blake3_derive_key_different_input_different_keys() {
        let key_a = blake3_derive_key("same context", b"input A");
        let key_b = blake3_derive_key("same context", b"input B");
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn blake3_hasher_streaming_matches_oneshot() {
        let oneshot = blake3_hash(b"hello world");
        let streaming = Blake3Hasher::new()
            .update(b"hello ")
            .update(b"world")
            .finalize();
        assert_eq!(oneshot, streaming);
    }
}
