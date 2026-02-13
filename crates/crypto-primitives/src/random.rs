/// Generate a vector of cryptographically secure random bytes.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).expect("failed to generate random bytes");
    buf
}

/// Generate a fixed-size array of cryptographically secure random bytes.
pub fn random_bytes_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("failed to generate random bytes");
    buf
}

/// Generate random bytes and return as a lowercase hex string.
pub fn random_hex(byte_len: usize) -> String {
    hex::encode(random_bytes(byte_len))
}

/// Generate a 16-byte random session identifier.
pub fn generate_session_id() -> [u8; 16] {
    random_bytes_array::<16>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_returns_correct_length() {
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(1).len(), 1);
        assert_eq!(random_bytes(64).len(), 64);
        assert_eq!(random_bytes(256).len(), 256);
    }

    #[test]
    fn random_hex_returns_correct_length() {
        // Each byte becomes 2 hex chars
        assert_eq!(random_hex(0).len(), 0);
        assert_eq!(random_hex(1).len(), 2);
        assert_eq!(random_hex(16).len(), 32);
        assert_eq!(random_hex(32).len(), 64);
    }

    #[test]
    fn generate_session_id_returns_16_bytes() {
        let id = generate_session_id();
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn two_session_ids_are_different() {
        let a = generate_session_id();
        let b = generate_session_id();
        assert_ne!(a, b);
    }
}
