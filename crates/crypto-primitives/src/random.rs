/// Errors that can occur during random number generation.
#[derive(Debug)]
pub enum RandomError {
    /// The underlying OS random number generator failed.
    GetrandomFailed,
}

impl std::fmt::Display for RandomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RandomError::GetrandomFailed => write!(f, "getrandom failed"),
        }
    }
}

impl std::error::Error for RandomError {}

/// Generate a vector of cryptographically secure random bytes.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, RandomError> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|_| RandomError::GetrandomFailed)?;
    Ok(buf)
}

/// Generate a fixed-size array of cryptographically secure random bytes.
pub fn random_bytes_array<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| RandomError::GetrandomFailed)?;
    Ok(buf)
}

/// Generate random bytes and return as a lowercase hex string.
pub fn random_hex(byte_len: usize) -> Result<String, RandomError> {
    Ok(hex::encode(random_bytes(byte_len)?))
}

/// Generate a 16-byte random session identifier.
pub fn generate_session_id() -> Result<[u8; 16], RandomError> {
    random_bytes_array::<16>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_returns_correct_length() {
        assert_eq!(random_bytes(0).unwrap().len(), 0);
        assert_eq!(random_bytes(1).unwrap().len(), 1);
        assert_eq!(random_bytes(64).unwrap().len(), 64);
        assert_eq!(random_bytes(256).unwrap().len(), 256);
    }

    #[test]
    fn random_hex_returns_correct_length() {
        // Each byte becomes 2 hex chars
        assert_eq!(random_hex(0).unwrap().len(), 0);
        assert_eq!(random_hex(1).unwrap().len(), 2);
        assert_eq!(random_hex(16).unwrap().len(), 32);
        assert_eq!(random_hex(32).unwrap().len(), 64);
    }

    #[test]
    fn generate_session_id_returns_16_bytes() {
        let id = generate_session_id().unwrap();
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn two_session_ids_are_different() {
        let a = generate_session_id().unwrap();
        let b = generate_session_id().unwrap();
        assert_ne!(a, b);
    }
}
