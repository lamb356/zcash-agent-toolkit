#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    Transparent,
    Sapling,
    Unified,
    Unknown,
}

/// Classify a Zcash address by its prefix.
///
/// Returns [`AddressType::Transparent`] for `t1`/`t3` prefixes,
/// [`AddressType::Sapling`] for `zs`, [`AddressType::Unified`] for `u1`,
/// and [`AddressType::Unknown`] for everything else.
pub fn classify_address(addr: &str) -> AddressType {
    if addr.len() < 20 {
        return AddressType::Unknown;
    }
    if addr.starts_with("t1") || addr.starts_with("t3") {
        AddressType::Transparent
    } else if addr.starts_with("zs") {
        AddressType::Sapling
    } else if addr.starts_with("u1") {
        AddressType::Unified
    } else {
        AddressType::Unknown
    }
}

/// Check if an address supports encrypted memo fields.
///
/// Only shielded address types (Sapling and Unified) support memos.
pub fn supports_memos(addr: &str) -> bool {
    matches!(
        classify_address(addr),
        AddressType::Sapling | AddressType::Unified
    )
}

/// Check if an address is shielded (same as [`supports_memos`] for now).
pub fn is_shielded(addr: &str) -> bool {
    supports_memos(addr)
}

/// Basic format validation -- checks prefix and minimum length.
///
/// This performs surface-level validation only (correct prefix and a
/// reasonable character count). It does **not** verify checksums or
/// perform full cryptographic validation.
pub fn validate_address(addr: &str) -> bool {
    let addr_type = classify_address(addr);
    if addr_type == AddressType::Unknown {
        return false;
    }
    match addr_type {
        AddressType::Transparent => addr.len() >= 26 && addr.len() <= 36,
        AddressType::Sapling => addr.len() >= 40,
        AddressType::Unified => addr.len() >= 40,
        AddressType::Unknown => false,
    }
}

/// Generate a deterministic agent ID from a 32-byte public key.
///
/// Computes the BLAKE3 hash of `pubkey`, takes the first 16 bytes of
/// the digest, and hex-encodes them into a 32-character lowercase string.
pub fn agent_id_from_pubkey(pubkey: &[u8; 32]) -> String {
    let hash = blake3::hash(pubkey);
    let bytes = hash.as_bytes();
    hex::encode(&bytes[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- classify_address ---

    #[test]
    fn classify_transparent_t1() {
        let addr = "t1RqbJRnFpMgP7hMGBg2yEMkfJFoNqai4nA";
        assert_eq!(classify_address(addr), AddressType::Transparent);
    }

    #[test]
    fn classify_transparent_t3() {
        let addr = "t3XyzABCDEFGHJKLMNPQRSTUVWXYZ012345";
        assert_eq!(classify_address(addr), AddressType::Transparent);
    }

    #[test]
    fn classify_sapling() {
        let addr = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly";
        assert_eq!(classify_address(addr), AddressType::Sapling);
    }

    #[test]
    fn classify_unified() {
        let addr = "u1abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890def";
        assert_eq!(classify_address(addr), AddressType::Unified);
    }

    #[test]
    fn classify_garbage() {
        assert_eq!(
            classify_address("this_is_not_a_real_address"),
            AddressType::Unknown
        );
    }

    #[test]
    fn classify_empty() {
        assert_eq!(classify_address(""), AddressType::Unknown);
    }

    #[test]
    fn classify_bitcoin_bech32() {
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        assert_eq!(classify_address(addr), AddressType::Unknown);
    }

    // --- supports_memos ---

    #[test]
    fn memos_false_for_transparent() {
        let addr = "t1RqbJRnFpMgP7hMGBg2yEMkfJFoNqai4nA";
        assert!(!supports_memos(addr));
    }

    #[test]
    fn memos_true_for_sapling() {
        let addr = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly";
        assert!(supports_memos(addr));
    }

    #[test]
    fn memos_true_for_unified() {
        let addr = "u1abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890def";
        assert!(supports_memos(addr));
    }

    // --- is_shielded ---

    #[test]
    fn shielded_matches_memos_transparent() {
        let addr = "t1RqbJRnFpMgP7hMGBg2yEMkfJFoNqai4nA";
        assert_eq!(is_shielded(addr), supports_memos(addr));
    }

    #[test]
    fn shielded_matches_memos_sapling() {
        let addr = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly";
        assert_eq!(is_shielded(addr), supports_memos(addr));
    }

    #[test]
    fn shielded_matches_memos_unified() {
        let addr = "u1abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890def";
        assert_eq!(is_shielded(addr), supports_memos(addr));
    }

    // --- validate_address ---

    #[test]
    fn validate_good_transparent() {
        // 35 chars, within 26..=36
        let addr = "t1RqbJRnFpMgP7hMGBg2yEMkfJFoNqai4nA";
        assert!(validate_address(addr));
    }

    #[test]
    fn validate_good_sapling() {
        let addr = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly";
        assert!(validate_address(addr));
    }

    #[test]
    fn validate_good_unified() {
        let addr = "u1abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890def";
        assert!(validate_address(addr));
    }

    #[test]
    fn validate_garbage() {
        assert!(!validate_address("garbage"));
    }

    #[test]
    fn validate_empty() {
        assert!(!validate_address(""));
    }

    #[test]
    fn validate_too_short_transparent() {
        // 20 chars, classified as transparent but too short for validation
        let addr = "t1ABCDEFGHIJKLMNOPQR";
        assert!(!validate_address(addr));
    }

    // --- agent_id_from_pubkey ---

    #[test]
    fn agent_id_deterministic() {
        let pubkey = [42u8; 32];
        let id1 = agent_id_from_pubkey(&pubkey);
        let id2 = agent_id_from_pubkey(&pubkey);
        assert_eq!(id1, id2);
    }

    #[test]
    fn agent_id_length() {
        let pubkey = [0u8; 32];
        let id = agent_id_from_pubkey(&pubkey);
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn agent_id_different_inputs() {
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        assert_ne!(agent_id_from_pubkey(&pk_a), agent_id_from_pubkey(&pk_b));
    }

    #[test]
    fn agent_id_lowercase_hex() {
        let pubkey = [0xff; 32];
        let id = agent_id_from_pubkey(&pubkey);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(id, id.to_lowercase());
    }
}
