pub mod classify;

use x25519_dalek::{PublicKey, StaticSecret};

pub use classify::*;

/// Verify that an `agent_id` was derived from a specific seed and index.
pub fn verify_agent_seed_binding(
    agent_id: &[u8; 32],
    seed: &[u8; 32],
    agent_index: u32,
) -> bool {
    let context = format!("zcash-agent-toolkit/v1/agent/{agent_index}");
    let derived_secret = blake3::derive_key(&context, seed);
    let static_secret = StaticSecret::from(derived_secret);
    let public_key = PublicKey::from(&static_secret);
    let expected_id: [u8; 32] = blake3::hash(public_key.as_bytes()).into();
    agent_id == &expected_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_agent_seed_binding_is_true_for_matching_input() {
        let seed = [42u8; 32];
        let context = "zcash-agent-toolkit/v1/agent/11";
        let derived = StaticSecret::from(blake3::derive_key(context, &seed));
        let public = PublicKey::from(&derived).to_bytes();
        let agent_id: [u8; 32] = blake3::hash(&public).into();

        let binding = verify_agent_seed_binding(&agent_id, &seed, 11);
        assert!(binding);
    }

    #[test]
    fn verify_agent_seed_binding_rejects_wrong_seed() {
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];
        let context = "zcash-agent-toolkit/v1/agent/0";
        let derived = StaticSecret::from(blake3::derive_key(context, &seed_a));
        let public = PublicKey::from(&derived).to_bytes();
        let agent_id: [u8; 32] = blake3::hash(&public).into();

        assert!(!verify_agent_seed_binding(&agent_id, &seed_b, 0));
    }

    #[test]
    fn verify_agent_seed_binding_rejects_wrong_index() {
        let seed = [9u8; 32];
        let context = "zcash-agent-toolkit/v1/agent/3";
        let derived = StaticSecret::from(blake3::derive_key(context, &seed));
        let public = PublicKey::from(&derived).to_bytes();
        let agent_id: [u8; 32] = blake3::hash(&public).into();

        assert!(!verify_agent_seed_binding(&agent_id, &seed, 7));
    }
}
