pub mod classify;

pub use classify::*;

/// Verify that an `agent_id` was derived from a specific seed and index.
pub fn verify_agent_seed_binding(
    agent_id: &[u8; 32],
    seed: &[u8; 32],
    agent_index: u32,
) -> bool {
    let context = format!("zcash-agent-toolkit/v1/agent/{agent_index}");
    let secret = blake3::derive_key(&context, seed);
    let expected_id: [u8; 32] = blake3::hash(&secret).into();
    agent_id == &expected_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_agent_seed_binding_is_true_for_matching_input() {
        let seed = [42u8; 32];
        let agent_id: [u8; 32] =
            blake3::hash(&blake3::derive_key("zcash-agent-toolkit/v1/agent/11", &seed)).into();
        let result = verify_agent_seed_binding(&agent_id, &seed, 11);
        assert!(result);
    }

    #[test]
    fn verify_agent_seed_binding_rejects_wrong_seed() {
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];
        let agent_id: [u8; 32] =
            blake3::hash(&blake3::derive_key("zcash-agent-toolkit/v1/agent/0", &seed_a)).into();

        assert!(!verify_agent_seed_binding(&agent_id, &seed_b, 0));
    }

    #[test]
    fn verify_agent_seed_binding_rejects_wrong_index() {
        let seed = [9u8; 32];
        let agent_id: [u8; 32] =
            blake3::hash(&blake3::derive_key("zcash-agent-toolkit/v1/agent/3", &seed)).into();
        assert!(!verify_agent_seed_binding(&agent_id, &seed, 7));
    }
}
