use serde::{Deserialize, Serialize};

use crypto_primitives::blake3_hash_hex;
use memo_codec::{chunk_message, decode_chunked_message, MessageType, MEMO_SIZE};

use crate::ProtocolError;

/// A task assignment sent from one agent to another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskAssignment {
    /// Unique identifier for this task.
    pub task_id: String,
    /// Human-readable description of what needs to be done.
    pub description: String,
    /// Reward in ZEC for completing the task.
    pub reward_zec: f64,
    /// Optional deadline in ISO 8601 format.
    pub deadline: Option<String>,
    /// Method used to verify task completion.
    pub verification_method: String,
}

/// Proof that a task has been completed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskProof {
    /// The task this proof relates to.
    pub task_id: String,
    /// Description of the action taken.
    pub action: String,
    /// Unix timestamp of when the proof was created.
    pub timestamp: u64,
    /// BLAKE3 hash of the proof data as a hex string.
    pub proof_hash: String,
    /// Optional metadata as a JSON string.
    pub metadata: Option<String>,
}

/// Confirmation that payment has been sent for a completed task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaymentConfirmation {
    /// The task this payment relates to.
    pub task_id: String,
    /// Amount paid in ZEC.
    pub amount_zec: f64,
    /// Zcash transaction ID.
    pub tx_id: String,
    /// Unix timestamp of the payment.
    pub timestamp: u64,
}

/// Create a task proof, auto-generating the BLAKE3 proof_hash from the provided proof data.
pub fn create_task_proof(
    task_id: &str,
    action: &str,
    proof_data: &[u8],
    timestamp: u64,
) -> TaskProof {
    TaskProof {
        task_id: task_id.to_string(),
        action: action.to_string(),
        timestamp,
        proof_hash: blake3_hash_hex(proof_data),
        metadata: None,
    }
}

/// Encode a TaskAssignment as TaskAssign-type memos.
pub fn encode_task_assignment(
    task: &TaskAssignment,
    session_id: &[u8; 16],
) -> Vec<[u8; MEMO_SIZE]> {
    let json = serde_json::to_vec(task).expect("task serializes");
    chunk_message(&json, MessageType::TaskAssign, session_id)
}

/// Encode a TaskProof as TaskProof-type memos.
pub fn encode_task_proof(proof: &TaskProof, session_id: &[u8; 16]) -> Vec<[u8; MEMO_SIZE]> {
    let json = serde_json::to_vec(proof).expect("proof serializes");
    chunk_message(&json, MessageType::TaskProof, session_id)
}

/// Encode a PaymentConfirmation as PaymentConfirm-type memos.
pub fn encode_payment_confirmation(
    payment: &PaymentConfirmation,
    session_id: &[u8; 16],
) -> Vec<[u8; MEMO_SIZE]> {
    let json = serde_json::to_vec(payment).expect("payment serializes");
    chunk_message(&json, MessageType::PaymentConfirm, session_id)
}

/// A decoded task-related message, discriminated by variant.
pub enum TaskMessage {
    /// A task assignment.
    Assignment(TaskAssignment),
    /// A proof of task completion.
    Proof(TaskProof),
    /// A payment confirmation.
    Payment(PaymentConfirmation),
}

/// Decode task-related memos. Returns the appropriate variant based on the message type.
pub fn decode_task_message(memos: &[[u8; MEMO_SIZE]]) -> Result<TaskMessage, ProtocolError> {
    let msg = decode_chunked_message(memos).map_err(ProtocolError::Memo)?;
    match msg.msg_type {
        MessageType::TaskAssign => {
            let task: TaskAssignment =
                serde_json::from_slice(&msg.data).map_err(ProtocolError::Json)?;
            Ok(TaskMessage::Assignment(task))
        }
        MessageType::TaskProof => {
            let proof: TaskProof =
                serde_json::from_slice(&msg.data).map_err(ProtocolError::Json)?;
            Ok(TaskMessage::Proof(proof))
        }
        MessageType::PaymentConfirm => {
            let payment: PaymentConfirmation =
                serde_json::from_slice(&msg.data).map_err(ProtocolError::Json)?;
            Ok(TaskMessage::Payment(payment))
        }
        other => Err(ProtocolError::UnexpectedMessageType {
            expected: MessageType::TaskAssign,
            actual: other,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_primitives::generate_session_id;

    fn sample_task() -> TaskAssignment {
        TaskAssignment {
            task_id: "task-001".to_string(),
            description: "Fetch the current ZEC price".to_string(),
            reward_zec: 0.01,
            deadline: Some("2026-12-31T23:59:59Z".to_string()),
            verification_method: "api_response_hash".to_string(),
        }
    }

    fn sample_proof() -> TaskProof {
        TaskProof {
            task_id: "task-001".to_string(),
            action: "fetched_price".to_string(),
            timestamp: 1700000000,
            proof_hash: blake3_hash_hex(b"price=42.50"),
            metadata: Some(r#"{"source":"coingecko"}"#.to_string()),
        }
    }

    fn sample_payment() -> PaymentConfirmation {
        PaymentConfirmation {
            task_id: "task-001".to_string(),
            amount_zec: 0.01,
            tx_id: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            timestamp: 1700000100,
        }
    }

    #[test]
    fn task_assignment_encode_decode_roundtrip() {
        let task = sample_task();
        let session_id = generate_session_id();

        let memos = encode_task_assignment(&task, &session_id);
        let decoded = decode_task_message(&memos).expect("decode");

        match decoded {
            TaskMessage::Assignment(t) => assert_eq!(t, task),
            _ => panic!("expected Assignment variant"),
        }
    }

    #[test]
    fn task_proof_encode_decode_roundtrip() {
        let proof = sample_proof();
        let session_id = generate_session_id();

        let memos = encode_task_proof(&proof, &session_id);
        let decoded = decode_task_message(&memos).expect("decode");

        match decoded {
            TaskMessage::Proof(p) => assert_eq!(p, proof),
            _ => panic!("expected Proof variant"),
        }
    }

    #[test]
    fn payment_confirmation_encode_decode_roundtrip() {
        let payment = sample_payment();
        let session_id = generate_session_id();

        let memos = encode_payment_confirmation(&payment, &session_id);
        let decoded = decode_task_message(&memos).expect("decode");

        match decoded {
            TaskMessage::Payment(p) => assert_eq!(p, payment),
            _ => panic!("expected Payment variant"),
        }
    }

    #[test]
    fn create_task_proof_generates_correct_blake3_hash() {
        let proof_data = b"some proof data for verification";
        let expected_hash = blake3_hash_hex(proof_data);

        let proof = create_task_proof("task-002", "completed_work", proof_data, 1700000050);

        assert_eq!(proof.task_id, "task-002");
        assert_eq!(proof.action, "completed_work");
        assert_eq!(proof.timestamp, 1700000050);
        assert_eq!(proof.proof_hash, expected_hash);
        assert!(proof.metadata.is_none());
    }

    #[test]
    fn full_lifecycle_assign_proof_confirm() {
        let session_id = generate_session_id();

        // Step 1: Assign
        let task = sample_task();
        let assign_memos = encode_task_assignment(&task, &session_id);
        let decoded_assign = decode_task_message(&assign_memos).expect("decode assign");
        match decoded_assign {
            TaskMessage::Assignment(t) => assert_eq!(t, task),
            _ => panic!("expected Assignment"),
        }

        // Step 2: Prove
        let proof = sample_proof();
        let proof_memos = encode_task_proof(&proof, &session_id);
        let decoded_proof = decode_task_message(&proof_memos).expect("decode proof");
        match decoded_proof {
            TaskMessage::Proof(p) => assert_eq!(p, proof),
            _ => panic!("expected Proof"),
        }

        // Step 3: Confirm payment
        let payment = sample_payment();
        let pay_memos = encode_payment_confirmation(&payment, &session_id);
        let decoded_pay = decode_task_message(&pay_memos).expect("decode payment");
        match decoded_pay {
            TaskMessage::Payment(p) => assert_eq!(p, payment),
            _ => panic!("expected Payment"),
        }
    }

    #[test]
    fn decode_task_message_identifies_correct_variant() {
        let session_id = generate_session_id();

        let task = sample_task();
        let memos = encode_task_assignment(&task, &session_id);
        assert!(matches!(
            decode_task_message(&memos).unwrap(),
            TaskMessage::Assignment(_)
        ));

        let proof = sample_proof();
        let memos = encode_task_proof(&proof, &session_id);
        assert!(matches!(
            decode_task_message(&memos).unwrap(),
            TaskMessage::Proof(_)
        ));

        let payment = sample_payment();
        let memos = encode_payment_confirmation(&payment, &session_id);
        assert!(matches!(
            decode_task_message(&memos).unwrap(),
            TaskMessage::Payment(_)
        ));
    }
}
