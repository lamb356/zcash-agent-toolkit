/** Message types matching the Rust MessageType enum. */
export enum MessageType {
  Handshake = 0x01,
  Text = 0x02,
  Command = 0x03,
  Response = 0x04,
  Ack = 0x05,
  Close = 0x06,
  Binary = 0x07,
  TaskAssign = 0x10,
  TaskProof = 0x11,
  PaymentConfirm = 0x12,
}

/** A decoded message from one or more memo chunks. */
export interface DecodedMessage {
  sessionId: string;
  msgType: number;
  data: Uint8Array;
  contentHash: string;
}

/** Handshake payload exchanged between agents. */
export interface AgentHandshake {
  agent_id: string;
  public_key: string;
  capabilities: string[];
  protocol_version: number;
}

/** A task assignment from one agent to another. */
export interface TaskAssignment {
  task_id: string;
  description: string;
  reward_zec: number;
  deadline?: string;
  verification_method: string;
  nonce: string;
  created_at?: number;
}

/** Proof that a task has been completed. */
export interface TaskProof {
  task_id: string;
  action: string;
  timestamp: number;
  proof_hash: string;
  metadata?: string;
  nonce: string;
}

/** Confirmation that payment has been sent. */
export interface PaymentConfirmation {
  task_id: string;
  amount_zec: number;
  tx_id: string;
  timestamp: number;
  nonce: string;
}

/** Decoded task message with discriminated type. */
export type TaskMessage =
  | { type: 'assignment'; data: TaskAssignment }
  | { type: 'proof'; data: TaskProof }
  | { type: 'payment'; data: PaymentConfirmation };
