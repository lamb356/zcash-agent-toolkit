import { ensureInit, getWasm } from './wasm.js';
import type {
  TaskAssignment,
  TaskProof,
  PaymentConfirmation,
  TaskMessage,
} from './types.js';
import { bytesToHex, hexToBytes } from './hex.js';

const MEMO_SIZE = 512;

/**
 * Static helpers for task/bounty workflow operations.
 */
export class TaskManager {
  /** Encode a task assignment as hex memo strings. */
  static async assignTask(
    sessionId: Uint8Array,
    task: TaskAssignment,
  ): Promise<string[]> {
    await ensureInit();
    const flat = getWasm().encodeTaskAssignment(task, sessionId);
    return flatToHexMemos(flat);
  }

  /** Encode a task proof as hex memo strings. */
  static async submitProof(
    sessionId: Uint8Array,
    proof: TaskProof,
  ): Promise<string[]> {
    await ensureInit();
    const flat = getWasm().encodeTaskProof(proof, sessionId);
    return flatToHexMemos(flat);
  }

  /** Encode a payment confirmation as hex memo strings. */
  static async confirmPayment(
    sessionId: Uint8Array,
    confirmation: PaymentConfirmation,
  ): Promise<string[]> {
    await ensureInit();
    const flat = getWasm().encodePaymentConfirmation(confirmation, sessionId);
    return flatToHexMemos(flat);
  }

  /** Create a task proof with auto-generated BLAKE3 proof hash. */
  static async createTaskProof(
    taskId: string,
    action: string,
    proofData: Uint8Array,
    timestamp: number,
  ): Promise<TaskProof> {
    await ensureInit();
    return getWasm().createTaskProof(taskId, action, proofData, timestamp);
  }

  /** Decode task-related memos into a discriminated TaskMessage. */
  static async processTaskMessage(
    memoHexArray: string[],
  ): Promise<TaskMessage> {
    await ensureInit();
    const flat = hexMemosToFlat(memoHexArray);
    return getWasm().decodeTaskMessage(flat);
  }
}

// --- Helpers ---

function flatToHexMemos(flat: Uint8Array): string[] {
  const count = flat.length / MEMO_SIZE;
  const memos: string[] = [];
  for (let i = 0; i < count; i++) {
    const slice = flat.slice(i * MEMO_SIZE, (i + 1) * MEMO_SIZE);
    memos.push(bytesToHex(slice));
  }
  return memos;
}

function hexMemosToFlat(hexArray: string[]): Uint8Array {
  const flat = new Uint8Array(hexArray.length * MEMO_SIZE);
  for (let i = 0; i < hexArray.length; i++) {
    const bytes = hexToBytes(hexArray[i], `memo[${i}]`);
    flat.set(bytes, i * MEMO_SIZE);
  }
  return flat;
}
