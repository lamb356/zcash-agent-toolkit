import { ensureInit, getWasm } from './wasm.js';
import type { AgentHandshake } from './types.js';

const MEMO_SIZE = 512;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Protocol-only agent session.
 *
 * Tracks identity and capabilities and handles memo-based message encoding/decoding.
 * No local encryption state is stored or managed here; Zcash shielded memos provide
 * confidentiality.
 */
export class AgentSession {
  private _agentId: string;
  private _capabilities: string[];
  private _sessionId: Uint8Array;

  private constructor(agentId: string, capabilities: string[], sessionId: Uint8Array) {
    this._agentId = agentId;
    this._capabilities = capabilities;
    this._sessionId = sessionId;
  }

  /**
   * Create a protocol session with a deterministic agent identifier and capabilities.
   */
  static async create(agentId: string, capabilities: string[]): Promise<AgentSession> {
    if (!agentId) {
      throw new Error('agentId is required');
    }
    await ensureInit();
    const sessionId = getWasm().generateSessionId();
    return new AgentSession(agentId, [...capabilities], sessionId);
  }

  /**
   * Current agent identifier.
   */
  get agentId(): string {
    return this._agentId;
  }

  /**
   * Current capabilities.
   */
  get capabilities(): string[] {
    return [...this._capabilities];
  }

  /**
   * Session identifier used for protocol message threading.
   */
  get sessionId(): Uint8Array {
    return this._sessionId;
  }

  /**
   * Encode this agent's identity and capabilities as handshake memos.
   */
  createHandshake(): Uint8Array[] {
    const handshake = getWasm().createHandshake(this._agentId, this._capabilities) as AgentHandshake;
    const flat = getWasm().encodeHandshake(handshake, this._sessionId);
    return unflatten(flat);
  }

  /**
   * Process a received handshake payload and return identity details.
   */
  processHandshake(memos: Uint8Array[]): {
    agentId: string;
    capabilities: string[];
  } {
    const flat = flatten(memos);
    const handshake: AgentHandshake = getWasm().decodeHandshake(flat);
    return {
      agentId: handshake.agent_id,
      capabilities: handshake.capabilities,
    };
  }

  /** Encode text as memo chunks for Text message type. */
  encodeMessage(text: string): Uint8Array[] {
    const data = encoder.encode(text);
    const flat = getWasm().encodeMemos(data, 0x02, this._sessionId);
    return unflatten(flat);
  }

  /** Decode memo chunks into text. */
  decodeMessage(memos: Uint8Array[]): string {
    const flat = flatten(memos);
    const decoded = getWasm().decodeMemos(flat);
    return decoder.decode(decoded.data);
  }

  /** Encode command JSON as memo chunks for Command message type. */
  encodeCommand(command: string): Uint8Array[] {
    const data = encoder.encode(command);
    const flat = getWasm().encodeMemos(data, 0x03, this._sessionId);
    return unflatten(flat);
  }

  /** Decode command memo chunks into UTF-8 string. */
  decodeCommand(memos: Uint8Array[]): string {
    const flat = flatten(memos);
    const decoded = getWasm().decodeMemos(flat);
    return decoder.decode(decoded.data);
  }
}

function flatten(memos: Uint8Array[]): Uint8Array {
  const flat = new Uint8Array(memos.length * MEMO_SIZE);
  for (let i = 0; i < memos.length; i++) {
    if (memos[i].length !== MEMO_SIZE) {
      throw new Error('each memo must be exactly 512 bytes');
    }
    flat.set(memos[i], i * MEMO_SIZE);
  }
  return flat;
}

function unflatten(flat: Uint8Array): Uint8Array[] {
  if (!flat.length || flat.length % MEMO_SIZE !== 0) {
    throw new Error('flat memo payload must be a non-empty multiple of 512 bytes');
  }
  const count = flat.length / MEMO_SIZE;
  const memos: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    memos.push(flat.slice(i * MEMO_SIZE, (i + 1) * MEMO_SIZE));
  }
  return memos;
}
