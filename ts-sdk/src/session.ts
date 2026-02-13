import { ensureInit, getWasm } from './wasm.js';
import type { AgentHandshake } from './types.js';

const MEMO_SIZE = 512;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * A full encrypted agent session.
 *
 * Manages keypair generation, handshake exchange, shared secret derivation,
 * and encrypted message sending/receiving.
 */
export class AgentSession {
  private _keypair: any; // WasmAgentKeyPair
  private _cipher: any | null = null; // WasmAgentCipher
  private _sessionId: Uint8Array;

  private constructor(keypair: any, sessionId: Uint8Array) {
    this._keypair = keypair;
    this._sessionId = sessionId;
  }

  /** Create a new agent session with a fresh keypair and random session ID. */
  static async create(): Promise<AgentSession> {
    await ensureInit();
    const wasm = getWasm();
    const keypair = new wasm.WasmAgentKeyPair();
    const sessionId = wasm.generateSessionId();
    return new AgentSession(keypair, sessionId);
  }

  /** Get the agent's public key as a hex string. */
  get publicKey(): string {
    return this._keypair.publicKeyHex();
  }

  /** Get the agent's deterministic ID (BLAKE3 hash of public key). */
  get agentId(): string {
    return getWasm().agentIdFromPubkey(this._keypair.publicKeyBytes());
  }

  /** Get the session ID as a hex string. */
  get sessionId(): string {
    return bytesToHex(this._sessionId);
  }

  /** Derive shared secret from peer's public key (hex). Returns shared secret hex. */
  async deriveSharedSecret(peerPublicKeyHex: string): Promise<string> {
    const peerBytes = hexToBytes(peerPublicKeyHex);
    const secret = this._keypair.diffieHellman(peerBytes);
    this._cipher = new (getWasm().WasmAgentCipher)(secret);
    return bytesToHex(secret);
  }

  /** Encrypt plaintext string. Requires deriveSharedSecret to have been called. */
  encrypt(plaintext: string): string {
    if (!this._cipher) throw new Error('No shared secret derived. Call deriveSharedSecret first.');
    const data = encoder.encode(plaintext);
    const encrypted = this._cipher.encrypt(data);
    return bytesToHex(encrypted);
  }

  /** Decrypt hex-encoded ciphertext. */
  decrypt(encryptedHex: string): string {
    if (!this._cipher) throw new Error('No shared secret derived. Call deriveSharedSecret first.');
    const data = hexToBytes(encryptedHex);
    const decrypted = this._cipher.decrypt(data);
    return decoder.decode(decrypted);
  }

  /** Create a handshake and encode it as hex memo strings. */
  async createHandshake(
    capabilities: string[] = [],
  ): Promise<{ handshake: AgentHandshake; memos: string[] }> {
    const wasm = getWasm();
    const handshake = wasm.createHandshake(this._keypair, capabilities);
    const flat = wasm.encodeHandshake(handshake, this._sessionId);
    return { handshake, memos: flatToHexMemos(flat) };
  }

  /** Process a received handshake from hex memos. Returns the peer's handshake. */
  async processHandshake(memoHexArray: string[]): Promise<AgentHandshake> {
    const flat = hexMemosToFlat(memoHexArray);
    return getWasm().decodeHandshake(flat);
  }

  /** Encrypt a command object and encode as hex memo strings. */
  async sendCommand(command: object): Promise<string[]> {
    if (!this._cipher) throw new Error('No shared secret derived.');
    const json = JSON.stringify(command);
    const data = encoder.encode(json);
    const encrypted = this._cipher.encrypt(data);
    const flat = getWasm().encodeMemos(encrypted, 0x03, this._sessionId);
    return flatToHexMemos(flat);
  }

  /** Decode and decrypt command memos back into an object. */
  async receiveCommand(memoHexArray: string[]): Promise<object> {
    if (!this._cipher) throw new Error('No shared secret derived.');
    const flat = hexMemosToFlat(memoHexArray);
    const decoded = getWasm().decodeMemos(flat);
    const decrypted = this._cipher.decrypt(decoded.data);
    const json = decoder.decode(decrypted);
    return JSON.parse(json);
  }
}

// --- Helpers ---

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

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
    const bytes = hexToBytes(hexArray[i]);
    flat.set(bytes, i * MEMO_SIZE);
  }
  return flat;
}
