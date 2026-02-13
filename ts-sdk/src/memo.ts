import { ensureInit, getWasm } from './wasm.js';
import type { DecodedMessage } from './types.js';

const MEMO_SIZE = 512;
const encoder = new TextEncoder();

/**
 * Codec for encoding/decoding structured messages into Zcash 512-byte memo fields.
 *
 * Handles automatic chunking for messages > 458 bytes, BLAKE3 content hashing,
 * and hex encoding for zcash-cli compatibility.
 */
export class MemoCodec {
  private _sessionId: Uint8Array;

  private constructor(sessionId: Uint8Array) {
    this._sessionId = sessionId;
  }

  /** Create a new MemoCodec with a random session ID. */
  static async create(): Promise<MemoCodec> {
    await ensureInit();
    const sessionId = getWasm().generateSessionId();
    return new MemoCodec(sessionId);
  }

  /** Create a MemoCodec with a specific session ID (hex string). */
  static async fromSession(sessionHex: string): Promise<MemoCodec> {
    await ensureInit();
    const bytes = hexToBytes(sessionHex);
    if (bytes.length !== 16) {
      throw new Error('Session ID must be 16 bytes (32 hex chars)');
    }
    return new MemoCodec(bytes);
  }

  /** Get the session ID as a hex string. */
  get sessionId(): string {
    return bytesToHex(this._sessionId);
  }

  /** Encode a text message into hex memo strings. */
  encodeText(text: string): string[] {
    const data = encoder.encode(text);
    const flat = getWasm().encodeMemos(data, 0x02, this._sessionId);
    return flatToHexMemos(flat);
  }

  /** Encode a JSON command into hex memo strings. */
  encodeCommand(json: object): string[] {
    const data = encoder.encode(JSON.stringify(json));
    const flat = getWasm().encodeMemos(data, 0x03, this._sessionId);
    return flatToHexMemos(flat);
  }

  /** Encode binary data into hex memo strings. */
  encodeBinary(data: Uint8Array): string[] {
    const flat = getWasm().encodeMemos(data, 0x07, this._sessionId);
    return flatToHexMemos(flat);
  }

  /** Encode a TaskAssign message into hex memo strings. */
  encodeTaskAssign(data: Uint8Array): string[] {
    const flat = getWasm().encodeMemos(data, 0x10, this._sessionId);
    return flatToHexMemos(flat);
  }

  /** Decode hex memo strings back into a message. */
  static async decode(memoHexArray: string[]): Promise<DecodedMessage> {
    await ensureInit();
    const flat = hexMemosToFlat(memoHexArray);
    return getWasm().decodeMemos(flat);
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
