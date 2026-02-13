import { ensureInit, getWasm } from './wasm.js';

/** Compute a BLAKE3 hash, returning 32 bytes. */
export async function blake3Hash(data: Uint8Array): Promise<Uint8Array> {
  await ensureInit();
  return getWasm().blake3Hash(data);
}

/** Compute a BLAKE3 hash, returning a lowercase hex string. */
export async function blake3Hex(data: Uint8Array): Promise<string> {
  await ensureInit();
  return getWasm().blake3HashHex(data);
}

/** Derive a 32-byte key via BLAKE3 KDF. */
export async function blake3DeriveKey(
  context: string,
  ikm: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return getWasm().blake3DeriveKey(context, ikm);
}

/** Compute a BLAKE3 keyed hash (MAC). Key must be 32 bytes. */
export async function blake3KeyedHash(
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  await ensureInit();
  return getWasm().blake3KeyedHash(key, data);
}

/** Generate cryptographically secure random bytes. */
export async function randomBytes(len: number): Promise<Uint8Array> {
  await ensureInit();
  return getWasm().randomBytes(len);
}

/** Generate random bytes as a lowercase hex string. */
export async function randomHex(byteLen: number): Promise<string> {
  await ensureInit();
  return getWasm().randomHex(byteLen);
}

/** Generate a 16-byte random session ID. */
export async function generateSessionId(): Promise<Uint8Array> {
  await ensureInit();
  return getWasm().generateSessionId();
}
