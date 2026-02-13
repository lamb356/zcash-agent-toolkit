import { ensureInit, getWasm } from './wasm.js';

/** Classify a Zcash address by prefix. Returns "Transparent", "Sapling", "Unified", or "Unknown". */
export async function classifyAddress(addr: string): Promise<string> {
  await ensureInit();
  return getWasm().classifyAddress(addr);
}

/** Check if an address supports encrypted memo fields. */
export async function supportsMemos(addr: string): Promise<boolean> {
  await ensureInit();
  return getWasm().supportsMemos(addr);
}

/** Check if an address is shielded. */
export async function isShielded(addr: string): Promise<boolean> {
  await ensureInit();
  return getWasm().isShielded(addr);
}

/** Basic format validation for Zcash addresses. */
export async function validateAddress(addr: string): Promise<boolean> {
  await ensureInit();
  return getWasm().validateAddress(addr);
}

/** Generate a deterministic agent ID from a 32-byte public key. */
export async function agentIdFromPubkey(pubkey: Uint8Array): Promise<string> {
  await ensureInit();
  return getWasm().agentIdFromPubkey(pubkey);
}
