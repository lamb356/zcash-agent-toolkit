import { ensureInit, getWasm } from './wasm.js';
import { validateHex, hexToBytes } from './hex.js';

/** Derive deterministic agent IDs from seed material. */
export async function deriveAgentId(seedHex: string, agentIndex: number): Promise<string> {
  validateHex(seedHex, 'seed');
  await ensureInit();
  const wasm = getWasm();
  const seedBytes = hexToBytes(seedHex);
  return wasm.deriveAgentId(seedBytes, agentIndex);
}
