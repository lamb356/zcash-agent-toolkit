import { ensureInit, getWasm } from './wasm.js';
import { validateHex, hexToBytes, bytesToHex } from './hex.js';

export class RotatingKeys {
  private inner: any;

  private constructor(inner: any) {
    this.inner = inner;
  }

  static async create(createdAt?: number): Promise<RotatingKeys> {
    await ensureInit();
    const wasm = getWasm();
    const now = createdAt ?? Math.floor(Date.now() / 1000);
    const inner = new wasm.WasmRotatingKeyPair(BigInt(now));
    return new RotatingKeys(inner);
  }

  rotate(now?: number): void {
    const timestamp = now ?? Math.floor(Date.now() / 1000);
    this.inner.rotate(BigInt(timestamp));
  }

  currentPublicKey(): string {
    return this.inner.currentPublicKey();
  }

  generation(): number {
    return this.inner.generation();
  }

  shouldRotate(maxAgeSecs: number = 3600, maxMessages: number = 1000): boolean {
    const now = Math.floor(Date.now() / 1000);
    return this.inner.shouldRotate(BigInt(maxAgeSecs), maxMessages, BigInt(now));
  }
}

export async function deriveAgentFromSeed(seedHex: string, agentIndex: number): Promise<{ publicKey: string }> {
  validateHex(seedHex, 'seed');
  await ensureInit();
  const wasm = getWasm();
  const seedBytes = hexToBytes(seedHex);
  const keypair = wasm.deriveAgentFromSeed(seedBytes, agentIndex);
  return { publicKey: bytesToHex(keypair.publicKeyBytes()) };
}

export async function agentIdFromSeed(seedHex: string, agentIndex: number): Promise<string> {
  validateHex(seedHex, 'seed');
  await ensureInit();
  const wasm = getWasm();
  const seedBytes = hexToBytes(seedHex);
  return wasm.agentIdFromSeed(seedBytes, agentIndex);
}
