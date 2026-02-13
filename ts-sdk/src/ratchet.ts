import { ensureInit, getWasm } from './wasm.js';
import { validateHex, hexToBytes } from './hex.js';

export class SecureSession {
  private ratchet: any;

  private constructor(ratchet: any) {
    this.ratchet = ratchet;
  }

  static async create(sharedSecretHex: string): Promise<SecureSession> {
    validateHex(sharedSecretHex, 'sharedSecret');
    await ensureInit();
    const wasm = getWasm();
    const keyBytes = hexToBytes(sharedSecretHex);
    const ratchet = new wasm.WasmRatchetState(keyBytes);
    return new SecureSession(ratchet);
  }

  ratchetForward(): { messageKey: string; messageIndex: number } {
    return this.ratchet.ratchetForward();
  }

  getMessageKey(index: number): string {
    return this.ratchet.getMessageKey(BigInt(index));
  }
}
