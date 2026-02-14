import { describe, it, expect } from 'vitest';
import { deriveAgentId } from '../src/keys.js';
import { randomHex } from '../src/crypto.js';

describe('Agent ID derivation', () => {
  it('derives deterministic IDs from seed', async () => {
    const seed = await randomHex(32);
    const id1 = await deriveAgentId(seed, 0);
    const id2 = await deriveAgentId(seed, 0);
    expect(id1).toBe(id2);
  });

  it('derives different IDs for different indices', async () => {
    const seed = await randomHex(32);
    const id0 = await deriveAgentId(seed, 0);
    const id1 = await deriveAgentId(seed, 1);
    expect(id0).not.toBe(id1);
  });

  it('produces 32-byte hex IDs', async () => {
    const seed = await randomHex(32);
    const id = await deriveAgentId(seed, 0);
    expect(id.length).toBe(64);
    expect(id).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects malformed hex seeds', async () => {
    await expect(deriveAgentId('xyz', 0)).rejects.toThrow();
  });
});
