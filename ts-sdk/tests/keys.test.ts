import { describe, it, expect } from 'vitest';
import { RotatingKeys, deriveAgentFromSeed, agentIdFromSeed } from '../src/keys.js';
import { randomHex } from '../src/crypto.js';

describe('RotatingKeys', () => {
  it('should produce different keys after rotation', async () => {
    const keys = await RotatingKeys.create(1000);
    const pk1 = keys.currentPublicKey();
    keys.rotate(2000);
    const pk2 = keys.currentPublicKey();
    expect(pk1).not.toBe(pk2);
    expect(keys.generation()).toBe(1);
  });

  it('should track generation correctly', async () => {
    const keys = await RotatingKeys.create(1000);
    expect(keys.generation()).toBe(0);
    keys.rotate(2000);
    expect(keys.generation()).toBe(1);
    keys.rotate(3000);
    expect(keys.generation()).toBe(2);
  });
});

describe('Key Derivation', () => {
  it('should derive deterministic keys from seed', async () => {
    const seed = await randomHex(32);
    const k1 = await deriveAgentFromSeed(seed, 0);
    const k2 = await deriveAgentFromSeed(seed, 0);
    expect(k1.publicKey).toBe(k2.publicKey);
  });

  it('should derive different keys for different indices', async () => {
    const seed = await randomHex(32);
    const k0 = await deriveAgentFromSeed(seed, 0);
    const k1 = await deriveAgentFromSeed(seed, 1);
    expect(k0.publicKey).not.toBe(k1.publicKey);
  });

  it('should generate deterministic agent IDs', async () => {
    const seed = await randomHex(32);
    const id1 = await agentIdFromSeed(seed, 0);
    const id2 = await agentIdFromSeed(seed, 0);
    expect(id1).toBe(id2);
    expect(id1.length).toBe(64);
  });

  it('should reject invalid hex', async () => {
    await expect(deriveAgentFromSeed('xyz', 0)).rejects.toThrow();
  });
});
