import { describe, it, expect } from 'vitest';
import { SecureSession } from '../src/ratchet.js';
import { randomHex } from '../src/crypto.js';

describe('SecureSession (Forward Secrecy)', () => {
  it('should produce unique keys on each ratchet', async () => {
    const rootKey = await randomHex(32);
    const session = await SecureSession.create(rootKey);
    const keys = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const { messageKey } = session.ratchetForward();
      keys.add(messageKey);
    }
    expect(keys.size).toBe(20);
  });

  it('should be deterministic from same root', async () => {
    const rootKey = await randomHex(32);
    const s1 = await SecureSession.create(rootKey);
    const s2 = await SecureSession.create(rootKey);
    for (let i = 0; i < 10; i++) {
      const k1 = s1.ratchetForward();
      const k2 = s2.ratchetForward();
      expect(k1.messageKey).toBe(k2.messageKey);
      expect(k1.messageIndex).toBe(k2.messageIndex);
    }
  });

  it('should handle out-of-order message keys', async () => {
    const rootKey = await randomHex(32);
    const sender = await SecureSession.create(rootKey);
    const receiver = await SecureSession.create(rootKey);

    const senderKeys: string[] = [];
    for (let i = 0; i < 5; i++) {
      senderKeys.push(sender.ratchetForward().messageKey);
    }

    const k4 = receiver.getMessageKey(4);
    expect(k4).toBe(senderKeys[4]);

    expect(receiver.getMessageKey(1)).toBe(senderKeys[1]);
    expect(receiver.getMessageKey(0)).toBe(senderKeys[0]);
    expect(receiver.getMessageKey(3)).toBe(senderKeys[3]);
    expect(receiver.getMessageKey(2)).toBe(senderKeys[2]);
  });

  it('should reject replay (same index twice)', async () => {
    const rootKey = await randomHex(32);
    const session = await SecureSession.create(rootKey);
    session.getMessageKey(0);
    expect(() => session.getMessageKey(0)).toThrow();
  });
});
