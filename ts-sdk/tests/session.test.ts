import { describe, it, expect, beforeAll } from 'vitest';
import { ensureInit, AgentSession } from '../src/index.js';

beforeAll(async () => {
  await ensureInit();
});

describe('AgentSession', () => {
  describe('create', () => {
    it('generates a unique public key', async () => {
      const a = await AgentSession.create();
      const b = await AgentSession.create();
      expect(a.publicKey).not.toBe(b.publicKey);
    });

    it('public key is 64-char hex (32 bytes)', async () => {
      const session = await AgentSession.create();
      expect(session.publicKey.length).toBe(64);
      expect(session.publicKey).toMatch(/^[0-9a-f]+$/);
    });

    it('generates a deterministic agent ID from public key', async () => {
      const session = await AgentSession.create();
      expect(typeof session.agentId).toBe('string');
      expect(session.agentId.length).toBe(32); // 16 bytes = 32 hex
      expect(session.agentId).toMatch(/^[0-9a-f]+$/);
    });

    it('generates a unique session ID', async () => {
      const a = await AgentSession.create();
      const b = await AgentSession.create();
      expect(a.sessionId).not.toBe(b.sessionId);
      expect(a.sessionId.length).toBe(32);
    });
  });

  describe('shared secret derivation', () => {
    it('both sides derive the same shared secret', async () => {
      const alice = await AgentSession.create();
      const bob = await AgentSession.create();

      const aliceSecret = await alice.deriveSharedSecret(bob.publicKey);
      const bobSecret = await bob.deriveSharedSecret(alice.publicKey);

      expect(aliceSecret).toBe(bobSecret);
    });

    it('different peers produce different secrets', async () => {
      const alice = await AgentSession.create();
      const bob = await AgentSession.create();
      const charlie = await AgentSession.create();

      const secretAB = await alice.deriveSharedSecret(bob.publicKey);
      const alice2 = await AgentSession.create();
      // Use a new session to derive with charlie (can't reuse alice since cipher is already set)
      const secretAC = await alice2.deriveSharedSecret(charlie.publicKey);

      expect(secretAB).not.toBe(secretAC);
    });
  });

  describe('encrypt/decrypt', () => {
    it('roundtrips plaintext', async () => {
      const alice = await AgentSession.create();
      const bob = await AgentSession.create();
      await alice.deriveSharedSecret(bob.publicKey);
      await bob.deriveSharedSecret(alice.publicKey);

      const ciphertext = alice.encrypt('Hello Bob!');
      const plaintext = bob.decrypt(ciphertext);
      expect(plaintext).toBe('Hello Bob!');
    });

    it('throws without shared secret', async () => {
      const session = await AgentSession.create();
      expect(() => session.encrypt('test')).toThrow('No shared secret');
    });

    it('wrong session cannot decrypt', async () => {
      const alice = await AgentSession.create();
      const bob = await AgentSession.create();
      const eve = await AgentSession.create();
      await alice.deriveSharedSecret(bob.publicKey);
      await eve.deriveSharedSecret(bob.publicKey); // eve knows bob's pubkey but not alice's secret

      const ciphertext = alice.encrypt('secret message');
      // Eve can't decrypt because DH(eve, bob) != DH(alice, bob)
      expect(() => eve.decrypt(ciphertext)).toThrow();
    });

    it('two encryptions of same plaintext differ (random nonce)', async () => {
      const alice = await AgentSession.create();
      const bob = await AgentSession.create();
      await alice.deriveSharedSecret(bob.publicKey);

      const ct1 = alice.encrypt('same message');
      const ct2 = alice.encrypt('same message');
      expect(ct1).not.toBe(ct2);
    });
  });

  describe('handshake', () => {
    it('creates handshake with capabilities', async () => {
      const session = await AgentSession.create();
      const { handshake, memos } = await session.createHandshake(['text', 'task']);
      expect(handshake.agent_id).toBe(session.agentId);
      expect(handshake.public_key).toBe(session.publicKey);
      expect(handshake.capabilities).toEqual(['text', 'task']);
      expect(handshake.protocol_version).toBe(1);
      expect(memos.length).toBeGreaterThan(0);
    });

    it('roundtrips handshake through memos', async () => {
      const alice = await AgentSession.create();
      const bob = await AgentSession.create();

      const { memos: aliceMemos } = await alice.createHandshake(['text', 'command']);
      const received = await bob.processHandshake(aliceMemos);

      expect(received.agent_id).toBe(alice.agentId);
      expect(received.public_key).toBe(alice.publicKey);
      expect(received.capabilities).toEqual(['text', 'command']);
    });

    it('full handshake flow establishes encrypted session', async () => {
      const alice = await AgentSession.create();
      const bob = await AgentSession.create();

      const { memos: aliceMemos } = await alice.createHandshake(['text']);
      const { memos: bobMemos } = await bob.createHandshake(['text']);

      const receivedBob = await alice.processHandshake(bobMemos);
      const receivedAlice = await bob.processHandshake(aliceMemos);

      const aliceSecret = await alice.deriveSharedSecret(receivedBob.public_key);
      const bobSecret = await bob.deriveSharedSecret(receivedAlice.public_key);
      expect(aliceSecret).toBe(bobSecret);
    });
  });

  describe('sendCommand / receiveCommand', () => {
    it('roundtrips encrypted command through memos', async () => {
      const alice = await AgentSession.create();
      const bob = await AgentSession.create();

      // Establish shared secret
      await alice.deriveSharedSecret(bob.publicKey);
      await bob.deriveSharedSecret(alice.publicKey);

      const command = { action: 'ping', data: { message: 'Hello from Alice!' } };
      const memos = await alice.sendCommand(command);
      const received = await bob.receiveCommand(memos);

      expect(received).toEqual(command);
    });

    it('throws without shared secret', async () => {
      const session = await AgentSession.create();
      await expect(session.sendCommand({ action: 'test' })).rejects.toThrow('No shared secret');
    });
  });
});
