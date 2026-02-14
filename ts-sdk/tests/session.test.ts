import { describe, it, expect, beforeAll } from 'vitest';
import { ensureInit, AgentSession } from '../src/index.js';

beforeAll(async () => {
  await ensureInit();
});

describe('AgentSession protocol behavior', () => {
  it('creates session with identity', async () => {
    const session = await AgentSession.create('agent-alpha', ['task', 'text']);
    expect(session.agentId).toBe('agent-alpha');
    expect(session.capabilities).toEqual(['task', 'text']);
    expect(session.sessionId.length).toBe(16);
  });

  it('encodes and decodes handshake', async () => {
    const alice = await AgentSession.create('agent-alpha', ['task', 'command']);
    const bob = await AgentSession.create('agent-beta', ['result', 'payment']);

    const handshakeMemos = alice.createHandshake();
    const peer = bob.processHandshake(handshakeMemos);

    expect(peer.agentId).toBe('agent-alpha');
    expect(peer.capabilities).toEqual(['task', 'command']);
  });

  it('roundtrips text messages', () => {
    const sessionPromise = AgentSession.create('agent-alpha', ['text']);
    return sessionPromise.then(async session => {
      const memos = session.encodeMessage('hello from alpha');
      const decoded = session.decodeMessage(memos);
      expect(decoded).toBe('hello from alpha');
    });
  });

  it('roundtrips command messages', () => {
    return AgentSession.create('agent-alpha', ['command']).then(session => {
      const command = 'Audit contract 0xABC for privacy leaks';
      const memos = session.encodeCommand(command);
      const decoded = session.decodeCommand(memos);
      expect(decoded).toBe(command);
    });
  });

  it('handles chunked messages', async () => {
    const session = await AgentSession.create('agent-alpha', ['text']);
    const longText = 'A'.repeat(2000);
    const memos = session.encodeMessage(longText);

    expect(memos.length).toBeGreaterThan(1);
    const decoded = session.decodeMessage(memos);
    expect(decoded).toBe(longText);
  });
});
