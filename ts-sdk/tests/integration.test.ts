import { describe, it, expect, beforeAll } from 'vitest';
import {
  ensureInit,
  AgentSession,
  TaskManager,
  MemoCodec,
  generateSessionId,
} from '../src/index.js';
import type { TaskAssignment, PaymentConfirmation } from '../src/index.js';

beforeAll(async () => {
  await ensureInit();
});

describe('Integration: Full PrivacyClaw Simulation', () => {
  it('complete handshake -> task -> proof -> payment workflow', async () => {
    // === Setup agents ===
    const privacyClaw = await AgentSession.create();
    const userAgent = await AgentSession.create();

    expect(privacyClaw.agentId).not.toBe(userAgent.agentId);

    // === Phase 1: Handshake ===
    const { handshake: pcHandshake, memos: pcMemos } =
      await privacyClaw.createHandshake(['task_assign', 'payment', 'verify']);
    const { handshake: userHandshake, memos: userMemos } =
      await userAgent.createHandshake(['task_accept', 'proof_submit']);

    // Process handshakes
    const receivedUser = await privacyClaw.processHandshake(userMemos);
    const receivedPC = await userAgent.processHandshake(pcMemos);

    expect(receivedUser.agent_id).toBe(userAgent.agentId);
    expect(receivedUser.public_key).toBe(userAgent.publicKey);
    expect(receivedPC.agent_id).toBe(privacyClaw.agentId);
    expect(receivedPC.capabilities).toEqual(['task_assign', 'payment', 'verify']);

    // Derive shared secrets
    const pcSecret = await privacyClaw.deriveSharedSecret(receivedUser.public_key);
    const userSecret = await userAgent.deriveSharedSecret(receivedPC.public_key);
    expect(pcSecret).toBe(userSecret);

    // === Phase 2: Encrypted communication ===
    const command = { action: 'ready', data: { agent_version: '1.0' } };
    const encMemos = await privacyClaw.sendCommand(command);
    const received = await userAgent.receiveCommand(encMemos);
    expect(received).toEqual(command);

    // === Phase 3: Task workflow ===
    const sessionId = await generateSessionId();

    const tasks: TaskAssignment[] = [
      {
        task_id: 'privacy-001',
        description: 'Install Signal messenger for encrypted communications',
        reward_zec: 0.05,
        deadline: '2026-04-01T00:00:00Z',
        verification_method: 'app_screenshot_hash',
      },
      {
        task_id: 'privacy-002',
        description: 'Set up a VPN and verify IP address is masked',
        reward_zec: 0.03,
        verification_method: 'ip_check_proof',
      },
    ];

    let totalPaid = 0;

    for (const task of tasks) {
      // Assign task
      const assignMemos = await TaskManager.assignTask(sessionId, task);
      const assignDecoded = await TaskManager.processTaskMessage(assignMemos);
      expect(assignDecoded.type).toBe('assignment');
      if (assignDecoded.type === 'assignment') {
        expect(assignDecoded.data.task_id).toBe(task.task_id);
        expect(assignDecoded.data.reward_zec).toBe(task.reward_zec);
      }

      // Submit proof
      const proofData = new TextEncoder().encode(`${task.task_id}-completed`);
      const proof = await TaskManager.createTaskProof(
        task.task_id,
        `completed_${task.verification_method}`,
        proofData,
        Date.now(),
      );
      const proofMemos = await TaskManager.submitProof(sessionId, proof);
      const proofDecoded = await TaskManager.processTaskMessage(proofMemos);
      expect(proofDecoded.type).toBe('proof');
      if (proofDecoded.type === 'proof') {
        expect(proofDecoded.data.task_id).toBe(task.task_id);
        expect(proofDecoded.data.proof_hash.length).toBe(64);
      }

      // Confirm payment
      const payment: PaymentConfirmation = {
        task_id: task.task_id,
        amount_zec: task.reward_zec,
        tx_id: 'abcd'.repeat(16),
        timestamp: Date.now(),
      };
      const payMemos = await TaskManager.confirmPayment(sessionId, payment);
      const payDecoded = await TaskManager.processTaskMessage(payMemos);
      expect(payDecoded.type).toBe('payment');
      if (payDecoded.type === 'payment') {
        expect(payDecoded.data.amount_zec).toBe(task.reward_zec);
        totalPaid += payDecoded.data.amount_zec;
      }
    }

    const expectedTotal = tasks.reduce((sum, t) => sum + t.reward_zec, 0);
    expect(totalPaid).toBeCloseTo(expectedTotal);
  });
});

describe('Integration: Multi-Agent Isolation', () => {
  it('three agents with separate encrypted sessions', async () => {
    const agentA = await AgentSession.create();
    const agentB = await AgentSession.create();
    const agentC = await AgentSession.create();

    // A <-> B session
    const sessionAB_A = await AgentSession.create();
    const sessionAB_B = await AgentSession.create();
    await sessionAB_A.deriveSharedSecret(sessionAB_B.publicKey);
    await sessionAB_B.deriveSharedSecret(sessionAB_A.publicKey);

    // A <-> C session
    const sessionAC_A = await AgentSession.create();
    const sessionAC_C = await AgentSession.create();
    await sessionAC_A.deriveSharedSecret(sessionAC_C.publicKey);
    await sessionAC_C.deriveSharedSecret(sessionAC_A.publicKey);

    // A sends to B
    const msgToB = { action: 'task', target: 'B' };
    const memosToB = await sessionAB_A.sendCommand(msgToB);
    const receivedByB = await sessionAB_B.receiveCommand(memosToB);
    expect(receivedByB).toEqual(msgToB);

    // A sends to C
    const msgToC = { action: 'task', target: 'C' };
    const memosToC = await sessionAC_A.sendCommand(msgToC);
    const receivedByC = await sessionAC_C.receiveCommand(memosToC);
    expect(receivedByC).toEqual(msgToC);

    // C cannot decrypt B's messages
    expect(() => {
      // Use sessionAC_C (C's session with A) to try decrypting B's memos
      // This should fail because the shared secret is different
      sessionAC_C.decrypt(
        // Extract the encrypted data from memosToB by trying to decrypt raw hex
        memosToB[0]
      );
    }).toThrow();

    // B cannot decrypt C's messages
    expect(() => {
      sessionAB_B.decrypt(memosToC[0]);
    }).toThrow();
  });
});

describe('Integration: MemoCodec + Session Combined', () => {
  it('MemoCodec encodes and session decodes across agents', async () => {
    // Create a codec and session that share the same session ID concept
    const codec = await MemoCodec.create();
    const text = 'Cross-module integration test message';
    const memos = codec.encodeText(text);

    // Decode with static method
    const decoded = await MemoCodec.decode(memos);
    const result = new TextDecoder().decode(decoded.data);
    expect(result).toBe(text);
    expect(decoded.sessionId).toBe(codec.sessionId);
  });

  it('large JSON command with chunking and encryption', async () => {
    const alice = await AgentSession.create();
    const bob = await AgentSession.create();
    await alice.deriveSharedSecret(bob.publicKey);
    await bob.deriveSharedSecret(alice.publicKey);

    // Create a large command that will require chunking after encryption
    const command = {
      action: 'batch_update',
      data: {
        items: Array.from({ length: 50 }, (_, i) => ({
          id: `item-${i}`,
          value: `value-${i}`.repeat(5),
          status: 'active',
        })),
      },
    };

    const memos = await alice.sendCommand(command);
    expect(memos.length).toBeGreaterThan(0);

    const received = await bob.receiveCommand(memos);
    expect(received).toEqual(command);
  });
});
