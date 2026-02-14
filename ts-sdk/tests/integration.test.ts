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

describe('Integration: Identity + Task Workflow', () => {
  it('completes handshake and command exchange', async () => {
    const privacyClaw = await AgentSession.create('privacy-claw', ['task-assign', 'payment']);
    const userAgent = await AgentSession.create('user-agent', ['task-accept', 'proof-submit']);

    const handshakeMemos = privacyClaw.createHandshake();
    const received = userAgent.processHandshake(handshakeMemos);

    expect(received.agentId).toBe('privacy-claw');
    expect(received.capabilities).toEqual(['task-assign', 'payment']);

    const commandText = 'Audit contract 0xABC for privacy leaks';
    const commandMemos = privacyClaw.encodeCommand(commandText);
    const decodedCommand = userAgent.decodeCommand(commandMemos);
    expect(decodedCommand).toBe(commandText);
  });

  it('supports task workflow handoff', async () => {
    const sessionId = await generateSessionId();

    const task: TaskAssignment = {
      task_id: 'privacy-001',
      description: 'Set up secure workflow and verify memo flow',
      reward_zec: 0.5,
      deadline: '2026-04-01T00:00:00Z',
      verification_method: 'app_screenshot_hash',
    };

    const assignmentMemos = await TaskManager.assignTask(sessionId, task);
    const decodedAssignment = await TaskManager.processTaskMessage(assignmentMemos);
    expect(decodedAssignment.type).toBe('assignment');
    if (decodedAssignment.type === 'assignment') {
      expect(decodedAssignment.data.task_id).toBe('privacy-001');
      expect(decodedAssignment.data.reward_zec).toBe(0.5);
    }

    const proof = await TaskManager.createTaskProof(
      task.task_id,
      'completed_app_screenshot_hash',
      new TextEncoder().encode(`${task.task_id}-completed`),
      Date.now(),
    );
    const proofMemos = await TaskManager.submitProof(sessionId, proof);
    const decodedProof = await TaskManager.processTaskMessage(proofMemos);
    expect(decodedProof.type).toBe('proof');
    if (decodedProof.type === 'proof') {
      expect(decodedProof.data.task_id).toBe(task.task_id);
      expect(decodedProof.data.proof_hash.length).toBe(64);
    }

    const payment: PaymentConfirmation = {
      task_id: task.task_id,
      amount_zec: task.reward_zec,
      tx_id: 'abcd'.repeat(16),
      timestamp: Date.now(),
    };
    const paymentMemos = await TaskManager.confirmPayment(sessionId, payment);
    const decodedPayment = await TaskManager.processTaskMessage(paymentMemos);
    expect(decodedPayment.type).toBe('payment');
    if (decodedPayment.type === 'payment') {
      expect(decodedPayment.data.task_id).toBe(task.task_id);
      expect(decodedPayment.data.amount_zec).toBe(task.reward_zec);
    }
  });
});

describe('Integration: MemoCodec + Session Combined', () => {
  it('roundtrips memo traffic across codecs and session', async () => {
    const codec = await MemoCodec.create();
    const text = 'Cross-module integration test message';
    const memos = codec.encodeText(text);
    const decoded = await MemoCodec.decode(memos);
    expect(new TextDecoder().decode(decoded.data)).toBe(text);

    const session = await AgentSession.create('agent-session', ['text', 'command']);
    const command = 'session-layer command';
    const sessionMemos = session.encodeCommand(command);
    const decodedCommand = session.decodeCommand(sessionMemos);
    expect(decodedCommand).toBe(command);
  });
});
