import { describe, it, expect, beforeAll } from 'vitest';
import { ensureInit, TaskManager, generateSessionId } from '../src/index.js';
import type { TaskAssignment, TaskProof, PaymentConfirmation } from '../src/index.js';

beforeAll(async () => {
  await ensureInit();
});

describe('TaskManager', () => {
  async function getSessionId(): Promise<Uint8Array> {
    return await generateSessionId();
  }

  describe('assignTask', () => {
    it('encodes a task assignment as memos', async () => {
      const sessionId = await getSessionId();
      const task: TaskAssignment = {
        task_id: 'task-001',
        description: 'Install Signal messenger',
        reward_zec: 0.05,
        deadline: '2026-04-01T00:00:00Z',
        verification_method: 'screenshot_hash',
      };
      const memos = await TaskManager.assignTask(sessionId, task);
      expect(memos.length).toBeGreaterThan(0);
      expect(memos[0].length).toBe(1024); // 512 bytes = 1024 hex
    });

    it('produces memos that decode as assignment', async () => {
      const sessionId = await getSessionId();
      const task: TaskAssignment = {
        task_id: 'task-002',
        description: 'Set up VPN',
        reward_zec: 0.03,
        verification_method: 'ip_check',
      };
      const memos = await TaskManager.assignTask(sessionId, task);
      const decoded = await TaskManager.processTaskMessage(memos);
      expect(decoded.type).toBe('assignment');
      if (decoded.type === 'assignment') {
        expect(decoded.data.task_id).toBe('task-002');
        expect(decoded.data.description).toBe('Set up VPN');
        expect(decoded.data.reward_zec).toBe(0.03);
        expect(decoded.data.verification_method).toBe('ip_check');
      }
    });
  });

  describe('createTaskProof', () => {
    it('generates a proof with BLAKE3 hash', async () => {
      const proofData = new TextEncoder().encode('proof-data-here');
      const proof = await TaskManager.createTaskProof(
        'task-001',
        'completed_screenshot',
        proofData,
        Date.now(),
      );
      expect(proof.task_id).toBe('task-001');
      expect(proof.action).toBe('completed_screenshot');
      expect(typeof proof.proof_hash).toBe('string');
      expect(proof.proof_hash.length).toBe(64); // BLAKE3 = 32 bytes = 64 hex
    });

    it('different data produces different proof hashes', async () => {
      const proof1 = await TaskManager.createTaskProof(
        'task-001',
        'action1',
        new TextEncoder().encode('data-1'),
        Date.now(),
      );
      const proof2 = await TaskManager.createTaskProof(
        'task-001',
        'action1',
        new TextEncoder().encode('data-2'),
        Date.now(),
      );
      expect(proof1.proof_hash).not.toBe(proof2.proof_hash);
    });
  });

  describe('submitProof', () => {
    it('encodes and decodes proof through memos', async () => {
      const sessionId = await getSessionId();
      const proofData = new TextEncoder().encode('signal-installed');
      const proof = await TaskManager.createTaskProof(
        'task-001',
        'installed_signal',
        proofData,
        1700000000000,
      );
      const memos = await TaskManager.submitProof(sessionId, proof);
      expect(memos.length).toBeGreaterThan(0);

      const decoded = await TaskManager.processTaskMessage(memos);
      expect(decoded.type).toBe('proof');
      if (decoded.type === 'proof') {
        expect(decoded.data.task_id).toBe('task-001');
        expect(decoded.data.action).toBe('installed_signal');
        expect(decoded.data.proof_hash).toBe(proof.proof_hash);
      }
    });
  });

  describe('confirmPayment', () => {
    it('encodes and decodes payment through memos', async () => {
      const sessionId = await getSessionId();
      const payment: PaymentConfirmation = {
        task_id: 'task-001',
        amount_zec: 0.05,
        tx_id: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
        timestamp: 1700000000000,
      };
      const memos = await TaskManager.confirmPayment(sessionId, payment);
      expect(memos.length).toBeGreaterThan(0);

      const decoded = await TaskManager.processTaskMessage(memos);
      expect(decoded.type).toBe('payment');
      if (decoded.type === 'payment') {
        expect(decoded.data.task_id).toBe('task-001');
        expect(decoded.data.amount_zec).toBe(0.05);
        expect(decoded.data.tx_id).toBe(payment.tx_id);
      }
    });
  });

  describe('full lifecycle', () => {
    it('assign -> proof -> payment', async () => {
      const sessionId = await getSessionId();

      // 1. Assign task
      const task: TaskAssignment = {
        task_id: 'bounty-001',
        description: 'Install Signal messenger and verify',
        reward_zec: 0.05,
        deadline: '2026-03-01T00:00:00Z',
        verification_method: 'screenshot_hash',
      };
      const assignMemos = await TaskManager.assignTask(sessionId, task);
      const assignDecoded = await TaskManager.processTaskMessage(assignMemos);
      expect(assignDecoded.type).toBe('assignment');

      // 2. Submit proof
      const proofData = new TextEncoder().encode('signal-screenshot-hash-data');
      const proof = await TaskManager.createTaskProof(
        'bounty-001',
        'installed_signal',
        proofData,
        Date.now(),
      );
      const proofMemos = await TaskManager.submitProof(sessionId, proof);
      const proofDecoded = await TaskManager.processTaskMessage(proofMemos);
      expect(proofDecoded.type).toBe('proof');

      // 3. Confirm payment
      const payment: PaymentConfirmation = {
        task_id: 'bounty-001',
        amount_zec: 0.05,
        tx_id: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        timestamp: Date.now(),
      };
      const payMemos = await TaskManager.confirmPayment(sessionId, payment);
      const payDecoded = await TaskManager.processTaskMessage(payMemos);
      expect(payDecoded.type).toBe('payment');
      if (payDecoded.type === 'payment') {
        expect(payDecoded.data.amount_zec).toBe(0.05);
      }
    });
  });
});
