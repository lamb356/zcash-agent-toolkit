/**
 * Task Bounty Workflow Example
 *
 * Demonstrates the full bounty lifecycle:
 * assign task -> submit proof -> confirm payment
 *
 * Run: npx tsx examples/task-bounty.ts
 */

import { AgentSession, TaskManager, generateSessionId, blake3Hex } from '../ts-sdk/dist/index.js';

async function main() {
  console.log('=== Zcash Task Bounty Workflow ===\n');

  // Setup: Create two agents and establish a session
  const employer = await AgentSession.create();
  const worker = await AgentSession.create();

  console.log(`Employer Agent: ${employer.agentId.slice(0, 16)}...`);
  console.log(`Worker Agent:   ${worker.agentId.slice(0, 16)}...`);

  // Generate a shared session ID for the task workflow
  const sessionId = await generateSessionId();
  const sessionHex = Array.from(sessionId).map(b => b.toString(16).padStart(2, '0')).join('');
  console.log(`Session: ${sessionHex}\n`);

  // Step 1: Assign task
  console.log('--- Step 1: Assign Task ---');
  const task = {
    task_id: 'bounty-001',
    description: 'Install Signal messenger and verify installation',
    reward_zec: 0.05,
    deadline: '2026-03-01T00:00:00Z',
    verification_method: 'screenshot_hash',
  };
  const assignMemos = await TaskManager.assignTask(sessionId, task);
  console.log(`Task assigned: "${task.description}"`);
  console.log(`Reward: ${task.reward_zec} ZEC`);
  console.log(`Encoded as ${assignMemos.length} memo(s)`);
  console.log(`Memo hex: ${assignMemos[0].slice(0, 60)}...\n`);

  // Worker decodes the task
  const decoded = await TaskManager.processTaskMessage(assignMemos);
  if (decoded.type === 'assignment') {
    console.log(`Worker received task: "${decoded.data.description}"`);
    console.log(`Reward offered: ${decoded.data.reward_zec} ZEC`);
  }

  // Step 2: Submit proof
  console.log('\n--- Step 2: Submit Proof ---');
  const proofData = new TextEncoder().encode('signal-installed-screenshot-2026-02-15.png');
  const proof = await TaskManager.createTaskProof(
    'bounty-001',
    'installed_signal',
    proofData,
    Date.now(),
  );
  console.log(`Proof created:`);
  console.log(`  Task: ${proof.task_id}`);
  console.log(`  Action: ${proof.action}`);
  console.log(`  Hash: ${proof.proof_hash.slice(0, 32)}...`);

  const proofMemos = await TaskManager.submitProof(sessionId, proof);
  console.log(`Proof encoded as ${proofMemos.length} memo(s)\n`);

  // Employer decodes the proof
  const decodedProof = await TaskManager.processTaskMessage(proofMemos);
  if (decodedProof.type === 'proof') {
    console.log(`Employer received proof: hash=${decodedProof.data.proof_hash.slice(0, 32)}...`);
  }

  // Step 3: Confirm payment
  console.log('\n--- Step 3: Confirm Payment ---');
  const payment = {
    task_id: 'bounty-001',
    amount_zec: 0.05,
    tx_id: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    timestamp: Date.now(),
  };
  const paymentMemos = await TaskManager.confirmPayment(sessionId, payment);
  console.log(`Payment confirmed: ${payment.amount_zec} ZEC`);
  console.log(`TX ID: ${payment.tx_id.slice(0, 16)}...`);
  console.log(`Encoded as ${paymentMemos.length} memo(s)\n`);

  // Worker decodes the payment
  const decodedPayment = await TaskManager.processTaskMessage(paymentMemos);
  if (decodedPayment.type === 'payment') {
    console.log(`Worker received payment confirmation: ${decodedPayment.data.amount_zec} ZEC`);
  }

  console.log('\n=== Bounty workflow complete! ===');
}

main().catch(console.error);
