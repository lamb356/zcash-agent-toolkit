/**
 * PrivacyClaw Agent Demo
 *
 * Simulates a PrivacyClaw-style agent that:
 * 1. Establishes encrypted sessions with user agents
 * 2. Assigns privacy tasks (install Signal, set up VPN, configure encrypted email)
 * 3. Receives and verifies task proofs
 * 4. Sends ZEC payment confirmations
 *
 * Run: npx tsx examples/privacyclaw-demo.ts
 */

import {
  AgentSession,
  TaskManager,
  MemoCodec,
  blake3Hex,
  generateSessionId,
} from '../ts-sdk/dist/index.js';

const PRIVACY_TASKS = [
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
    deadline: '2026-04-01T00:00:00Z',
    verification_method: 'ip_check_proof',
  },
  {
    task_id: 'privacy-003',
    description: 'Configure ProtonMail for encrypted email',
    reward_zec: 0.04,
    deadline: '2026-04-01T00:00:00Z',
    verification_method: 'account_creation_proof',
  },
];

async function main() {
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║     PrivacyClaw Agent Simulation Demo        ║');
  console.log('║     Private AI Agent Communication           ║');
  console.log('║     over Zcash Shielded Memo Fields          ║');
  console.log('╚══════════════════════════════════════════════╝\n');

  // Create agents
  const privacyClaw = await AgentSession.create();
  const userAgent = await AgentSession.create();

  console.log(`PrivacyClaw Agent ID: ${privacyClaw.agentId}`);
  console.log(`User Agent ID:       ${userAgent.agentId}`);
  console.log(`PrivacyClaw PubKey:  ${privacyClaw.publicKey.slice(0, 32)}...`);
  console.log(`User PubKey:         ${userAgent.publicKey.slice(0, 32)}...`);

  // === Phase 1: Handshake ===
  console.log('\n━━━ Phase 1: Encrypted Session Establishment ━━━\n');

  const { handshake: pcHandshake, memos: pcMemos } =
    await privacyClaw.createHandshake(['task_assign', 'payment', 'verify']);
  console.log(`PrivacyClaw sends handshake (${pcMemos.length} memo):`);
  console.log(`  Capabilities: ${pcHandshake.capabilities.join(', ')}`);
  printMemoPreview(pcMemos);

  const { handshake: userHandshake, memos: userMemos } =
    await userAgent.createHandshake(['task_accept', 'proof_submit']);
  console.log(`User agent sends handshake (${userMemos.length} memo):`);
  console.log(`  Capabilities: ${userHandshake.capabilities.join(', ')}`);
  printMemoPreview(userMemos);

  // Process handshakes
  const receivedUser = await privacyClaw.processHandshake(userMemos);
  const receivedPC = await userAgent.processHandshake(pcMemos);

  const pcSecret = await privacyClaw.deriveSharedSecret(receivedUser.public_key);
  const userSecret = await userAgent.deriveSharedSecret(receivedPC.public_key);
  console.log(`Shared secret derived: ${pcSecret === userSecret ? 'MATCH' : 'MISMATCH'}`);
  console.log(`Session encrypted with ChaCha20-Poly1305`);

  // === Phase 2: Task Assignment & Completion ===
  const sessionId = await generateSessionId();

  for (const taskDef of PRIVACY_TASKS) {
    console.log(`\n━━━ Task: ${taskDef.task_id} ━━━\n`);

    // Assign
    console.log(`[PrivacyClaw] Assigning: "${taskDef.description}"`);
    console.log(`  Reward: ${taskDef.reward_zec} ZEC | Method: ${taskDef.verification_method}`);
    const assignMemos = await TaskManager.assignTask(sessionId, taskDef);
    console.log(`  → Encoded as ${assignMemos.length} Zcash memo(s)`);
    printMemoPreview(assignMemos);

    // Worker processes
    const decoded = await TaskManager.processTaskMessage(assignMemos);
    if (decoded.type === 'assignment') {
      console.log(`[UserAgent] Received task: "${decoded.data.description}"`);
    }

    // Submit proof
    const proofDataStr = `${taskDef.task_id}-completed-${Date.now()}`;
    const proofData = new TextEncoder().encode(proofDataStr);
    const proof = await TaskManager.createTaskProof(
      taskDef.task_id,
      `completed_${taskDef.verification_method}`,
      proofData,
      Date.now(),
    );
    console.log(`[UserAgent] Submitting proof:`);
    console.log(`  BLAKE3 hash: ${proof.proof_hash.slice(0, 48)}...`);

    const proofMemos = await TaskManager.submitProof(sessionId, proof);
    console.log(`  → Encoded as ${proofMemos.length} memo(s)`);
    printMemoPreview(proofMemos);

    // Verify proof
    const decodedProof = await TaskManager.processTaskMessage(proofMemos);
    if (decodedProof.type === 'proof') {
      console.log(`[PrivacyClaw] Proof verified: hash=${decodedProof.data.proof_hash.slice(0, 32)}...`);
    }

    // Payment
    const payment = {
      task_id: taskDef.task_id,
      amount_zec: taskDef.reward_zec,
      tx_id: Array.from(await generateSessionId())
        .concat(Array.from(await generateSessionId()))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(''),
      timestamp: Date.now(),
    };
    const payMemos = await TaskManager.confirmPayment(sessionId, payment);
    console.log(`[PrivacyClaw] Payment sent: ${payment.amount_zec} ZEC`);
    console.log(`  TX: ${payment.tx_id.slice(0, 32)}...`);
    console.log(`  → Encoded as ${payMemos.length} memo(s)`);
    printMemoPreview(payMemos);

    const decodedPay = await TaskManager.processTaskMessage(payMemos);
    if (decodedPay.type === 'payment') {
      console.log(`[UserAgent] Payment received: ${decodedPay.data.amount_zec} ZEC`);
    }
  }

  // Summary
  const totalReward = PRIVACY_TASKS.reduce((sum, t) => sum + t.reward_zec, 0);
  console.log('\n╔══════════════════════════════════════════════╗');
  console.log(`║  Demo complete: ${PRIVACY_TASKS.length} tasks, ${totalReward} ZEC total       ║`);
  console.log('║  All communication was via 512-byte memos    ║');
  console.log('║  encrypted with ChaCha20-Poly1305            ║');
  console.log('║  over Zcash shielded transactions            ║');
  console.log('╚══════════════════════════════════════════════╝');
}

function printMemoPreview(memos: string[]) {
  for (let i = 0; i < Math.min(memos.length, 2); i++) {
    console.log(`  Memo[${i}]: ${memos[i].slice(0, 64)}...`);
  }
  if (memos.length > 2) {
    console.log(`  ... and ${memos.length - 2} more memo(s)`);
  }
}

main().catch(console.error);
