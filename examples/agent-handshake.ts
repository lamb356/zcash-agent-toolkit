/**
 * Agent Handshake Example
 *
 * Demonstrates two AI agents establishing an encrypted session
 * over Zcash shielded memo fields.
 *
 * Run: npx tsx examples/agent-handshake.ts
 * (from the ts-sdk/ directory after building)
 */

import { AgentSession } from '../ts-sdk/dist/index.js';

async function main() {
  console.log('=== Zcash Agent Handshake Demo ===\n');

  // Step 1: Both agents create sessions
  console.log('1. Creating agent sessions...');
  const alice = await AgentSession.create();
  const bob = await AgentSession.create();

  console.log(`   Alice - Agent ID: ${alice.agentId}`);
  console.log(`   Alice - Public Key: ${alice.publicKey.slice(0, 16)}...`);
  console.log(`   Bob   - Agent ID: ${bob.agentId}`);
  console.log(`   Bob   - Public Key: ${bob.publicKey.slice(0, 16)}...`);

  // Step 2: Exchange handshakes
  console.log('\n2. Exchanging handshakes...');
  const { handshake: aliceHandshake, memos: aliceMemos } =
    await alice.createHandshake(['text', 'command', 'task']);
  console.log(`   Alice sends ${aliceMemos.length} memo(s)`);
  console.log(`   First memo (hex): ${aliceMemos[0].slice(0, 40)}...`);

  const { handshake: bobHandshake, memos: bobMemos } =
    await bob.createHandshake(['text', 'response']);
  console.log(`   Bob sends ${bobMemos.length} memo(s)`);

  // Step 3: Process received handshakes
  console.log('\n3. Processing handshakes...');
  const receivedBob = await alice.processHandshake(bobMemos);
  console.log(`   Alice received Bob's handshake:`);
  console.log(`     Agent ID: ${receivedBob.agent_id}`);
  console.log(`     Capabilities: ${receivedBob.capabilities.join(', ')}`);

  const receivedAlice = await bob.processHandshake(aliceMemos);
  console.log(`   Bob received Alice's handshake:`);
  console.log(`     Agent ID: ${receivedAlice.agent_id}`);
  console.log(`     Capabilities: ${receivedAlice.capabilities.join(', ')}`);

  // Step 4: Derive shared secrets
  console.log('\n4. Deriving shared secrets...');
  const aliceSecret = await alice.deriveSharedSecret(receivedBob.public_key);
  const bobSecret = await bob.deriveSharedSecret(receivedAlice.public_key);
  console.log(`   Alice's shared secret: ${aliceSecret.slice(0, 16)}...`);
  console.log(`   Bob's shared secret:   ${bobSecret.slice(0, 16)}...`);
  console.log(`   Secrets match: ${aliceSecret === bobSecret}`);

  // Step 5: Send encrypted messages
  console.log('\n5. Sending encrypted messages...');
  const command = { action: 'ping', data: { message: 'Hello from Alice!' } };
  const encryptedMemos = await alice.sendCommand(command);
  console.log(`   Alice sends encrypted command (${encryptedMemos.length} memo(s))`);

  const received = await bob.receiveCommand(encryptedMemos);
  console.log(`   Bob decrypted: ${JSON.stringify(received)}`);

  console.log('\n=== Handshake complete! Agents can now communicate privately. ===');
}

main().catch(console.error);
