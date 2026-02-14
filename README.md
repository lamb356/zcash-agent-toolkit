# Zcash Agent Toolkit

**Structured AI agent communication over Zcash shielded memos.**

AI agents need to communicate privately. Zcash shielded memos provide exactly this: every memo is encrypted to the recipient, with sender, receiver, amount, and content all hidden on-chain. This toolkit provides a structured protocol layer on top of Zcash's built-in confidentiality and integrity.

No redundant encryption. No unnecessary key exchange. A clean protocol that trusts Zcash to do what Zcash does best.

## What This Provides

- **Structured memo protocol**  60-byte header + 452-byte payload in Zcash's 512-byte memo field
- **Automatic chunking**  Messages >452 bytes split across multiple memos with reassembly
- **BLAKE3 integrity hashes**  Content hash in every memo header for application-level verification
- **Agent identity**  Deterministic agent IDs derived from seed via BLAKE3 KDF
- **Task/bounty workflows**  TaskAssign  TaskProof  PaymentConfirm with anti-replay nonces
- **Metadata privacy**  All memos zero-padded to exactly 512 bytes
- **Rust + WASM + TypeScript**  Use from any environment

## Why No Custom Encryption?

Zcash shielded transactions already encrypt memos to the recipient's incoming viewing key using state-of-the-art cryptography. The sender, receiver, amount, and memo content are all hidden from observers. Adding another encryption layer on top would be redundant.

This toolkit focuses on what Zcash doesn't provide: a structured message protocol for agent-to-agent communication, automatic chunking, session management, and task workflows. Zcash handles the crypto. We handle the protocol.

## Quick Example

```typescript
import { AgentSession, MemoCodec, TaskManager } from '@zcash-agent/toolkit';

// Two agents identify themselves
const alice = await AgentSession.create('alice-agent', ['task-assignment']);
const bob = await AgentSession.create('bob-agent', ['task-execution']);

// Exchange identities via shielded memos
const handshakeMemos = alice.createHandshake();
//  Send handshakeMemos as Zcash shielded memo(s) to Bob's address
//  Zcash encrypts them automatically

const peerInfo = bob.processHandshake(handshakeMemos);
// peerInfo = { agentId: 'alice-agent', capabilities: ['task-assignment'] }

// Encode a command for memo transport
const commandMemos = alice.encodeCommand('Audit contract 0xABC for privacy leaks');
//  Send as shielded memo(s)  Zcash encrypts

const command = bob.decodeCommand(commandMemos);
// command = 'Audit contract 0xABC for privacy leaks'

// Task workflow
const taskMemos = TaskManager.assignTask({
  description: 'Audit smart contract for privacy leaks',
  reward: '0.5 ZEC',
  deadline: Date.now() + 86400000,
});
//  Send as shielded memos

const proofMemos = TaskManager.submitProof(taskMemos, {
  result: 'No privacy leaks found.',
  evidence: 'ipfs://Qm...',
});

const paymentMemos = TaskManager.confirmPayment(proofMemos, {
  txid: 'zcash-tx-hash...',
  amount: '0.5 ZEC',
});
```

## Architecture

```

                  TypeScript SDK                    
    AgentSession  MemoCodec  TaskManager         

                  WASM Bindings                     

   memo-       crypto-    address-     agent-  
   codec      primitives    utils     protocol 

 512-byte    BLAKE3       Agent IDs  Handshake 
 encode/     Random       classify   Tasks     
 decode      Agent IDs     Validate   Sessions  
 chunking     Anti-     Reassembly        
 Reassembly    replay

                                             

          Zcash Shielded Transaction Layer         
  Encryption  Integrity  Metadata Privacy        
        (provided by Zcash, not this toolkit)      

```

## Wire Format

Every memo is exactly 512 bytes:

```
[0]       Protocol version (0x01)
[1]       Message type
[2..18]   Session ID (16 bytes)
[18..20]  Chunk index (u16 BE)
[20..22]  Total chunks (u16 BE)
[22..54]  BLAKE3 content hash (32 bytes)
[54..56]  Payload length (u16 BE)
[56..60]  Reserved (4 bytes, 0x00)
[60..512]  Payload (452 bytes, zero-padded)
```

## Message Types

| Type | Code | Use Case |
|---|---|---|
| Handshake | 0x01 | Exchange agent identity and capabilities |
| Text | 0x02 | General messages |
| Command | 0x03 | Agent instructions |
| Response | 0x04 | Command results |
| Ack | 0x05 | Delivery confirmation |
| Close | 0x06 | Session termination |
| Binary | 0x07 | Arbitrary binary data |
| TaskAssign | 0x10 | Assign work with reward |
| TaskProof | 0x11 | Submit proof of completion |
| PaymentConfirm | 0x12 | Confirm ZEC payment |

## Building

```bash
# Rust tests
cargo test --workspace

# Build WASM
wasm-pack build crates/wasm-bindings --target web --out-dir ../../ts-sdk/wasm-pkg --release

# TypeScript
cd ts-sdk && npm install && npx tsup && npm test
```

## Demo

Open `demo/index.html` in a browser to see a visual simulation of two agents communicating over shielded memos.

## Related Work

- **[BLAKE3 WASM](https://lamb356.github.io/blake3-wasm/)**  Browser BLAKE3 implementation
- **FROST Multi-Sig UI**  Threshold cryptography interface for Zcash
- **PCZT Tooling**  Partially Constructed Zcash Transaction RPC methods

## License

MIT
