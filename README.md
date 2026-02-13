# Zcash Agent Toolkit

**Private AI agent communication over Zcash shielded memos.**

AI agents need to talk to each other. But every existing transport — HTTP, WebSockets, message queues — leaks metadata: who's talking, when, how often, and to whom. Zcash shielded memos fix this. On-chain, all memos look identical. No observer can tell which agents are communicating or what they're saying.

This toolkit gives agents a complete encrypted communication stack built on Zcash's 512-byte memo field:

- **Structured protocol** — 60-byte header + 452-byte payload with automatic chunking for large messages
- **End-to-end encryption** — X25519 key exchange + ChaCha20-Poly1305, on top of Zcash's native shielded encryption
- **Forward secrecy** — BLAKE3-based symmetric ratchet. Old keys are zeroized. Compromising today's key reveals nothing about yesterday's messages.
- **Key rotation** — Per-session keypair rotation with previous-key fallback for in-flight messages
- **Zcash key derivation** — Agent identity derived from seed via domain-separated BLAKE3 KDF, tying agents to Zcash addresses
- **Task/bounty workflows** — Built-in TaskAssign → TaskProof → PaymentConfirm protocol with anti-replay nonces
- **Rust + WASM + TypeScript** — Use from any environment

## Quick Example

```typescript
import { AgentSession, MemoCodec, TaskManager } from '@zcash-agent/toolkit';

// Two agents establish an encrypted session
const alice = await AgentSession.create();
const bob = await AgentSession.create();

// Exchange public keys (via initial shielded memo)
const aliceHandshake = alice.createHandshake('alice-agent', ['task-execution']);
const bobHandshake = bob.createHandshake('bob-agent', ['task-assignment']);

// Derive shared secret from Diffie-Hellman
alice.deriveSharedSecret(bob.publicKey());
bob.deriveSharedSecret(alice.publicKey());

// Encrypt a command — ready to embed in a Zcash shielded memo
const encrypted = alice.encrypt('Execute privacy audit on contract 0x...');
const decrypted = bob.decrypt(encrypted);

// Task workflow with payment
const task = TaskManager.assignTask(alice, {
  description: 'Audit smart contract for privacy leaks',
  reward: '0.5 ZEC',
  deadline: Date.now() + 86400000,
});

const proof = TaskManager.submitProof(bob, task, {
  result: 'No privacy leaks found. Full report attached.',
  evidence: 'ipfs://Qm...',
});

const payment = TaskManager.confirmPayment(alice, proof, {
  txid: 'zcash-tx-hash...',
  amount: '0.5 ZEC',
});
```

## Demo

Open [`demo/index.html`](demo/index.html) in a browser to see a visual simulation of two agents communicating over shielded memos.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  TypeScript SDK                       │
│  AgentSession │ MemoCodec │ TaskManager               │
│  SecureSession │ RotatingKeys │ deriveAgentFromSeed   │
├──────────────┬──────────────┬────────────────────────┤
│              │  WASM Bindings (wasm-bindgen)          │
├──────────────┼──────────────┼────────────────────────┤
│  memo-codec  │   crypto-    │  agent-protocol        │
│              │  primitives  │                         │
│  512-byte    │  BLAKE3      │  Handshake             │
│  encode/     │  X25519      │  Task/Bounty           │
│  decode      │  ChaCha20    │  Encrypted relay       │
│  chunking    │  Ratchet     │                         │
│  reassembly  │  Rotation    │  address-utils         │
│              │  Zeroize     │  Zcash key derivation  │
└──────────────┴──────────────┴────────────────────────┘
```

## Security Properties

| Property | How |
|---|---|
| **Confidentiality** | Zcash shielded encryption + ChaCha20-Poly1305 |
| **Integrity** | BLAKE3 content hash in every memo header |
| **Forward secrecy** | Symmetric ratchet with chain key zeroization |
| **Authentication** | X25519 Diffie-Hellman key exchange |
| **Anti-replay** | Nonces on task messages + consumed key tracking |
| **Metadata privacy** | All memos zero-padded to exactly 512 bytes |
| **Key hygiene** | Zeroize on drop for all secret material |

## Message Types

| Type | Code | Use Case |
|---|---|---|
| Handshake | 0x01 | Exchange public keys and capabilities |
| Text | 0x02 | General encrypted messages |
| Command | 0x03 | Agent instructions |
| Response | 0x04 | Command results |
| Ack | 0x05 | Delivery confirmation |
| Close | 0x06 | Session termination |
| Binary | 0x07 | Arbitrary binary data |
| TaskAssign | 0x10 | Assign work with reward |
| TaskProof | 0x11 | Submit proof of completion |
| PaymentConfirm | 0x12 | Confirm ZEC payment |

## Wire Format

Every Zcash memo is exactly 512 bytes:

```
[0]       Protocol version (0x01)
[1]       Message type
[2..18]   Session ID (16 bytes)
[18..20]  Chunk index (u16 BE)
[20..22]  Total chunks (u16 BE)
[22..54]  BLAKE3 content hash (32 bytes)
[54..56]  Payload length (u16 BE)
[56..60]  Reserved (4 bytes, 0x00)
[60..512] Payload (452 bytes, zero-padded)
```

Messages larger than 452 bytes are automatically chunked across multiple memos with the same session ID and content hash. The reassembly buffer handles out-of-order delivery.

## Building

```bash
# Rust tests
cargo test --workspace

# Build WASM
wasm-pack build crates/wasm-bindings --target web --out-dir ../../ts-sdk/wasm-pkg --release

# TypeScript
cd ts-sdk
npm install
npx tsup
npm test
```

## Test Coverage

- **115 Rust tests** across 5 crates (codec, crypto, address, protocol, WASM)
- **70 TypeScript tests** across 7 test files
- Forward secrecy proofs, replay rejection, key rotation, full protocol simulations

## Related Work

- **[BLAKE3 WASM](https://lamb356.github.io/blake3-wasm/)** — Browser BLAKE3 implementation (collaboration with Zooko Wilcox)
- **FROST Multi-Sig UI** — Threshold cryptography interface for Zcash
- **PCZT Tooling** — Partially Constructed Zcash Transaction RPC methods
- **Zchat / zsend.xyz** — Private messenger built on Zcash memos (potential integration)

## License

MIT
