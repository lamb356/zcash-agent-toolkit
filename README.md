# @zcash-agent/toolkit

AI agent communication toolkit over Zcash shielded memo fields.

Turn Zcash's 512-byte encrypted memo field into a structured communication protocol for AI agents, with built-in support for bounty/task workflows.

## Features

- **Structured 512-byte memo protocol** with automatic chunking for large messages
- **BLAKE3** hashing, KDF, and content integrity verification (v1.8.3, WASM SIMD optimized)
- **X25519** Diffie-Hellman key exchange for agent-to-agent session establishment
- **ChaCha20-Poly1305** authenticated encryption
- **Task/bounty workflow**: assign tasks, submit proofs, confirm payments
- **TypeScript SDK** with clean async API, published as `@zcash-agent/toolkit`
- **250 KB WASM binary** (release build with LTO)

## Quick Start

```typescript
import { AgentSession, TaskManager } from '@zcash-agent/toolkit';

// Two agents establish an encrypted session
const alice = await AgentSession.create();
const bob = await AgentSession.create();

// Exchange handshakes (these produce hex strings ready for zcash-cli z_sendmany)
const { handshake: aliceHS, memos: aliceMemos } = await alice.createHandshake(['text', 'task']);
const { handshake: bobHS, memos: bobMemos } = await bob.createHandshake(['text']);

// Process handshakes and derive shared secrets
const receivedBob = await alice.processHandshake(bobMemos);
const receivedAlice = await bob.processHandshake(aliceMemos);
await alice.deriveSharedSecret(receivedBob.public_key);
await bob.deriveSharedSecret(receivedAlice.public_key);

// Send encrypted commands
const memos = await alice.sendCommand({ action: 'ping', data: 'Hello!' });
const received = await bob.receiveCommand(memos);
// received = { action: 'ping', data: 'Hello!' }
```

## Memo Protocol Format

Each memo is exactly 512 bytes:

```
[0]       version (0x01)
[1]       message type
[2..18]   session ID (16 bytes)
[18..20]  chunk index (u16 BE)
[20..22]  total chunks (u16 BE)
[22..54]  BLAKE3 content hash (32 bytes)
[54..512] payload (458 bytes, zero-padded)
```

Messages larger than 458 bytes are automatically chunked across multiple memos.

## Message Types

| Type | Byte | Description |
|------|------|-------------|
| Handshake | `0x01` | Key exchange initiation |
| Text | `0x02` | Plain text message |
| Command | `0x03` | Structured JSON command |
| Response | `0x04` | Command response |
| Ack | `0x05` | Acknowledgement |
| Close | `0x06` | Session termination |
| Binary | `0x07` | Raw binary data |
| TaskAssign | `0x10` | Bounty task assignment |
| TaskProof | `0x11` | Proof of task completion |
| PaymentConfirm | `0x12` | ZEC payment confirmation |

## Architecture

```
zcash-agent-toolkit/
  crates/
    memo-codec/          # 512-byte memo encode/decode, chunking, reassembly
    crypto-primitives/   # BLAKE3, X25519, ChaCha20-Poly1305, random
    address-utils/       # Zcash address classification, agent ID generation
    agent-protocol/      # Handshake, task/bounty, encrypted relay
    wasm-bindings/       # WASM facade (wasm-bindgen wrappers)
  ts-sdk/                # TypeScript SDK (@zcash-agent/toolkit)
  examples/              # Demo scripts
```

All library crates are pure Rust. The `wasm-bindings` facade crate is the only one with `wasm-bindgen` dependency, keeping the architecture clean.

## Building

### Prerequisites

- Rust (stable)
- wasm-pack
- Node.js 18+

### Full build

```bash
# Linux/macOS
./build.sh

# Windows
.\build.ps1
```

### Manual steps

```bash
# Rust tests
cargo test --workspace

# WASM build
wasm-pack build crates/wasm-bindings --target web --out-dir ../../ts-sdk/wasm-pkg

# TypeScript SDK
cd ts-sdk && npm install && npm run build:ts
```

## Examples

```bash
cd ts-sdk
npx tsx ../examples/agent-handshake.ts    # Two agents establish encrypted session
npx tsx ../examples/task-bounty.ts        # Full bounty workflow
npx tsx ../examples/privacyclaw-demo.ts   # PrivacyClaw-style agent simulation
```

## API Reference

### `AgentSession`

Full encrypted agent session with keypair management.

```typescript
const session = await AgentSession.create();
session.publicKey;     // X25519 public key hex
session.agentId;       // Deterministic BLAKE3-based agent ID
session.sessionId;     // Random 16-byte session ID hex
await session.deriveSharedSecret(peerPublicKeyHex);
session.encrypt(plaintext);
session.decrypt(encryptedHex);
await session.createHandshake(capabilities?);
await session.processHandshake(memoHexArray);
await session.sendCommand(object);
await session.receiveCommand(memoHexArray);
```

### `MemoCodec`

Low-level memo encoding/decoding.

```typescript
const codec = await MemoCodec.create();
codec.sessionId;                        // hex string
codec.encodeText('hello');              // string[] (hex memos)
codec.encodeCommand({ action: 'do' }); // string[]
codec.encodeBinary(data);              // string[]
await MemoCodec.decode(hexMemos);       // DecodedMessage
```

### `TaskManager`

Bounty workflow helpers.

```typescript
await TaskManager.assignTask(sessionId, task);
await TaskManager.submitProof(sessionId, proof);
await TaskManager.confirmPayment(sessionId, payment);
await TaskManager.createTaskProof(taskId, action, proofData, timestamp);
await TaskManager.processTaskMessage(memoHexArray);
```

### Crypto Utilities

```typescript
await blake3Hash(data);                    // Uint8Array (32 bytes)
await blake3Hex(data);                     // hex string
await blake3DeriveKey(context, ikm);       // Uint8Array (32 bytes)
await blake3KeyedHash(key, data);          // Uint8Array (32 bytes)
await randomBytes(len);                    // Uint8Array
await randomHex(byteLen);                 // hex string
await generateSessionId();                 // Uint8Array (16 bytes)
```

### Address Utilities

```typescript
await classifyAddress('zs1...');  // "Sapling"
await supportsMemos('t1...');     // false
await isShielded('u1...');        // true
await validateAddress('zs1...');  // true
await agentIdFromPubkey(pubkey);  // deterministic hex ID
```

## License

MIT OR Apache-2.0
