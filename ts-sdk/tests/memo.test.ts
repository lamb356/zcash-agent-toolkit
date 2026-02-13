import { describe, it, expect, beforeAll } from 'vitest';
import { ensureInit, MemoCodec } from '../src/index.js';

beforeAll(async () => {
  await ensureInit();
});

describe('MemoCodec', () => {
  describe('create', () => {
    it('creates a codec with a session ID', async () => {
      const codec = await MemoCodec.create();
      expect(typeof codec.sessionId).toBe('string');
      expect(codec.sessionId.length).toBe(32); // 16 bytes = 32 hex chars
      expect(codec.sessionId).toMatch(/^[0-9a-f]+$/);
    });

    it('creates unique session IDs', async () => {
      const a = await MemoCodec.create();
      const b = await MemoCodec.create();
      expect(a.sessionId).not.toBe(b.sessionId);
    });
  });

  describe('fromSession', () => {
    it('preserves the session ID', async () => {
      const hex = 'aabbccddeeff00112233445566778899';
      const codec = await MemoCodec.fromSession(hex);
      expect(codec.sessionId).toBe(hex);
    });

    it('rejects invalid length', async () => {
      await expect(MemoCodec.fromSession('aabb')).rejects.toThrow();
    });
  });

  describe('text encoding', () => {
    it('encodes short text as 1 memo', async () => {
      const codec = await MemoCodec.create();
      const memos = codec.encodeText('Hello, Zcash!');
      expect(memos.length).toBe(1);
      expect(memos[0].length).toBe(1024); // 512 bytes = 1024 hex chars
    });

    it('roundtrips text', async () => {
      const codec = await MemoCodec.create();
      const text = 'Hello, Zcash agent protocol!';
      const memos = codec.encodeText(text);
      const decoded = await MemoCodec.decode(memos);
      const result = new TextDecoder().decode(decoded.data);
      expect(result).toBe(text);
    });

    it('roundtrips unicode text', async () => {
      const codec = await MemoCodec.create();
      const text = 'Privacy is a right! 🔒🛡️ Zcash 隐私';
      const memos = codec.encodeText(text);
      const decoded = await MemoCodec.decode(memos);
      const result = new TextDecoder().decode(decoded.data);
      expect(result).toBe(text);
    });

    it('preserves session ID in memos', async () => {
      const codec = await MemoCodec.create();
      const memos = codec.encodeText('test');
      const decoded = await MemoCodec.decode(memos);
      expect(decoded.sessionId).toBe(codec.sessionId);
    });

    it('sets correct message type (0x02 = Text)', async () => {
      const codec = await MemoCodec.create();
      const memos = codec.encodeText('test');
      const decoded = await MemoCodec.decode(memos);
      expect(decoded.msgType).toBe(0x02);
    });

    it('all memos are exactly 512 bytes (1024 hex chars)', async () => {
      const codec = await MemoCodec.create();
      const memos = codec.encodeText('test');
      for (const memo of memos) {
        expect(memo.length).toBe(1024);
      }
    });
  });

  describe('command encoding', () => {
    it('roundtrips JSON command', async () => {
      const codec = await MemoCodec.create();
      const command = { action: 'ping', data: { message: 'Hello!' } };
      const memos = codec.encodeCommand(command);
      const decoded = await MemoCodec.decode(memos);
      const result = JSON.parse(new TextDecoder().decode(decoded.data));
      expect(result).toEqual(command);
    });

    it('sets message type 0x03 (Command)', async () => {
      const codec = await MemoCodec.create();
      const memos = codec.encodeCommand({ action: 'test' });
      const decoded = await MemoCodec.decode(memos);
      expect(decoded.msgType).toBe(0x03);
    });
  });

  describe('binary encoding', () => {
    it('roundtrips binary data', async () => {
      const codec = await MemoCodec.create();
      const data = new Uint8Array([0, 1, 2, 255, 254, 253]);
      const memos = codec.encodeBinary(data);
      const decoded = await MemoCodec.decode(memos);
      // Binary payloads may include zero-padding, compare original length
      expect(decoded.data.slice(0, data.length)).toEqual(data);
    });

    it('sets message type 0x07 (Binary)', async () => {
      const codec = await MemoCodec.create();
      const memos = codec.encodeBinary(new Uint8Array([1, 2, 3]));
      const decoded = await MemoCodec.decode(memos);
      expect(decoded.msgType).toBe(0x07);
    });
  });

  describe('chunking', () => {
    it('chunks messages larger than 458 bytes', async () => {
      const codec = await MemoCodec.create();
      // 500 bytes of text will exceed the 458-byte payload limit
      const text = 'A'.repeat(500);
      const memos = codec.encodeText(text);
      expect(memos.length).toBeGreaterThan(1);
    });

    it('roundtrips 5KB message', async () => {
      const codec = await MemoCodec.create();
      const text = 'X'.repeat(5000);
      const memos = codec.encodeText(text);
      expect(memos.length).toBeGreaterThan(1);
      const decoded = await MemoCodec.decode(memos);
      const result = new TextDecoder().decode(decoded.data);
      expect(result).toBe(text);
    });

    it('verifies content hash', async () => {
      const codec = await MemoCodec.create();
      const memos = codec.encodeText('integrity check');
      const decoded = await MemoCodec.decode(memos);
      expect(typeof decoded.contentHash).toBe('string');
      expect(decoded.contentHash.length).toBe(64); // BLAKE3 = 32 bytes = 64 hex
    });

    it('exactly 458 bytes fits in 1 chunk', async () => {
      const codec = await MemoCodec.create();
      // 458 ASCII chars = 458 bytes
      const text = 'B'.repeat(458);
      const memos = codec.encodeText(text);
      expect(memos.length).toBe(1);
    });

    it('459 bytes requires 2 chunks', async () => {
      const codec = await MemoCodec.create();
      const text = 'C'.repeat(459);
      const memos = codec.encodeText(text);
      expect(memos.length).toBe(2);
    });
  });
});
