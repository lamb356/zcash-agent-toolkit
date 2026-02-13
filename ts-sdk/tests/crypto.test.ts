import { describe, it, expect, beforeAll } from 'vitest';
import {
  ensureInit,
  blake3Hash,
  blake3Hex,
  blake3DeriveKey,
  blake3KeyedHash,
  randomBytes,
  randomHex,
  generateSessionId,
} from '../src/index.js';

beforeAll(async () => {
  await ensureInit();
});

describe('blake3Hash', () => {
  it('returns 32 bytes', async () => {
    const hash = await blake3Hash(new Uint8Array([1, 2, 3]));
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  it('is deterministic', async () => {
    const data = new TextEncoder().encode('hello world');
    const hash1 = await blake3Hash(data);
    const hash2 = await blake3Hash(data);
    expect(hash1).toEqual(hash2);
  });

  it('different inputs produce different hashes', async () => {
    const hash1 = await blake3Hash(new TextEncoder().encode('hello'));
    const hash2 = await blake3Hash(new TextEncoder().encode('world'));
    expect(hash1).not.toEqual(hash2);
  });
});

describe('blake3Hex', () => {
  it('returns a 64-char hex string', async () => {
    const hex = await blake3Hex(new TextEncoder().encode('test'));
    expect(typeof hex).toBe('string');
    expect(hex.length).toBe(64);
    expect(hex).toMatch(/^[0-9a-f]+$/);
  });

  it('matches blake3Hash output', async () => {
    const data = new TextEncoder().encode('consistency check');
    const hash = await blake3Hash(data);
    const hex = await blake3Hex(data);
    const hashHex = Array.from(hash)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    expect(hex).toBe(hashHex);
  });
});

describe('blake3DeriveKey', () => {
  it('returns 32 bytes', async () => {
    const key = await blake3DeriveKey('test context', new Uint8Array([1, 2, 3]));
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it('different contexts produce different keys', async () => {
    const ikm = new TextEncoder().encode('same input');
    const key1 = await blake3DeriveKey('context A', ikm);
    const key2 = await blake3DeriveKey('context B', ikm);
    expect(key1).not.toEqual(key2);
  });

  it('is deterministic for same context and ikm', async () => {
    const ikm = new TextEncoder().encode('input key material');
    const key1 = await blake3DeriveKey('my context', ikm);
    const key2 = await blake3DeriveKey('my context', ikm);
    expect(key1).toEqual(key2);
  });
});

describe('blake3KeyedHash', () => {
  it('returns 32 bytes', async () => {
    const key = new Uint8Array(32);
    key.fill(0x42);
    const mac = await blake3KeyedHash(key, new TextEncoder().encode('message'));
    expect(mac).toBeInstanceOf(Uint8Array);
    expect(mac.length).toBe(32);
  });

  it('different keys produce different MACs', async () => {
    const key1 = new Uint8Array(32);
    key1.fill(0x01);
    const key2 = new Uint8Array(32);
    key2.fill(0x02);
    const data = new TextEncoder().encode('same data');
    const mac1 = await blake3KeyedHash(key1, data);
    const mac2 = await blake3KeyedHash(key2, data);
    expect(mac1).not.toEqual(mac2);
  });
});

describe('randomBytes', () => {
  it('returns correct length', async () => {
    const bytes = await randomBytes(16);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(16);
  });

  it('two calls produce different results', async () => {
    const a = await randomBytes(32);
    const b = await randomBytes(32);
    expect(a).not.toEqual(b);
  });
});

describe('randomHex', () => {
  it('returns hex string of correct length', async () => {
    const hex = await randomHex(16);
    expect(typeof hex).toBe('string');
    expect(hex.length).toBe(32); // 16 bytes = 32 hex chars
    expect(hex).toMatch(/^[0-9a-f]+$/);
  });
});

describe('generateSessionId', () => {
  it('returns 16 bytes', async () => {
    const sid = await generateSessionId();
    expect(sid).toBeInstanceOf(Uint8Array);
    expect(sid.length).toBe(16);
  });

  it('generates unique IDs', async () => {
    const sid1 = await generateSessionId();
    const sid2 = await generateSessionId();
    expect(sid1).not.toEqual(sid2);
  });
});
