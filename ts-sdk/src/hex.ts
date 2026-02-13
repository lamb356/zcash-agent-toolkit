/**
 * Validated hex encoding/decoding utilities.
 *
 * Centralises all hex conversions with input validation to prevent
 * silent corruption from odd-length or non-hex strings.
 */

/** Validate that a string is valid hex (even length, only hex chars). */
export function validateHex(input: string, label?: string): void {
  if (input.length % 2 !== 0) {
    throw new Error(`${label ?? 'Hex'}: odd length`);
  }
  if (!/^[0-9a-fA-F]*$/.test(input)) {
    throw new Error(`${label ?? 'Hex'}: invalid characters`);
  }
}

/** Decode a hex string to bytes, with validation. */
export function hexToBytes(hex: string, label?: string): Uint8Array {
  validateHex(hex, label);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Encode bytes to a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
