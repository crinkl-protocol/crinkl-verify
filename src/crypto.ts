import * as ed25519 from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalize } from "json-canonicalize";

const encoder = new TextEncoder();
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

if (!ed25519.etc.sha512Sync) {
  ed25519.etc.sha512Sync = (...messages: Uint8Array[]) => sha512(ed25519.etc.concatBytes(...messages));
}

export function canonicalizeJcs(value: unknown): string {
  return canonicalize(value);
}

export function sha256HexUtf8(value: string): string {
  return bytesToHex(sha256(encoder.encode(value)));
}

/** SHA-256 over raw bytes (as opposed to {@link sha256HexUtf8}'s UTF-8 string input). */
export function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array | undefined {
  if (!/^[0-9a-f]{64}$/i.test(hex)) return undefined;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

export function base64ToBytes(value: string): Uint8Array | undefined {
  try {
    const decode = globalThis.atob;
    const encode = globalThis.btoa;
    if (typeof decode !== "function" || typeof encode !== "function" || !CANONICAL_BASE64.test(value)) return undefined;
    const decoded = decode(value);
    const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return encode(binary) === value ? bytes : undefined;
  } catch {
    return undefined;
  }
}

export async function verifyEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  return ed25519.verify(signature, message, publicKey);
}
