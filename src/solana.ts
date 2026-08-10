import type {
  ChainEvidenceSolanaRpc,
  RewardBatchCommittedPayload,
  SolanaEvidenceTrustResolver
} from "./types.js";
import { Point } from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";

const TX_REF = /^solana:([^:]+):([^:]+):(0|[1-9][0-9]*):(0|[1-9][0-9]*):(0|[1-9][0-9]*):([^:]+)$/;
const HEX_8 = /^[0-9a-f]{16}$/;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const TEXT = new TextEncoder();
const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";

export const PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1 = Object.freeze({
  binding: "crinkl-platform-solana-create-batch-imprint/v1" as const,
  sourceCommit: "ae3fca9fc1d501591f2c2f377bfdea1f35fa6389" as const,
  instructionDiscriminatorHex: "f5f3194de5a7ac64"
});

export interface SolanaAnchorVerification {
  valid: boolean;
  mismatch?: boolean;
  message?: string;
  path?: string;
  cause?: "input" | "trust" | "network";
}

interface RpcEnvelope {
  jsonrpc: "2.0";
  id: number;
  result?: unknown;
  error?: unknown;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function safeIndex(value: string): number | undefined {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function decodeBase58(value: string): Uint8Array | undefined {
  if (value.length === 0) return new Uint8Array();
  let numeric = 0n;
  for (const character of value) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) return undefined;
    numeric = numeric * 58n + BigInt(digit);
  }
  let leadingZeroes = 0;
  while (leadingZeroes < value.length && value[leadingZeroes] === "1") leadingZeroes += 1;
  const body: number[] = [];
  while (numeric > 0n) {
    body.push(Number(numeric & 0xffn));
    numeric >>= 8n;
  }
  const output = new Uint8Array(leadingZeroes + body.length);
  for (let i = 0; i < body.length; i += 1) output[output.length - 1 - i] = body[i]!;
  return output;
}

class SolanaEvidenceMismatch extends Error {}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encodeBase58(value: Uint8Array): string {
  let numeric = 0n;
  for (const byte of value) numeric = (numeric << 8n) | BigInt(byte);
  let body = "";
  while (numeric > 0n) {
    body = BASE58[Number(numeric % 58n)] + body;
    numeric /= 58n;
  }
  let leadingZeroes = 0;
  while (leadingZeroes < value.length && value[leadingZeroes] === 0) leadingZeroes += 1;
  return "1".repeat(leadingZeroes) + body;
}

function concat(...values: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function isOnCurve(value: Uint8Array): boolean {
  try {
    Point.fromHex(value);
    return true;
  } catch {
    return false;
  }
}

function findProgramAddress(seeds: Uint8Array[], programId: Uint8Array): string | undefined {
  const marker = TEXT.encode("ProgramDerivedAddress");
  for (let bump = 255; bump >= 0; bump -= 1) {
    const address = sha256(concat(...seeds, Uint8Array.of(bump), programId, marker));
    if (!isOnCurve(address)) return encodeBase58(address);
  }
  return undefined;
}

function readU64Le(value: Uint8Array, offset: number): bigint {
  let result = 0n;
  for (let i = 7; i >= 0; i -= 1) result = (result << 8n) | BigInt(value[offset + i]!);
  return result;
}

function readU32Le(value: Uint8Array, offset: number): number {
  return new DataView(value.buffer, value.byteOffset, value.byteLength).getUint32(offset, true);
}

function expectedBatchId(batchId: string): bigint | undefined {
  const prefix = batchId.replace(/-/g, "").slice(0, 16);
  return HEX_8.test(prefix) ? BigInt(`0x${prefix}`) : undefined;
}

async function rpc(fetchImpl: typeof fetch, rpcUrl: string, id: number, method: string, params: unknown[]): Promise<unknown> {
  const response = await fetchImpl(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params })
  });
  if (!response.ok) throw new Error(`${method} returned HTTP ${response.status}`);
  const envelope = object(await response.json()) as RpcEnvelope | undefined;
  if (!envelope || envelope.jsonrpc !== "2.0" || envelope.id !== id || envelope.error !== undefined || !("result" in envelope)) {
    throw new Error(`${method} returned an invalid JSON-RPC envelope`);
  }
  return envelope.result;
}

export async function verifySolanaBatchAnchor(
  batch: RewardBatchCommittedPayload,
  chainId: string,
  evidence: ChainEvidenceSolanaRpc,
  trust: SolanaEvidenceTrustResolver | undefined
): Promise<SolanaAnchorVerification> {
  const match = TX_REF.exec(batch.txRef);
  if (!match) return { valid: false, message: "batch.txRef is not a canonical Solana transaction reference.", path: "$.batch.txRef", cause: "input" };
  const [, cluster, programId, slotText, txIndexText, instructionIndexText, signature] = match;
  const slot = safeIndex(slotText!);
  const txIndex = safeIndex(txIndexText!);
  const instructionIndex = safeIndex(instructionIndexText!);
  if (slot === undefined || txIndex === undefined || instructionIndex === undefined || slot === 0) {
    return { valid: false, message: "batch.txRef must identify a non-zero slot and exact transaction/instruction positions.", path: "$.batch.txRef", cause: "input" };
  }
  if (chainId !== `solana:${cluster}` && chainId !== `solana-${cluster}`) {
    return { valid: false, message: "batch.txRef cluster does not match token.chainId.", path: "$.batch.txRef", cause: "trust" };
  }
  const programBytes = decodeBase58(programId!);
  const signatureBytes = decodeBase58(signature!);
  if (!programBytes || programBytes.length !== 32 || !signatureBytes || signatureBytes.length !== 64) {
    return { valid: false, message: "batch.txRef program ID or transaction signature is not canonical base58.", path: "$.batch.txRef", cause: "input" };
  }
  if (evidence.binding !== PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1.binding || !evidence.rpcUrl) {
    return { valid: false, message: "solana-rpc mode requires the supported pinned Platform binding and an RPC URL.", path: "$.options.chainEvidence", cause: "input" };
  }
  if (!trust) return { valid: false, message: "No solanaEvidenceTrust resolver authorized the Solana evidence boundary.", path: "$.options.solanaEvidenceTrust", cause: "trust" };
  let trusted = false;
  try {
    trusted = await trust({
      binding: PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1.binding,
      sourceCommit: PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1.sourceCommit,
      cluster: cluster!,
      rpcUrl: evidence.rpcUrl,
      programId: programId!,
      instructionDiscriminatorHex: PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1.instructionDiscriminatorHex,
      requiredFinality: "finalized"
    });
  } catch {
    trusted = false;
  }
  if (!trusted) return { valid: false, message: "The caller did not authorize this Solana evidence boundary.", path: "$.options.solanaEvidenceTrust", cause: "trust" };

  const fetchImpl = evidence.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") return { valid: false, message: "No fetch implementation is available for Solana JSON-RPC.", path: "$.options.chainEvidence.rpcUrl", cause: "network" };

  try {
    const transactionRaw = await rpc(fetchImpl, evidence.rpcUrl, 1, "getTransaction", [signature, { encoding: "json", commitment: "finalized", maxSupportedTransactionVersion: 0 }]);
    const statusRaw = await rpc(fetchImpl, evidence.rpcUrl, 2, "getSignatureStatuses", [[signature], { searchTransactionHistory: true }]);
    const blockRaw = await rpc(fetchImpl, evidence.rpcUrl, 3, "getBlock", [slot, { commitment: "finalized", transactionDetails: "signatures", rewards: false, maxSupportedTransactionVersion: 0 }]);

    const transaction = object(transactionRaw);
    const meta = object(transaction?.meta);
    const tx = object(transaction?.transaction);
    const message = object(tx?.message);
    const staticAccountKeys = message?.accountKeys;
    const loadedAddresses = object(meta?.loadedAddresses);
    const loadedWritable = loadedAddresses?.writable;
    const loadedReadonly = loadedAddresses?.readonly;
    const accountKeys = Array.isArray(staticAccountKeys) &&
      (loadedWritable === undefined || Array.isArray(loadedWritable)) &&
      (loadedReadonly === undefined || Array.isArray(loadedReadonly))
      ? [...staticAccountKeys, ...(loadedWritable ?? []), ...(loadedReadonly ?? [])]
      : undefined;
    const instructions = message?.instructions;
    const header = object(message?.header);
    const signatures = tx?.signatures;
    if (!transaction || transaction.slot !== slot || meta?.err !== null || !accountKeys || !accountKeys.every((key) => typeof key === "string") || !Array.isArray(instructions) || !Array.isArray(signatures) || signatures[0] !== signature || !header || !Number.isSafeInteger(header.numRequiredSignatures) || Number(header.numRequiredSignatures) < 1) {
      throw new SolanaEvidenceMismatch("getTransaction result does not match the successful transaction named by batch.txRef");
    }

    const statusValue = object(statusRaw)?.value;
    const status = Array.isArray(statusValue) ? object(statusValue[0]) : undefined;
    if (!status || status.err !== null || status.slot !== slot || status.confirmationStatus !== "finalized") {
      throw new SolanaEvidenceMismatch("signature is not finalized at the slot named by batch.txRef");
    }

    const blockSignatures = object(blockRaw)?.signatures;
    if (!Array.isArray(blockSignatures) || blockSignatures[txIndex] !== signature) {
      throw new SolanaEvidenceMismatch("transaction is not at the block position named by batch.txRef");
    }

    const instruction = object(instructions[instructionIndex]);
    const programIdIndex = instruction?.programIdIndex;
    const dataText = instruction?.data;
    const accounts = instruction?.accounts;
    if (!Number.isSafeInteger(programIdIndex) || typeof dataText !== "string" || accountKeys[programIdIndex as number] !== programId || !Array.isArray(accounts) || accounts.length !== 4 || !accounts.every(Number.isSafeInteger)) {
      throw new SolanaEvidenceMismatch("instruction program or position does not match batch.txRef");
    }
    const data = decodeBase58(dataText);
    if (!data || data.length !== 61) throw new SolanaEvidenceMismatch("commitment instruction data must be exactly 61 bytes");
    if (bytesToHex(data.slice(0, 8)) !== PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1.instructionDiscriminatorHex) throw new SolanaEvidenceMismatch("commitment instruction discriminator mismatch");
    const batchId = expectedBatchId(batch.batchId);
    if (batchId === undefined || readU64Le(data, 8) !== batchId) throw new SolanaEvidenceMismatch("commitment instruction batchId mismatch");
    if (bytesToHex(data.slice(16, 48)) !== batch.root) throw new SolanaEvidenceMismatch("commitment instruction root mismatch");
    if (readU32Le(data, 48) !== batch.leafCount) throw new SolanaEvidenceMismatch("commitment instruction leafCount mismatch");
    if (data[60] !== Number(batch.schemaVersion[0])) throw new SolanaEvidenceMismatch("commitment instruction schemaVersion mismatch");
    const programBytesForPda = decodeBase58(programId!);
    const expectedBatchPda = findProgramAddress([TEXT.encode("crinkl"), TEXT.encode("batch"), data.slice(8, 16)], programBytesForPda!);
    const expectedConfigPda = findProgramAddress([TEXT.encode("crinkl"), TEXT.encode("authority")], programBytesForPda!);
    if (
      accountKeys[accounts[0] as number] !== expectedBatchPda ||
      accountKeys[accounts[1] as number] !== accountKeys[0] ||
      accountKeys[accounts[2] as number] !== expectedConfigPda ||
      accountKeys[accounts[3] as number] !== SYSTEM_PROGRAM_ID
    ) {
      throw new SolanaEvidenceMismatch("commitment instruction account ABI mismatch");
    }
    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      mismatch: error instanceof SolanaEvidenceMismatch,
      message: `Solana JSON-RPC evidence failed: ${error instanceof Error ? error.message : "unknown error"}.`,
      path: "$.options.chainEvidence",
      cause: error instanceof SolanaEvidenceMismatch ? "trust" : "network"
    };
  }
}
