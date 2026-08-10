import type {
  ChainEvidenceSolanaRpc,
  RewardBatchCommittedPayload,
  SolanaEvidenceTrustResolver
} from "./types.js";

const TX_REF = /^solana:([^:]+):([^:]+):(0|[1-9][0-9]*):(0|[1-9][0-9]*):(0|[1-9][0-9]*):([^:]+)$/;
const HEX_8 = /^[0-9a-f]{16}$/;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
  if (!evidence.rpcUrl || !HEX_8.test(evidence.instructionDiscriminatorHex)) {
    return { valid: false, message: "solana-rpc mode requires an RPC URL and lowercase 8-byte discriminator hex.", path: "$.options.chainEvidence", cause: "input" };
  }
  if (!trust) return { valid: false, message: "No solanaEvidenceTrust resolver authorized the Solana evidence boundary.", path: "$.options.solanaEvidenceTrust", cause: "trust" };
  let trusted = false;
  try {
    trusted = await trust({
      cluster: cluster!,
      rpcUrl: evidence.rpcUrl,
      programId: programId!,
      instructionDiscriminatorHex: evidence.instructionDiscriminatorHex,
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
    const signatures = tx?.signatures;
    if (!transaction || transaction.slot !== slot || meta?.err !== null || !accountKeys || !accountKeys.every((key) => typeof key === "string") || !Array.isArray(instructions) || !Array.isArray(signatures) || signatures[0] !== signature) {
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
    if (!Number.isSafeInteger(programIdIndex) || typeof dataText !== "string" || accountKeys[programIdIndex as number] !== programId) {
      throw new SolanaEvidenceMismatch("instruction program or position does not match batch.txRef");
    }
    const data = decodeBase58(dataText);
    if (!data || data.length !== 61) throw new SolanaEvidenceMismatch("commitment instruction data must be exactly 61 bytes");
    if (bytesToHex(data.slice(0, 8)) !== evidence.instructionDiscriminatorHex) throw new SolanaEvidenceMismatch("commitment instruction discriminator mismatch");
    const batchId = expectedBatchId(batch.batchId);
    if (batchId === undefined || readU64Le(data, 8) !== batchId) throw new SolanaEvidenceMismatch("commitment instruction batchId mismatch");
    if (bytesToHex(data.slice(16, 48)) !== batch.root) throw new SolanaEvidenceMismatch("commitment instruction root mismatch");
    if (readU32Le(data, 48) !== batch.leafCount) throw new SolanaEvidenceMismatch("commitment instruction leafCount mismatch");
    if (data[60] !== Number(batch.schemaVersion[0])) throw new SolanaEvidenceMismatch("commitment instruction schemaVersion mismatch");
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
