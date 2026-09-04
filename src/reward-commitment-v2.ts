import { base64ToBytes, canonicalizeJcs, hexToBytes, sha256HexUtf8, verifyEd25519 } from "./crypto.js";
import { createInertJsonSnapshot, type JsonValue } from "./json.js";
import { verifyInclusionProof } from "./merkle.js";
import { replaySystemStreamSuffix, validateSystemStreamEventShape } from "./system-stream.js";
import { verifySolanaBatchAnchor } from "./solana.js";
import type {
  AnchorStatus,
  AuthorityCheckpointRegistryRecordV1,
  AuthorityCheckpointV1,
  ChainCommitmentRecordEvidence,
  RewardCommitmentTokenV2,
  RewardCommitmentV2VerificationOptions,
  RewardCommitmentV2VerificationResult,
  SystemStreamEvent,
  VerificationCause,
  VerificationErrorCode
} from "./types.js";

const AMOUNT = /^(0|[1-9][0-9]*)$/;
const HASH = /^[0-9a-f]{64}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CLOSED_SCHEMA_VERSIONS = ["1a", "1b", "2a", "2b"] as const;
const CHECKPOINT_PROFILE = "configured-checkpoint-root/v1" as const;
const CHECKPOINT_PROTOCOL_VERSION = "1.0.0-rc.1";
const MAX_SUFFIX_EVENTS = 128;

function object(value: JsonValue | undefined): { readonly [key: string]: JsonValue } | undefined {
  return value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value)
    ? (value as { readonly [key: string]: JsonValue })
    : undefined;
}

function array(value: JsonValue | undefined): readonly JsonValue[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isPoints(value: unknown): value is string {
  return typeof value === "string" && AMOUNT.test(value);
}

function owns(value: { readonly [key: string]: JsonValue }, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function exactlyKeys(value: { readonly [key: string]: JsonValue }, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => owns(value, key));
}

function deepEqualJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((item, index) => deepEqualJson(item, b[index]));
  const aObj = a as Record<string, unknown>;
  const bObj = b as Record<string, unknown>;
  const aKeys = Object.keys(aObj).sort();
  const bKeys = Object.keys(bObj).sort();
  return aKeys.length === bKeys.length && aKeys.every((key, index) => key === bKeys[index] && deepEqualJson(aObj[key], bObj[key]));
}

function resultFor(): RewardCommitmentV2VerificationResult {
  return {
    format: "crinkl-reward-commitment/v2",
    schemaVersion: "unknown",
    checkpointValid: false,
    systemStreamValid: false,
    authorityValid: "not_checked",
    commitmentValid: false,
    merkleValid: false,
    economicTier: "unknown",
    backingValid: "not_applicable",
    anchor: "not-checked",
    accepted: false,
    errors: [],
    warnings: [],
    metadata: {}
  };
}

function addError(result: RewardCommitmentV2VerificationResult, code: VerificationErrorCode, message: string, cause: VerificationCause, path?: string): void {
  result.errors.push({ code, message, cause, path });
}

function addWarning(result: RewardCommitmentV2VerificationResult, code: "ANCHOR_NOT_CHECKED" | "ANCHOR_INDETERMINATE", message: string): void {
  result.warnings.push({ code, message });
}

function invalid(result: RewardCommitmentV2VerificationResult, path: string, message: string): void {
  addError(result, "SCHEMA_INVALID", message, "input", path);
}

function parseSystemEvent(input: JsonValue, path: string, result: RewardCommitmentV2VerificationResult): SystemStreamEvent | undefined {
  const parsed = validateSystemStreamEventShape(input, path);
  if (parsed.error) {
    invalid(result, path, parsed.error);
    return undefined;
  }
  return parsed.event;
}

/** SHA-256 over the exact checkpoint authority-state commitment. */
export function computeAuthorityCheckpointRegistryStateHash(
  chainId: string,
  coveredHeadEventHash: string,
  records: readonly AuthorityCheckpointRegistryRecordV1[]
): string {
  return sha256HexUtf8(canonicalizeJcs({
    stateType: "AUTHORITY_REGISTRY_STATE",
    chainId,
    coveredHeadEventHash,
    records
  }));
}

/** SHA-256 over RFC 8785 checkpoint bytes with its signatures object omitted. */
export function computeAuthorityCheckpointV1Hash(checkpoint: AuthorityCheckpointV1): string {
  const { signatures: _signatures, ...unsigned } = checkpoint;
  return sha256HexUtf8(canonicalizeJcs(unsigned));
}

function parseCheckpoint(
  input: JsonValue,
  result: RewardCommitmentV2VerificationResult
): AuthorityCheckpointV1 | undefined {
  const checkpoint = object(input);
  if (!checkpoint) {
    invalid(result, "$.authorityCheckpoint", "authorityCheckpoint must be a JSON object.");
    return undefined;
  }
  const expectedKeys = [
    "checkpointType", "schemaVersion", "protocol", "evidenceProfile", "chainId", "sequence", "covered",
    "authorityState", "previousCheckpointHash", "limits", "signatures"
  ];
  if (!exactlyKeys(checkpoint, expectedKeys)) invalid(result, "$.authorityCheckpoint", "authorityCheckpoint has an unexpected field set.");
  if (checkpoint.checkpointType !== "AUTHORITY_CHECKPOINT") invalid(result, "$.authorityCheckpoint.checkpointType", "Expected AUTHORITY_CHECKPOINT.");
  if (checkpoint.schemaVersion !== 1) invalid(result, "$.authorityCheckpoint.schemaVersion", "Expected checkpoint schemaVersion 1.");
  if (checkpoint.evidenceProfile !== CHECKPOINT_PROFILE) invalid(result, "$.authorityCheckpoint.evidenceProfile", `Expected ${CHECKPOINT_PROFILE}.`);
  if (!isNonEmptyString(checkpoint.chainId)) invalid(result, "$.authorityCheckpoint.chainId", "checkpoint chainId must be a non-empty string.");
  if (!Number.isSafeInteger(checkpoint.sequence) || Number(checkpoint.sequence) < 1) invalid(result, "$.authorityCheckpoint.sequence", "checkpoint sequence must be a positive safe integer.");
  if (checkpoint.previousCheckpointHash !== null && (typeof checkpoint.previousCheckpointHash !== "string" || !HASH.test(checkpoint.previousCheckpointHash))) {
    invalid(result, "$.authorityCheckpoint.previousCheckpointHash", "previousCheckpointHash must be null or a lowercase SHA-256 digest.");
  }

  const protocol = object(checkpoint.protocol);
  if (!protocol || !exactlyKeys(protocol, ["protocolVersion"]) || protocol.protocolVersion !== CHECKPOINT_PROTOCOL_VERSION) {
    invalid(result, "$.authorityCheckpoint.protocol", `checkpoint protocolVersion must equal ${CHECKPOINT_PROTOCOL_VERSION}.`);
  }
  const covered = object(checkpoint.covered);
  if (
    !covered || !exactlyKeys(covered, ["streamHeight", "headEventHash", "effectiveAt"])
    || !Number.isSafeInteger(covered.streamHeight) || Number(covered.streamHeight) < 1
    || typeof covered.headEventHash !== "string" || !HASH.test(covered.headEventHash)
    || typeof covered.effectiveAt !== "string" || !TIMESTAMP.test(covered.effectiveAt)
  ) {
    invalid(result, "$.authorityCheckpoint.covered", "covered must contain a positive streamHeight, headEventHash, and UTC millisecond effectiveAt.");
  }
  const limits = object(checkpoint.limits);
  if (!limits || !exactlyKeys(limits, ["maxSuffixEvents"]) || limits.maxSuffixEvents !== MAX_SUFFIX_EVENTS) {
    invalid(result, "$.authorityCheckpoint.limits", "checkpoint limits.maxSuffixEvents must equal 128.");
  }
  const authorityState = object(checkpoint.authorityState);
  const recordsRaw = authorityState ? array(authorityState.records) : undefined;
  const records: AuthorityCheckpointRegistryRecordV1[] = [];
  if (!authorityState || !exactlyKeys(authorityState, ["stateHash", "records"]) || typeof authorityState.stateHash !== "string" || !HASH.test(authorityState.stateHash) || !recordsRaw || recordsRaw.length === 0) {
    invalid(result, "$.authorityCheckpoint.authorityState", "authorityState must contain a lowercase stateHash and non-empty records.");
  } else {
    let priorAuthorityId: string | undefined;
    for (const [index, raw] of recordsRaw.entries()) {
      const record = object(raw);
      if (!record || !exactlyKeys(record, ["authorityId", "publicKey", "validFrom", "validUntil", "revokedBy"])) {
        invalid(result, `$.authorityCheckpoint.authorityState.records[${index}]`, "authority record has an unexpected field set.");
        continue;
      }
      const authorityId = record.authorityId;
      const publicKey = record.publicKey;
      const validFrom = record.validFrom;
      const validUntil = record.validUntil;
      const revokedBy = record.revokedBy;
      if (!isNonEmptyString(authorityId) || !isNonEmptyString(publicKey) || typeof validFrom !== "string" || !TIMESTAMP.test(validFrom) || (validUntil !== null && (typeof validUntil !== "string" || !TIMESTAMP.test(validUntil))) || (revokedBy !== null && !isNonEmptyString(revokedBy))) {
        invalid(result, `$.authorityCheckpoint.authorityState.records[${index}]`, "authority record contains invalid authority or validity fields.");
        continue;
      }
      if ((validUntil === null) !== (revokedBy === null) || (typeof validUntil === "string" && validUntil < validFrom)) {
        invalid(result, `$.authorityCheckpoint.authorityState.records[${index}]`, "authority record revocation fields are inconsistent.");
        continue;
      }
      if (priorAuthorityId !== undefined && authorityId <= priorAuthorityId) {
        invalid(result, "$.authorityCheckpoint.authorityState.records", "authority records must be strictly ordered by authorityId without duplicates.");
      }
      priorAuthorityId = authorityId;
      records.push({ authorityId, publicKey, validFrom, validUntil, revokedBy });
    }
  }
  const signatures = object(checkpoint.signatures);
  if (
    !signatures || !exactlyKeys(signatures, ["issuedBy", "keyId", "publicKey", "checkpointHash", "signature"])
    || !isNonEmptyString(signatures.issuedBy) || !isNonEmptyString(signatures.keyId) || !isNonEmptyString(signatures.publicKey)
    || typeof signatures.checkpointHash !== "string" || !HASH.test(signatures.checkpointHash) || !isNonEmptyString(signatures.signature)
  ) {
    invalid(result, "$.authorityCheckpoint.signatures", "checkpoint signatures are malformed.");
  }
  if (result.errors.length > 0 || !protocol || !covered || !limits || !authorityState || !signatures || !isNonEmptyString(checkpoint.chainId)) return undefined;

  return {
    checkpointType: "AUTHORITY_CHECKPOINT",
    schemaVersion: 1,
    protocol: { protocolVersion: CHECKPOINT_PROTOCOL_VERSION },
    evidenceProfile: CHECKPOINT_PROFILE,
    chainId: checkpoint.chainId,
    sequence: checkpoint.sequence as number,
    covered: {
      streamHeight: covered.streamHeight as number,
      headEventHash: covered.headEventHash as string,
      effectiveAt: covered.effectiveAt as string
    },
    authorityState: { stateHash: authorityState.stateHash as string, records },
    previousCheckpointHash: checkpoint.previousCheckpointHash as string | null,
    limits: { maxSuffixEvents: MAX_SUFFIX_EVENTS },
    signatures: {
      issuedBy: signatures.issuedBy as string,
      keyId: signatures.keyId as string,
      publicKey: signatures.publicKey as string,
      checkpointHash: signatures.checkpointHash as string,
      signature: signatures.signature as string
    }
  };
}

function parseToken(input: JsonValue, result: RewardCommitmentV2VerificationResult): RewardCommitmentTokenV2 | undefined {
  const token = object(input);
  if (!token) {
    invalid(result, "$", "Reward commitment token must be a JSON object.");
    return undefined;
  }
  const allowed = ["tokenType", "schemaVersion", "evidenceProfile", "chainId", "economicTier", "commitmentEvent", "authorityCheckpoint", "systemEventSuffix", "batch", "recipientId", "leaf", "proof", "rewardInclusionProof", "backingEvent"];
  if (Object.keys(token).some((key) => !allowed.includes(key))) invalid(result, "$", "Reward Commitment Token V2 contains an unexpected field.");
  if (token.tokenType !== "REWARD_COMMITMENT") invalid(result, "$.tokenType", "Expected REWARD_COMMITMENT.");
  if (token.schemaVersion !== 2) invalid(result, "$.schemaVersion", "Expected reward-commitment schemaVersion 2.");
  if (token.evidenceProfile !== CHECKPOINT_PROFILE) invalid(result, "$.evidenceProfile", `Expected ${CHECKPOINT_PROFILE}.`);
  if (!isNonEmptyString(token.chainId)) invalid(result, "$.chainId", "chainId must be a non-empty string.");
  if (token.economicTier !== "COMMITTED" && token.economicTier !== "COMMITTED_BACKED") invalid(result, "$.economicTier", "economicTier must be COMMITTED or COMMITTED_BACKED.");

  const checkpoint = parseCheckpoint(token.authorityCheckpoint as JsonValue, result);
  const commitmentEvent = parseSystemEvent(token.commitmentEvent as JsonValue, "$.commitmentEvent", result);
  const backingPresent = owns(token, "backingEvent");
  const backingEvent = backingPresent ? parseSystemEvent(token.backingEvent as JsonValue, "$.backingEvent", result) : undefined;
  if (token.economicTier === "COMMITTED_BACKED" && !backingPresent) addError(result, "BACKING_EVENT_INVALID", "economicTier is COMMITTED_BACKED but backingEvent is absent.", "input", "$.backingEvent");
  if (token.economicTier === "COMMITTED" && backingPresent) addError(result, "BACKING_EVENT_INVALID", "economicTier is COMMITTED but backingEvent is present.", "input", "$.backingEvent");

  const suffixRaw = array(token.systemEventSuffix as JsonValue);
  const systemEventSuffix: SystemStreamEvent[] = [];
  if (!suffixRaw || suffixRaw.length === 0) {
    invalid(result, "$.systemEventSuffix", "systemEventSuffix must be a non-empty array.");
  } else {
    suffixRaw.forEach((raw, index) => {
      const event = parseSystemEvent(raw, `$.systemEventSuffix[${index}]`, result);
      if (event) systemEventSuffix.push(event);
    });
  }

  const batch = object(token.batch as JsonValue);
  if (!batch || !isNonEmptyString(batch.batchId) || !HASH.test(String(batch.root)) || !isNonEmptyString(batch.schemaVersion) || !isNonEmptyString(batch.txRef) || !isNonEmptyString(batch.committedAt)) {
    invalid(result, "$.batch", "batch must contain valid batchId, root, schemaVersion, txRef, and committedAt fields.");
  }
  const batchSchema = typeof batch?.schemaVersion === "string" ? batch.schemaVersion : undefined;
  if (batchSchema !== undefined && !CLOSED_SCHEMA_VERSIONS.includes(batchSchema as (typeof CLOSED_SCHEMA_VERSIONS)[number])) addError(result, "UNKNOWN_SCHEMA_VERSION", `Unknown reward-batch leaf schemaVersion "${batchSchema}".`, "policy", "$.batch.schemaVersion");
  if (!isNonEmptyString(token.recipientId)) invalid(result, "$.recipientId", "recipientId must be a non-empty string.");
  const leaf = object(token.leaf as JsonValue);
  if (!leaf) invalid(result, "$.leaf", "leaf must be a JSON object.");
  else if (batchSchema && CLOSED_SCHEMA_VERSIONS.includes(batchSchema as (typeof CLOSED_SCHEMA_VERSIONS)[number])) {
    const blinded = batchSchema.endsWith("b");
    const linkable = batchSchema.startsWith("2");
    const expectedLeafKeys = linkable ? ["batchId", "recipientId", "totalPoints", "rewardEventsRoot"] : ["batchId", "recipientId", "totalPoints"];
    if (!exactlyKeys(leaf, expectedLeafKeys)) invalid(result, "$.leaf", `leaf for schemaVersion "${batchSchema}" has an unexpected field set.`);
    else {
      if (!isNonEmptyString(leaf.batchId) || leaf.batchId !== batch?.batchId) invalid(result, "$.leaf.batchId", "leaf.batchId must equal batch.batchId.");
      if (!isPoints(leaf.totalPoints)) invalid(result, "$.leaf.totalPoints", "leaf.totalPoints must be a non-negative base-10 integer string.");
      const recipientOk = blinded ? HASH.test(String(leaf.recipientId)) : isNonEmptyString(leaf.recipientId);
      if (!recipientOk || leaf.recipientId !== token.recipientId) invalid(result, "$.leaf.recipientId", "leaf recipientId is invalid or does not equal token recipientId.");
      if (linkable && !HASH.test(String(leaf.rewardEventsRoot))) invalid(result, "$.leaf.rewardEventsRoot", "linkable leaf rewardEventsRoot must be a lowercase SHA-256 digest.");
    }
  }
  const proof = object(token.proof as JsonValue);
  const proofLeaf = proof ? object(proof.leaf as JsonValue) : undefined;
  const siblings = proof ? array(proof.siblings as JsonValue) : undefined;
  if (!proof || !isNonEmptyString(proof.batchId) || !proofLeaf || !HASH.test(String(proof.leafHash)) || !siblings || !siblings.every((sibling) => typeof sibling === "string" && HASH.test(sibling))) {
    invalid(result, "$.proof", "proof must contain batchId, leaf, a lowercase SHA-256 leafHash, and sibling hashes.");
  } else if (proof.batchId !== batch?.batchId) invalid(result, "$.proof.batchId", "proof.batchId must equal batch.batchId.");
  let rewardInclusionProof: RewardCommitmentTokenV2["rewardInclusionProof"];
  if (owns(token, "rewardInclusionProof")) {
    const rip = object(token.rewardInclusionProof as JsonValue);
    const ripLeaf = rip ? object(rip.leaf as JsonValue) : undefined;
    const ripSiblings = rip ? array(rip.siblings as JsonValue) : undefined;
    if (!rip || !isNonEmptyString(rip.batchId) || !isNonEmptyString(rip.recipientId) || !HASH.test(String(rip.rewardEventsRoot)) || !ripLeaf || !exactlyKeys(ripLeaf, ["spendId", "rewardEventHash"]) || !isNonEmptyString(ripLeaf.spendId) || !HASH.test(String(ripLeaf.rewardEventHash)) || !HASH.test(String(rip.leafHash)) || !ripSiblings || !ripSiblings.every((sibling) => typeof sibling === "string" && HASH.test(sibling))) {
      invalid(result, "$.rewardInclusionProof", "rewardInclusionProof is malformed.");
    } else {
      rewardInclusionProof = { batchId: rip.batchId as string, recipientId: rip.recipientId as string, rewardEventsRoot: rip.rewardEventsRoot as string, leaf: { spendId: ripLeaf.spendId as string, rewardEventHash: ripLeaf.rewardEventHash as string }, leafHash: rip.leafHash as string, siblings: ripSiblings as string[] };
    }
  }
  if (result.errors.length > 0 || !checkpoint || !commitmentEvent || !batch || !leaf || !proof || !proofLeaf || !siblings || !isNonEmptyString(token.chainId)) return undefined;
  return {
    tokenType: "REWARD_COMMITMENT", schemaVersion: 2, evidenceProfile: CHECKPOINT_PROFILE, chainId: token.chainId,
    economicTier: token.economicTier as "COMMITTED" | "COMMITTED_BACKED", authorityCheckpoint: checkpoint, systemEventSuffix,
    commitmentEvent, backingEvent, batch: batch as unknown as RewardCommitmentTokenV2["batch"], recipientId: token.recipientId as string,
    leaf, proof: { batchId: proof.batchId as string, leaf: proofLeaf, leafHash: proof.leafHash as string, siblings: siblings as string[] }, rewardInclusionProof
  };
}

function isChainCommitmentRecordEvidence(value: unknown): value is ChainCommitmentRecordEvidence {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return isNonEmptyString(record.batchId) && HASH.test(String(record.root)) && isNonEmptyString(record.schemaVersion) && (record.txRef === undefined || typeof record.txRef === "string") && (record.committedAt === undefined || typeof record.committedAt === "string");
}

function chainEvidenceMatches(batch: RewardCommitmentTokenV2["batch"], evidence: ChainCommitmentRecordEvidence): string | undefined {
  if (evidence.batchId !== batch.batchId) return "batchId";
  if (evidence.root !== batch.root) return "root";
  if (evidence.schemaVersion !== batch.schemaVersion) return "schemaVersion";
  if (evidence.txRef !== undefined && evidence.txRef !== batch.txRef) return "txRef";
  if (evidence.committedAt !== undefined && evidence.committedAt !== batch.committedAt) return "committedAt";
  return undefined;
}

async function applyChainEvidence(result: RewardCommitmentV2VerificationResult, token: RewardCommitmentTokenV2, options: RewardCommitmentV2VerificationOptions): Promise<void> {
  const chainEvidence = options.chainEvidence ?? { mode: "none" as const };
  if (chainEvidence.mode === "none") {
    addWarning(result, "ANCHOR_NOT_CHECKED", 'chainEvidence.mode is "none"; on-chain anchoring for batch.txRef/root was not checked.');
    return;
  }
  if (chainEvidence.mode === "provided") {
    if (!isChainCommitmentRecordEvidence(chainEvidence.tx)) {
      addError(result, "CHAIN_EVIDENCE_INVALID", "chainEvidence.tx is not well formed.", "input", "$.options.chainEvidence.tx");
      result.anchor = "indeterminate";
      return;
    }
    const mismatch = chainEvidenceMatches(token.batch, chainEvidence.tx);
    if (mismatch) {
      addError(result, "CHAIN_EVIDENCE_MISMATCH", `Caller-supplied chain evidence disagrees with batch.${mismatch}.`, "trust", `$.options.chainEvidence.tx.${mismatch}`);
      result.anchor = "indeterminate";
      return;
    }
    result.anchor = "verified";
    return;
  }
  if (chainEvidence.mode === "solana-rpc") {
    const verification = await verifySolanaBatchAnchor(token.batch, token.chainId, chainEvidence, options.solanaEvidenceTrust);
    if (!verification.valid) {
      addError(result, verification.mismatch ? "CHAIN_EVIDENCE_MISMATCH" : "CHAIN_EVIDENCE_INVALID", verification.message ?? "Solana evidence is invalid.", verification.cause ?? "network", verification.path);
      result.anchor = "indeterminate";
      return;
    }
    result.anchor = "verified";
    return;
  }
  if (!isNonEmptyString(chainEvidence.url)) {
    addError(result, "CHAIN_EVIDENCE_INVALID", 'chainEvidence.mode is "rpc" but no url was supplied.', "input", "$.options.chainEvidence.url");
    result.anchor = "indeterminate";
    return;
  }
  const fetchImpl = chainEvidence.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    addError(result, "CHAIN_EVIDENCE_INVALID", "No fetch implementation is available for chain evidence.", "network", "$.options.chainEvidence.url");
    result.anchor = "indeterminate";
    return;
  }
  try {
    const response = await fetchImpl(chainEvidence.url);
    const evidence: unknown = await response.json();
    if (!isChainCommitmentRecordEvidence(evidence)) throw new Error("malformed evidence");
    const mismatch = chainEvidenceMatches(token.batch, evidence);
    if (mismatch) {
      addError(result, "CHAIN_EVIDENCE_MISMATCH", `Chain RPC response disagrees with batch.${mismatch}.`, "trust", "$.options.chainEvidence.url");
      result.anchor = "indeterminate";
      return;
    }
    result.anchor = "verified";
  } catch {
    addError(result, "CHAIN_EVIDENCE_INVALID", "Chain RPC lookup failed or returned malformed evidence.", "network", "$.options.chainEvidence.url");
    result.anchor = "indeterminate";
  }
}

async function verifyCheckpoint(
  checkpoint: AuthorityCheckpointV1,
  tokenChainId: string,
  options: RewardCommitmentV2VerificationOptions,
  result: RewardCommitmentV2VerificationResult
): Promise<boolean> {
  const calculatedStateHash = computeAuthorityCheckpointRegistryStateHash(checkpoint.chainId, checkpoint.covered.headEventHash, checkpoint.authorityState.records);
  if (calculatedStateHash !== checkpoint.authorityState.stateHash) {
    addError(result, "CHECKPOINT_INVALID", "checkpoint authorityState.stateHash does not match canonical authority records.", "crypto", "$.authorityCheckpoint.authorityState.stateHash");
    return false;
  }
  const calculatedCheckpointHash = computeAuthorityCheckpointV1Hash(checkpoint);
  if (calculatedCheckpointHash !== checkpoint.signatures.checkpointHash) {
    addError(result, "CHECKPOINT_INVALID", "checkpoint signatures.checkpointHash does not match canonical checkpoint bytes.", "crypto", "$.authorityCheckpoint.signatures.checkpointHash");
    return false;
  }
  if (checkpoint.chainId !== tokenChainId) {
    addError(result, "CHECKPOINT_INVALID", "checkpoint chainId does not equal token chainId.", "input", "$.authorityCheckpoint.chainId");
    return false;
  }
  const minimum = options.minimumCheckpointSequence;
  if (minimum !== undefined && (!Number.isSafeInteger(minimum) || minimum < 1 || checkpoint.sequence < minimum)) {
    addError(result, "CHECKPOINT_INVALID", "checkpoint sequence is below the configured durable sequence floor.", "policy", "$.options.minimumCheckpointSequence");
    return false;
  }
  if (options.expectedPreviousCheckpointHash !== undefined && checkpoint.previousCheckpointHash !== options.expectedPreviousCheckpointHash) {
    addError(result, "CHECKPOINT_INVALID", "checkpoint predecessor does not equal the caller-configured expected predecessor.", "policy", "$.authorityCheckpoint.previousCheckpointHash");
    return false;
  }
  const signature = base64ToBytes(checkpoint.signatures.signature);
  const publicKey = base64ToBytes(checkpoint.signatures.publicKey);
  const digest = hexToBytes(checkpoint.signatures.checkpointHash);
  let signatureValid = false;
  try {
    signatureValid = Boolean(signature && signature.length === 64 && publicKey && publicKey.length === 32 && digest && await verifyEd25519(signature, digest, publicKey));
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    addError(result, "CHECKPOINT_INVALID", "checkpoint signature does not verify.", "crypto", "$.authorityCheckpoint.signatures.signature");
    return false;
  }
  if (!options.authorityCheckpointTrust) {
    addError(result, "CHECKPOINT_UNTRUSTED", "No configured checkpoint-root trust resolver authorized this checkpoint.", "trust", "$.options.authorityCheckpointTrust");
    return false;
  }
  let trusted = false;
  try {
    trusted = await options.authorityCheckpointTrust({
      profile: CHECKPOINT_PROFILE,
      checkpointHash: checkpoint.signatures.checkpointHash,
      chainId: checkpoint.chainId,
      sequence: checkpoint.sequence,
      streamHeight: checkpoint.covered.streamHeight,
      headEventHash: checkpoint.covered.headEventHash,
      previousCheckpointHash: checkpoint.previousCheckpointHash,
      issuedBy: checkpoint.signatures.issuedBy,
      keyId: checkpoint.signatures.keyId,
      publicKey: checkpoint.signatures.publicKey
    });
  } catch {
    trusted = false;
  }
  if (!trusted) {
    addError(result, "CHECKPOINT_UNTRUSTED", "The configured checkpoint-root trust resolver did not authorize this checkpoint.", "trust", "$.authorityCheckpoint.signatures");
    return false;
  }
  return true;
}

/**
 * Verifies RewardCommitmentTokenV2 using configured-checkpoint-root/v1 and a
 * bounded authority suffix. V1 history resolution is deliberately never used.
 */
export async function verifyRewardCommitmentV2(input: unknown, options: RewardCommitmentV2VerificationOptions = {}): Promise<RewardCommitmentV2VerificationResult> {
  const result = resultFor();
  const snapshot = createInertJsonSnapshot(input);
  if (snapshot.error || snapshot.value === undefined) {
    invalid(result, "$", `Reward commitment token must be inert JSON: ${snapshot.error ?? "missing JSON value"}`);
    return result;
  }
  const token = parseToken(snapshot.value, result);
  if (!token) return result;
  result.schemaVersion = "2";
  result.metadata = {
    chainId: token.chainId,
    batchId: token.batch.batchId,
    recipientId: token.recipientId,
    committedAt: token.batch.committedAt,
    checkpointSequence: token.authorityCheckpoint.sequence,
    checkpointHash: token.authorityCheckpoint.signatures.checkpointHash,
    suffixEventCount: token.systemEventSuffix.length
  };

  const maxSuffixEvents = options.maxSuffixEvents ?? MAX_SUFFIX_EVENTS;
  if (!Number.isSafeInteger(maxSuffixEvents) || maxSuffixEvents < 1 || maxSuffixEvents > MAX_SUFFIX_EVENTS || token.systemEventSuffix.length > maxSuffixEvents) {
    addError(result, "CHECKPOINT_INVALID", "systemEventSuffix exceeds the configured bounded suffix policy.", "policy", "$.systemEventSuffix");
    return result;
  }
  const checkpointValid = await verifyCheckpoint(token.authorityCheckpoint, token.chainId, options, result);
  result.checkpointValid = checkpointValid;
  if (!checkpointValid) return result;

  const replay = await replaySystemStreamSuffix(token.systemEventSuffix, token.chainId, token.authorityCheckpoint.covered.headEventHash, token.authorityCheckpoint.authorityState.records);
  const replayRejected = replay.errors.some((error) => error.code === "SYSTEM_STREAM_INVALID" || error.code === "AUTHORITY_INVALID");
  result.systemStreamValid = replay.integrityValid && !replayRejected;
  for (const error of replay.errors) addError(result, error.code, error.message, error.cause, error.path);

  const commitmentIncluded = replay.ordered.some((event) => deepEqualJson(event, token.commitmentEvent));
  const commitmentSignatureValid = replay.eventSignatureValid.get(token.commitmentEvent.eventHash) === true;
  const commitmentNameValid = token.commitmentEvent.eventName === "REWARD_BATCH_COMMITTED";
  const batchMatches = deepEqualJson(token.batch, token.commitmentEvent.payload);
  const terminal = replay.ordered.at(-1);
  const commitmentTerminal = deepEqualJson(terminal, token.commitmentEvent);
  result.authorityValid = commitmentSignatureValid && !replayRejected;
  result.commitmentValid = commitmentIncluded && commitmentSignatureValid && commitmentNameValid && batchMatches && commitmentTerminal;
  if (!commitmentIncluded) addError(result, "COMMITMENT_EVENT_INVALID", "commitmentEvent is not present in systemEventSuffix.", "input", "$.commitmentEvent");
  if (!commitmentSignatureValid) addError(result, "COMMITMENT_EVENT_INVALID", "commitmentEvent signature or authority validation failed.", "crypto", "$.commitmentEvent");
  if (!commitmentNameValid) addError(result, "COMMITMENT_EVENT_INVALID", "commitmentEvent.eventName must be REWARD_BATCH_COMMITTED.", "input", "$.commitmentEvent.eventName");
  if (!batchMatches) addError(result, "COMMITMENT_EVENT_INVALID", "batch does not equal commitmentEvent.payload.", "input", "$.batch");
  if (!commitmentTerminal) addError(result, "COMMITMENT_EVENT_INVALID", "commitmentEvent must be the terminal event of systemEventSuffix.", "input", "$.systemEventSuffix");

  const merkle = verifyInclusionProof({ leaf: token.leaf, leafHash: token.proof.leafHash, siblings: token.proof.siblings, expectedRoot: token.batch.root });
  result.merkleValid = merkle.valid;
  if (!merkle.valid) addError(result, "MERKLE_PROOF_INVALID", merkle.leafHashMismatch ? "Recomputed leaf hash does not match proof.leafHash." : "The Merkle inclusion proof does not resolve to batch.root.", "crypto", "$.proof");

  result.economicTier = token.economicTier;
  if (token.economicTier === "COMMITTED_BACKED") {
    const backingIncluded = Boolean(token.backingEvent && replay.ordered.some((event) => deepEqualJson(event, token.backingEvent)));
    const backingName = token.backingEvent?.eventName === "REWARD_BATCH_BACKING_ATTESTED";
    const backingPayload = token.backingEvent?.payload;
    const backingBatch = backingPayload?.batchId === token.batch.batchId;
    const backingSignature = Boolean(token.backingEvent && replay.eventSignatureValid.get(token.backingEvent.eventHash) === true);
    result.backingValid = backingIncluded && backingName && backingBatch && backingSignature;
    if (!result.backingValid) addError(result, "BACKING_EVENT_INVALID", "backingEvent is absent, invalid, not signed by a valid authority, or not included in systemEventSuffix.", "crypto", "$.backingEvent");
  }

  await applyChainEvidence(result, token, options);
  result.accepted = result.checkpointValid && result.systemStreamValid && result.authorityValid === true && result.commitmentValid && result.merkleValid && (result.economicTier !== "COMMITTED_BACKED" || result.backingValid === true) && ((options.chainEvidence?.mode ?? "none") === "none" || result.anchor === "verified");
  return result;
}
