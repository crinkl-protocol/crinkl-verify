import { base64ToBytes, canonicalizeJcs, hexToBytes, sha256HexUtf8, verifyEd25519 } from "./crypto.js";
import type { JsonValue } from "./json.js";
import type {
  AuthorityCheckpointRegistryRecordV1,
  AuthorityTrustResolver,
  SystemStreamEvent,
  VerificationCause,
  VerificationErrorCode
} from "./types.js";

const HASH = /^[0-9a-f]{64}$/;
const AMOUNT = /^(0|[1-9][0-9]*)$/;
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export interface ReplayError {
  code: VerificationErrorCode;
  message: string;
  cause: VerificationCause;
  path?: string;
}

export interface AuthorityRecordState {
  publicKeyBase64: string;
  chainId: string;
  validFrom: string;
  validUntil: string | null;
}

export type AuthorityBootstrapStatus =
  | "trusted"
  | "untrusted"
  | "not_checked"
  | "no_genesis_authority"
  | "not_genesis"
  | "integrity_failed";

export interface SystemStreamReplayResult {
  ordered: SystemStreamEvent[];
  /** True when the provided segment's earliest event has `prevHash === null`. */
  genesisStart: boolean;
  /** Every event's `eventHash` recomputes correctly and the segment is a single contiguous, fork-free chain. */
  integrityValid: boolean;
  fork: boolean;
  gap: boolean;
  authorityBootstrap: AuthorityBootstrapStatus;
  /** Final Authority Registry state after replaying the whole segment. */
  registry: Map<string, AuthorityRecordState>;
  /** Per-event (`eventHash`) signature verification outcome. Only populated when a genesis authority was bootstrapped and trusted. */
  eventSignatureValid: Map<string, boolean>;
  errors: ReplayError[];
}

/** Result of replaying a bounded suffix from a separately trusted checkpoint. */
export interface SystemStreamSuffixReplayResult {
  ordered: SystemStreamEvent[];
  integrityValid: boolean;
  fork: boolean;
  gap: boolean;
  registry: Map<string, AuthorityRecordState>;
  eventSignatureValid: Map<string, boolean>;
  errors: ReplayError[];
}

function object(value: JsonValue): { readonly [key: string]: JsonValue } | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as { readonly [key: string]: JsonValue })
    : undefined;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** eventHash = SHA-256 of RFC 8785 canonical JSON excluding eventHash and signature (EVENTS.md / DATA_STRUCTURES.md#integrity-envelope). */
export function computeSystemEventHash(event: SystemStreamEvent): string {
  const { eventHash: _eventHash, signature: _signature, ...unsigned } = event;
  return sha256HexUtf8(canonicalizeJcs(unsigned));
}

async function verifyEnvelopeSignature(event: SystemStreamEvent, publicKeyBase64: string): Promise<boolean> {
  const signature = base64ToBytes(event.signature);
  const publicKey = base64ToBytes(publicKeyBase64);
  const digest = hexToBytes(event.eventHash);
  if (!signature || signature.length !== 64 || !publicKey || publicKey.length !== 32 || !digest) return false;
  try {
    return await verifyEd25519(signature, digest, publicKey);
  } catch {
    return false;
  }
}

/** Structural validation of the System-Stream Event Envelope (EVENTS.md#system-stream-event-envelope). */
export function validateSystemStreamEventShape(input: JsonValue, path: string): { event?: SystemStreamEvent; error?: string } {
  const value = object(input);
  if (!value) return { error: `${path}: SystemStreamEvent must be a JSON object.` };
  if (!isNonEmptyString(value.eventId)) return { error: `${path}.eventId: must be a non-empty string.` };
  if (!isNonEmptyString(value.eventName)) return { error: `${path}.eventName: must be a non-empty string.` };
  if (!isNonEmptyString(value.chainId)) return { error: `${path}.chainId: must be a non-empty string.` };
  if (!isNonEmptyString(value.signedBy)) return { error: `${path}.signedBy: must be a non-empty string.` };
  const payload = object(value.payload as JsonValue);
  if (!payload) return { error: `${path}.payload: must be a JSON object.` };
  if (!isRfc3339UtcMillisecond(value.timestamp)) return { error: `${path}.timestamp: must be a valid UTC millisecond timestamp.` };
  if (typeof value.protocolVersion !== "string" || !VERSION.test(value.protocolVersion)) return { error: `${path}.protocolVersion: must be SemVer 2.0 compatible.` };
  if (typeof value.eventHash !== "string" || !HASH.test(value.eventHash)) return { error: `${path}.eventHash: must be a lowercase SHA-256 hex digest.` };
  if (value.prevHash !== null && (typeof value.prevHash !== "string" || !HASH.test(value.prevHash))) return { error: `${path}.prevHash: must be null or a lowercase SHA-256 hex digest.` };
  if (typeof value.signature !== "string" || value.signature.length === 0) return { error: `${path}.signature: must be a non-empty string.` };
  const expectedKeys = ["eventId", "eventName", "chainId", "signedBy", "payload", "timestamp", "protocolVersion", "eventHash", "prevHash", "signature"];
  const extra = Object.keys(value).filter((key) => !expectedKeys.includes(key));
  if (extra.length > 0) return { error: `${path}: unexpected fields ${extra.join(", ")}.` };
  return {
    event: {
      eventId: value.eventId as string,
      eventName: value.eventName as string,
      chainId: value.chainId as string,
      signedBy: value.signedBy as string,
      payload,
      timestamp: value.timestamp as string,
      protocolVersion: value.protocolVersion as string,
      eventHash: value.eventHash as string,
      prevHash: value.prevHash as string | null,
      signature: value.signature as string
    }
  };
}

/** Orders a segment by its `prevHash` chain, detecting forks and gaps (EVENTS.md#system-stream-ordering). */
function orderSegment(events: readonly SystemStreamEvent[]): { ordered: SystemStreamEvent[]; fork: boolean; gap: boolean; genesisStart: boolean } {
  const byPrevHash = new Map<string | null, SystemStreamEvent[]>();
  const byEventHash = new Map<string, SystemStreamEvent>();
  for (const event of events) {
    byEventHash.set(event.eventHash, event);
    const bucket = byPrevHash.get(event.prevHash);
    if (bucket) bucket.push(event);
    else byPrevHash.set(event.prevHash, [event]);
  }
  const fork = [...byPrevHash.values()].some((bucket) => bucket.length > 1);
  if (fork) return { ordered: [], fork: true, gap: false, genesisStart: false };

  // Find the segment's earliest event: one whose prevHash is null, or whose
  // prevHash is not itself the eventHash of another event in the segment.
  const roots = events.filter((event) => event.prevHash === null || !byEventHash.has(event.prevHash));
  if (roots.length !== 1) return { ordered: [], fork: roots.length > 1, gap: roots.length === 0, genesisStart: false };

  const ordered: SystemStreamEvent[] = [roots[0]];
  const genesisStart = roots[0].prevHash === null;
  let cursor = roots[0];
  while (ordered.length < events.length) {
    const next = byPrevHash.get(cursor.eventHash);
    if (!next || next.length === 0) return { ordered: [], fork: false, gap: true, genesisStart };
    if (next.length > 1) return { ordered: [], fork: true, gap: false, genesisStart };
    ordered.push(next[0]);
    cursor = next[0];
  }
  return { ordered, fork: false, gap: false, genesisStart };
}

function effectiveTime(event: SystemStreamEvent): string {
  const candidates = [event.payload.committedAt, event.payload.registeredAt, event.payload.revokedAt, event.payload.backedAt];
  const found = candidates.find(isRfc3339UtcMillisecond);
  return found ?? event.timestamp;
}

function authorityValidAt(record: AuthorityRecordState, atTime: string): boolean {
  return isRfc3339UtcMillisecond(record.validFrom)
    && isRfc3339UtcMillisecond(atTime)
    && (record.validUntil === null || isRfc3339UtcMillisecond(record.validUntil))
    && record.validFrom <= atTime
    && (record.validUntil === null || atTime < record.validUntil);
}

function countAuthoritiesValidAt(registry: ReadonlyMap<string, AuthorityRecordState>, atTime: string): number {
  let count = 0;
  for (const record of registry.values()) {
    if (authorityValidAt(record, atTime)) count += 1;
  }
  return count;
}

function authorityWindowsOverlap(left: AuthorityRecordState, right: AuthorityRecordState): boolean {
  return (left.validUntil === null || right.validFrom < left.validUntil)
    && (right.validUntil === null || left.validFrom < right.validUntil);
}

function registryHasOverlappingAuthorityWindows(registry: ReadonlyMap<string, AuthorityRecordState>): boolean {
  const ordered = [...registry.values()].sort((left, right) => left.validFrom < right.validFrom ? -1 : left.validFrom > right.validFrom ? 1 : 0);
  let latestValidUntil: string | null | undefined;
  for (const record of ordered) {
    if (latestValidUntil === null || (latestValidUntil !== undefined && record.validFrom < latestValidUntil)) return true;
    if (record.validUntil === null || latestValidUntil === undefined || record.validUntil > latestValidUntil) {
      latestValidUntil = record.validUntil;
    }
  }
  return false;
}

const CHECKPOINT_SUFFIX_EVENT_NAMES = new Set([
  "AUTHORITY_REGISTERED",
  "AUTHORITY_REVOKED",
  "REWARD_BATCH_COMMITTED",
  "REWARD_BATCH_BACKING_ATTESTED",
  "REWARD_BATCH_CORRECTION",
  "CUMULATIVE_SNAPSHOT_COMMITTED"
]);
const CHECKPOINT_PROTOCOL_VERSION = "1.0.0-rc.1";

function exactlyKeys(value: { readonly [key: string]: JsonValue }, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

/** True only for canonical RFC 3339 UTC timestamps with millisecond precision. */
export function isRfc3339UtcMillisecond(value: unknown): value is string {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function isEd25519PublicKey(value: unknown): value is string {
  const bytes = typeof value === "string" ? base64ToBytes(value) : undefined;
  return bytes !== undefined && bytes.length === 32;
}

function isPoints(value: unknown): value is string {
  return typeof value === "string" && AMOUNT.test(value);
}

function validCommittedPayload(payload: { readonly [key: string]: JsonValue }): boolean {
  return exactlyKeys(payload, ["batchId", "root", "leafCount", "totalPoints", "schemaVersion", "txRef", "committedAt"])
    && isNonEmptyString(payload.batchId)
    && typeof payload.root === "string" && HASH.test(payload.root)
    && Number.isSafeInteger(payload.leafCount) && Number(payload.leafCount) > 0
    && isPoints(payload.totalPoints)
    && (payload.schemaVersion === "2a" || payload.schemaVersion === "2b")
    && isNonEmptyString(payload.txRef)
    && isRfc3339UtcMillisecond(payload.committedAt);
}

function validBackingPayload(payload: { readonly [key: string]: JsonValue }): boolean {
  const backingAsset = object(payload.backingAsset as JsonValue);
  return exactlyKeys(payload, ["batchId", "backingAsset", "backingAmount", "backingVault", "backingTxRef", "backedAt"])
    && isNonEmptyString(payload.batchId)
    && !!backingAsset
    && exactlyKeys(backingAsset, ["chainId", "mint", "decimals"])
    && isNonEmptyString(backingAsset.chainId)
    && isNonEmptyString(backingAsset.mint)
    && Number.isSafeInteger(backingAsset.decimals) && Number(backingAsset.decimals) >= 0
    && isPoints(payload.backingAmount)
    && isNonEmptyString(payload.backingVault)
    && isNonEmptyString(payload.backingTxRef)
    && isRfc3339UtcMillisecond(payload.backedAt);
}

function validCorrectionPayload(payload: { readonly [key: string]: JsonValue }): boolean {
  if (!exactlyKeys(payload, ["correctionBatchId", "targetBatchId", "reason", "adjustments", "root", "txRef", "committedAt"])
    || !isNonEmptyString(payload.correctionBatchId)
    || !isNonEmptyString(payload.targetBatchId)
    || !isNonEmptyString(payload.reason)
    || !Array.isArray(payload.adjustments)
    || typeof payload.root !== "string" || !HASH.test(payload.root)
    || !isNonEmptyString(payload.txRef)
    || !isRfc3339UtcMillisecond(payload.committedAt)) return false;
  return payload.adjustments.every((adjustment) => {
    const entry = object(adjustment as JsonValue);
    return !!entry
      && exactlyKeys(entry, ["recipientId", "deltaPoints", "correctionType", "targetBatchId"])
      && isNonEmptyString(entry.recipientId)
      && isPoints(entry.deltaPoints)
      && (entry.correctionType === "adjust" || entry.correctionType === "add_missing")
      && isNonEmptyString(entry.targetBatchId);
  });
}

function validCumulativeSnapshotPayload(payload: { readonly [key: string]: JsonValue }): boolean {
  return exactlyKeys(payload, ["snapshotId", "snapshotRoot", "leafCount", "throughBatchId", "throughEventHash", "txRef", "committedAt"])
    && isNonEmptyString(payload.snapshotId)
    && typeof payload.snapshotRoot === "string" && HASH.test(payload.snapshotRoot)
    && Number.isSafeInteger(payload.leafCount) && Number(payload.leafCount) >= 0
    && isNonEmptyString(payload.throughBatchId)
    && typeof payload.throughEventHash === "string" && HASH.test(payload.throughEventHash)
    && isNonEmptyString(payload.txRef)
    && isRfc3339UtcMillisecond(payload.committedAt);
}

export function validateCheckpointSuffixEvent(event: SystemStreamEvent): string | undefined {
  if (!CHECKPOINT_SUFFIX_EVENT_NAMES.has(event.eventName)) return `Checkpoint suffix eventName "${event.eventName}" is unsupported.`;
  if (event.protocolVersion !== CHECKPOINT_PROTOCOL_VERSION) return `Checkpoint suffix event protocolVersion must equal ${CHECKPOINT_PROTOCOL_VERSION}.`;
  const expectedEventId = `sha256:${sha256HexUtf8(canonicalizeJcs({
    chainId: event.chainId,
    eventName: event.eventName,
    payload: event.payload,
    protocolVersion: event.protocolVersion
  }))}`;
  if (event.eventId !== expectedEventId) return "Checkpoint suffix eventId does not match its canonical event domain.";
  if (event.eventName === "REWARD_BATCH_COMMITTED" && !validCommittedPayload(event.payload)) return "REWARD_BATCH_COMMITTED payload is malformed.";
  if (event.eventName === "REWARD_BATCH_BACKING_ATTESTED" && !validBackingPayload(event.payload)) return "REWARD_BATCH_BACKING_ATTESTED payload is malformed.";
  if (event.eventName === "REWARD_BATCH_CORRECTION" && !validCorrectionPayload(event.payload)) return "REWARD_BATCH_CORRECTION payload is malformed.";
  if (event.eventName === "CUMULATIVE_SNAPSHOT_COMMITTED" && !validCumulativeSnapshotPayload(event.payload)) return "CUMULATIVE_SNAPSHOT_COMMITTED payload is malformed.";
  return undefined;
}

/**
 * Replays a system-stream segment: reconstructs canonical order, verifies
 * integrity (`eventHash` + `prevHash` chaining), and — only when the segment
 * starts at genesis and the caller's {@link AuthorityTrustResolver} vouches
 * for the self-signed genesis `AUTHORITY_REGISTERED` event — replays the
 * Authority Registry forward, verifying every event's signature against the
 * authority valid at its effective time (COMMITMENT_LAYER.md#authority-registry).
 *
 * Per TOKENS.md's Reward Commitment Token derivation rules: if the segment
 * does not start at genesis, authority validation is indeterminate; this
 * function reflects that by returning `authorityBootstrap: "not_genesis"`
 * without attempting any signature verification (there is no root of trust
 * available to verify against).
 */
export async function replaySystemStreamSegment(
  events: readonly SystemStreamEvent[],
  chainId: string,
  authorityTrust: AuthorityTrustResolver | undefined
): Promise<SystemStreamReplayResult> {
  const errors: ReplayError[] = [];
  const scoped = events.filter((event) => event.chainId === chainId);
  if (scoped.length !== events.length) {
    errors.push({ code: "SYSTEM_STREAM_INVALID", message: "systemEvents contains an event for a different chainId.", cause: "input", path: "$.systemEvents" });
  }

  const { ordered, fork, gap, genesisStart } = orderSegment(scoped);
  if (fork) errors.push({ code: "SYSTEM_STREAM_INVALID", message: "systemEvents forms a fork: two events share a prevHash.", cause: "input", path: "$.systemEvents" });
  if (gap) errors.push({ code: "SYSTEM_STREAM_INVALID", message: "systemEvents is not a single contiguous chain.", cause: "input", path: "$.systemEvents" });

  let integrityValid = !fork && !gap && ordered.length === scoped.length;
  for (const event of ordered) {
    if (computeSystemEventHash(event) !== event.eventHash) {
      integrityValid = false;
      errors.push({ code: "SYSTEM_STREAM_INVALID", message: `Recomputed eventHash does not match the stated value for eventId ${event.eventId}.`, cause: "crypto", path: "$.systemEvents" });
    }
  }

  const registry = new Map<string, AuthorityRecordState>();
  const eventSignatureValid = new Map<string, boolean>();

  if (!integrityValid) {
    return { ordered, genesisStart, integrityValid, fork, gap, authorityBootstrap: "integrity_failed", registry, eventSignatureValid, errors };
  }
  if (!genesisStart) {
    return { ordered, genesisStart, integrityValid, fork, gap, authorityBootstrap: "not_genesis", registry, eventSignatureValid, errors };
  }

  const genesis = ordered[0];
  if (genesis.eventName !== "AUTHORITY_REGISTERED" || genesis.signedBy !== genesis.payload.authorityId) {
    errors.push({ code: "AUTHORITY_INVALID", message: "A genesis system-stream segment must open with a self-signed AUTHORITY_REGISTERED event.", cause: "trust", path: "$.systemEvents[0]" });
    return { ordered, genesisStart, integrityValid, fork, gap, authorityBootstrap: "no_genesis_authority", registry, eventSignatureValid, errors };
  }
  const genesisAuthorityId = genesis.payload.authorityId;
  const genesisPublicKey = genesis.payload.publicKey;
  const genesisValidFrom = genesis.payload.validFrom;
  if (typeof genesisAuthorityId !== "string" || typeof genesisPublicKey !== "string" || typeof genesisValidFrom !== "string") {
    errors.push({ code: "SYSTEM_STREAM_INVALID", message: "Genesis AUTHORITY_REGISTERED payload is malformed.", cause: "input", path: "$.systemEvents[0].payload" });
    return { ordered, genesisStart, integrityValid: false, fork, gap, authorityBootstrap: "no_genesis_authority", registry, eventSignatureValid, errors };
  }
  const genesisSignatureValid = await verifyEnvelopeSignature(genesis, genesisPublicKey);
  eventSignatureValid.set(genesis.eventHash, genesisSignatureValid);
  if (!genesisSignatureValid) {
    errors.push({ code: "AUTHORITY_INVALID", message: "Genesis AUTHORITY_REGISTERED self-signature does not verify.", cause: "crypto", path: "$.systemEvents[0]" });
    return { ordered, genesisStart, integrityValid: false, fork, gap, authorityBootstrap: "no_genesis_authority", registry, eventSignatureValid, errors };
  }

  if (!authorityTrust) {
    return { ordered, genesisStart, integrityValid, fork, gap, authorityBootstrap: "not_checked", registry, eventSignatureValid, errors };
  }
  let trusted: boolean;
  try {
    trusted = await authorityTrust({ chainId, authorityId: genesisAuthorityId, publicKeyBase64: genesisPublicKey, validFrom: genesisValidFrom });
  } catch {
    trusted = false;
  }
  if (!trusted) {
    errors.push({ code: "AUTHORITY_UNTRUSTED", message: "The caller-supplied authority trust resolver did not authorize the genesis authority.", cause: "trust", path: "$.systemEvents[0]" });
    return { ordered, genesisStart, integrityValid, fork, gap, authorityBootstrap: "untrusted", registry, eventSignatureValid, errors };
  }

  registry.set(genesisAuthorityId, { publicKeyBase64: genesisPublicKey, chainId, validFrom: genesisValidFrom, validUntil: null });

  for (const event of ordered.slice(1)) {
    const signer = registry.get(event.signedBy);
    const at = effectiveTime(event);
    const signerValid = signer !== undefined && authorityValidAt(signer, at);
    if (!signerValid) {
      eventSignatureValid.set(event.eventHash, false);
      errors.push({ code: "AUTHORITY_INVALID", message: `signedBy "${event.signedBy}" is not a valid authority for chainId "${chainId}" at effective time ${at}.`, cause: "trust", path: "$.systemEvents" });
      continue;
    }
    const signatureValid = await verifyEnvelopeSignature(event, signer.publicKeyBase64);
    eventSignatureValid.set(event.eventHash, signatureValid);
    if (!signatureValid) {
      errors.push({ code: "AUTHORITY_INVALID", message: `Signature verification failed for eventId ${event.eventId}.`, cause: "crypto", path: "$.systemEvents" });
      continue;
    }

    if (event.eventName === "AUTHORITY_REGISTERED") {
      const authorityId = event.payload.authorityId;
      const publicKey = event.payload.publicKey;
      const validFrom = event.payload.validFrom;
      if (typeof authorityId === "string" && typeof publicKey === "string" && typeof validFrom === "string") {
        registry.set(authorityId, { publicKeyBase64: publicKey, chainId, validFrom, validUntil: null });
      } else {
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: `AUTHORITY_REGISTERED payload is malformed for eventId ${event.eventId}.`, cause: "input", path: "$.systemEvents" });
      }
    } else if (event.eventName === "AUTHORITY_REVOKED") {
      const authorityId = event.payload.authorityId;
      const validUntil = event.payload.validUntil;
      const revokedBy = event.payload.revokedBy;
      if (typeof authorityId !== "string" || typeof validUntil !== "string" || typeof revokedBy !== "string" || revokedBy !== event.signedBy) {
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: `AUTHORITY_REVOKED payload is malformed or revokedBy does not match signedBy for eventId ${event.eventId}.`, cause: "input", path: "$.systemEvents" });
        continue;
      }
      const target = registry.get(authorityId);
      if (!target) {
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: `AUTHORITY_REVOKED references an unknown authorityId "${authorityId}".`, cause: "input", path: "$.systemEvents" });
        continue;
      }
      target.validUntil = validUntil;
    }
  }

  return { ordered, genesisStart, integrityValid, fork, gap, authorityBootstrap: "trusted", registry, eventSignatureValid, errors };
}

/**
 * Replays a contiguous System Stream suffix whose predecessor authority state
 * was authenticated by an AuthorityCheckpointV1. The checkpoint itself is
 * verified by the V2 reward verifier before this function is called.
 */
export async function replaySystemStreamSuffix(
  events: readonly SystemStreamEvent[],
  chainId: string,
  expectedPrevHash: string,
  checkpointRegistry: readonly AuthorityCheckpointRegistryRecordV1[]
): Promise<SystemStreamSuffixReplayResult> {
  const errors: ReplayError[] = [];
  const scoped = events.filter((event) => event.chainId === chainId);
  if (scoped.length !== events.length) {
    errors.push({ code: "SYSTEM_STREAM_INVALID", message: "systemEventSuffix contains an event for a different chainId.", cause: "input", path: "$.systemEventSuffix" });
  }

  const { ordered, fork, gap } = orderSegment(scoped);
  if (fork) errors.push({ code: "SYSTEM_STREAM_INVALID", message: "systemEventSuffix forms a fork: two events share a prevHash.", cause: "input", path: "$.systemEventSuffix" });
  if (gap) errors.push({ code: "SYSTEM_STREAM_INVALID", message: "systemEventSuffix is not a single contiguous chain.", cause: "input", path: "$.systemEventSuffix" });

  let integrityValid = !fork && !gap && ordered.length === scoped.length && ordered.length > 0;
  if (ordered[0]?.prevHash !== expectedPrevHash) {
    integrityValid = false;
    errors.push({ code: "SYSTEM_STREAM_INVALID", message: "systemEventSuffix does not begin at authorityCheckpoint.covered.headEventHash.", cause: "input", path: "$.systemEventSuffix[0].prevHash" });
  }
  for (const event of ordered) {
    if (computeSystemEventHash(event) !== event.eventHash) {
      integrityValid = false;
      errors.push({ code: "SYSTEM_STREAM_INVALID", message: `Recomputed eventHash does not match the stated value for eventId ${event.eventId}.`, cause: "crypto", path: "$.systemEventSuffix" });
    }
  }

  const registry = new Map<string, AuthorityRecordState>();
  const eventSignatureValid = new Map<string, boolean>();
  for (const record of checkpointRegistry) {
    registry.set(record.authorityId, {
      publicKeyBase64: record.publicKey,
      chainId,
      validFrom: record.validFrom,
      validUntil: record.validUntil
    });
  }
  if (!integrityValid) return { ordered, integrityValid, fork, gap, registry, eventSignatureValid, errors };

  const eventIds = new Set<string>();
  let pendingRotation: { predecessorId: string; successorId: string; boundary: string } | undefined;
  for (const event of ordered) {
    const shapeError = validateCheckpointSuffixEvent(event);
    if (shapeError) {
      eventSignatureValid.set(event.eventHash, false);
      errors.push({ code: "SYSTEM_STREAM_INVALID", message: shapeError, cause: "input", path: "$.systemEventSuffix" });
      continue;
    }
    if (eventIds.has(event.eventId)) {
      eventSignatureValid.set(event.eventHash, false);
      errors.push({ code: "SYSTEM_STREAM_INVALID", message: `systemEventSuffix repeats eventId ${event.eventId}.`, cause: "input", path: "$.systemEventSuffix" });
      continue;
    }
    eventIds.add(event.eventId);
    if (pendingRotation) {
      const payload = event.payload;
      if (
        event.eventName !== "AUTHORITY_REVOKED"
        || event.signedBy !== pendingRotation.successorId
        || payload.authorityId !== pendingRotation.predecessorId
        || payload.revokedBy !== pendingRotation.successorId
        || payload.validUntil !== pendingRotation.boundary
        || payload.revokedAt !== pendingRotation.boundary
      ) {
        eventSignatureValid.set(event.eventHash, false);
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: "A transient authority overlap must be closed by the exact immediate successor-signed revocation at its validFrom boundary.", cause: "input", path: "$.systemEventSuffix" });
        break;
      }
    }
    const signer = registry.get(event.signedBy);
    const at = effectiveTime(event);
    if (
      (event.eventName === "REWARD_BATCH_COMMITTED"
        || event.eventName === "REWARD_BATCH_BACKING_ATTESTED"
        || event.eventName === "REWARD_BATCH_CORRECTION"
        || event.eventName === "CUMULATIVE_SNAPSHOT_COMMITTED")
      && countAuthoritiesValidAt(registry, at) !== 1
    ) {
      eventSignatureValid.set(event.eventHash, false);
      errors.push({ code: "AUTHORITY_INVALID", message: `ordinary ${event.eventName} evidence is ambiguous because it has more than one valid authority at effective time ${at}.`, cause: "trust", path: "$.systemEventSuffix" });
      continue;
    }
    if (!signer || !authorityValidAt(signer, at)) {
      eventSignatureValid.set(event.eventHash, false);
      errors.push({ code: "AUTHORITY_INVALID", message: `signedBy "${event.signedBy}" is not a valid authority for chainId "${chainId}" at effective time ${at}.`, cause: "trust", path: "$.systemEventSuffix" });
      continue;
    }
    const signatureValid = await verifyEnvelopeSignature(event, signer.publicKeyBase64);
    eventSignatureValid.set(event.eventHash, signatureValid);
    if (!signatureValid) {
      errors.push({ code: "AUTHORITY_INVALID", message: `Signature verification failed for eventId ${event.eventId}.`, cause: "crypto", path: "$.systemEventSuffix" });
      continue;
    }
    if (event.eventName === "AUTHORITY_REGISTERED") {
      const authorityId = event.payload.authorityId;
      const publicKey = event.payload.publicKey;
      const validFrom = event.payload.validFrom;
      const predecessorId = event.payload.predecessorId;
      const registeredAt = event.payload.registeredAt;
      if (
        exactlyKeys(event.payload, ["authorityId", "publicKey", "validFrom", "predecessorId", "txRef", "registeredAt"])
        && isNonEmptyString(authorityId) && isEd25519PublicKey(publicKey) && isRfc3339UtcMillisecond(validFrom)
        && isNonEmptyString(predecessorId) && predecessorId === event.signedBy && registry.has(predecessorId)
        && isNonEmptyString(event.payload.txRef) && isRfc3339UtcMillisecond(registeredAt)
        && registeredAt >= event.timestamp && validFrom >= registeredAt
        && !registry.has(authorityId)
        && ![...registry.values()].some((record) => record.publicKeyBase64 === publicKey)
      ) {
        const successor = { publicKeyBase64: publicKey, chainId, validFrom, validUntil: null };
        const predecessor = registry.get(predecessorId);
        registry.set(authorityId, successor);
        if (predecessor && authorityWindowsOverlap(predecessor, successor)) {
          pendingRotation = { predecessorId, successorId: authorityId, boundary: validFrom };
        }
      } else {
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: `AUTHORITY_REGISTERED payload is malformed, does not name its valid signing predecessor, or attempts a duplicate registration for eventId ${event.eventId}.`, cause: "input", path: "$.systemEventSuffix" });
      }
    } else if (event.eventName === "AUTHORITY_REVOKED") {
      const authorityId = event.payload.authorityId;
      const validUntil = event.payload.validUntil;
      const revokedBy = event.payload.revokedBy;
      const revokedAt = event.payload.revokedAt;
      if (
        !exactlyKeys(event.payload, ["authorityId", "validUntil", "revokedBy", "reason", "txRef", "revokedAt"])
        || !isNonEmptyString(authorityId) || !isRfc3339UtcMillisecond(validUntil) || !isNonEmptyString(revokedBy)
        || revokedBy !== event.signedBy || !isNonEmptyString(event.payload.reason) || !isNonEmptyString(event.payload.txRef)
        || !isRfc3339UtcMillisecond(revokedAt) || validUntil !== revokedAt || revokedAt < event.timestamp
      ) {
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: `AUTHORITY_REVOKED payload is malformed, retroactive, or revokedBy does not match signedBy for eventId ${event.eventId}.`, cause: "input", path: "$.systemEventSuffix" });
        continue;
      }
      const target = registry.get(authorityId);
      if (!target || target.validUntil !== null || validUntil <= target.validFrom) {
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: `AUTHORITY_REVOKED references an unknown, already revoked, or not-yet-valid authorityId "${authorityId}".`, cause: "input", path: "$.systemEventSuffix" });
        continue;
      }
      target.validUntil = validUntil;
      if (pendingRotation) pendingRotation = undefined;
    } else if (event.eventName === "REWARD_BATCH_CORRECTION" || event.eventName === "CUMULATIVE_SNAPSHOT_COMMITTED") {
      // These signed events authenticate stream continuity only. They neither
      // replace the token's terminal commitment/backing event nor alter its tier.
    }
  }

  if (pendingRotation || registryHasOverlappingAuthorityWindows(registry)) {
    errors.push({ code: "SYSTEM_STREAM_INVALID", message: "Authority validity windows must not retain a transient overlap after suffix replay.", cause: "input", path: "$.systemEventSuffix" });
  }

  return { ordered, integrityValid, fork, gap, registry, eventSignatureValid, errors };
}

export function findAuthorityRecordAt(
  registry: Map<string, AuthorityRecordState>,
  authorityId: string,
  atTime: string
): AuthorityRecordState | undefined {
  const record = registry.get(authorityId);
  return record && authorityValidAt(record, atTime) ? record : undefined;
}
