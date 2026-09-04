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
  if (typeof value.timestamp !== "string" || !TIMESTAMP.test(value.timestamp)) return { error: `${path}.timestamp: must be a valid UTC millisecond timestamp.` };
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
  const found = candidates.find((candidate) => typeof candidate === "string");
  return typeof found === "string" ? found : event.timestamp;
}

function authorityValidAt(record: AuthorityRecordState, atTime: string): boolean {
  return record.validFrom <= atTime && (record.validUntil === null || atTime < record.validUntil);
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

  for (const event of ordered) {
    const signer = registry.get(event.signedBy);
    const at = effectiveTime(event);
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
      if (typeof authorityId === "string" && typeof publicKey === "string" && typeof validFrom === "string") {
        registry.set(authorityId, { publicKeyBase64: publicKey, chainId, validFrom, validUntil: null });
      } else {
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: `AUTHORITY_REGISTERED payload is malformed for eventId ${event.eventId}.`, cause: "input", path: "$.systemEventSuffix" });
      }
    } else if (event.eventName === "AUTHORITY_REVOKED") {
      const authorityId = event.payload.authorityId;
      const validUntil = event.payload.validUntil;
      const revokedBy = event.payload.revokedBy;
      if (typeof authorityId !== "string" || typeof validUntil !== "string" || typeof revokedBy !== "string" || revokedBy !== event.signedBy) {
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: `AUTHORITY_REVOKED payload is malformed or revokedBy does not match signedBy for eventId ${event.eventId}.`, cause: "input", path: "$.systemEventSuffix" });
        continue;
      }
      const target = registry.get(authorityId);
      if (!target) {
        errors.push({ code: "SYSTEM_STREAM_INVALID", message: `AUTHORITY_REVOKED references an unknown authorityId "${authorityId}".`, cause: "input", path: "$.systemEventSuffix" });
        continue;
      }
      target.validUntil = validUntil;
    }
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
