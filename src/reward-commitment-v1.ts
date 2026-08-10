import { canonicalizeJcs } from "./crypto.js";
import { createInertJsonSnapshot, type JsonValue } from "./json.js";
import { verifyInclusionProof } from "./merkle.js";
import { findAuthorityRecordAt, replaySystemStreamSegment, validateSystemStreamEventShape } from "./system-stream.js";
import { verifySolanaBatchAnchor } from "./solana.js";
import type {
  AnchorStatus,
  ChainCommitmentRecordEvidence,
  RewardCommitmentTokenV1,
  RewardCommitmentVerificationOptions,
  RewardCommitmentVerificationResult,
  SystemStreamEvent,
  VerificationCause,
  VerificationErrorCode
} from "./types.js";

const AMOUNT = /^(0|[1-9][0-9]*)$/;
const HASH = /^[0-9a-f]{64}$/;
const CLOSED_SCHEMA_VERSIONS = ["1a", "1b", "2a", "2b"] as const;
const DEFAULT_MAX_HISTORY_EVENTS = 100_000;
const MAX_HISTORY_EVENTS = 1_000_000;
const DEFAULT_HISTORY_TIMEOUT_MS = 15_000;
const MAX_HISTORY_TIMEOUT_MS = 120_000;

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

function resultFor(): RewardCommitmentVerificationResult {
  return {
    format: "crinkl-reward-commitment/v1",
    schemaVersion: "unknown",
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

function addError(result: RewardCommitmentVerificationResult, code: VerificationErrorCode, message: string, cause: VerificationCause, path?: string): void {
  result.errors.push({ code, message, cause, path });
}

function addWarning(result: RewardCommitmentVerificationResult, code: "AUTHORITY_INDETERMINATE_NON_GENESIS_SEGMENT" | "AUTHORITY_NOT_CHECKED" | "ANCHOR_NOT_CHECKED" | "ANCHOR_INDETERMINATE", message: string): void {
  result.warnings.push({ code, message });
}

function invalid(result: RewardCommitmentVerificationResult, path: string, message: string): void {
  addError(result, "SCHEMA_INVALID", message, "input", path);
}

interface ParsedSystemEvent {
  raw: SystemStreamEvent;
}

function parseSystemEvent(input: JsonValue, path: string, result: RewardCommitmentVerificationResult): SystemStreamEvent | undefined {
  const { event, error } = validateSystemStreamEventShape(input, path);
  if (error) {
    invalid(result, path, error);
    return undefined;
  }
  return event;
}

function deepEqualJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((item, index) => deepEqualJson(item, b[index]));
  }
  const aObj = a as Record<string, unknown>;
  const bObj = b as Record<string, unknown>;
  const aKeys = Object.keys(aObj).sort();
  const bKeys = Object.keys(bObj).sort();
  if (aKeys.length !== bKeys.length || aKeys.some((key, index) => key !== bKeys[index])) return false;
  return aKeys.every((key) => deepEqualJson(aObj[key], bObj[key]));
}

type HistoryResolution =
  | { status: "complete" | "incomplete"; events: SystemStreamEvent[] }
  | { status: "invalid"; events: SystemStreamEvent[]; message: string };

function parseHistoryEvent(
  input: unknown,
  path: string,
  alreadySnapshotted = false
): { event?: SystemStreamEvent; message?: string } {
  const snapshot = alreadySnapshotted ? { value: input as JsonValue } : createInertJsonSnapshot(input);
  if (snapshot.value === undefined || ("error" in snapshot && snapshot.error)) {
    return { message: `${path}: ${"error" in snapshot ? snapshot.error : "missing event"}` };
  }
  const parsed = validateSystemStreamEventShape(snapshot.value, path);
  return parsed.error ? { message: parsed.error } : { event: parsed.event };
}

async function resolveSystemStreamHistory(
  tokenEvents: readonly SystemStreamEvent[],
  orderedTokenEvents: readonly SystemStreamEvent[],
  chainId: string,
  options: RewardCommitmentVerificationOptions
): Promise<HistoryResolution> {
  const maxHistoryEvents = options.maxHistoryEvents ?? DEFAULT_MAX_HISTORY_EVENTS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_HISTORY_TIMEOUT_MS;
  if (
    !Number.isInteger(maxHistoryEvents) ||
    maxHistoryEvents < 1 ||
    maxHistoryEvents > MAX_HISTORY_EVENTS ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > MAX_HISTORY_TIMEOUT_MS
  ) {
    return { status: "invalid", events: [...tokenEvents], message: "System Stream history bounds are invalid." };
  }

  const tokenByHash = new Map(tokenEvents.map((event) => [event.eventHash, canonicalizeJcs(event)]));
  const historyByHash = new Map<string, { event: SystemStreamEvent; canonical: string }>();
  const deadline = Date.now() + timeoutMs;
  const addHistoryEvent = (event: SystemStreamEvent): string | undefined => {
    if (event.chainId !== chainId) return "System Stream history contains an event for a different chainId.";
    const canonical = canonicalizeJcs(event);
    const tokenCanonical = tokenByHash.get(event.eventHash);
    if (tokenCanonical !== undefined) {
      return tokenCanonical === canonical ? undefined : "System Stream history contains a conflicting duplicate eventHash.";
    }
    const existing = historyByHash.get(event.eventHash);
    if (existing) {
      return existing.canonical === canonical ? undefined : "System Stream history contains a conflicting duplicate eventHash.";
    }
    historyByHash.set(event.eventHash, { event, canonical });
    return undefined;
  };

  const suppliedHistory = options.systemStreamHistory ?? [];
  if (suppliedHistory.length > maxHistoryEvents) return { status: "incomplete", events: [...tokenEvents] };
  for (const [index, raw] of suppliedHistory.entries()) {
    if (Date.now() >= deadline) {
      return { status: "incomplete", events: [...historyByHash.values()].map((item) => item.event).concat(tokenEvents) };
    }
    const parsed = parseHistoryEvent(raw, `$.options.systemStreamHistory[${index}]`);
    if (!parsed.event) {
      return { status: "invalid", events: [...tokenEvents], message: parsed.message ?? "Malformed System Stream history event." };
    }
    const conflict = addHistoryEvent(parsed.event);
    if (conflict) return { status: "invalid", events: [...tokenEvents], message: conflict };
  }
  if (historyByHash.size > maxHistoryEvents) return { status: "incomplete", events: [...tokenEvents] };

  let headHash = orderedTokenEvents[0]?.prevHash ?? null;
  if (headHash === null) return { status: "complete", events: [...tokenEvents] };
  const requested = new Set<string>();
  while (headHash !== null) {
    if (requested.has(headHash)) {
      return { status: "invalid", events: [...historyByHash.values()].map((item) => item.event).concat(tokenEvents), message: "System Stream history contains a cycle." };
    }
    requested.add(headHash);
    const supplied = historyByHash.get(headHash);
    if (supplied) {
      headHash = supplied.event.prevHash;
      continue;
    }
    const remaining = maxHistoryEvents - historyByHash.size;
    if (remaining <= 0 || Date.now() >= deadline || !options.systemStreamHistoryResolver) {
      return { status: "incomplete", events: [...historyByHash.values()].map((item) => item.event).concat(tokenEvents) };
    }

    const controller = new AbortController();
    const remainingMs = Math.max(1, deadline - Date.now());
    let timer: ReturnType<typeof setTimeout> | undefined;
    let rawPage: unknown;
    try {
      rawPage = await Promise.race([
        Promise.resolve(options.systemStreamHistoryResolver({
          chainId,
          headHash,
          limit: Math.min(1000, remaining),
          signal: controller.signal
        })),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new Error("history timeout"));
          }, remainingMs);
        })
      ]);
    } catch {
      if (timer !== undefined) clearTimeout(timer);
      return { status: "incomplete", events: [...historyByHash.values()].map((item) => item.event).concat(tokenEvents) };
    }
    if (timer !== undefined) clearTimeout(timer);

    const snapshot = createInertJsonSnapshot(rawPage);
    const envelope = snapshot.value === undefined ? undefined : object(snapshot.value);
    if (!envelope) {
      return { status: "invalid", events: [...tokenEvents], message: "System Stream history resolver returned a malformed envelope." };
    }
    if (envelope.success === false) {
      return envelope.error === "system_stream_event_not_found"
        ? { status: "incomplete", events: [...historyByHash.values()].map((item) => item.event).concat(tokenEvents) }
        : { status: "invalid", events: [...tokenEvents], message: "System Stream history resolver returned a conflict or invalid request." };
    }
    const data = object(envelope.data as JsonValue);
    const pageEvents = data ? array(data.events as JsonValue) : undefined;
    const requestedHeadHash = headHash;
    const pageLimit = Math.min(1000, remaining);
    if (
      envelope.success !== true ||
      !data ||
      data.chainId !== chainId ||
      data.requestedHeadHash !== requestedHeadHash ||
      !pageEvents ||
      pageEvents.length === 0 ||
      pageEvents.length > pageLimit ||
      (data.nextHeadHash !== null && (typeof data.nextHeadHash !== "string" || !HASH.test(data.nextHeadHash))) ||
      typeof data.hasMore !== "boolean" ||
      data.hasMore !== (data.nextHeadHash !== null)
    ) {
      return { status: "invalid", events: [...tokenEvents], message: "System Stream history resolver returned a malformed page." };
    }
    let expected = requestedHeadHash;
    let oldestPrevHash: string | null = null;
    for (const [index, raw] of pageEvents.entries()) {
      const parsed = parseHistoryEvent(raw, `$.historyPage.events[${index}]`, true);
      if (!parsed.event || parsed.event.eventHash !== expected) {
        return { status: "invalid", events: [...tokenEvents], message: parsed.message ?? "System Stream history page is not contiguous." };
      }
      const conflict = addHistoryEvent(parsed.event);
      if (conflict) return { status: "invalid", events: [...tokenEvents], message: conflict };
      oldestPrevHash = parsed.event.prevHash;
      expected = parsed.event.prevHash ?? "";
    }
    if (data.nextHeadHash !== oldestPrevHash) {
      return { status: "invalid", events: [...tokenEvents], message: "System Stream history continuation does not match the oldest event." };
    }
    headHash = oldestPrevHash;
  }
  return { status: "complete", events: [...historyByHash.values()].map((item) => item.event).concat(tokenEvents) };
}

function parseToken(input: JsonValue, result: RewardCommitmentVerificationResult): RewardCommitmentTokenV1 | undefined {
  const token = object(input);
  if (!token) {
    invalid(result, "$", "Reward commitment token must be a JSON object.");
    return undefined;
  }
  if (token.tokenType !== "REWARD_COMMITMENT") invalid(result, "$.tokenType", "Expected REWARD_COMMITMENT.");
  if (token.schemaVersion !== 1) invalid(result, "$.schemaVersion", "Expected reward-commitment schemaVersion 1.");
  if (!isNonEmptyString(token.chainId)) invalid(result, "$.chainId", "chainId must be a non-empty string.");
  if (token.economicTier !== "COMMITTED" && token.economicTier !== "COMMITTED_BACKED") {
    invalid(result, "$.economicTier", 'economicTier must be "COMMITTED" or "COMMITTED_BACKED".');
  }

  const commitmentEvent = parseSystemEvent(token.commitmentEvent as JsonValue, "$.commitmentEvent", result);
  const backingEventPresent = owns(token, "backingEvent");
  const backingEvent = backingEventPresent ? parseSystemEvent(token.backingEvent as JsonValue, "$.backingEvent", result) : undefined;
  if (token.economicTier === "COMMITTED_BACKED" && !backingEventPresent) {
    addError(result, "BACKING_EVENT_INVALID", "economicTier is COMMITTED_BACKED but backingEvent is absent.", "input", "$.backingEvent");
  }

  const systemEventsArray = array(token.systemEvents as JsonValue);
  const systemEvents: SystemStreamEvent[] = [];
  if (!systemEventsArray || systemEventsArray.length === 0) {
    invalid(result, "$.systemEvents", "systemEvents must be a non-empty array.");
  } else {
    systemEventsArray.forEach((raw, index) => {
      const parsed = parseSystemEvent(raw, `$.systemEvents[${index}]`, result);
      if (parsed) systemEvents.push(parsed);
    });
  }

  const batch = object(token.batch as JsonValue);
  if (
    !batch ||
    !isNonEmptyString(batch.batchId) ||
    !HASH.test(String(batch.root)) ||
    !isNonEmptyString(batch.schemaVersion) ||
    !isNonEmptyString(batch.txRef) ||
    !isNonEmptyString(batch.committedAt)
  ) {
    invalid(result, "$.batch", "batch must contain valid batchId, root, schemaVersion, txRef, and committedAt fields.");
  }
  const schemaVersion = batch && typeof batch.schemaVersion === "string" ? batch.schemaVersion : undefined;
  if (schemaVersion !== undefined && !CLOSED_SCHEMA_VERSIONS.includes(schemaVersion as (typeof CLOSED_SCHEMA_VERSIONS)[number])) {
    addError(result, "UNKNOWN_SCHEMA_VERSION", `Unknown reward-batch leaf schemaVersion "${schemaVersion}".`, "policy", "$.batch.schemaVersion");
  }

  if (!isNonEmptyString(token.recipientId)) invalid(result, "$.recipientId", "recipientId must be a non-empty string.");

  const leaf = object(token.leaf as JsonValue);
  if (!leaf) {
    invalid(result, "$.leaf", "leaf must be a JSON object.");
  } else if (schemaVersion !== undefined && CLOSED_SCHEMA_VERSIONS.includes(schemaVersion as (typeof CLOSED_SCHEMA_VERSIONS)[number])) {
    const blinded = schemaVersion.endsWith("b");
    const linkable = schemaVersion.startsWith("2");
    const expectedKeys = linkable ? ["batchId", "recipientId", "totalPoints", "rewardEventsRoot"] : ["batchId", "recipientId", "totalPoints"];
    if (!exactlyKeys(leaf, expectedKeys)) {
      invalid(result, "$.leaf", `leaf for schemaVersion "${schemaVersion}" must contain exactly ${expectedKeys.join(", ")}.`);
    } else {
      if (!isNonEmptyString(leaf.batchId) || leaf.batchId !== batch?.batchId) invalid(result, "$.leaf.batchId", "leaf.batchId must equal batch.batchId.");
      if (!isPoints(leaf.totalPoints)) invalid(result, "$.leaf.totalPoints", "leaf.totalPoints must be a non-negative base-10 integer string.");
      const recipientOk = blinded ? HASH.test(String(leaf.recipientId)) : isNonEmptyString(leaf.recipientId);
      if (!recipientOk) invalid(result, "$.leaf.recipientId", blinded ? "leaf.recipientId must be a lowercase SHA-256 hex commitment for a blinded schema." : "leaf.recipientId must be a non-empty string for a transparent schema.");
      if (leaf.recipientId !== token.recipientId) invalid(result, "$.leaf.recipientId", "leaf.recipientId must equal the token's recipientId.");
      if (linkable && !HASH.test(String(leaf.rewardEventsRoot))) invalid(result, "$.leaf.rewardEventsRoot", "leaf.rewardEventsRoot must be a lowercase SHA-256 hex digest.");
    }
  }

  const proof = object(token.proof as JsonValue);
  const proofLeaf = proof ? object(proof.leaf as JsonValue) : undefined;
  const siblings = proof ? array(proof.siblings as JsonValue) : undefined;
  if (
    !proof ||
    !isNonEmptyString(proof.batchId) ||
    !proofLeaf ||
    !HASH.test(String(proof.leafHash)) ||
    !siblings ||
    !siblings.every((sibling) => typeof sibling === "string" && HASH.test(sibling))
  ) {
    invalid(result, "$.proof", "proof must contain batchId, leaf, a lowercase SHA-256 leafHash, and an array of sibling hex digests.");
  } else if (proof.batchId !== batch?.batchId) {
    invalid(result, "$.proof.batchId", "proof.batchId must equal batch.batchId.");
  }

  let rewardInclusionProof: RewardCommitmentTokenV1["rewardInclusionProof"];
  if (owns(token, "rewardInclusionProof")) {
    const rip = object(token.rewardInclusionProof as JsonValue);
    const ripLeaf = rip ? object(rip.leaf as JsonValue) : undefined;
    const ripSiblings = rip ? array(rip.siblings as JsonValue) : undefined;
    if (
      !rip ||
      !isNonEmptyString(rip.batchId) ||
      !isNonEmptyString(rip.recipientId) ||
      !HASH.test(String(rip.rewardEventsRoot)) ||
      !ripLeaf ||
      !exactlyKeys(ripLeaf, ["spendId", "rewardEventHash"]) ||
      !isNonEmptyString(ripLeaf.spendId) ||
      !HASH.test(String(ripLeaf.rewardEventHash)) ||
      !HASH.test(String(rip.leafHash)) ||
      !ripSiblings ||
      !ripSiblings.every((sibling) => typeof sibling === "string" && HASH.test(sibling))
    ) {
      invalid(result, "$.rewardInclusionProof", "rewardInclusionProof is malformed.");
    } else {
      rewardInclusionProof = {
        batchId: rip.batchId as string,
        recipientId: rip.recipientId as string,
        rewardEventsRoot: rip.rewardEventsRoot as string,
        leaf: { spendId: ripLeaf.spendId as string, rewardEventHash: ripLeaf.rewardEventHash as string },
        leafHash: rip.leafHash as string,
        siblings: ripSiblings as string[]
      };
    }
  }

  if (result.errors.length > 0) return undefined;

  return {
    tokenType: "REWARD_COMMITMENT",
    schemaVersion: 1,
    chainId: token.chainId as string,
    economicTier: token.economicTier as "COMMITTED" | "COMMITTED_BACKED",
    commitmentEvent: commitmentEvent as SystemStreamEvent,
    backingEvent,
    systemEvents,
    batch: batch as unknown as RewardCommitmentTokenV1["batch"],
    recipientId: token.recipientId as string,
    leaf: leaf as { readonly [key: string]: JsonValue },
    proof: {
      batchId: proof!.batchId as string,
      leaf: proofLeaf as { readonly [key: string]: JsonValue },
      leafHash: proof!.leafHash as string,
      siblings: siblings as string[]
    },
    rewardInclusionProof
  };
}

function evaluateChainEvidence(
  batch: RewardCommitmentTokenV1["batch"],
  evidence: ChainCommitmentRecordEvidence
): { matches: boolean; mismatchField?: string } {
  if (evidence.batchId !== batch.batchId) return { matches: false, mismatchField: "batchId" };
  if (evidence.root !== batch.root) return { matches: false, mismatchField: "root" };
  if (evidence.schemaVersion !== batch.schemaVersion) return { matches: false, mismatchField: "schemaVersion" };
  if (evidence.txRef !== undefined && evidence.txRef !== batch.txRef) return { matches: false, mismatchField: "txRef" };
  if (evidence.committedAt !== undefined && evidence.committedAt !== batch.committedAt) return { matches: false, mismatchField: "committedAt" };
  return { matches: true };
}

function isChainCommitmentRecordEvidence(value: unknown): value is ChainCommitmentRecordEvidence {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return (
    isNonEmptyString(record.batchId) &&
    HASH.test(String(record.root)) &&
    isNonEmptyString(record.schemaVersion) &&
    (record.txRef === undefined || typeof record.txRef === "string") &&
    (record.committedAt === undefined || typeof record.committedAt === "string")
  );
}

async function applyChainEvidence(result: RewardCommitmentVerificationResult, token: RewardCommitmentTokenV1, options: RewardCommitmentVerificationOptions): Promise<void> {
  const chainEvidence = options.chainEvidence ?? { mode: "none" as const };

  if (chainEvidence.mode === "none") {
    result.anchor = "not-checked";
    addWarning(result, "ANCHOR_NOT_CHECKED", 'chainEvidence.mode is "none"; on-chain anchoring for batch.txRef/root was not checked.');
    return;
  }

  if (chainEvidence.mode === "provided") {
    if (!isChainCommitmentRecordEvidence(chainEvidence.tx)) {
      addError(result, "CHAIN_EVIDENCE_INVALID", "chainEvidence.tx is not a well-formed ChainCommitmentRecordEvidence.", "input", "$.options.chainEvidence.tx");
      result.anchor = "indeterminate";
      return;
    }
    const { matches, mismatchField } = evaluateChainEvidence(token.batch, chainEvidence.tx);
    if (!matches) {
      addError(result, "CHAIN_EVIDENCE_MISMATCH", `Caller-supplied chain evidence disagrees with the token's batch.${mismatchField}.`, "trust", `$.options.chainEvidence.tx.${mismatchField}`);
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

  // mode === "rpc": caller-directed package convenience endpoint returning
  // an already-decoded logical record, not raw chain transport.
  if (!isNonEmptyString(chainEvidence.url)) {
    addError(result, "CHAIN_EVIDENCE_INVALID", "chainEvidence.mode is \"rpc\" but no url was supplied.", "input", "$.options.chainEvidence.url");
    result.anchor = "indeterminate";
    return;
  }
  const fetchImpl = chainEvidence.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    addError(result, "CHAIN_EVIDENCE_INVALID", "No fetch implementation is available to perform the requested chain RPC lookup.", "network", "$.options.chainEvidence.url");
    result.anchor = "indeterminate";
    return;
  }
  let evidence: unknown;
  try {
    const response = await fetchImpl(chainEvidence.url);
    evidence = await response.json();
  } catch (error) {
    addError(result, "CHAIN_EVIDENCE_INVALID", `Chain RPC lookup failed: ${error instanceof Error ? error.message : "unknown error"}.`, "network", "$.options.chainEvidence.url");
    result.anchor = "indeterminate";
    return;
  }
  if (!isChainCommitmentRecordEvidence(evidence)) {
    addError(result, "CHAIN_EVIDENCE_INVALID", "Chain RPC response is not a well-formed ChainCommitmentRecordEvidence.", "network", "$.options.chainEvidence.url");
    result.anchor = "indeterminate";
    return;
  }
  const { matches, mismatchField } = evaluateChainEvidence(token.batch, evidence);
  if (!matches) {
    addError(result, "CHAIN_EVIDENCE_MISMATCH", `Chain RPC response disagrees with the token's batch.${mismatchField}.`, "trust", `$.options.chainEvidence.url`);
    result.anchor = "indeterminate";
    return;
  }
  result.anchor = "verified";
}

/**
 * Verifies a `RewardCommitmentTokenV1` per TOKENS.md's "Reward Commitment
 * Token" section (the six-step verification procedure) and
 * COMMITMENT_LAYER.md's Merkle/Authority Registry rules.
 *
 * This proves that a recipient has a leaf included under a committed,
 * authority-signed batch root — i.e. that an issuer attached an economic
 * (reward) liability to a batch, and (for `economicTier ===
 * "COMMITTED_BACKED"`) attested that liability as backed. It does NOT prove
 * current wallet balance, funds custody, solvency, or "already paid out"
 * (TOKENS.md's explicit non-claims for this token type).
 */
export async function verifyRewardCommitmentV1(input: unknown, options: RewardCommitmentVerificationOptions = {}): Promise<RewardCommitmentVerificationResult> {
  const result = resultFor();
  const snapshot = createInertJsonSnapshot(input);
  if (snapshot.error || snapshot.value === undefined) {
    invalid(result, "$", `Reward commitment token must be inert JSON: ${snapshot.error ?? "missing JSON value"}`);
    return result;
  }
  const token = parseToken(snapshot.value, result);
  if (!token) return result;

  result.schemaVersion = "1";
  result.metadata = {
    chainId: token.chainId,
    batchId: token.batch.batchId,
    recipientId: token.recipientId,
    committedAt: token.batch.committedAt
  };

  let replay = await replaySystemStreamSegment(token.systemEvents, token.chainId, options.authorityTrust);
  let historyInvalid = false;
  if (
    replay.authorityBootstrap === "not_genesis" &&
    (options.systemStreamHistory !== undefined ||
      options.systemStreamHistoryResolver !== undefined ||
      options.maxHistoryEvents !== undefined ||
      options.timeoutMs !== undefined)
  ) {
    const history = await resolveSystemStreamHistory(
      token.systemEvents,
      replay.ordered,
      token.chainId,
      options
    );
    if (history.status === "invalid") {
      historyInvalid = true;
      addError(result, "SYSTEM_STREAM_INVALID", history.message, "input", "$.options.systemStreamHistory");
    } else {
      replay = await replaySystemStreamSegment(history.events, token.chainId, options.authorityTrust);
    }
  }
  result.systemStreamValid = replay.integrityValid && !historyInvalid;
  for (const error of replay.errors) addError(result, error.code, error.message, error.cause, error.path);

  switch (replay.authorityBootstrap) {
    case "trusted": {
      const signatureValid = replay.eventSignatureValid.get(token.commitmentEvent.eventHash);
      result.authorityValid = signatureValid === true;
      break;
    }
    case "not_genesis":
      result.authorityValid = "indeterminate";
      addWarning(result, "AUTHORITY_INDETERMINATE_NON_GENESIS_SEGMENT", "systemEvents does not start at genesis (prevHash = null); authority validity cannot be established from this segment alone.");
      break;
    case "not_checked":
      result.authorityValid = "not_checked";
      addWarning(result, "AUTHORITY_NOT_CHECKED", "No authorityTrust resolver was supplied; the genesis authority was not authorized.");
      break;
    default:
      result.authorityValid = false;
  }
  if (historyInvalid) result.authorityValid = false;

  // Step 2: commitmentEvent is included in systemEvents, and batch === commitmentEvent.payload.
  const commitmentIncluded = replay.ordered.some((event) => deepEqualJson(event, token.commitmentEvent));
  const commitmentIsBatchCommitted = token.commitmentEvent.eventName === "REWARD_BATCH_COMMITTED";
  const batchMatchesPayload = deepEqualJson(token.batch, token.commitmentEvent.payload);
  result.commitmentValid = commitmentIncluded && commitmentIsBatchCommitted && batchMatchesPayload;
  if (!commitmentIncluded) addError(result, "COMMITMENT_EVENT_INVALID", "commitmentEvent is not present in systemEvents.", "input", "$.commitmentEvent");
  if (!commitmentIsBatchCommitted) addError(result, "COMMITMENT_EVENT_INVALID", "commitmentEvent.eventName must be REWARD_BATCH_COMMITTED.", "input", "$.commitmentEvent.eventName");
  if (!batchMatchesPayload) addError(result, "COMMITMENT_EVENT_INVALID", "batch does not equal commitmentEvent.payload.", "input", "$.batch");

  // Step 3: Merkle inclusion proof against batch.root.
  const merkle = verifyInclusionProof({ leaf: token.leaf, leafHash: token.proof.leafHash, siblings: token.proof.siblings, expectedRoot: token.batch.root });
  result.merkleValid = merkle.valid;
  if (!merkle.valid) {
    addError(
      result,
      "MERKLE_PROOF_INVALID",
      merkle.leafHashMismatch
        ? "Recomputed leaf hash does not match proof.leafHash."
        : "The Merkle inclusion proof does not resolve to batch.root.",
      "crypto",
      "$.proof"
    );
  }

  // Step 4: economicTier / backingEvent.
  result.economicTier = token.economicTier;
  if (token.economicTier === "COMMITTED_BACKED") {
    if (!token.backingEvent) {
      result.backingValid = false;
      // Already recorded as a BACKING_EVENT_INVALID error during shape parsing when absent; parseToken
      // returns undefined in that case, so reaching here backingEvent is always present.
    } else {
      const backingIncluded = replay.ordered.some((event) => deepEqualJson(event, token.backingEvent));
      const backingIsCorrectName = token.backingEvent.eventName === "REWARD_BATCH_BACKING_ATTESTED";
      const backingPayload = object(token.backingEvent.payload);
      const backingMatchesBatch = backingPayload?.batchId === token.batch.batchId;
      const backingSignatureValid = replay.authorityBootstrap === "trusted" ? replay.eventSignatureValid.get(token.backingEvent.eventHash) === true : false;
      result.backingValid = backingIncluded && backingIsCorrectName && backingMatchesBatch && backingSignatureValid;
      if (!backingIncluded) addError(result, "BACKING_EVENT_INVALID", "backingEvent is not present in systemEvents.", "input", "$.backingEvent");
      if (!backingIsCorrectName) addError(result, "BACKING_EVENT_INVALID", "backingEvent.eventName must be REWARD_BATCH_BACKING_ATTESTED.", "input", "$.backingEvent.eventName");
      if (!backingMatchesBatch) addError(result, "BACKING_EVENT_INVALID", "backingEvent.payload.batchId does not equal batch.batchId.", "input", "$.backingEvent.payload.batchId");
      if (!backingSignatureValid && replay.authorityBootstrap === "trusted") addError(result, "BACKING_EVENT_INVALID", "backingEvent signature/authority verification failed.", "crypto", "$.backingEvent");
    }
  } else {
    result.backingValid = "not_applicable";
  }

  // Step 5: local chain acceptance policy.
  await applyChainEvidence(result, token, options);

  result.accepted =
    result.systemStreamValid &&
    result.authorityValid === true &&
    result.commitmentValid &&
    result.merkleValid &&
    (result.economicTier !== "COMMITTED_BACKED" || result.backingValid === true) &&
    ((options.chainEvidence?.mode ?? "none") === "none" || result.anchor === "verified");

  return result;
}
