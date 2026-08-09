import {
  base64ToBytes,
  canonicalizeJcs,
  concatBytes,
  hexToBytes,
  sha256Hex,
  sha256HexUtf8,
  verifyEd25519
} from "./crypto.js";
import { createInertJsonSnapshot, type JsonValue } from "./json.js";
import { verifyNativeSpendAttestationSnapshot } from "./native-v1.js";
import type {
  SpendAttestationTokenV2,
  SpendHolderChallengeV2,
  SpendHolderControlProofV2,
  SpendHolderControlDecisionCode,
  SpendHolderControlVerificationOptions,
  SpendHolderControlVerificationResult,
  SpendHolderExpectedContextV2,
  SpendHolderPurposeV2,
  VerificationResult
} from "./types.js";

const HASH_ID = /^sha256:[0-9a-f]{64}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PURPOSES = new Set<SpendHolderPurposeV2>([
  "TOKEN_PRESENTATION",
  "CAMPAIGN_PROOF_AUTHORIZATION",
  "CAMPAIGN_ACTION_AUTHORIZATION"
]);
const encoder = new TextEncoder();

function object(value: JsonValue | undefined): Record<string, JsonValue> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, JsonValue>)
    : undefined;
}

function string(value: JsonValue | undefined): value is string {
  return typeof value === "string" && value.length > 0;
}

function owns(value: Record<string, JsonValue>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function exactlyKeys(value: Record<string, JsonValue>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => owns(value, key));
}

function isTimestamp(value: string): boolean {
  if (!TIMESTAMP.test(value)) return false;
  const date = new Date(value);
  return Number.isFinite(date.valueOf()) && date.toISOString() === value;
}

function result(
  tokenVerification: VerificationResult,
  code: SpendHolderControlDecisionCode
): SpendHolderControlVerificationResult {
  return { accepted: code === "holder_control_verified", code, tokenVerification };
}

function parseChallenge(input: JsonValue): SpendHolderChallengeV2 | undefined {
  const value = object(input);
  if (!value || !exactlyKeys(value, [
    "domain", "schemaVersion", "nonceBase64", "spendTokenHash", "scopeId",
    "requestContextHash", "purpose", "verifierId", "issuedAt", "expiresAt"
  ])) return undefined;
  if (value.domain !== "crinkl.spend-holder-challenge.v2" || value.schemaVersion !== 2 ||
    !string(value.nonceBase64) || !string(value.spendTokenHash) || !HASH_ID.test(value.spendTokenHash) ||
    !string(value.scopeId) || !HASH_ID.test(value.scopeId) ||
    !string(value.requestContextHash) || !HASH_ID.test(value.requestContextHash) ||
    !string(value.purpose) || !PURPOSES.has(value.purpose as SpendHolderPurposeV2) ||
    !string(value.verifierId) || !string(value.issuedAt) || !isTimestamp(value.issuedAt) ||
    !string(value.expiresAt) || !isTimestamp(value.expiresAt)) return undefined;
  const nonce = base64ToBytes(value.nonceBase64);
  if (!nonce || nonce.length !== 32) return undefined;
  return value as unknown as SpendHolderChallengeV2;
}

function parseProof(input: JsonValue): SpendHolderControlProofV2 | undefined {
  const value = object(input);
  if (!value || !exactlyKeys(value, [
    "schemaVersion", "scheme", "spendTokenHash", "scopeId", "challengeId",
    "holderPublicKeyBase64", "signatureBase64"
  ])) return undefined;
  if (value.schemaVersion !== 2 || value.scheme !== "crinkl.holder.v2" ||
    !string(value.spendTokenHash) || !HASH_ID.test(value.spendTokenHash) ||
    !string(value.scopeId) || !HASH_ID.test(value.scopeId) ||
    !string(value.challengeId) || !HASH_ID.test(value.challengeId) ||
    !string(value.holderPublicKeyBase64) || !string(value.signatureBase64)) return undefined;
  const publicKey = base64ToBytes(value.holderPublicKeyBase64);
  const signature = base64ToBytes(value.signatureBase64);
  if (!publicKey || publicKey.length !== 32 || !signature || signature.length !== 64) return undefined;
  return value as unknown as SpendHolderControlProofV2;
}

function validExpectedContext(context: SpendHolderExpectedContextV2): boolean {
  return HASH_ID.test(context.spendTokenHash) && HASH_ID.test(context.scopeId) &&
    HASH_ID.test(context.requestContextHash) && PURPOSES.has(context.purpose) &&
    typeof context.verifierId === "string" && context.verifierId.length > 0;
}

function validNow(now: string): number | undefined {
  return isTimestamp(now) ? Date.parse(now) : undefined;
}

/**
 * Verifies one fresh holder-control response. Challenge issuance/authentication
 * and atomic outstanding-challenge consumption remain caller-owned; this
 * package neither creates challenge state nor contacts a network service.
 */
export async function verifySpendHolderControl(
  spendToken: unknown,
  challengeInput: unknown,
  proofInput: unknown,
  options: SpendHolderControlVerificationOptions
): Promise<SpendHolderControlVerificationResult> {
  const tokenSnapshot = createInertJsonSnapshot(spendToken);
  const emptyTokenVerification: VerificationResult = {
    format: "unknown", profileVersion: "unknown", cryptographicallyValid: false,
    issuerAuthorized: "not_checked", current: "not_checked", accepted: false,
    errors: [], warnings: [], metadata: {}
  };
  if (tokenSnapshot.error || tokenSnapshot.value === undefined) return result(emptyTokenVerification, "holder_token_invalid");

  const tokenVerification = await verifyNativeSpendAttestationSnapshot(tokenSnapshot.value, options);
  const token = object(tokenSnapshot.value) as unknown as SpendAttestationTokenV2 | undefined;
  if (!token || token.schemaVersion !== 2 || tokenVerification.cryptographicallyValid !== true ||
    tokenVerification.issuerAuthorized !== true || tokenVerification.errors.length !== 0) {
    return result(tokenVerification, "holder_token_invalid");
  }
  if (!token.holderBinding) return result(tokenVerification, "holder_control_unavailable");

  const challengeSnapshot = createInertJsonSnapshot(challengeInput);
  const proofSnapshot = createInertJsonSnapshot(proofInput);
  if (challengeSnapshot.error || challengeSnapshot.value === undefined || proofSnapshot.error || proofSnapshot.value === undefined) {
    return result(tokenVerification, "holder_challenge_invalid");
  }
  const challenge = parseChallenge(challengeSnapshot.value);
  const proof = parseProof(proofSnapshot.value);
  const expectedContext = options?.expectedContext;
  if (!challenge || !proof || !expectedContext || !validExpectedContext(expectedContext)) {
    return result(tokenVerification, "holder_challenge_invalid");
  }

  const expectedTokenHash = `sha256:${token.signatures.tokenHash}`;
  if (expectedContext.spendTokenHash !== expectedTokenHash ||
    challenge.spendTokenHash !== expectedContext.spendTokenHash ||
    challenge.scopeId !== expectedContext.scopeId ||
    challenge.requestContextHash !== expectedContext.requestContextHash ||
    challenge.purpose !== expectedContext.purpose ||
    challenge.verifierId !== expectedContext.verifierId) {
    return result(tokenVerification, "holder_expected_context_mismatch");
  }

  let authenticated = false;
  try {
    authenticated = typeof options?.authenticateChallenge === "function" &&
      await options.authenticateChallenge(Object.freeze(challenge));
  } catch {
    authenticated = false;
  }
  if (!authenticated) return result(tokenVerification, "holder_challenge_invalid");

  const now = validNow(options.now);
  const issuedAt = Date.parse(challenge.issuedAt);
  const expiresAt = Date.parse(challenge.expiresAt);
  if (now === undefined || expiresAt <= issuedAt || expiresAt - issuedAt > 300_000 || now < issuedAt || now >= expiresAt) {
    return result(tokenVerification, "holder_challenge_expired");
  }

  const holderPublicKey = base64ToBytes(proof.holderPublicKeyBase64);
  const holderCommitment = `sha256:${sha256Hex(concatBytes(
    encoder.encode("crinkl.holder.v2:"), encoder.encode(token.spendId), holderPublicKey as Uint8Array
  ))}`;
  if (holderCommitment !== token.holderBinding.commitment) return result(tokenVerification, "holder_commitment_mismatch");

  let challengeDigestHex: string;
  try {
    challengeDigestHex = sha256HexUtf8(canonicalizeJcs(challenge));
  } catch {
    return result(tokenVerification, "holder_challenge_invalid");
  }
  const challengeId = `sha256:${challengeDigestHex}`;
  if (proof.challengeId !== challengeId) return result(tokenVerification, "holder_challenge_id_mismatch");
  if (proof.spendTokenHash !== challenge.spendTokenHash || proof.scopeId !== challenge.scopeId) {
    return result(tokenVerification, "holder_proof_binding_mismatch");
  }

  const signature = base64ToBytes(proof.signatureBase64);
  const digest = hexToBytes(challengeDigestHex);
  try {
    if (!signature || !digest || !holderPublicKey || !await verifyEd25519(signature, digest, holderPublicKey)) {
      return result(tokenVerification, "holder_signature_invalid");
    }
  } catch {
    return result(tokenVerification, "holder_signature_invalid");
  }

  try {
    if (typeof options?.consumeChallenge !== "function" || !await options.consumeChallenge(Object.freeze(challenge))) return result(tokenVerification, "holder_challenge_replayed");
  } catch {
    return result(tokenVerification, "holder_challenge_replayed");
  }
  return result(tokenVerification, "holder_control_verified");
}
