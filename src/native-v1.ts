import {
  base64ToBytes,
  canonicalizeJcs,
  hexToBytes,
  sha256HexUtf8,
  verifyEd25519
} from "./crypto.js";
import { addError, finalize, resultFor } from "./result.js";
import type { NativeVerificationOptions, SpendAttestationTokenV1, VerificationResult } from "./types.js";

const HASH = /^[0-9a-f]{64}$/;

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function string(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function invalid(result: VerificationResult, path: string, message: string): VerificationResult {
  return addError(result, "SCHEMA_INVALID", message, "input", path);
}

function parseToken(input: unknown, result: VerificationResult): SpendAttestationTokenV1 | undefined {
  const token = object(input);
  if (!token) {
    invalid(result, "$", "Native spend attestation must be a JSON object.");
    return undefined;
  }
  if (token.tokenType !== "SPEND_ATTESTATION") invalid(result, "$.tokenType", "Expected SPEND_ATTESTATION.");
  if (token.schemaVersion !== 1) invalid(result, "$.schemaVersion", "Expected native schemaVersion 1.");
  if (!string(token.spendId)) invalid(result, "$.spendId", "spendId must be a non-empty string.");

  const canonical = object(token.canonical);
  if (!canonical || !["HARD_VERIFIED", "CORRECTED", "INVALIDATED"].includes(String(canonical.status))) {
    invalid(result, "$.canonical.status", "canonical.status must be HARD_VERIFIED, CORRECTED, or INVALIDATED.");
  }
  const lineage = object(token.lineage);
  const eventCount = lineage?.eventCount;
  if (!lineage || !string(lineage.headEventHash) || !HASH.test(lineage.headEventHash) || typeof eventCount !== "number" || !Number.isSafeInteger(eventCount) || eventCount < 1) {
    invalid(result, "$.lineage", "lineage must contain a lowercase SHA-256 headEventHash and positive integer eventCount.");
  }
  const protocol = object(token.protocol);
  if (!protocol || !string(protocol.protocolVersion)) invalid(result, "$.protocol.protocolVersion", "protocol.protocolVersion must be a non-empty string.");
  const signatures = object(token.signatures);
  if (!signatures || !string(signatures.issuedBy) || !string(signatures.publicKey) || !string(signatures.tokenHash) || !HASH.test(signatures.tokenHash) || !string(signatures.signature)) {
    invalid(result, "$.signatures", "signatures must include issuedBy, publicKey, lowercase tokenHash, and signature.");
  }
  return result.errors.length === 0 ? (token as SpendAttestationTokenV1) : undefined;
}

export async function verifyNativeSpendAttestation(
  input: unknown,
  options: NativeVerificationOptions = {}
): Promise<VerificationResult> {
  const result = resultFor("crinkl-native-spend-attestation/v1", "1");
  const token = parseToken(input, result);
  if (!token) return finalize(result);

  result.metadata = {
    spendId: token.spendId,
    issuer: token.signatures.issuedBy,
    tokenHash: token.signatures.tokenHash
  };
  if (options.supportedProtocolVersions && !options.supportedProtocolVersions.includes(token.protocol.protocolVersion)) {
    addError(result, "UNSUPPORTED_PROTOCOL_VERSION", `Unsupported protocolVersion ${token.protocol.protocolVersion}.`, "policy", "$.protocol.protocolVersion");
    return finalize(result);
  }

  let actualTokenHash: string;
  try {
    actualTokenHash = computeNativeSpendAttestationTokenHash(token);
  } catch {
    addError(result, "JCS_INVALID_VALUE", "The token cannot be canonicalized with RFC 8785 JCS.", "input");
    return finalize(result);
  }
  if (actualTokenHash !== token.signatures.tokenHash) {
    addError(result, "TOKEN_HASH_MISMATCH", "signatures.tokenHash does not match the canonical unsigned token.", "crypto", "$.signatures.tokenHash");
    return finalize(result);
  }

  const signature = base64ToBytes(token.signatures.signature);
  const publicKey = base64ToBytes(token.signatures.publicKey);
  const digest = hexToBytes(actualTokenHash);
  if (!signature || signature.length !== 64 || !publicKey || publicKey.length !== 32 || !digest) {
    addError(result, "SCHEMA_INVALID", "Native Ed25519 key/signature encoding is invalid.", "input", "$.signatures");
    return finalize(result);
  }
  try {
    result.cryptographicallyValid = await verifyEd25519(signature, digest, publicKey);
  } catch {
    result.cryptographicallyValid = false;
  }
  if (!result.cryptographicallyValid) {
    addError(result, "SIGNATURE_INVALID", "Native Ed25519 signature verification failed.", "crypto", "$.signatures.signature");
    return finalize(result);
  }

  if (!options.issuerTrust) {
    result.issuerAuthorized = "not_checked";
    result.warnings.push({
      code: "ISSUER_NOT_CHECKED",
      message: "No issuerTrust resolver was supplied; a valid signature is not issuer authorization."
    });
  } else {
    try {
      result.issuerAuthorized = await options.issuerTrust({
        issuedBy: token.signatures.issuedBy,
        publicKeyBase64: token.signatures.publicKey,
        protocolVersion: token.protocol.protocolVersion,
        token
      });
    } catch {
      result.issuerAuthorized = false;
    }
    if (result.issuerAuthorized !== true) {
      addError(result, "UNTRUSTED_ISSUER", "The caller-supplied issuer trust resolver did not authorize this key.", "trust", "$.signatures");
      return finalize(result);
    }
  }

  result.current = token.canonical.status === "INVALIDATED" ? false : "unknown";
  if (token.canonical.status === "INVALIDATED") {
    addError(result, "POLICY_REJECTED", "The native token is marked INVALIDATED and is not accepted for current reliance.", "policy", "$.canonical.status");
  } else {
    result.warnings.push({
      code: "CURRENTNESS_NOT_CHECKED",
      message: "Native token signatures prove an issuance snapshot; currentness requires caller policy or additional protocol evidence."
    });
  }
  return finalize(result);
}

/**
 * Computes the released native-v1 token hash: SHA-256 over the RFC 8785
 * canonical serialization of the token with its complete `signatures` member
 * removed. It does not validate the surrounding token shape.
 */
export function computeNativeSpendAttestationTokenHash(token: Record<string, unknown>): string {
  const unsignedToken = { ...token };
  delete unsignedToken.signatures;
  return sha256HexUtf8(canonicalizeJcs(unsignedToken));
}
