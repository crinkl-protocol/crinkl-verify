import {
  base64ToBytes,
  canonicalizeJcs,
  hexToBytes,
  sha256HexUtf8,
  verifyEd25519
} from "./crypto.js";
import { createInertJsonSnapshot, type JsonValue } from "./json.js";
import { addError, finalize, resultFor } from "./result.js";
import type { NativeVerificationOptions, SpendAttestationTokenV1, VerificationResult } from "./types.js";

const DEFAULT_SUPPORTED_PROTOCOL_VERSIONS = ["1.0.0-rc.1"] as const;
const HASH = /^[0-9a-f]{64}$/;
const AMOUNT = /^(0|[1-9][0-9]*)$/;
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CURRENCY = /^[A-Z]{3}$/;
const REGION = /^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/;
const CBSA = /^(?:\d{5}|non-metro:[A-Z]{2}(?:-[A-Z0-9]{1,3})?|UNKNOWN)$/;

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

function isDate(value: string): boolean {
  if (!DATE.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 10) === value;
}

function isVersion(value: string): boolean {
  const match = VERSION.exec(value);
  if (!match) return false;
  const prerelease = match[4];
  return prerelease === undefined || prerelease.split(".").every((identifier) =>
    !/^[0-9]+$/.test(identifier) || identifier === "0" || !identifier.startsWith("0")
  );
}

function invalid(result: VerificationResult, path: string, message: string): VerificationResult {
  return addError(result, "SCHEMA_INVALID", message, "input", path);
}

function validateOptionalString(
  value: Record<string, JsonValue>,
  key: string,
  path: string,
  predicate: (candidate: string) => boolean,
  description: string,
  result: VerificationResult
): void {
  if (owns(value, key) && (!string(value[key]) || !predicate(value[key] as string))) {
    invalid(result, path, description);
  }
}

function validateCommitments(value: JsonValue | undefined, result: VerificationResult): void {
  const commitments = object(value);
  const required = ["C_store", "C_total", "C_dayIndex", "C_geoRegion"];
  if (!commitments || !required.every((key) => owns(commitments, key))) {
    invalid(result, "$.zk.commitments", "zk.commitments must contain the required V1 commitment labels.");
  }
}

function parseToken(input: JsonValue, result: VerificationResult): SpendAttestationTokenV1 | undefined {
  const token = object(input);
  if (!token) {
    invalid(result, "$", "Native spend attestation must be a JSON object.");
    return undefined;
  }
  if (token.tokenType !== "SPEND_ATTESTATION") invalid(result, "$.tokenType", "Expected SPEND_ATTESTATION.");
  if (token.schemaVersion !== 1) invalid(result, "$.schemaVersion", "Expected native schemaVersion 1.");
  if (!string(token.spendId)) invalid(result, "$.spendId", "spendId must be a non-empty string.");
  validateOptionalString(token, "wallet", "$.wallet", () => true, "wallet must be a non-empty string.", result);

  const canonical = object(token.canonical);
  if (!canonical || !["HARD_VERIFIED", "CORRECTED", "INVALIDATED"].includes(String(canonical.status))) {
    invalid(result, "$.canonical", "canonical must contain a supported status.");
  } else {
    validateOptionalString(canonical, "storeHash", "$.canonical.storeHash", (candidate) => /^sha256:[0-9a-f]{64}$/.test(candidate), "storeHash must be sha256: followed by lowercase SHA-256 hex.", result);
    validateOptionalString(canonical, "date", "$.canonical.date", isDate, "date must be a valid UTC YYYY-MM-DD value.", result);
    validateOptionalString(canonical, "totalCents", "$.canonical.totalCents", (candidate) => AMOUNT.test(candidate), "totalCents must be a non-negative base-10 integer string.", result);
    validateOptionalString(canonical, "currency", "$.canonical.currency", (candidate) => CURRENCY.test(candidate), "currency must be an uppercase ISO 4217 code.", result);
    validateOptionalString(canonical, "timestamp", "$.canonical.timestamp", isTimestamp, "timestamp must be a valid UTC millisecond timestamp.", result);
    validateOptionalString(canonical, "geoRegion", "$.canonical.geoRegion", (candidate) => REGION.test(candidate), "geoRegion must be an ISO 3166-1 or ISO 3166-2 code.", result);
    validateOptionalString(canonical, "cbsaCode", "$.canonical.cbsaCode", (candidate) => CBSA.test(candidate), "cbsaCode must be a five-digit CBSA, non-metro region, or UNKNOWN.", result);
    validateOptionalString(canonical, "verificationVersion", "$.canonical.verificationVersion", isVersion, "verificationVersion must be SemVer 2.0 compatible.", result);
  }

  const lineage = object(token.lineage);
  const eventCount = lineage?.eventCount;
  if (!lineage || !string(lineage.headEventHash) || !HASH.test(lineage.headEventHash) || typeof eventCount !== "number" || !Number.isSafeInteger(eventCount) || eventCount < 1) {
    invalid(result, "$.lineage", "lineage must contain a lowercase SHA-256 headEventHash and positive integer eventCount.");
  }

  const protocol = object(token.protocol);
  if (!protocol || !string(protocol.protocolVersion) || !isVersion(protocol.protocolVersion)) {
    invalid(result, "$.protocol.protocolVersion", "protocolVersion must be a SemVer 2.0 compatible string.");
  }

  if (owns(token, "zk")) {
    const zk = object(token.zk);
    if (!zk) {
      invalid(result, "$.zk", "zk must be a JSON object when present.");
    } else if (owns(zk, "commitments")) {
      validateCommitments(zk.commitments, result);
    }
  }

  const signatures = object(token.signatures);
  if (!signatures || !exactlyKeys(signatures, ["issuedBy", "publicKey", "tokenHash", "signature"]) || !string(signatures.issuedBy) || !string(signatures.publicKey) || !string(signatures.tokenHash) || !HASH.test(signatures.tokenHash) || !string(signatures.signature)) {
    invalid(result, "$.signatures", "signatures must contain exactly issuedBy, publicKey, tokenHash, and signature.");
  }
  return result.errors.length === 0 ? (token as unknown as SpendAttestationTokenV1) : undefined;
}

function computeHashFromSnapshot(token: Record<string, JsonValue>): string {
  const unsignedToken: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
  for (const key of Object.keys(token)) {
    if (key !== "signatures") unsignedToken[key] = token[key];
  }
  return sha256HexUtf8(canonicalizeJcs(unsignedToken));
}

export async function verifyNativeSpendAttestation(
  input: unknown,
  options: NativeVerificationOptions = {}
): Promise<VerificationResult> {
  const result = resultFor("crinkl-native-spend-attestation/v1", "1");
  const snapshot = createInertJsonSnapshot(input);
  if (snapshot.error || snapshot.value === undefined) {
    invalid(result, "$", `Native spend attestation must be inert JSON: ${snapshot.error ?? "missing JSON value"}`);
    return finalize(result);
  }
  return verifyNativeSpendAttestationSnapshot(snapshot.value, options);
}

export async function verifyNativeSpendAttestationSnapshot(
  input: JsonValue,
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
  const supportedProtocolVersions = options.supportedProtocolVersions ?? DEFAULT_SUPPORTED_PROTOCOL_VERSIONS;
  if (!supportedProtocolVersions.includes(token.protocol.protocolVersion)) {
    addError(result, "UNSUPPORTED_PROTOCOL_VERSION", `Unsupported protocolVersion ${token.protocol.protocolVersion}.`, "policy", "$.protocol.protocolVersion");
    return finalize(result);
  }

  let actualTokenHash: string;
  try {
    actualTokenHash = computeHashFromSnapshot(token as unknown as Record<string, JsonValue>);
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

/** Computes SHA-256 over RFC 8785 JCS unsigned native-token bytes. */
export function computeNativeSpendAttestationTokenHash(token: Record<string, unknown>): string {
  const snapshot = createInertJsonSnapshot(token);
  if (snapshot.error || !snapshot.value || !object(snapshot.value)) {
    throw new TypeError(snapshot.error ?? "Native token hash input must be an inert JSON object.");
  }
  return computeHashFromSnapshot(object(snapshot.value) as Record<string, JsonValue>);
}
