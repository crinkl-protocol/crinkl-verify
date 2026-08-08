export type ArtifactFormat =
  | "crinkl-native-spend-attestation/v1"
  | "w3c-vc-crinkl-spend-attestation/v1";

export type VerificationErrorCode =
  | "MALFORMED_JSON"
  | "UNSUPPORTED_FORMAT"
  | "UNSUPPORTED_PROFILE_VERSION"
  | "UNSUPPORTED_PROTOCOL_VERSION"
  | "SCHEMA_INVALID"
  | "JCS_INVALID_VALUE"
  | "TOKEN_HASH_MISMATCH"
  | "SIGNATURE_INVALID"
  | "UNTRUSTED_ISSUER"
  | "DID_RESOLUTION_FAILED"
  | "DID_DOCUMENT_INVALID"
  | "VERIFICATION_METHOD_NOT_AUTHORIZED"
  | "PROOF_CONTEXT_MISMATCH"
  | "PROOF_CONFIGURATION_INVALID"
  | "STATUS_LIST_UNAVAILABLE"
  | "STATUS_LIST_INVALID"
  | "CREDENTIAL_REVOKED"
  | "CREDENTIAL_REFRESH_REQUIRED"
  | "REFRESH_UNAVAILABLE"
  | "POLICY_REJECTED";

export type VerificationCause = "input" | "crypto" | "trust" | "network" | "policy";

export interface VerificationError {
  code: VerificationErrorCode;
  message: string;
  cause: VerificationCause;
  path?: string;
}

export interface VerificationWarning {
  code: "EXPERIMENTAL_W3C_PROFILE" | "CURRENTNESS_NOT_CHECKED" | "ISSUER_NOT_CHECKED";
  message: string;
}

export interface VerificationMetadata {
  credentialId?: string;
  spendId?: string;
  issuer?: string;
  tokenHash?: string;
  verificationMethod?: string;
}

export interface VerificationResult {
  format: ArtifactFormat | "unknown";
  profileVersion: string | "unknown";
  cryptographicallyValid: boolean;
  issuerAuthorized: boolean | "not_checked";
  current: boolean | "unknown" | "not_checked";
  accepted: boolean;
  errors: VerificationError[];
  warnings: VerificationWarning[];
  metadata: VerificationMetadata;
}

export interface NativeIssuerTrustInput {
  issuedBy: string;
  publicKeyBase64: string;
  protocolVersion: string;
  token: unknown;
}

/**
 * Resolve authorization from a local configuration or caller-owned trust
 * registry. The package never fetches issuer material itself.
 */
export type NativeIssuerTrustResolver = (
  input: NativeIssuerTrustInput
) => boolean | Promise<boolean>;

export interface NativeVerificationOptions {
  issuerTrust?: NativeIssuerTrustResolver;
  /** Defaults to the released native V1 protocolVersion (1.0.0-rc.1). */
  supportedProtocolVersions?: readonly string[];
}

export interface DidResolver {
  resolve(did: string): Promise<unknown>;
}

export interface StatusListResolver {
  resolve(url: string): Promise<unknown>;
}

export interface RefreshResolver {
  resolve(url: string): Promise<unknown>;
}

export interface W3cVerificationOptions {
  /** Only explicitly pinned profiles may be attempted in a future release. */
  supportedProfileVersions?: readonly string[];
  didResolver?: DidResolver;
  statusListResolver?: StatusListResolver;
  refreshResolver?: RefreshResolver;
}

export interface VerificationOptions extends NativeVerificationOptions, W3cVerificationOptions {}

export interface SpendAttestationTokenV1 {
  tokenType: "SPEND_ATTESTATION";
  schemaVersion: 1;
  spendId: string;
  wallet?: string;
  canonical: {
    status: "HARD_VERIFIED" | "CORRECTED" | "INVALIDATED";
    storeHash?: string;
    date?: string;
    totalCents?: string;
    currency?: string;
    timestamp?: string;
    geoRegion?: string;
    cbsaCode?: string;
    verificationVersion?: string;
    [key: string]: unknown;
  };
  lineage: { headEventHash: string; eventCount: number; [key: string]: unknown };
  protocol: { protocolVersion: string; [key: string]: unknown };
  zk?: { commitments?: ZkCommitments; [key: string]: unknown };
  signatures: {
    issuedBy: string;
    publicKey: string;
    tokenHash: string;
    signature: string;
  };
  [key: string]: unknown;
}

/**
 * Commitment encodings remain scheme-defined. The native verifier checks the
 * signed V1 envelope and treats each commitment value as opaque JSON data.
 */
export interface ZkCommitments {
  C_store: unknown;
  C_total: unknown;
  C_dayIndex: unknown;
  C_geoRegion: unknown;
  C_cbsaCode?: unknown;
}
