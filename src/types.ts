import type { JsonValue } from "./json.js";

export type ArtifactFormat =
  | "crinkl-native-spend-attestation/v1"
  | "crinkl-native-spend-attestation/v2"
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
  | "POLICY_REJECTED"
  | "SYSTEM_STREAM_INVALID"
  | "AUTHORITY_INVALID"
  | "AUTHORITY_UNTRUSTED"
  | "COMMITMENT_EVENT_INVALID"
  | "MERKLE_PROOF_INVALID"
  | "UNKNOWN_SCHEMA_VERSION"
  | "BACKING_EVENT_INVALID"
  | "REWARD_INCLUSION_PROOF_INVALID"
  | "SPEND_REWARD_LINKAGE_MISMATCH"
  | "CHAIN_EVIDENCE_INVALID"
  | "CHAIN_EVIDENCE_MISMATCH";

export type VerificationCause = "input" | "crypto" | "trust" | "network" | "policy";

export interface VerificationError {
  code: VerificationErrorCode;
  message: string;
  cause: VerificationCause;
  path?: string;
}

export interface VerificationWarning {
  code:
    | "EXPERIMENTAL_W3C_PROFILE"
    | "CURRENTNESS_NOT_CHECKED"
    | "ISSUER_NOT_CHECKED"
    | "AUTHORITY_INDETERMINATE_NON_GENESIS_SEGMENT"
    | "AUTHORITY_NOT_CHECKED"
    | "ANCHOR_NOT_CHECKED"
    | "ANCHOR_INDETERMINATE"
    | "REWARD_COMMITMENT_NOT_PROVIDED";
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

/** Signed optional holder commitment defined by SpendAttestationTokenV2. */
export interface SpendHolderBindingV2 {
  scheme: "crinkl.holder.v2";
  commitment: `sha256:${string}`;
}

/**
 * SpendAttestationTokenV2 retains the V1 shape and adds an optional signed
 * holderBinding. Its absence does not invalidate the Spend Token.
 */
export interface SpendAttestationTokenV2 {
  tokenType: "SPEND_ATTESTATION";
  schemaVersion: 2;
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
  holderBinding?: SpendHolderBindingV2;
  signatures: {
    issuedBy: string;
    publicKey: string;
    tokenHash: string;
    signature: string;
  };
  [key: string]: unknown;
}

export type SpendAttestationToken = SpendAttestationTokenV1 | SpendAttestationTokenV2;

export type SpendHolderPurposeV2 =
  | "TOKEN_PRESENTATION"
  | "CAMPAIGN_PROOF_AUTHORIZATION"
  | "CAMPAIGN_ACTION_AUTHORIZATION";

export interface SpendHolderChallengeV2 {
  domain: "crinkl.spend-holder-challenge.v2";
  schemaVersion: 2;
  nonceBase64: string;
  spendTokenHash: `sha256:${string}`;
  scopeId: `sha256:${string}`;
  requestContextHash: `sha256:${string}`;
  purpose: SpendHolderPurposeV2;
  verifierId: string;
  issuedAt: string;
  expiresAt: string;
}

export interface SpendHolderControlProofV2 {
  schemaVersion: 2;
  scheme: "crinkl.holder.v2";
  spendTokenHash: `sha256:${string}`;
  scopeId: `sha256:${string}`;
  challengeId: `sha256:${string}`;
  holderPublicKeyBase64: string;
  signatureBase64: string;
}

export interface SpendHolderExpectedContextV2 {
  spendTokenHash: `sha256:${string}`;
  scopeId: `sha256:${string}`;
  requestContextHash: `sha256:${string}`;
  purpose: SpendHolderPurposeV2;
  verifierId: string;
}

/** The relying verifier owns challenge authentication and atomic consumption. */
export interface SpendHolderControlVerificationOptions extends NativeVerificationOptions {
  expectedContext: SpendHolderExpectedContextV2;
  now: string;
  authenticateChallenge: (challenge: Readonly<SpendHolderChallengeV2>) => boolean | Promise<boolean>;
  /**
   * Atomically consume the authenticated outstanding `(verifierId, nonceBase64)`
   * challenge. It may resolve `true` only after durable consumption succeeds.
   */
  consumeChallenge: (challenge: Readonly<SpendHolderChallengeV2>) => boolean | Promise<boolean>;
}

export type SpendHolderControlDecisionCode =
  | "holder_control_verified"
  | "holder_token_invalid"
  | "holder_control_unavailable"
  | "holder_challenge_invalid"
  | "holder_expected_context_mismatch"
  | "holder_challenge_expired"
  | "holder_challenge_replayed"
  | "holder_commitment_mismatch"
  | "holder_challenge_id_mismatch"
  | "holder_proof_binding_mismatch"
  | "holder_signature_invalid";

export interface SpendHolderControlVerificationResult {
  accepted: boolean;
  code: SpendHolderControlDecisionCode;
  tokenVerification: VerificationResult;
}

/**
 * Commitment encodings remain scheme-defined. The native verifier checks the
 * signed V1 envelope and treats each commitment value as opaque JSON data.
 */
export interface ZkCommitments {
  C_store: unknown;
  C_total: unknown;
  C_dayIndex: unknown;
  C_currency?: unknown;
  C_geoRegion?: unknown;
  C_cbsaCode?: unknown;
}

// ---------------------------------------------------------------------------
// Reward Commitment Token V1 (TOKENS.md#reward-commitment-token) and the
// Commitment Layer primitives (COMMITMENT_LAYER.md) it depends on.
// ---------------------------------------------------------------------------

/**
 * System-stream event envelope (EVENTS.md#system-stream-event-envelope /
 * DATA_STRUCTURES.md#integrity-envelope). `payload` is left as opaque JSON;
 * this package interprets the payload only for the specific event names it
 * verifies (REWARD_BATCH_COMMITTED, REWARD_BATCH_BACKING_ATTESTED,
 * AUTHORITY_REGISTERED, AUTHORITY_REVOKED). Unknown event names are carried
 * with a validated envelope but an unread payload, consistent with tolerating
 * version skew rather than rejecting a segment for containing events this
 * package does not need to interpret.
 */
export interface SystemStreamEvent {
  eventId: string;
  eventName: string;
  chainId: string;
  signedBy: string;
  payload: { readonly [key: string]: JsonValue };
  timestamp: string;
  protocolVersion: string;
  eventHash: string;
  prevHash: string | null;
  signature: string;
}

/** REWARD_BATCH_COMMITTED payload (COMMITMENT_LAYER.md#reward_batch_committed). */
export interface RewardBatchCommittedPayload {
  batchId: string;
  root: string;
  leafCount: number;
  totalPoints: string;
  schemaVersion: "1a" | "1b" | "2a" | "2b";
  txRef: string;
  committedAt: string;
  [key: string]: JsonValue;
}

/** REWARD_BATCH_BACKING_ATTESTED payload (COMMITMENT_LAYER.md#reward_batch_backing_attested). */
export interface RewardBatchBackingAttestedPayload {
  batchId: string;
  backingAsset: { chainId: string; mint: string; decimals: number };
  backingAmount: string;
  backingVault: string;
  backingTxRef: string;
  backedAt: string;
  [key: string]: JsonValue;
}

/** Merkle inclusion proof structure (COMMITMENT_LAYER.md#proof-structure). */
export interface InclusionProofV1 {
  batchId: string;
  leaf: { readonly [key: string]: JsonValue };
  leafHash: string;
  siblings: string[];
  leafIndex?: number;
}

/** Spend/reward linkage proof structure (COMMITMENT_LAYER.md#reward-inclusion-proof-structure). */
export interface RewardInclusionProofV1 {
  batchId: string;
  recipientId: string;
  rewardEventsRoot: string;
  leaf: { spendId: string; rewardEventHash: string; [key: string]: JsonValue };
  leafHash: string;
  siblings: string[];
}

/** Portable shape (TOKENS.md#reward-commitment-token, "Portable shape (normative)"). */
export interface RewardCommitmentTokenV1 {
  tokenType: "REWARD_COMMITMENT";
  schemaVersion: 1;
  chainId: string;
  economicTier: "COMMITTED" | "COMMITTED_BACKED";
  commitmentEvent: SystemStreamEvent;
  backingEvent?: SystemStreamEvent;
  systemEvents: SystemStreamEvent[];
  batch: RewardBatchCommittedPayload;
  recipientId: string;
  leaf: { readonly [key: string]: JsonValue };
  proof: InclusionProofV1;
  rewardInclusionProof?: RewardInclusionProofV1;
  [key: string]: unknown;
}

/**
 * Caller-owned resolver that authorizes the *genesis* authority of a
 * `chainId` (the authority established by the first `AUTHORITY_REGISTERED`
 * event in a segment whose `prevHash` is `null`). Reconstructing authority
 * validity for every later authority is done entirely from the signed
 * `AUTHORITY_REGISTERED` / `AUTHORITY_REVOKED` chain (each later rotation is
 * itself signed by a prior already-valid authority) — but the very first
 * authority has no predecessor to vouch for it, so, exactly like
 * {@link NativeIssuerTrustResolver}, the package never invents a root of
 * trust and instead asks the caller. The package never fetches authority
 * material itself.
 */
export type AuthorityTrustResolver = (input: {
  chainId: string;
  authorityId: string;
  publicKeyBase64: string;
  validFrom: string;
}) => boolean | Promise<boolean>;

/** Skip on-chain anchoring entirely (default). Zero network access. */
export interface ChainEvidenceNone {
  mode: "none";
}

/**
 * The chain-agnostic "logical content" COMMITMENT_LAYER.md requires any chain
 * binding to expose (see `#commitment-record` and
 * `#long-term-verifiability`), already decoded by the caller from whatever
 * chain-specific transport/encoding they used. This is deliberately NOT raw
 * transaction bytes: COMMITMENT_LAYER.md's `#chain-bindings` section states
 * that Solana/EVM/etc. memo-or-anchor byte encodings are chain-specific and
 * "documented separately from this core specification" — no such document
 * exists for reward-commitment batches in the protocol spec snapshot this
 * package was written against, so this package does not parse raw
 * transaction bytes (doing so would mean inventing a binding the protocol
 * has not defined). It only checks that the caller's already-decoded record
 * is internally consistent with the token's claimed batch.
 */
export interface ChainCommitmentRecordEvidence {
  batchId: string;
  root: string;
  schemaVersion: string;
  txRef?: string;
  committedAt?: string;
  leafCount?: number;
  totalPoints?: string;
}

/** Verify batch/root binding offline against caller-supplied, already-decoded chain evidence. Zero network access. */
export interface ChainEvidenceProvided {
  mode: "provided";
  tx: ChainCommitmentRecordEvidence;
}

/**
 * The only chain-evidence mode that may touch the network, and only because
 * the caller explicitly supplied `url`. This package defines a minimal
 * request/response contract of its own for this hook (a GET to `url`
 * expected to return a JSON `ChainCommitmentRecordEvidence` body) — that
 * contract is a package-level convenience, not a normative protocol wire
 * format, because (as with {@link ChainEvidenceProvided}) the protocol does
 * not define one.
 */
export interface ChainEvidenceRpc {
  mode: "rpc";
  url: string;
  /** Injectable for testing; defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

/** Caller-owned authorization for one Solana RPC trust boundary. */
export interface SolanaEvidenceTrustInput {
  cluster: string;
  rpcUrl: string;
  programId: string;
  instructionDiscriminatorHex: string;
  requiredFinality: "finalized";
}

export type SolanaEvidenceTrustResolver = (
  input: SolanaEvidenceTrustInput
) => boolean | Promise<boolean>;

/**
 * Fetch and decode the finalized Solana transaction named by `batch.txRef`.
 * The caller supplies both the endpoint and expected instruction discriminator;
 * neither value is inferred as trusted by this package.
 */
export interface ChainEvidenceSolanaRpc {
  mode: "solana-rpc";
  rpcUrl: string;
  instructionDiscriminatorHex: string;
  /** Injectable for testing; defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

export type ChainEvidence = ChainEvidenceNone | ChainEvidenceProvided | ChainEvidenceRpc | ChainEvidenceSolanaRpc;

export type AnchorStatus = "verified" | "not-checked" | "indeterminate";

export interface RewardCommitmentVerificationOptions {
  /** Defaults to `{ mode: "none" }`. */
  chainEvidence?: ChainEvidence;
  authorityTrust?: AuthorityTrustResolver;
  /** Required by `chainEvidence.mode === "solana-rpc"`. */
  solanaEvidenceTrust?: SolanaEvidenceTrustResolver;
}

export interface RewardCommitmentVerificationResult {
  format: "crinkl-reward-commitment/v1";
  schemaVersion: "1" | "unknown";
  /** Integrity envelope + prevHash chaining across `systemEvents` (step 1, integrity half). */
  systemStreamValid: boolean;
  /**
   * Authority validity for `commitmentEvent.signedBy` (step 1, authority
   * half). `"indeterminate"` per TOKENS.md when the segment does not start
   * at genesis and no missing history was supplied.
   */
  authorityValid: boolean | "indeterminate" | "not_checked";
  /** `commitmentEvent` located in `systemEvents` and `batch === commitmentEvent.payload` (steps 2). */
  commitmentValid: boolean;
  /** Merkle inclusion proof verifies against `batch.root` (step 3). */
  merkleValid: boolean;
  economicTier: "COMMITTED" | "COMMITTED_BACKED" | "unknown";
  /** Only meaningful when `economicTier === "COMMITTED_BACKED"` (step 4). */
  backingValid: boolean | "not_applicable";
  /** Step 5 (local chain acceptance policy). */
  anchor: AnchorStatus;
  accepted: boolean;
  errors: VerificationError[];
  warnings: VerificationWarning[];
  metadata: {
    chainId?: string;
    batchId?: string;
    recipientId?: string;
    committedAt?: string;
  };
}

/**
 * `"invalid"` means the base spend attestation itself failed cryptographic
 * or issuer verification — no tier applies. Otherwise the tier is the
 * highest rung this package could establish: a signed claim
 * (`"crypto-valid"`), a claim with an anchored batch-level reward liability
 * (`"committed"`), or a claim with a liability additionally attested as
 * economically backed (`"committed-backed"`). For linkable 2a/2b batches,
 * the composite may return a committed tier only when an exact
 * `rewardInclusionProof` binds the verified spend metadata to the aggregate
 * leaf; otherwise it remains `"crypto-valid"`.
 */
export type SpendRewardClaimTier = "invalid" | "crypto-valid" | "committed" | "committed-backed";

export type SpendRewardLinkageStatus =
  | "verified"
  | "not-applicable"
  | "not-checked"
  | "mismatch";

export interface SpendWithRewardCommitmentOptions extends NativeVerificationOptions {
  rewardCommitment?: RewardCommitmentVerificationOptions;
}

export interface SpendWithRewardCommitmentResult {
  tier: SpendRewardClaimTier;
  spend: VerificationResult;
  rewardCommitment?: RewardCommitmentVerificationResult;
  linkage: SpendRewardLinkageStatus;
  anchor: AnchorStatus;
  errors: VerificationError[];
  warnings: VerificationWarning[];
}
