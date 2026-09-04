# `@crinkl/verify`

Verify Crinkl Spend Attestation Tokens and Reward Commitment Tokens locally,
without accounts. Verification is offline by default; only an explicitly
configured reward-chain RPC evidence mode uses the network.

The `0.1.0-alpha.5` candidate verifies the released native `SpendAttestationTokenV1`
profile, the released `SpendAttestationTokenV2` holder-binding profile, and the
`RewardCommitmentTokenV1` profile offline. It also composes native Spend Token
and reward-commitment verification into tiered spend + reward-commitment
verification. The separately documented geography compatibility profile in
the adopted V1/V2 geography compatibility rule. W3C VC verification is
intentionally experimental and fails closed
until a released Crinkl profile bundle pins its context, schemas, vectors,
issuer-key history, and status/refresh rules.

## Install

```bash
npm install @crinkl/verify@0.1.0-alpha.5
```

## Browser compatibility

The published ESM verifier has no Node runtime imports and can be bundled for
modern browsers. It requires the platform `structuredClone` API (available in
current evergreen browsers and Node 17+): the verifier uses it only as a final
Proxy rejection screen, while descriptor-based copying remains the signed
input snapshot. Unsupported runtimes fail closed for object inputs rather than
silently accepting an object whose Proxy status cannot be checked.

Accessor properties, custom prototypes, sparse arrays, cycles, shared object
references, symbols, and Proxies are rejected as non-inert JSON. The
descriptor walk rejects normal accessors before `structuredClone`, so their
getter is never used as verification input. A hostile Proxy can run reflective
traps before rejection; JavaScript does not expose a portable zero-trap Proxy
test. Parse untrusted serialized tokens with `JSON.parse` before verification
when the caller needs to avoid executing any behavior supplied by an object.

## Version boundaries

These identifiers describe different layers and are not interchangeable:

| Surface | Supported or published value |
|---|---|
| npm package candidate | `@crinkl/verify@0.1.0-alpha.5` (not published) |
| Native Spend Attestation Token schema | `schemaVersion: 1` and `schemaVersion: 2` |
| Default embedded Spend Token protocol object version | `protocolVersion: "1.0.0-rc.1"` |
| Latest immutable public specification release | `v1.0.0-rc.7` |
| Current public specification source | `1.0.0-rc.8`, release candidate not published |

The public specification documents the `SpendAttestationTokenV2`
holder-binding profile and the adopted V1/V2 geography compatibility rule: new
privacy-preserving issuance omits plaintext `canonical.geoRegion` and
`canonical.cbsaCode`; signed legacy tokens containing those fields remain
verifiable; and `C_geoRegion` and `C_cbsaCode` are independently optional ZK
commitments. When any ZK commitments are present, `C_store`, `C_total`, and
`C_dayIndex` are required.

## Quick start

```ts
import { verifyNativeSpendAttestation, verifySpendHolderControl } from "@crinkl/verify";

const result = await verifyNativeSpendAttestation(token, {
  issuerTrust: ({ issuedBy, publicKeyBase64, protocolVersion }) =>
    issuedBy === "crinkl-authority" &&
    publicKeyBase64 === pinnedKey &&
    protocolVersion === "1.0.0-rc.1"
});

if (!result.cryptographicallyValid || result.issuerAuthorized !== true || result.errors.length > 0) {
  throw new Error(result.errors.map((error) => error.code).join(", "));
}

// This proves an authorized historical issuance snapshot only. Do not treat
// it as accepted for a current reward, claim, or eligibility decision without
// separately obtaining and applying your currentness policy/evidence.

const holderControl = await verifySpendHolderControl(token, challenge, proof, {
  issuerTrust: ({ issuedBy, publicKeyBase64 }) => localIssuerTrust(issuedBy, publicKeyBase64),
  expectedContext: {
    spendTokenHash: challenge.spendTokenHash,
    scopeId: expectedScopeId,
    requestContextHash: expectedRequestContextHash,
    purpose: "TOKEN_PRESENTATION",
    verifierId: "your-verifier-id"
  },
  now: "2026-07-28T00:02:00.000Z",
  authenticateChallenge: (issuedChallenge) => localChallengeStore.authenticates(issuedChallenge),
  // Atomically consume the outstanding (verifierId, nonceBase64) entry.
  consumeChallenge: (issuedChallenge) => localChallengeStore.consumeOnce(issuedChallenge)
});
```

`cryptographicallyValid`, `issuerAuthorized`, `current`, and `accepted` are
separate values. Native V1 and V2 are issuance snapshots, so offline verification
reports currentness as `"unknown"` and does not mark the artifact accepted for
current reliance. The calling application supplies currentness/acceptance
policy and issuer trust; this package does not fetch keys, DIDs, contexts,
status lists, or refresh endpoints.

Native V1 and V2 default to the released `protocolVersion` `1.0.0-rc.1`. Supply
`supportedProtocolVersions` only when the calling application deliberately
pins a different explicit set.

This verifier validates the token's canonical encoding, hash, signature,
declared schema, and caller-supplied issuer authorization and policy evidence.
It does not rerun the issuer's private receipt-ingestion or receipt-verification
process, and it does not independently prove that the physical purchase
occurred.

## Reward-commitment and anchored-spend tiers

`verifyRewardCommitmentV1` checks a `RewardCommitmentTokenV1` (TOKENS.md's
"Reward Commitment Token") against its bundled system-stream segment: envelope
integrity + `prevHash` chaining, Authority Registry replay (rotations and
revocations, bootstrapped only through a caller-supplied `authorityTrust`
resolver — this package never invents a root of trust), Merkle inclusion
against `batch.root`, and — for `economicTier: "COMMITTED_BACKED"` — a valid
`REWARD_BATCH_BACKING_ATTESTED` event for the same batch. On-chain anchoring
of `batch.txRef`/`batch.root` (step 5 of the verification procedure) is
controlled by `options.chainEvidence` and is always additive to, never a
substitute for, the signed system-stream check:

- `{ mode: "none" }` (default) — skip anchoring; `anchor: "not-checked"`.
- `{ mode: "provided", tx }` — verify offline against a caller-already-decoded
  logical commitment record. This checks consistency with the token; it does
  not independently authenticate where the caller obtained that record.
- `{ mode: "rpc", url }` — caller-directed logical-record lookup; fetches the
  supplied `url` and applies the same
  logical-record consistency check as `"provided"`. This package convenience
  endpoint is not Solana JSON-RPC.
- `{ mode: "solana-rpc", binding, rpcUrl }` — fetch raw
  `getTransaction`, `getSignatureStatuses`, and `getBlock` JSON-RPC responses.
  The decoder requires the exact cluster, program, slot, transaction position,
  instruction position, 8-byte discriminator, batch ID mapping, root,
  `leafCount`, schema family, successful execution, and finalized status.

Raw Solana mode requires the caller to authorize all trust-bearing inputs before
the package performs network access:

```js
const result = await verifyRewardCommitmentV1(rewardCommitmentToken, {
  authorityTrust: ({ chainId, authorityId, publicKeyBase64 }) =>
    localAuthorityRegistry.allows(chainId, authorityId, publicKeyBase64),
  chainEvidence: {
    mode: "solana-rpc",
    binding: "crinkl-platform-solana-create-batch-imprint/v1",
    rpcUrl: "https://api.devnet.solana.com",
  },
  solanaEvidenceTrust: ({
    binding,
    sourceCommit,
    cluster,
    rpcUrl,
    programId,
    instructionDiscriminatorHex,
    requiredFinality
  }) =>
    binding === "crinkl-platform-solana-create-batch-imprint/v1" &&
    sourceCommit === "ae3fca9fc1d501591f2c2f377bfdea1f35fa6389" &&
    cluster === "devnet" &&
    rpcUrl === "https://api.devnet.solana.com" &&
    programId === configuredCommitmentProgramId &&
    instructionDiscriminatorHex === "f5f3194de5a7ac64" &&
    requiredFinality === "finalized"
});
```

`issuerTrust`, `rewardCommitment.authorityTrust`, and
`rewardCommitment.solanaEvidenceTrust` belong to the calling application. The
package supplies no trusted issuer, Authority Registry root, Solana cluster,
RPC endpoint, program ID, or instruction discriminator.

Raw Solana decoding is application-specific. The supported binding and its
implementation-source pins, complete instruction/account ABI, limitations, and
captured real devnet fixture are documented in
[`docs/platform-solana-create-batch-imprint-v1.md`](docs/platform-solana-create-batch-imprint-v1.md).
It does not redefine Protocol C1.3 or make this Platform ABI universal.

`verifySpendWithRewardCommitment` composes native spend verification with (1)
and, when the batch leaf schema is linkable (`2a`/`2b`), the optional
spend↔reward linkage proof. The result is a tier:

| Tier | Means |
|---|---|
| `crypto-valid` | The issuer signed this exact canonical claim (native V1 result alone). |
| `committed` | ...and the issuer attached a batch-level reward liability, anchored in a signed, authority-verified commitment. |
| `committed-backed` | ...and the issuer additionally attested that liability as economically backed. |

A missing reward-commitment token is not an error for the spend token — the
result just stays at `crypto-valid`.

For a linkable `2a` or `2b` batch, the composite may report `committed` or
`committed-backed` only after an exact `rewardInclusionProof` verifies: its
Merkle path, recipient, batch, aggregate `rewardEventsRoot`, and `spendId`
must all bind to the already verified Spend Token metadata. An absent linkage
proof is `not-checked` and leaves the composite at `crypto-valid`. A supplied
malformed or mismatching proof fails closed for the composite economic tier
(with `linkage: "mismatch"`), while preserving the separately reported
Reward Commitment verification result. Non-linkable `1a`/`1b` batches retain
`linkage: "not-applicable"` and their independent committed-tier behavior.

**This package proves that an issuer signed the canonical claim and, for
`committed`/`committed-backed`, that the issuer attached and anchored an
economic (reward) liability to it. It does not prove the underlying purchase
occurred.**

### Checkpoint-backed Reward Commitment V2

`verifyRewardCommitmentV2` verifies a bounded System Stream suffix from a
caller-authorized `AuthorityCheckpointV1`; it does not fetch or replay the
full history. The suffix accepts the authority, commitment, backing,
`REWARD_BATCH_CORRECTION`, and `CUMULATIVE_SNAPSHOT_COMMITTED` event shapes
defined by the configured checkpoint profile. Corrections and snapshots are
authenticated continuity evidence only: they do not replace the token's
terminal commitment/backing evidence or alter its economic tier.

## Scope

- Native V1 and V2: RFC 8785 JCS unsigned-token hashing, Ed25519 verification over
  raw SHA-256 digest bytes, caller-owned issuer authorization, and explicit
  version/schema failures.
- V2 holder control: `holderBinding` is optional and signed. A V2 Spend Token
  without it remains valid, but portable holder control is unavailable.
  `verifySpendHolderControl` checks the exact caller-owned request context,
  authenticated fresh challenge, committed holder key, and Ed25519 signature
  over the raw challenge digest. It has no network or challenge store; its
  required `consumeChallenge` callback must durably atomically consume the
  outstanding challenge before it resolves `true`.
- W3C VC: experimental API scaffold only; returns
  `UNSUPPORTED_PROFILE_VERSION` without network I/O.

Native V1 fixtures are pinned to
`crinkl-protocol@d81a68a47170a3fd23712504dece25e38f18b1d8`. The reward-batch
Merkle-primitive fixtures reused from released conformance vectors are pinned
to `crinkl-protocol@5eb7c6360333adb430ead7f2f105f0494cd096c3` (`fixtures/provenance.json`
tracks a `commit` per artifact/binding so both can coexist). Run
`CRINKL_PROTOCOL_DIR=/path/to/crinkl-protocol npm run fixtures:check` to compare
provenance against those exact commits.

`fixtures/reward-commitment-v1.json` is a verifier-generated test suite rather
than the adopted C1.2 two-token fixture. It is deterministically self-signed
by `scripts/generate-reward-commitment-fixtures.mjs` with clearly-fake test
keys, independent of `src/*.ts`, so the test suite exercises real
verification logic against data generated by different code.

## Local checks

```bash
npm run lint
npm run typecheck
npm test
npm run test:conformance
npm run fixtures:check
npm run solana-binding:check
npm run pack:dry-run
```

Publishing this package does not create an endpoint or production runtime
dependency. Applications choose when to adopt a published version.
