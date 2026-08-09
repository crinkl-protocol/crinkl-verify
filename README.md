# `@crinkl/verify`

Verify Crinkl Spend Attestation Tokens and Reward Commitment Tokens locally,
without accounts. Verification is offline by default; only an explicitly
configured reward-chain RPC evidence mode uses the network.

`0.1.0-alpha.1` verifies the released native `SpendAttestationTokenV1` and
`SpendAttestationTokenV2` profiles and the `RewardCommitmentTokenV1` profile
offline, and composes native Spend Token and reward-commitment verification
into tiered spend + reward-commitment verification. W3C VC verification is
intentionally experimental and fails closed until a released Crinkl profile
bundle pins its context, schemas, vectors, issuer-key history, and
status/refresh rules.

## Install

```bash
npm install @crinkl/verify@0.1.0-alpha.1
```

## Version boundaries

These identifiers describe different layers and are not interchangeable:

| Surface | Supported or published value |
|---|---|
| npm package | `@crinkl/verify@0.1.0-alpha.1` |
| Native Spend Attestation Token schema | `schemaVersion: 1` and `schemaVersion: 2` |
| Default embedded Spend Token protocol object version | `protocolVersion: "1.0.0-rc.1"` |
| Latest immutable public specification release | `v1.0.0-rc.4` |
| Current public specification source | `1.0.0-rc.5`, release candidate not published |

The released public `v1.0.0-rc.4` bundle includes the
`SpendAttestationTokenV2` holder-binding profile. Current public specification
source also documents the adopted V1/V2 geography compatibility rule: new
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
  on-chain commitment record. Not raw transaction bytes: the protocol leaves
  chain-specific memo/anchor binding formats undefined outside this
  spec snapshot (`COMMITMENT_LAYER.md#chain-bindings` says such bindings are
  "documented separately"; no such document exists for reward-commitment
  batches here), so this package does not invent one.
- `{ mode: "rpc", url }` — the only path that may touch the network, and only
  because the caller passed a URL; fetches `url` and applies the same
  consistency check as `"provided"`.

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

**This package proves that an issuer signed the canonical claim and, for
`committed`/`committed-backed`, that the issuer attached and anchored an
economic (reward) liability to it. It does not prove the underlying purchase
occurred.**

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

`fixtures/reward-commitment-v1.json` is not a released protocol conformance
vector — no signed end-to-end `RewardCommitmentTokenV1` vector exists in the
protocol repository as of this writing. It is deterministically self-signed
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
npm run pack:dry-run
```

Publishing this package does not create an endpoint or production runtime
dependency. Applications choose when to adopt a published version.
