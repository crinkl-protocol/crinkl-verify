# `@crinkl/verify`

Private, unpublished TypeScript verifier for Crinkl portable spend artifacts.

`0.1.0-alpha.1` verifies the released native `SpendAttestationTokenV1` profile
offline. W3C VC verification is intentionally experimental and fails closed
until a released Crinkl profile bundle pins its context, schemas, vectors,
issuer-key history, and status/refresh rules.

## Quick start

```ts
import { verifyNativeSpendAttestation } from "@crinkl/verify";

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
```

`cryptographicallyValid`, `issuerAuthorized`, `current`, and `accepted` are
separate values. Native V1 is an issuance snapshot, so offline verification
reports currentness as `"unknown"` and does not mark the artifact accepted for
current reliance. The calling application supplies currentness/acceptance
policy and issuer trust; this package does not fetch keys, DIDs, contexts,
status lists, or refresh endpoints.

Native V1 defaults to the released `protocolVersion` `1.0.0-rc.1`. Supply
`supportedProtocolVersions` only when the calling application deliberately
pins a different explicit set.

## Scope

- Native V1: RFC 8785 JCS unsigned-token hashing, Ed25519 verification over
  raw SHA-256 digest bytes, caller-owned issuer authorization, and explicit
  version/schema failures.
- W3C VC: experimental API scaffold only; returns
  `UNSUPPORTED_PROFILE_VERSION` without network I/O.
- Native schema V2/holder binding: deliberately unsupported until its adopted
  protocol profile is separately pinned.

Fixtures are pinned to `crinkl-protocol@d81a68a47170a3fd23712504dece25e38f18b1d8`.
Run `CRINKL_PROTOCOL_DIR=/path/to/crinkl-protocol pnpm fixtures:check` to
compare their provenance against that exact commit.

## Local checks

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm test:conformance
pnpm fixtures:check
pnpm pack:dry-run
```

No npm publication, endpoint, production dependency, or runtime behavior is
part of this repository state.
