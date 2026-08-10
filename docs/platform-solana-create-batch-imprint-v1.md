# Crinkl Platform Solana `create_batch_imprint` binding V1

This document defines the application binding decoded by
`@crinkl/verify`. It is not a Crinkl Protocol token schema, wire-protocol
version, or claim that Protocol C1.3 adopted a universal Solana ABI.

## Source identity

The binding is pinned to these implementation objects:

| Source | Commit | Path | Git blob |
|---|---|---|---|
| `crinkl-platform` | `ae3fca9fc1d501591f2c2f377bfdea1f35fa6389` | `packages/commitment/src/solanaClient.ts` | `549bff752417401ee34eb1782d99f802a0866327` |
| `crinkl-platform` | `ae3fca9fc1d501591f2c2f377bfdea1f35fa6389` | `services/commitment-publisher/src/adapters/infra/nats/worker.ts` | `a99b6478db804654ab65563a6ed371f2f770c91f` |
| `crinkl-onchain-processor` | `7d8ef217b1448cdb86836f20487a643600dbd631` | `programs/onchain-processor/idl.json` | `5541eb650236cbed7854d34fdcc1c6962a81fc5c` |
| `crinkl-onchain-processor` | `7d8ef217b1448cdb86836f20487a643600dbd631` | `programs/onchain-processor/src/lib.rs` | `e7ebebe97a7afaf8df23de3343722fc247d3e832` |

The runtime program ID is not fixed by this document. Platform obtains it from
`COMMITMENT_SOLANA_PROGRAM_ID`, emits it in `txRef`, and the verifier requires
the calling application to authorize it through `solanaEvidenceTrust`.

## Transaction reference

```text
solana:<cluster>:<programId>:<slot>:<transactionIndex>:<instructionIndex>:<signature>
```

All positions are unsigned safe integers. A zero slot is not independently
verifiable and fails closed. The signature and program ID use canonical base58
encodings of 64 and 32 bytes respectively.

## Outer instruction

The selected outer compiled instruction resolves `programIdIndex` through the
static message keys followed by loaded writable and loaded readonly addresses.
It has exactly four ordered accounts:

1. writable BatchImprint PDA: seeds `"crinkl"`, `"batch"`, and batch-prefix
   `u64` encoded little-endian;
2. writable signing authority, equal to the transaction's first signer;
3. readonly AuthorityConfig PDA: seeds `"crinkl"`, `"authority"`;
4. Solana System Program `11111111111111111111111111111111`.

The instruction data is exactly 61 bytes:

| Offset | Length | Meaning |
|---:|---:|---|
| 0 | 8 | caller-authorized discriminator (`f5f3194de5a7ac64` for the pinned source) |
| 8 | 8 | first 64 bits of Platform's UUID batch ID, interpreted as big-endian hex and serialized as `u64` little-endian |
| 16 | 32 | reward batch Merkle root |
| 48 | 4 | `leafCount` as `u32` little-endian |
| 52 | 8 | instruction creation time as signed Unix seconds, little-endian |
| 60 | 1 | reward batch schema family (`1` for `1a`/`1b`, `2` for `2a`/`2b`) |

The on-chain batch prefix is not a lossless encoding of the complete Protocol
`batchId`. The verifier's anchor claim is therefore the exact signed batch
root, leaf count, schema family, transaction location, and finalized execution;
it does not claim that Solana independently stores the full opaque Protocol
batch identifier.

## Finality and position

The verifier requires all of the following from the caller-authorized endpoint:

- `getTransaction(signature, { encoding: "json", commitment: "finalized" })`
  returns a successful transaction at the `txRef` slot;
- `getSignatureStatuses` reports the same slot with `confirmationStatus:
  "finalized"` and no error;
- `getBlock(slot, { transactionDetails: "signatures", commitment:
  "finalized" })` contains the signature at the exact `transactionIndex`; and
- the decoded outer instruction at `instructionIndex` matches the complete
  account and data ABI above.

## Captured fixture

`fixtures/solana-platform-create-batch-imprint-v1.json` contains faithful raw
JSON-RPC responses captured from `https://api.devnet.solana.com` for finalized
transaction
`iALu1WYEPgVA5HHLqxxBsKf4rTGB8YveiAopFMFv4WkvBSWEQ8mCzpPyN3aMfB7S6aPN4KZ7QvDEFhFA19szcjQ`
at slot `480354025`. The fixture records the RPC method outputs without treating
the public endpoint as package-supplied trust; runtime callers still authorize
their own endpoint, cluster, program, discriminator, and binding identity.
