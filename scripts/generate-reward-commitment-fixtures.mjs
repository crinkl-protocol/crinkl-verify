// Generates test-only fixtures for RewardCommitmentTokenV1 verification.
//
// These are NOT released protocol conformance vectors (no such signed
// end-to-end vector exists for RewardCommitmentTokenV1 in the protocol spec
// snapshot this package was written against — see fixtures/provenance.json
// for what *is* reused from released vectors: the Merkle math primitives).
// They are self-signed with deterministic, clearly-fake test keys derived
// from labels via SHA-256 (never a real protocol key), and are constructed
// independently of src/*.ts so that the test suite exercises the real
// package logic against data this script did not share verification code
// with.
//
// Run: node scripts/generate-reward-commitment-fixtures.mjs
import { writeFileSync } from "node:fs";
import * as ed25519 from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalize } from "json-canonicalize";

if (!ed25519.etc.sha512Sync) {
  ed25519.etc.sha512Sync = (...messages) => sha512(ed25519.etc.concatBytes(...messages));
}

const enc = new TextEncoder();
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const sha256Hex = (bytes) => hex(sha256(bytes));
const canon = (value) => canonicalize(value);
const concat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
};
const seedFromLabel = (label) => sha256(enc.encode(`crinkl-verify-test-seed:${label}`));

function leafHash(obj) {
  return sha256Hex(concat(Uint8Array.of(0x00), enc.encode(canon(obj))));
}
function combine(a, b) {
  const [lo, hi] = a < b ? [a, b] : [b, a];
  return sha256Hex(concat(Uint8Array.of(0x01), hexToBytes(lo), hexToBytes(hi)));
}

async function keypair(label) {
  const seed = seedFromLabel(label);
  const publicKey = await ed25519.getPublicKeyAsync(seed);
  return { seed, publicKeyBase64: b64(publicKey) };
}

async function signEnvelope(fields, seed) {
  const eventHash = sha256Hex(enc.encode(canon(fields)));
  const signature = b64(await ed25519.signAsync(hexToBytes(eventHash), seed));
  return { ...fields, eventHash, signature };
}

async function systemEvent({ eventName, chainId, signedBy, payload, timestamp, protocolVersion = "1.0.0-rc.1", prevHash, seed, idSuffix }) {
  const unsigned = { eventId: `sha256:evt-${idSuffix}`, eventName, chainId, signedBy, payload, timestamp, protocolVersion, prevHash };
  return signEnvelope(unsigned, seed);
}

async function nativeSpendToken(spendId, seed, issuedBy) {
  const unsignedToken = {
    tokenType: "SPEND_ATTESTATION",
    schemaVersion: 1,
    spendId,
    wallet: "wallet-subject-linkable",
    canonical: {
      status: "HARD_VERIFIED",
      storeHash: `sha256:${sha256Hex(enc.encode(spendId))}`,
      timestamp: "2026-01-04T00:00:00.000Z",
      date: "2026-01-04",
      totalCents: "1500",
      currency: "USD",
      verificationVersion: "1.0.0"
    },
    lineage: { headEventHash: sha256Hex(enc.encode(`${spendId}-head`)), eventCount: 3 },
    protocol: { protocolVersion: "1.0.0-rc.1" }
  };
  const tokenHash = sha256Hex(enc.encode(canon(unsignedToken)));
  const publicKey = b64(await ed25519.getPublicKeyAsync(seed));
  const signature = b64(await ed25519.signAsync(hexToBytes(tokenHash), seed));
  return { ...unsignedToken, signatures: { issuedBy, publicKey, tokenHash, signature } };
}

async function main() {
  const chainId = "solana:devnet";
  const genesis = await keypair("reward-commitment-authority-genesis");
  const authority2 = await keypair("reward-commitment-authority-rotated");
  const spendIssuer = await keypair("reward-commitment-spend-issuer");

  // --- Case: committed.1a — transparent recipient, non-linkable, exercises
  // a full authority rotation (register -> rotate -> revoke predecessor)
  // before the commitment event. ---
  const t0 = "2026-01-01T00:00:00.000Z";
  const t1 = "2026-01-02T00:00:00.000Z";
  const t2 = "2026-01-03T00:00:00.000Z";
  const t3 = "2026-01-04T00:00:00.000Z";

  const genesisEvent = await signEnvelope(
    { eventId: "sha256:evt-genesis-1a", eventName: "AUTHORITY_REGISTERED", chainId, signedBy: "authority-genesis", payload: { authorityId: "authority-genesis", publicKey: genesis.publicKeyBase64, validFrom: t0, predecessorId: null, txRef: "solana:devnet:tx-genesis", registeredAt: t0 }, timestamp: t0, protocolVersion: "1.0.0-rc.1", prevHash: null },
    genesis.seed
  );
  const rotateEvent = await systemEvent({ eventName: "AUTHORITY_REGISTERED", chainId, signedBy: "authority-genesis", payload: { authorityId: "authority-rotated", publicKey: authority2.publicKeyBase64, validFrom: t1, predecessorId: "authority-genesis", txRef: "solana:devnet:tx-rotate", registeredAt: t1 }, timestamp: t1, prevHash: genesisEvent.eventHash, seed: genesis.seed, idSuffix: "rotate-1a" });
  const revokeEvent = await systemEvent({ eventName: "AUTHORITY_REVOKED", chainId, signedBy: "authority-rotated", payload: { authorityId: "authority-genesis", validUntil: t2, revokedBy: "authority-rotated", reason: "scheduled rotation", txRef: "solana:devnet:tx-revoke", revokedAt: t2 }, timestamp: t2, prevHash: rotateEvent.eventHash, seed: authority2.seed, idSuffix: "revoke-1a" });

  const batchId1a = "batch-1a-committed";
  const leafSubject1a = { batchId: batchId1a, recipientId: "wallet-subject-1a", totalPoints: "500" };
  const leafOther1a = { batchId: batchId1a, recipientId: "wallet-other-1a", totalPoints: "300" };
  const hashSubject1a = leafHash(leafSubject1a);
  const hashOther1a = leafHash(leafOther1a);
  const root1a = combine(hashSubject1a, hashOther1a);
  const batchPayload1a = { batchId: batchId1a, root: root1a, leafCount: 2, totalPoints: "800", schemaVersion: "1a", txRef: "solana:devnet:tx-batch-1a", committedAt: t3 };
  const commitmentEvent1a = await systemEvent({ eventName: "REWARD_BATCH_COMMITTED", chainId, signedBy: "authority-rotated", payload: batchPayload1a, timestamp: t3, prevHash: revokeEvent.eventHash, seed: authority2.seed, idSuffix: "commit-1a" });

  const case1a = {
    id: "rewardCommitment.v1.committed.1a",
    token: {
      tokenType: "REWARD_COMMITMENT",
      schemaVersion: 1,
      chainId,
      economicTier: "COMMITTED",
      commitmentEvent: commitmentEvent1a,
      systemEvents: [genesisEvent, rotateEvent, revokeEvent, commitmentEvent1a],
      batch: batchPayload1a,
      recipientId: "wallet-subject-1a",
      leaf: leafSubject1a,
      proof: { batchId: batchId1a, leaf: leafSubject1a, leafHash: hashSubject1a, siblings: [hashOther1a] }
    },
    genesisAuthorityId: "authority-genesis",
    genesisPublicKeyBase64: genesis.publicKeyBase64,
    genesisValidFrom: t0
  };

  // --- Case: committed.1b — blinded recipient, single (non-rotated) authority. ---
  const batchId1b = "batch-1b-committed";
  const blinderBytes1b = sha256(enc.encode("crinkl-verify-test-blinder:1b"));
  const wallet1b = "wallet-subject-1b";
  const recipientId1b = sha256Hex(concat(enc.encode("crinkl.recipient.v1:"), enc.encode(wallet1b), enc.encode(":"), enc.encode(batchId1b), enc.encode(":"), blinderBytes1b));
  const otherRecipientId1b = sha256Hex(enc.encode("wallet-other-1b-commitment"));
  const leafSubject1b = { batchId: batchId1b, recipientId: recipientId1b, totalPoints: "220" };
  const leafOther1b = { batchId: batchId1b, recipientId: otherRecipientId1b, totalPoints: "110" };
  const hashSubject1b = leafHash(leafSubject1b);
  const hashOther1b = leafHash(leafOther1b);
  const root1b = combine(hashSubject1b, hashOther1b);
  const batchPayload1b = { batchId: batchId1b, root: root1b, leafCount: 2, totalPoints: "330", schemaVersion: "1b", txRef: "solana:devnet:tx-batch-1b", committedAt: t0 };
  const genesisEvent1b = await signEnvelope(
    { eventId: "sha256:evt-genesis-1b", eventName: "AUTHORITY_REGISTERED", chainId, signedBy: "authority-genesis-1b", payload: { authorityId: "authority-genesis-1b", publicKey: genesis.publicKeyBase64, validFrom: t0, predecessorId: null, txRef: "solana:devnet:tx-genesis-1b", registeredAt: t0 }, timestamp: t0, protocolVersion: "1.0.0-rc.1", prevHash: null },
    genesis.seed
  );
  const commitmentEvent1b = await systemEvent({ eventName: "REWARD_BATCH_COMMITTED", chainId, signedBy: "authority-genesis-1b", payload: batchPayload1b, timestamp: t0, prevHash: genesisEvent1b.eventHash, seed: genesis.seed, idSuffix: "commit-1b" });
  const case1b = {
    id: "rewardCommitment.v1.committed.1b",
    token: {
      tokenType: "REWARD_COMMITMENT",
      schemaVersion: 1,
      chainId,
      economicTier: "COMMITTED",
      commitmentEvent: commitmentEvent1b,
      systemEvents: [genesisEvent1b, commitmentEvent1b],
      batch: batchPayload1b,
      recipientId: recipientId1b,
      leaf: leafSubject1b,
      proof: { batchId: batchId1b, leaf: leafSubject1b, leafHash: hashSubject1b, siblings: [hashOther1b] }
    },
    genesisAuthorityId: "authority-genesis-1b",
    genesisPublicKeyBase64: genesis.publicKeyBase64,
    genesisValidFrom: t0,
    wallet: wallet1b,
    blinderHex: hex(blinderBytes1b)
  };

  // --- Case: committed-backed.2a — transparent + linkable + backed. ---
  const batchId2a = "batch-2a-committed-backed";
  const spendId2a = "spend-2a-linked-001";
  const otherSpendId2a = "spend-2a-linked-002";
  const rewardEventHash2a = sha256Hex(enc.encode(`${spendId2a}-reward-event`));
  const otherRewardEventHash2a = sha256Hex(enc.encode(`${otherSpendId2a}-reward-event`));
  const rewardLeaf2a = { spendId: spendId2a, rewardEventHash: rewardEventHash2a };
  const otherRewardLeaf2a = { spendId: otherSpendId2a, rewardEventHash: otherRewardEventHash2a };
  const rewardLeafHash2a = leafHash(rewardLeaf2a);
  const otherRewardLeafHash2a = leafHash(otherRewardLeaf2a);
  // RewardIssuanceLeaf entries are sorted by spendId (lexicographic).
  const [firstHash2a, secondHash2a] = spendId2a < otherSpendId2a ? [rewardLeafHash2a, otherRewardLeafHash2a] : [otherRewardLeafHash2a, rewardLeafHash2a];
  const rewardEventsRoot2a = combine(firstHash2a, secondHash2a);

  const leafSubject2a = { batchId: batchId2a, recipientId: "wallet-subject-2a", totalPoints: "150", rewardEventsRoot: rewardEventsRoot2a };
  const leafOther2a = { batchId: batchId2a, recipientId: "wallet-other-2a", totalPoints: "90", rewardEventsRoot: sha256Hex(enc.encode("unrelated-root-2a")) };
  const hashSubject2a = leafHash(leafSubject2a);
  const hashOther2a = leafHash(leafOther2a);
  const root2a = combine(hashSubject2a, hashOther2a);
  const batchPayload2a = { batchId: batchId2a, root: root2a, leafCount: 2, totalPoints: "240", schemaVersion: "2a", txRef: "solana:devnet:tx-batch-2a", committedAt: t0 };
  const genesisEvent2a = await signEnvelope(
    { eventId: "sha256:evt-genesis-2a", eventName: "AUTHORITY_REGISTERED", chainId, signedBy: "authority-genesis-2a", payload: { authorityId: "authority-genesis-2a", publicKey: genesis.publicKeyBase64, validFrom: t0, predecessorId: null, txRef: "solana:devnet:tx-genesis-2a", registeredAt: t0 }, timestamp: t0, protocolVersion: "1.0.0-rc.1", prevHash: null },
    genesis.seed
  );
  const commitmentEvent2a = await systemEvent({ eventName: "REWARD_BATCH_COMMITTED", chainId, signedBy: "authority-genesis-2a", payload: batchPayload2a, timestamp: t0, prevHash: genesisEvent2a.eventHash, seed: genesis.seed, idSuffix: "commit-2a" });
  const backingPayload2a = { batchId: batchId2a, backingAsset: { chainId: "solana:mainnet-beta", mint: "cbBTC-mint-2a", decimals: 8 }, backingAmount: "24000", backingVault: "vault-2a", backingTxRef: "solana:mainnet-beta:tx-backing-2a", backedAt: t1 };
  const backingEvent2a = await systemEvent({ eventName: "REWARD_BATCH_BACKING_ATTESTED", chainId, signedBy: "authority-genesis-2a", payload: backingPayload2a, timestamp: t1, prevHash: commitmentEvent2a.eventHash, seed: genesis.seed, idSuffix: "backing-2a" });

  const spendToken2a = await nativeSpendToken(spendId2a, spendIssuer.seed, "crinkl-authority-reward-linked");

  const case2a = {
    id: "rewardCommitment.v1.committedBacked.2a",
    token: {
      tokenType: "REWARD_COMMITMENT",
      schemaVersion: 1,
      chainId,
      economicTier: "COMMITTED_BACKED",
      commitmentEvent: commitmentEvent2a,
      backingEvent: backingEvent2a,
      systemEvents: [genesisEvent2a, commitmentEvent2a, backingEvent2a],
      batch: batchPayload2a,
      recipientId: "wallet-subject-2a",
      leaf: leafSubject2a,
      proof: { batchId: batchId2a, leaf: leafSubject2a, leafHash: hashSubject2a, siblings: [hashOther2a] },
      rewardInclusionProof: {
        batchId: batchId2a,
        recipientId: "wallet-subject-2a",
        rewardEventsRoot: rewardEventsRoot2a,
        leaf: rewardLeaf2a,
        leafHash: rewardLeafHash2a,
        siblings: [otherRewardLeafHash2a]
      }
    },
    spendToken: spendToken2a,
    genesisAuthorityId: "authority-genesis-2a",
    genesisPublicKeyBase64: genesis.publicKeyBase64,
    genesisValidFrom: t0,
    spendIssuer: { publicKeyBase64: spendIssuer.publicKeyBase64, issuedBy: "crinkl-authority-reward-linked" }
  };

  const output = {
    generatedBy: "scripts/generate-reward-commitment-fixtures.mjs",
    note: "Self-signed, deterministic test-only fixtures; not released protocol conformance vectors. See fixtures/provenance.json for the released Merkle vectors this package's Merkle primitive is separately checked against.",
    cases: [case1a, case1b, case2a],
    rogueAuthority: {
      note: "An Ed25519 key never registered in any fixture's Authority Registry; adversarial tests use it to sign events that must be rejected as AUTHORITY_INVALID.",
      seedLabel: "reward-commitment-authority-rogue"
    }
  };

  writeFileSync(new URL("../fixtures/reward-commitment-v1.json", import.meta.url), `${JSON.stringify(output, null, 2)}\n`);
  console.log("Wrote fixtures/reward-commitment-v1.json");
}

main();
