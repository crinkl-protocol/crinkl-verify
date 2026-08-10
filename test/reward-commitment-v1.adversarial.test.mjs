import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as ed25519 from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalize } from "json-canonicalize";
import { verifyRewardCommitmentV1, verifySpendWithRewardCommitment } from "../dist/index.js";

if (!ed25519.etc.sha512Sync) {
  ed25519.etc.sha512Sync = (...messages) => sha512(ed25519.etc.concatBytes(...messages));
}

const enc = new TextEncoder();
const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const sha256Hex = (bytes) => hex(sha256(bytes));
const clone = (value) => JSON.parse(JSON.stringify(value));
const seed = (label) => sha256(enc.encode(`crinkl-verify-test-seed:${label}`));
// This is the same genesis keypair the fixture generator used for every
// case (registered under a different authorityId string per case); see
// scripts/generate-reward-commitment-fixtures.mjs.
const GENESIS_SEED = seed("reward-commitment-authority-genesis");
const ROTATED_AUTHORITY_SEED = seed("reward-commitment-authority-rotated");
const ROGUE_SEED = seed("some-rogue-unregistered-key");
const SPEND_ISSUER_SEED = seed("reward-commitment-spend-issuer");

async function resign(event, signingSeed, payloadOverride) {
  const base = clone(event);
  const unsigned = {
    eventId: base.eventId,
    eventName: base.eventName,
    chainId: base.chainId,
    signedBy: base.signedBy,
    payload: payloadOverride ?? base.payload,
    timestamp: base.timestamp,
    protocolVersion: base.protocolVersion,
    prevHash: base.prevHash
  };
  const eventHash = sha256Hex(enc.encode(canonicalize(unsigned)));
  const signature = Buffer.from(await ed25519.signAsync(Buffer.from(eventHash, "hex"), signingSeed)).toString("base64");
  return { ...unsigned, eventHash, signature };
}

async function resignSpendWithId(spend, spendId) {
  const unsigned = clone(spend);
  delete unsigned.signatures;
  unsigned.spendId = spendId;
  unsigned.canonical.storeHash = `sha256:${sha256Hex(enc.encode(spendId))}`;
  unsigned.lineage.headEventHash = sha256Hex(enc.encode(`${spendId}-head`));
  const tokenHash = sha256Hex(enc.encode(canonicalize(unsigned)));
  const signature = Buffer.from(await ed25519.signAsync(Buffer.from(tokenHash, "hex"), SPEND_ISSUER_SEED)).toString("base64");
  return { ...unsigned, signatures: { ...spend.signatures, tokenHash, signature } };
}

async function resignAfter(event, signingSeed, prevHash, overrides = {}) {
  const base = { ...clone(event), prevHash, ...(overrides.signedBy ? { signedBy: overrides.signedBy } : {}) };
  return resign(base, signingSeed, overrides.payload);
}

const fixture = JSON.parse(readFileSync(new URL("../fixtures/reward-commitment-v1.json", import.meta.url)));
const case1a = fixture.cases.find((c) => c.id === "rewardCommitment.v1.committed.1a");
const case2a = fixture.cases.find((c) => c.id === "rewardCommitment.v1.committedBacked.2a");
const trust1a = async ({ authorityId, publicKeyBase64 }) => authorityId === case1a.genesisAuthorityId && publicKeyBase64 === case1a.genesisPublicKeyBase64;
const trust2a = async ({ authorityId, publicKeyBase64 }) => authorityId === case2a.genesisAuthorityId && publicKeyBase64 === case2a.genesisPublicKeyBase64;

test("fails closed: tampered batch.root (batch no longer equals commitmentEvent.payload)", async () => {
  const token = clone(case1a.token);
  token.batch = { ...token.batch, root: "1".repeat(64) };
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "COMMITMENT_EVENT_INVALID"));
  assert.ok(result.errors.some((e) => e.code === "MERKLE_PROOF_INVALID"));
});

test("fails closed: tampered batch.root that also re-signs commitmentEvent.payload (isolates the Merkle check)", async () => {
  const token = clone(case1a.token);
  const forgedPayload = { ...token.commitmentEvent.payload, root: "1".repeat(64) };
  // authority-rotated signs commitmentEvent in this fixture; re-sign with that authority's seed
  // so the envelope integrity check passes and only the Merkle proof is broken.
  const resigned = await resign(token.commitmentEvent, ROTATED_AUTHORITY_SEED, forgedPayload);
  token.commitmentEvent = clone(resigned);
  token.batch = clone(forgedPayload);
  token.systemEvents = [...token.systemEvents.slice(0, -1).map(clone), clone(resigned)];
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.commitmentValid, true);
  assert.equal(result.merkleValid, false);
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "MERKLE_PROOF_INVALID"));
});

test("fails closed: wrong leaf (leaf hash no longer matches proof.leafHash)", async () => {
  const token = clone(case1a.token);
  token.leaf = { ...token.leaf, totalPoints: "999999999" };
  token.proof = { ...token.proof, leaf: token.leaf };
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.merkleValid, false);
  assert.equal(result.accepted, false);
});

test("fails closed: broken prevHash chain (dangling prevHash reference)", async () => {
  const token = clone(case1a.token);
  const [genesisEvent, rotateEvent, revokeEvent, commitmentEvent] = token.systemEvents.map(clone);
  revokeEvent.prevHash = "f".repeat(64); // no longer references rotateEvent.eventHash
  token.systemEvents = [genesisEvent, rotateEvent, clone(revokeEvent), clone(commitmentEvent)];
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.systemStreamValid, false);
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "SYSTEM_STREAM_INVALID"));
});

test("fails closed: fork in segment (two events share a prevHash)", async () => {
  const token = clone(case1a.token);
  const events = token.systemEvents.map(clone);
  const forked = clone(events[2]);
  forked.eventId = "sha256:evt-forked-duplicate";
  // forked keeps the same prevHash as events[2], creating a fork.
  token.systemEvents = [...events, forked];
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.systemStreamValid, false);
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "SYSTEM_STREAM_INVALID"));
});

test("fails closed: commitmentEvent not present in systemEvents", async () => {
  const token = clone(case1a.token);
  token.systemEvents = token.systemEvents.slice(0, -1).map(clone);
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.commitmentValid, false);
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "COMMITMENT_EVENT_INVALID"));
});

test("fails closed: authority-invalid signer (correctly formed signature from an unregistered key)", async () => {
  const token = clone(case1a.token);
  const events = token.systemEvents.map(clone);
  const forgedCommitment = await resign(events[3], ROGUE_SEED);
  token.commitmentEvent = clone(forgedCommitment);
  token.systemEvents = [events[0], events[1], events[2], clone(forgedCommitment)];
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.authorityValid, false);
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "AUTHORITY_INVALID"));
});

test("fails closed: economicTier COMMITTED_BACKED without a backingEvent", async () => {
  const token = clone(case2a.token);
  delete token.backingEvent;
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust2a });
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "BACKING_EVENT_INVALID"));
});

test("fails closed: backingEvent.payload.batchId mismatch", async () => {
  const token = clone(case2a.token);
  const forgedBacking = await resign(token.backingEvent, GENESIS_SEED, { ...token.backingEvent.payload, batchId: "some-other-batch-id" });
  token.backingEvent = clone(forgedBacking);
  token.systemEvents = [clone(token.systemEvents[0]), clone(token.systemEvents[1]), clone(forgedBacking)];
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust2a });
  assert.equal(result.backingValid, false);
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "BACKING_EVENT_INVALID"));
});

test("fails closed: tampered rewardInclusionProof linkage (spendId swapped)", async () => {
  const token = clone(case2a.token);
  token.rewardInclusionProof = { ...token.rewardInclusionProof, leaf: { ...token.rewardInclusionProof.leaf, spendId: "not-the-real-spend-id" } };
  const issuerTrust = ({ issuedBy, publicKeyBase64 }) => issuedBy === case2a.spendIssuer.issuedBy && publicKeyBase64 === case2a.spendIssuer.publicKeyBase64;
  const result = await verifySpendWithRewardCommitment(case2a.spendToken, token, { issuerTrust, rewardCommitment: { authorityTrust: trust2a } });
  assert.equal(result.linkage, "mismatch");
  assert.ok(result.errors.some((e) => e.code === "SPEND_REWARD_LINKAGE_MISMATCH"));
});

test("fails closed: tampered rewardInclusionProof leafHash (breaks the Merkle sub-proof, not just field equality)", async () => {
  const token = clone(case2a.token);
  token.rewardInclusionProof = { ...token.rewardInclusionProof, leafHash: "0".repeat(64) };
  const issuerTrust = ({ issuedBy, publicKeyBase64 }) => issuedBy === case2a.spendIssuer.issuedBy && publicKeyBase64 === case2a.spendIssuer.publicKeyBase64;
  const result = await verifySpendWithRewardCommitment(case2a.spendToken, token, { issuerTrust, rewardCommitment: { authorityTrust: trust2a } });
  assert.equal(result.linkage, "mismatch");
});

test("fails closed for composite tiers: a different but valid Spend Token cannot claim a linkable reward proof", async () => {
  const spend = await resignSpendWithId(case2a.spendToken, "spend-2a-different-valid-001");
  const issuerTrust = ({ issuedBy, publicKeyBase64 }) => issuedBy === case2a.spendIssuer.issuedBy && publicKeyBase64 === case2a.spendIssuer.publicKeyBase64;
  const result = await verifySpendWithRewardCommitment(spend, case2a.token, { issuerTrust, rewardCommitment: { authorityTrust: trust2a } });
  assert.equal(result.spend.cryptographicallyValid, true);
  assert.equal(result.rewardCommitment.accepted, true);
  assert.equal(result.linkage, "mismatch");
  assert.equal(result.tier, "crypto-valid");
  assert.ok(result.errors.some((e) => e.code === "SPEND_REWARD_LINKAGE_MISMATCH"));
});

test("fails closed for composite tiers: a supplied malformed linkable proof is mismatch, not a committed tier", async () => {
  const token = clone(case2a.token);
  token.rewardInclusionProof = { malformed: true };
  const issuerTrust = ({ issuedBy, publicKeyBase64 }) => issuedBy === case2a.spendIssuer.issuedBy && publicKeyBase64 === case2a.spendIssuer.publicKeyBase64;
  const result = await verifySpendWithRewardCommitment(case2a.spendToken, token, { issuerTrust, rewardCommitment: { authorityTrust: trust2a } });
  assert.equal(result.spend.cryptographicallyValid, true);
  assert.equal(result.rewardCommitment.accepted, false);
  assert.equal(result.linkage, "mismatch");
  assert.equal(result.tier, "crypto-valid");
  assert.ok(result.errors.some((e) => e.code === "SPEND_REWARD_LINKAGE_MISMATCH"));
});

test("fails closed: unknown batch.schemaVersion", async () => {
  const token = clone(case1a.token);
  token.batch = { ...token.batch, schemaVersion: "9z" };
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "UNKNOWN_SCHEMA_VERSION"));
});

test("fails closed: unknown tokenType", async () => {
  const token = clone(case1a.token);
  token.tokenType = "SOMETHING_ELSE";
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "SCHEMA_INVALID"));
});

test("fails closed: wrong reward-commitment schemaVersion (2 instead of 1)", async () => {
  const token = clone(case1a.token);
  token.schemaVersion = 2;
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: trust1a });
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((e) => e.code === "SCHEMA_INVALID"));
});

test("fails closed: conflicting duplicate history events are never deduplicated", async () => {
  const token = clone(case1a.token);
  const history = token.systemEvents.slice(0, -1).map(clone);
  token.systemEvents = [clone(token.commitmentEvent)];
  const conflicting = clone(history[0]);
  conflicting.payload = { ...conflicting.payload, publicKey: case1a.genesisPublicKeyBase64.replace(/.$/, "A") };
  const result = await verifyRewardCommitmentV1(token, {
    authorityTrust: trust1a,
    systemStreamHistory: [...history, conflicting]
  });
  assert.equal(result.systemStreamValid, false);
  assert.equal(result.authorityValid, false);
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((error) => error.code === "SYSTEM_STREAM_INVALID"));
});

test("fails closed: malformed, wrong-chain, gapped, and conflicting provider history", async () => {
  const token = clone(case1a.token);
  const fullHistory = token.systemEvents.slice(0, -1).map(clone);
  token.systemEvents = [clone(token.commitmentEvent)];
  const providers = [
    async () => ({ success: true, data: { malformed: true } }),
    async ({ chainId, headHash }) => ({ success: true, data: {
      chainId,
      requestedHeadHash: headHash,
      events: [{ ...clone(fullHistory.at(-1)), chainId: "wrong-chain" }],
      nextHeadHash: fullHistory.at(-1).prevHash,
      hasMore: true
    } }),
    async ({ chainId, headHash }) => ({ success: true, data: {
      chainId,
      requestedHeadHash: headHash,
      events: [clone(fullHistory.at(-1)), clone(fullHistory[0])],
      nextHeadHash: null,
      hasMore: false
    } }),
    async () => ({ success: false, error: "system_stream_history_conflict" })
  ];
  for (const systemStreamHistoryResolver of providers) {
    const result = await verifyRewardCommitmentV1(token, {
      authorityTrust: trust1a,
      systemStreamHistoryResolver
    });
    assert.equal(result.accepted, false);
    assert.equal(result.authorityValid, false);
    assert.ok(result.errors.some((error) => error.code === "SYSTEM_STREAM_INVALID"));
  }
});

test("fails closed: invalid history bounds never clamp or default", async () => {
  const token = clone(case1a.token);
  token.systemEvents = [clone(token.commitmentEvent)];
  for (const bounds of [
    { maxHistoryEvents: 0 },
    { maxHistoryEvents: 1_000_001 },
    { maxHistoryEvents: 1.5 },
    { timeoutMs: 0 },
    { timeoutMs: 120_001 }
  ]) {
    const result = await verifyRewardCommitmentV1(token, {
      authorityTrust: trust1a,
      systemStreamHistory: [],
      ...bounds
    });
    assert.equal(result.systemStreamValid, false);
    assert.equal(result.authorityValid, false);
    assert.equal(result.accepted, false);
  }
});

test("fails closed: recovered history rejects every invalid authority lifecycle and signature condition", async (t) => {
  async function verifyRecovered(events) {
    const token = clone(case1a.token);
    token.commitmentEvent = clone(events.at(-1));
    token.systemEvents = [clone(events.at(-1))];
    return verifyRewardCommitmentV1(token, {
      authorityTrust: trust1a,
      systemStreamHistory: events.slice(0, -1).map(clone)
    });
  }

  async function expectRejected(events, expectedCode) {
    const result = await verifyRecovered(events);
    assert.equal(result.systemStreamValid, false);
    assert.equal(result.authorityValid, false);
    assert.equal(result.accepted, false);
    assert.ok(result.errors.some((error) => error.code === expectedCode));
  }

  const [genesis, originalRotation, originalRevocation, originalCommitment] = case1a.token.systemEvents.map(clone);

  await t.test("malformed registration", async () => {
    const { publicKey: _publicKey, ...malformedPayload } = originalRotation.payload;
    const rotation = await resignAfter(originalRotation, GENESIS_SEED, genesis.eventHash, { payload: malformedPayload });
    const revocation = await resignAfter(originalRevocation, ROTATED_AUTHORITY_SEED, rotation.eventHash);
    const commitment = await resignAfter(originalCommitment, ROTATED_AUTHORITY_SEED, revocation.eventHash);
    await expectRejected([genesis, rotation, revocation, commitment], "SYSTEM_STREAM_INVALID");
  });

  await t.test("malformed revocation", async () => {
    const rotation = clone(originalRotation);
    const revocation = await resignAfter(originalRevocation, ROTATED_AUTHORITY_SEED, rotation.eventHash, {
      payload: { ...originalRevocation.payload, revokedBy: "authority-genesis" }
    });
    const commitment = await resignAfter(originalCommitment, ROTATED_AUTHORITY_SEED, revocation.eventHash);
    await expectRejected([genesis, rotation, revocation, commitment], "SYSTEM_STREAM_INVALID");
  });

  await t.test("invalid intermediate signature", async () => {
    const replacement = originalRotation.signature.startsWith("A") ? "B" : "A";
    const rotation = { ...clone(originalRotation), signature: replacement + originalRotation.signature.slice(1) };
    await expectRejected([genesis, rotation, clone(originalRevocation), clone(originalCommitment)], "AUTHORITY_INVALID");
  });

  await t.test("skipped or unknown authority", async () => {
    const rotation = await resignAfter(originalRotation, ROGUE_SEED, genesis.eventHash, { signedBy: "authority-unknown" });
    const revocation = await resignAfter(originalRevocation, ROTATED_AUTHORITY_SEED, rotation.eventHash);
    const commitment = await resignAfter(originalCommitment, ROTATED_AUTHORITY_SEED, revocation.eventHash);
    await expectRejected([genesis, rotation, revocation, commitment], "AUTHORITY_INVALID");
  });

  await t.test("revoked signer", async () => {
    const rotation = clone(originalRotation);
    const revocation = await resignAfter(originalRevocation, ROTATED_AUTHORITY_SEED, rotation.eventHash, {
      payload: {
        ...originalRevocation.payload,
        authorityId: "authority-rotated",
        validUntil: "2026-01-03T00:00:00.000Z"
      }
    });
    const commitment = await resignAfter(originalCommitment, ROTATED_AUTHORITY_SEED, revocation.eventHash);
    await expectRejected([genesis, rotation, revocation, commitment], "AUTHORITY_INVALID");
  });
});
