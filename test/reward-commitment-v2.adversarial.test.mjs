import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as ed25519 from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalize } from "json-canonicalize";
import {
  computeAuthorityCheckpointRegistryStateHash,
  computeAuthorityCheckpointV1Hash,
  verifyRewardCommitmentV2
} from "../dist/index.js";

if (!ed25519.etc.sha512Sync) ed25519.etc.sha512Sync = (...messages) => sha512(ed25519.etc.concatBytes(...messages));

const encoder = new TextEncoder();
const clone = (value) => JSON.parse(JSON.stringify(value));
const seed = (label) => sha256(encoder.encode(`crinkl-verify-test-seed:${label}`));
const ROOT_SEED = seed("authority-checkpoint-root");
const GENESIS_AUTHORITY_SEED = seed("reward-commitment-authority-genesis");
const fixture = JSON.parse(readFileSync(new URL("../fixtures/reward-commitment-v1.json", import.meta.url)));
const case2a = fixture.cases.find((candidate) => candidate.id === "rewardCommitment.v1.committedBacked.2a");

async function rootPublicKey() {
  return Buffer.from(await ed25519.getPublicKeyAsync(ROOT_SEED)).toString("base64");
}

async function signCheckpoint(checkpoint) {
  checkpoint.authorityState.stateHash = computeAuthorityCheckpointRegistryStateHash(checkpoint.chainId, checkpoint.covered.headEventHash, checkpoint.authorityState.records);
  checkpoint.signatures.checkpointHash = computeAuthorityCheckpointV1Hash(checkpoint);
  checkpoint.signatures.signature = Buffer.from(await ed25519.signAsync(Buffer.from(checkpoint.signatures.checkpointHash, "hex"), ROOT_SEED)).toString("base64");
  return checkpoint;
}

async function signSystemEvent(event, signingSeed) {
  const unsigned = {
    eventId: event.eventId,
    eventName: event.eventName,
    chainId: event.chainId,
    signedBy: event.signedBy,
    payload: event.payload,
    timestamp: event.timestamp,
    protocolVersion: event.protocolVersion,
    prevHash: event.prevHash
  };
  const eventHash = Array.from(sha256(encoder.encode(canonicalize(unsigned))), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const signature = Buffer.from(await ed25519.signAsync(Buffer.from(eventHash, "hex"), signingSeed)).toString("base64");
  return { ...unsigned, eventHash, signature };
}

async function goodToken() {
  const [genesis, ...suffix] = clone(case2a.token.systemEvents);
  const records = [{ authorityId: genesis.payload.authorityId, publicKey: genesis.payload.publicKey, validFrom: genesis.payload.validFrom, validUntil: null, revokedBy: null }];
  const checkpoint = await signCheckpoint({
    checkpointType: "AUTHORITY_CHECKPOINT",
    schemaVersion: 1,
    protocol: { protocolVersion: "1.0.0-rc.1" },
    evidenceProfile: "configured-checkpoint-root/v1",
    chainId: case2a.token.chainId,
    sequence: 3,
    covered: { streamHeight: 1, headEventHash: genesis.eventHash, effectiveAt: genesis.timestamp },
    authorityState: { stateHash: "0".repeat(64), records },
    previousCheckpointHash: "1".repeat(64),
    limits: { maxSuffixEvents: 128 },
    signatures: { issuedBy: "crinkl-checkpoint-root", keyId: "checkpoint-root-test-v1", publicKey: await rootPublicKey(), checkpointHash: "0".repeat(64), signature: "pending" }
  });
  return {
    tokenType: "REWARD_COMMITMENT", schemaVersion: 2, evidenceProfile: "configured-checkpoint-root/v1", chainId: case2a.token.chainId,
    economicTier: "COMMITTED_BACKED", commitmentEvent: clone(case2a.token.commitmentEvent), backingEvent: clone(case2a.token.backingEvent), authorityCheckpoint: checkpoint,
    systemEventSuffix: suffix, batch: clone(case2a.token.batch), recipientId: case2a.token.recipientId, leaf: clone(case2a.token.leaf), proof: clone(case2a.token.proof), rewardInclusionProof: clone(case2a.token.rewardInclusionProof)
  };
}

async function trust(input) {
  return input.issuedBy === "crinkl-checkpoint-root" && input.keyId === "checkpoint-root-test-v1" && input.publicKey === await rootPublicKey();
}

test("fails closed for a checkpoint state hash mismatch", async () => {
  const token = await goodToken();
  token.authorityCheckpoint.authorityState.stateHash = "f".repeat(64);
  const result = await verifyRewardCommitmentV2(token, { authorityCheckpointTrust: trust });
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((error) => error.code === "CHECKPOINT_INVALID"));
});

test("fails closed when a configured predecessor or durable sequence floor does not match", async () => {
  const token = await goodToken();
  const predecessor = await verifyRewardCommitmentV2(token, { authorityCheckpointTrust: trust, expectedPreviousCheckpointHash: "2".repeat(64) });
  assert.equal(predecessor.accepted, false);
  const rollback = await verifyRewardCommitmentV2(token, { authorityCheckpointTrust: trust, minimumCheckpointSequence: 4 });
  assert.equal(rollback.accepted, false);
  assert.ok(rollback.errors.some((error) => error.code === "CHECKPOINT_INVALID"));
});

test("fails closed for a suffix that does not begin at the covered checkpoint head", async () => {
  const token = await goodToken();
  token.authorityCheckpoint.covered.headEventHash = "e".repeat(64);
  await signCheckpoint(token.authorityCheckpoint);
  const result = await verifyRewardCommitmentV2(token, { authorityCheckpointTrust: trust });
  assert.equal(result.accepted, false);
  assert.equal(result.systemStreamValid, false);
  assert.ok(result.errors.some((error) => error.code === "SYSTEM_STREAM_INVALID"));
});

test("fails closed above the hard 128-event suffix limit before trust or history access", async () => {
  const token = await goodToken();
  token.systemEventSuffix = Array.from({ length: 129 }, () => clone(token.systemEventSuffix[0]));
  let trusted = false;
  const result = await verifyRewardCommitmentV2(token, { authorityCheckpointTrust: async () => { trusted = true; return true; } });
  assert.equal(result.accepted, false);
  assert.equal(trusted, false);
  assert.ok(result.errors.some((error) => error.code === "CHECKPOINT_INVALID"));
});

test("fails closed when checkpoint-root identity is not authorized", async () => {
  const result = await verifyRewardCommitmentV2(await goodToken(), { authorityCheckpointTrust: async () => false });
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((error) => error.code === "CHECKPOINT_UNTRUSTED"));
});

test("fails closed when the backing signer is revoked before terminal backing", async () => {
  const token = await goodToken();
  const [commitment, originalBacking] = token.systemEventSuffix;
  const revocation = await signSystemEvent({
    eventId: "sha256:fixture-revoke-backing-signer",
    eventName: "AUTHORITY_REVOKED",
    chainId: token.chainId,
    signedBy: originalBacking.signedBy,
    timestamp: "2026-01-03T12:00:00.000Z",
    protocolVersion: "1.0.0-rc.1",
    prevHash: commitment.eventHash,
    payload: {
      authorityId: originalBacking.signedBy,
      validUntil: "2026-01-03T12:00:00.000Z",
      revokedBy: originalBacking.signedBy,
      revokedAt: "2026-01-03T12:00:00.000Z"
    }
  }, GENESIS_AUTHORITY_SEED);
  const backing = await signSystemEvent({
    ...clone(originalBacking),
    prevHash: revocation.eventHash,
    timestamp: "2026-01-04T12:00:00.000Z",
    payload: { ...originalBacking.payload, backedAt: "2026-01-04T12:00:00.000Z" }
  }, GENESIS_AUTHORITY_SEED);
  token.backingEvent = backing;
  token.systemEventSuffix = [clone(commitment), clone(revocation), clone(backing)];
  const result = await verifyRewardCommitmentV2(token, { authorityCheckpointTrust: trust });
  assert.equal(result.accepted, false);
  assert.equal(result.backingValid, false);
  assert.ok(result.errors.some((error) => error.code === "AUTHORITY_INVALID"));
});

test("fails closed when backed proof omits terminal backing or binds it to another batch", async () => {
  const notTerminal = await goodToken();
  notTerminal.systemEventSuffix = notTerminal.systemEventSuffix.slice(0, -1);
  const first = await verifyRewardCommitmentV2(notTerminal, { authorityCheckpointTrust: trust });
  assert.equal(first.accepted, false);
  assert.equal(first.backingValid, false);

  const wrongBatch = await goodToken();
  wrongBatch.backingEvent = await signSystemEvent({
    ...clone(wrongBatch.backingEvent),
    payload: { ...wrongBatch.backingEvent.payload, batchId: "other-batch" }
  }, GENESIS_AUTHORITY_SEED);
  wrongBatch.systemEventSuffix = [clone(wrongBatch.systemEventSuffix[0]), clone(wrongBatch.backingEvent)];
  const second = await verifyRewardCommitmentV2(wrongBatch, { authorityCheckpointTrust: trust });
  assert.equal(second.accepted, false);
  assert.equal(second.backingValid, false);
  assert.ok(second.errors.some((error) => error.code === "BACKING_EVENT_INVALID"));
});
