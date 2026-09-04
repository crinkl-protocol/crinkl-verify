import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import * as ed25519 from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalize } from "json-canonicalize";
import { verifyRewardCommitmentV2 } from "../dist/index.js";

if (!ed25519.etc.sha512Sync) ed25519.etc.sha512Sync = (...messages) => sha512(ed25519.etc.concatBytes(...messages));

const vectorPath = resolve(
  process.env.CRINKL_PROTOCOL_DIR ?? "/mnt/worktrees/crinkl-protocol-authority-checkpoint-protocol-revocation-parity-20260904",
  "conformance/authority-checkpoint/v1/vectors/authority-checkpoint-reward-v2.v1.json"
);
const hasVectors = existsSync(vectorPath);
const vectors = hasVectors ? JSON.parse(readFileSync(vectorPath, "utf8")) : undefined;
const encoder = new TextEncoder();
const clone = (value) => JSON.parse(JSON.stringify(value));
const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

function options(vectorCase) {
  const root = vectorCase.trust.checkpointRoot;
  return { authorityCheckpointTrust: (input) => input.profile === "configured-checkpoint-root/v1" && input.issuedBy === root.issuedBy && input.keyId === root.keyId && input.publicKey === root.publicKey };
}

async function signedEvent(event, seedByte) {
  const payload = event.payload;
  const eventIdDigest = hex(sha256(encoder.encode(canonicalize({ chainId: event.chainId, eventName: event.eventName, payload, protocolVersion: "1.0.0-rc.1" }))));
  const eventId = `sha256:${eventIdDigest}`;
  const unsigned = { eventId, eventName: event.eventName, chainId: event.chainId, signedBy: event.signedBy, payload, timestamp: event.timestamp, protocolVersion: "1.0.0-rc.1", prevHash: event.prevHash };
  const eventHash = hex(sha256(encoder.encode(canonicalize(unsigned))));
  const signature = Buffer.from(await ed25519.signAsync(Buffer.from(eventHash, "hex"), new Uint8Array(32).fill(seedByte))).toString("base64");
  return { ...unsigned, eventHash, signature };
}

test("rejects malformed checkpoint registry, succession, and pre-parse over-limit suffixes", { skip: !hasVectors }, async () => {
  const base = vectors.positiveCases[0];
  const malformed = [
    (token) => token.authorityCheckpoint.authorityState.records.push({ ...clone(token.authorityCheckpoint.authorityState.records[0]), authorityId: "fixture-authority-z" }),
    (token) => token.authorityCheckpoint.authorityState.records.push({ authorityId: "fixture-authority-z", publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", validFrom: "2026-09-04T00:00:00.000Z", validUntil: null, revokedBy: null }),
    (token) => { token.authorityCheckpoint.authorityState.records[0].revokedBy = "fixture-authority-b"; },
    (token) => { token.authorityCheckpoint.previousCheckpointHash = "0".repeat(64); },
    (token) => { token.authorityCheckpoint.sequence = 2; token.authorityCheckpoint.previousCheckpointHash = null; }
  ];
  for (const mutate of malformed) {
    const token = clone(base.rewardCommitmentToken);
    mutate(token);
    const result = await verifyRewardCommitmentV2(token, options(base));
    assert.equal(result.accepted, false);
    assert.ok(result.errors.some((error) => error.code === "SCHEMA_INVALID"));
  }

  const oversized = clone(base.rewardCommitmentToken);
  oversized.systemEventSuffix = Array.from({ length: 129 }, () => null);
  let trusted = false;
  const result = await verifyRewardCommitmentV2(oversized, { authorityCheckpointTrust: async () => { trusted = true; return true; } });
  assert.equal(result.accepted, false);
  assert.equal(trusted, false);
  assert.ok(result.errors.some((error) => error.path === "$.systemEventSuffix"));
});

test("rejects exact-profile suffix domain deviations and duplicate registrations", { skip: !hasVectors }, async () => {
  const base = vectors.positiveCases[0];
  for (const mutate of [
    (token) => { token.systemEventSuffix[0].eventName = "REWARD_BATCH_CORRECTION"; },
    (token) => { token.systemEventSuffix[0].protocolVersion = "1.0.1"; },
    (token) => { token.systemEventSuffix[0].eventId = "sha256:" + "0".repeat(64); }
  ]) {
    const token = clone(base.rewardCommitmentToken);
    mutate(token);
    const result = await verifyRewardCommitmentV2(token, options(base));
    assert.equal(result.accepted, false);
    assert.ok(result.errors.some((error) => error.code === "SCHEMA_INVALID"));
  }

  const duplicateRegistration = clone(base.rewardCommitmentToken);
  duplicateRegistration.systemEventSuffix = [await signedEvent({
    ...duplicateRegistration.systemEventSuffix[0],
    payload: { ...duplicateRegistration.systemEventSuffix[0].payload, authorityId: "fixture-authority-a", predecessorId: "fixture-authority-a" }
  }, 83)];
  const duplicateResult = await verifyRewardCommitmentV2(duplicateRegistration, options(base));
  assert.equal(duplicateResult.accepted, false);
  assert.ok(duplicateResult.errors.some((error) => error.code === "SYSTEM_STREAM_INVALID"));
});

test("rejects backdated authority registration and revocation lifecycle events", { skip: !hasVectors }, async () => {
  const base = vectors.positiveCases[0];
  const backdatedRegistration = clone(base.rewardCommitmentToken);
  backdatedRegistration.systemEventSuffix[0] = await signedEvent({
    ...backdatedRegistration.systemEventSuffix[0],
    payload: { ...backdatedRegistration.systemEventSuffix[0].payload, validFrom: "2026-09-04T00:00:00.000Z" }
  }, 83);
  const registrationResult = await verifyRewardCommitmentV2(backdatedRegistration, options(base));
  assert.equal(registrationResult.accepted, false);
  assert.ok(registrationResult.errors.some((error) => error.code === "SYSTEM_STREAM_INVALID"));

  const backdatedRevocation = clone(base.rewardCommitmentToken);
  backdatedRevocation.systemEventSuffix[1] = await signedEvent({
    ...backdatedRevocation.systemEventSuffix[1],
    payload: {
      ...backdatedRevocation.systemEventSuffix[1].payload,
      validUntil: "2026-09-04T00:00:01.000Z",
      revokedAt: "2026-09-04T00:00:01.000Z"
    }
  }, 84);
  const revocationResult = await verifyRewardCommitmentV2(backdatedRevocation, options(base));
  assert.equal(revocationResult.accepted, false);
  assert.ok(revocationResult.errors.some((error) => error.code === "SYSTEM_STREAM_INVALID"));
});

test("requires a valid reward inclusion proof under the aggregate leaf root", { skip: !hasVectors }, async () => {
  const base = vectors.positiveCases[0];
  const absent = clone(base.rewardCommitmentToken);
  delete absent.rewardInclusionProof;
  const absentResult = await verifyRewardCommitmentV2(absent, options(base));
  assert.equal(absentResult.accepted, false);
  assert.equal(absentResult.rewardInclusionProofValid, false);

  const tampered = clone(base.rewardCommitmentToken);
  tampered.rewardInclusionProof.leafHash = "0".repeat(64);
  const tamperedResult = await verifyRewardCommitmentV2(tampered, options(base));
  assert.equal(tamperedResult.accepted, false);
  assert.equal(tamperedResult.rewardInclusionProofValid, false);
  assert.ok(tamperedResult.errors.some((error) => error.code === "REWARD_INCLUSION_PROOF_INVALID"));
});
