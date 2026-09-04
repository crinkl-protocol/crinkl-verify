import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import { resolve } from "node:path";
import { verifyRewardCommitmentV2 } from "../dist/index.js";

const vectorPath = resolve(
  process.env.CRINKL_PROTOCOL_DIR ?? "/mnt/worktrees/crinkl-protocol-authority-checkpoint-presentation-v2-proof-bound-20260904",
  "conformance/authority-checkpoint/v1/vectors/authority-checkpoint-reward-v2.v1.json"
);
const hasAuthorityCheckpointVectors = existsSync(vectorPath);
const authorityCheckpointVectors = hasAuthorityCheckpointVectors ? JSON.parse(readFileSync(vectorPath, "utf8")) : undefined;

function admittedCheckpointHistory(vectorCase) {
  const checkpoint = vectorCase.rewardCommitmentToken.authorityCheckpoint;
  const history = vectorCase.checkpointHistory ?? [];
  if (history.length !== checkpoint.sequence - 1) return new Map();
  let expectedPreviousHash = null;
  for (const [index, candidate] of history.entries()) {
    if (candidate.sequence !== index + 1 || candidate.previousCheckpointHash !== expectedPreviousHash) return new Map();
    expectedPreviousHash = candidate.signatures?.checkpointHash;
  }
  return new Map(history.map((candidate) => [candidate.signatures.checkpointHash, candidate]));
}

function checkpointOptions(vectorCase) {
  const root = vectorCase.trust.checkpointRoot;
  const admitted = admittedCheckpointHistory(vectorCase);
  const predecessor = vectorCase.checkpointHistory?.at(-1);
  return {
    authorityCheckpointTrust: (input) => input.profile === "configured-checkpoint-root/v1"
      && input.issuedBy === root.issuedBy
      && input.keyId === root.keyId
      && input.publicKey === root.publicKey,
    resolveAdmittedAuthorityCheckpoint: (checkpointHash) => admitted.get(checkpointHash) ?? null,
    expectedPreviousCheckpointHash: admitted.size > 0 ? predecessor?.signatures.checkpointHash : undefined
  };
}

test("consumes every Protocol AuthorityCheckpointV1 positive vector", { skip: !hasAuthorityCheckpointVectors }, async () => {
  for (const vectorCase of authorityCheckpointVectors.positiveCases) {
    const result = await verifyRewardCommitmentV2(vectorCase.rewardCommitmentToken, checkpointOptions(vectorCase));
    assert.equal(result.accepted, true, vectorCase.id);
    assert.equal(result.checkpointValid, true, vectorCase.id);
    assert.equal(result.systemStreamValid, true, vectorCase.id);
    assert.equal(result.commitmentValid, true, vectorCase.id);
    assert.equal(result.merkleValid, true, vectorCase.id);
    assert.equal(result.rewardInclusionProofValid, true, vectorCase.id);
    assert.equal(result.backingValid, vectorCase.rewardCommitmentToken.economicTier === "COMMITTED_BACKED" ? true : "not_applicable", vectorCase.id);
  }
});

test("accepts the exact V2 correction and snapshot shape without changing the terminal commitment tier", { skip: !hasAuthorityCheckpointVectors }, async () => {
  const vectorCase = authorityCheckpointVectors.positiveCases.find(
    (candidate) => candidate.id === "valid-checkpoint-correction-and-snapshot-suffix"
  );
  assert.ok(vectorCase, "Protocol vectors must provide the V2 correction/snapshot suffix case.");
  const token = vectorCase.rewardCommitmentToken;
  assert.deepEqual(
    token.systemEventSuffix.map((event) => event.eventName),
    ["AUTHORITY_REGISTERED", "AUTHORITY_REVOKED", "REWARD_BATCH_CORRECTION", "CUMULATIVE_SNAPSHOT_COMMITTED", "REWARD_BATCH_COMMITTED"]
  );

  const result = await verifyRewardCommitmentV2(token, checkpointOptions(vectorCase));
  assert.equal(result.accepted, true);
  assert.equal(result.systemStreamValid, true);
  assert.equal(result.commitmentValid, true);
  assert.equal(result.backingValid, "not_applicable");
});

test("rejects every hostile Protocol AuthorityCheckpointV1 vector", { skip: !hasAuthorityCheckpointVectors }, async () => {
  for (const hostile of authorityCheckpointVectors.negativeCases) {
    const result = await verifyRewardCommitmentV2(hostile.case.rewardCommitmentToken, checkpointOptions(hostile.case));
    assert.equal(result.accepted, false, `${hostile.id}: ${hostile.expectedRejectCode}`);
  }
});

test("reproduces Protocol depth-three custody and transient-rotation failures through the admitted predecessor resolver", { skip: !hasAuthorityCheckpointVectors }, async () => {
  for (const id of ["depth-three-missing-predecessor", "depth-three-reordered-predecessor", "overlap-ordinary-event"]) {
    const hostile = authorityCheckpointVectors.negativeCases.find((candidate) => candidate.id === id);
    assert.ok(hostile, `Protocol vectors must include ${id}.`);
    const result = await verifyRewardCommitmentV2(hostile.case.rewardCommitmentToken, checkpointOptions(hostile.case));
    assert.equal(result.accepted, false, `${id}: ${hostile.expectedRejectCode}`);
  }
});
