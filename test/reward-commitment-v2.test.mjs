import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import { resolve } from "node:path";
import { verifyRewardCommitmentV2 } from "../dist/index.js";

const vectorPath = resolve(
  process.env.CRINKL_PROTOCOL_DIR ?? "/mnt/worktrees/crinkl-protocol-authority-checkpoint-protocol-revocation-parity-20260904",
  "conformance/authority-checkpoint/v1/vectors/authority-checkpoint-reward-v2.v1.json"
);
const hasAuthorityCheckpointVectors = existsSync(vectorPath);
const authorityCheckpointVectors = hasAuthorityCheckpointVectors ? JSON.parse(readFileSync(vectorPath, "utf8")) : undefined;

function checkpointOptions(vectorCase) {
  const root = vectorCase.trust.checkpointRoot;
  return {
    authorityCheckpointTrust: (input) => input.profile === "configured-checkpoint-root/v1"
      && input.issuedBy === root.issuedBy
      && input.keyId === root.keyId
      && input.publicKey === root.publicKey
  };
}

test("consumes both Protocol AuthorityCheckpointV1 positive vectors", { skip: !hasAuthorityCheckpointVectors }, async () => {
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

test("rejects every hostile Protocol AuthorityCheckpointV1 vector", { skip: !hasAuthorityCheckpointVectors }, async () => {
  for (const hostile of authorityCheckpointVectors.negativeCases) {
    const result = await verifyRewardCommitmentV2(hostile.case.rewardCommitmentToken, checkpointOptions(hostile.case));
    assert.equal(result.accepted, false, `${hostile.id}: ${hostile.expectedRejectCode}`);
  }
});
