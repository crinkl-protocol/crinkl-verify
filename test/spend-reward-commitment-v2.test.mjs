import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { verifySpendRewardCommitmentV2 } from "../dist/index.js";

const vectorPath = resolve(
  process.env.CRINKL_PROTOCOL_DIR ?? "/mnt/worktrees/crinkl-protocol-authority-checkpoint-protocol-conformance-repair-20260904",
  "conformance/authority-checkpoint/v1/vectors/authority-checkpoint-reward-v2.v1.json"
);
const hasVectors = existsSync(vectorPath);
const vectors = hasVectors ? JSON.parse(readFileSync(vectorPath, "utf8")) : undefined;
const nativeFixture = JSON.parse(readFileSync(new URL("../fixtures/native-v1.json", import.meta.url), "utf8"));

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

function options(vectorCase, issuer = vectorCase.trust.spendIssuer) {
  const root = vectorCase.trust.checkpointRoot;
  const admitted = admittedCheckpointHistory(vectorCase);
  const predecessor = vectorCase.checkpointHistory?.at(-1);
  return {
    issuerTrust: ({ issuedBy, publicKeyBase64 }) => issuedBy === issuer.id && publicKeyBase64 === issuer.publicKey,
    rewardCommitment: {
      authorityCheckpointTrust: (input) => input.profile === "configured-checkpoint-root/v1"
        && input.issuedBy === root.issuedBy
        && input.keyId === root.keyId
        && input.publicKey === root.publicKey,
      resolveAdmittedAuthorityCheckpoint: (checkpointHash) => admitted.get(checkpointHash) ?? null,
      expectedPreviousCheckpointHash: admitted.size > 0 ? predecessor?.signatures.checkpointHash : undefined
    }
  };
}

test("V2 composite verifies each Protocol positive Spend-to-reward reference", { skip: !hasVectors }, async () => {
  for (const vectorCase of vectors.positiveCases) {
    const result = await verifySpendRewardCommitmentV2(vectorCase.spendToken, vectorCase.rewardCommitmentToken, options(vectorCase));
    assert.equal(result.linkage, "verified", vectorCase.id);
    assert.equal(result.tier, vectorCase.rewardCommitmentToken.economicTier === "COMMITTED_BACKED" ? "committed-backed" : "committed", vectorCase.id);
  }
});

test("V2 composite rejects a different independently valid Spend Token", { skip: !hasVectors }, async () => {
  const vectorCase = vectors.positiveCases[0];
  const otherSpend = nativeFixture.case.token;
  const result = await verifySpendRewardCommitmentV2(otherSpend, vectorCase.rewardCommitmentToken, options(vectorCase, {
    id: otherSpend.signatures.issuedBy,
    publicKey: otherSpend.signatures.publicKey
  }));
  assert.equal(result.spend.cryptographicallyValid, true);
  assert.equal(result.spend.issuerAuthorized, true);
  assert.equal(result.rewardCommitment.accepted, true);
  assert.equal(result.linkage, "mismatch");
  assert.equal(result.tier, "crypto-valid");
  assert.ok(result.errors.some((error) => error.code === "SPEND_REWARD_LINKAGE_MISMATCH"));
});

test("V2 composite retains the pre-await Spend snapshot for verification and linkage", { skip: !hasVectors }, async () => {
  const vectorCase = vectors.positiveCases[0];
  const spend = JSON.parse(JSON.stringify(vectorCase.spendToken));
  const originalSpendId = spend.spendId;
  const originalHeadEventHash = spend.lineage.headEventHash;
  let mutated = false;
  const root = vectorCase.trust.checkpointRoot;
  const result = await verifySpendRewardCommitmentV2(spend, vectorCase.rewardCommitmentToken, {
    issuerTrust: async ({ issuedBy, publicKeyBase64 }) => {
      spend.spendId = "attacker-controlled-spend";
      spend.lineage.headEventHash = "0".repeat(64);
      mutated = true;
      return issuedBy === vectorCase.trust.spendIssuer.id && publicKeyBase64 === vectorCase.trust.spendIssuer.publicKey;
    },
    rewardCommitment: {
      authorityCheckpointTrust: (input) => input.profile === "configured-checkpoint-root/v1"
        && input.issuedBy === root.issuedBy
        && input.keyId === root.keyId
        && input.publicKey === root.publicKey
    }
  });
  assert.equal(mutated, true);
  assert.equal(result.spend.metadata.spendId, originalSpendId);
  assert.equal(originalHeadEventHash, vectorCase.rewardCommitmentToken.rewardInclusionProof.leaf.rewardEventHash);
  assert.equal(result.linkage, "verified");
  assert.equal(result.tier, "committed");
});
