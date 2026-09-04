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
  verifyRewardCommitmentV1,
  verifyRewardCommitmentV2
} from "../dist/index.js";

if (!ed25519.etc.sha512Sync) {
  ed25519.etc.sha512Sync = (...messages) => sha512(ed25519.etc.concatBytes(...messages));
}

const encoder = new TextEncoder();
const clone = (value) => JSON.parse(JSON.stringify(value));
const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const seed = (label) => sha256(encoder.encode(`crinkl-verify-test-seed:${label}`));
const fixture = JSON.parse(readFileSync(new URL("../fixtures/reward-commitment-v1.json", import.meta.url)));
const case1a = fixture.cases.find((candidate) => candidate.id === "rewardCommitment.v1.committed.1a");
const ROOT_SEED = seed("authority-checkpoint-root");

async function rootPublicKey() {
  return Buffer.from(await ed25519.getPublicKeyAsync(ROOT_SEED)).toString("base64");
}

async function makeCheckpoint(records, overrides = {}) {
  const genesis = case1a.token.systemEvents[0];
  const checkpoint = {
    checkpointType: "AUTHORITY_CHECKPOINT",
    schemaVersion: 1,
    protocol: { protocolVersion: "1.0.0-rc.1" },
    evidenceProfile: "configured-checkpoint-root/v1",
    chainId: case1a.token.chainId,
    sequence: 1,
    covered: { streamHeight: 1, headEventHash: genesis.eventHash, effectiveAt: genesis.timestamp },
    authorityState: {
      stateHash: computeAuthorityCheckpointRegistryStateHash(case1a.token.chainId, genesis.eventHash, records),
      records
    },
    previousCheckpointHash: null,
    limits: { maxSuffixEvents: 128 },
    signatures: {
      issuedBy: "crinkl-checkpoint-root",
      keyId: "checkpoint-root-test-v1",
      publicKey: await rootPublicKey(),
      checkpointHash: "0".repeat(64),
      signature: "pending"
    },
    ...overrides
  };
  checkpoint.signatures.checkpointHash = computeAuthorityCheckpointV1Hash(checkpoint);
  checkpoint.signatures.signature = Buffer.from(await ed25519.signAsync(Buffer.from(checkpoint.signatures.checkpointHash, "hex"), ROOT_SEED)).toString("base64");
  return checkpoint;
}

async function v2Token() {
  const [genesis, ...suffix] = clone(case1a.token.systemEvents);
  const records = [{
    authorityId: genesis.payload.authorityId,
    publicKey: genesis.payload.publicKey,
    validFrom: genesis.payload.validFrom,
    validUntil: null,
    revokedBy: null
  }];
  const checkpoint = await makeCheckpoint(records);
  return {
    tokenType: "REWARD_COMMITMENT",
    schemaVersion: 2,
    evidenceProfile: "configured-checkpoint-root/v1",
    chainId: case1a.token.chainId,
    economicTier: "COMMITTED",
    commitmentEvent: clone(case1a.token.commitmentEvent),
    authorityCheckpoint: checkpoint,
    systemEventSuffix: suffix,
    batch: clone(case1a.token.batch),
    recipientId: case1a.token.recipientId,
    leaf: clone(case1a.token.leaf),
    proof: clone(case1a.token.proof)
  };
}

async function trust(input) {
  return input.profile === "configured-checkpoint-root/v1"
    && input.issuedBy === "crinkl-checkpoint-root"
    && input.keyId === "checkpoint-root-test-v1"
    && input.publicKey === await rootPublicKey();
}

test("V2 checkpoint verification reaches the same commitment result as the V1 full-history oracle", async () => {
  const v1 = await verifyRewardCommitmentV1(case1a.token, {
    authorityTrust: ({ authorityId, publicKeyBase64 }) => authorityId === case1a.genesisAuthorityId && publicKeyBase64 === case1a.genesisPublicKeyBase64
  });
  const v2 = await verifyRewardCommitmentV2(await v2Token(), {
    authorityCheckpointTrust: trust,
    chainEvidence: { mode: "provided", tx: case1a.token.batch }
  });
  assert.equal(v1.accepted, true);
  assert.equal(v2.accepted, true);
  assert.equal(v2.checkpointValid, true);
  assert.equal(v2.systemStreamValid, true);
  assert.equal(v2.authorityValid, true);
  assert.equal(v2.commitmentValid, true);
  assert.equal(v2.merkleValid, true);
  assert.equal(v2.anchor, "verified");
  assert.equal(v2.metadata.suffixEventCount, 3);
});

test("V2 checkpoint path requires configured checkpoint-root trust", async () => {
  const result = await verifyRewardCommitmentV2(await v2Token());
  assert.equal(result.accepted, false);
  assert.equal(result.checkpointValid, false);
  assert.ok(result.errors.some((error) => error.code === "CHECKPOINT_UNTRUSTED"));
});

test("V2 accepts a configured predecessor and sequence floor", async () => {
  const token = await v2Token();
  const result = await verifyRewardCommitmentV2(token, {
    authorityCheckpointTrust: trust,
    minimumCheckpointSequence: 1,
    expectedPreviousCheckpointHash: null
  });
  assert.equal(result.accepted, true);
});
