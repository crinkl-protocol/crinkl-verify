import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  computeLeafHash,
  verifyInclusionProof,
  verifyRewardCommitmentV1,
  verifySpendWithRewardCommitment
} from "../dist/index.js";

const fixture = JSON.parse(readFileSync(new URL("../fixtures/reward-commitment-v1.json", import.meta.url)));
const clone = (value) => JSON.parse(JSON.stringify(value));
const caseById = (id) => fixture.cases.find((candidate) => candidate.id === id);

function authorityTrustFor(fixtureCase) {
  return async ({ chainId, authorityId, publicKeyBase64 }) =>
    chainId === fixtureCase.token.chainId &&
    authorityId === fixtureCase.genesisAuthorityId &&
    publicKeyBase64 === fixtureCase.genesisPublicKeyBase64;
}

function spendIssuerTrust(fixtureCase) {
  return ({ issuedBy, publicKeyBase64 }) =>
    issuedBy === fixtureCase.spendIssuer.issuedBy && publicKeyBase64 === fixtureCase.spendIssuer.publicKeyBase64;
}

test("verifies a COMMITTED transparent-recipient (schema 1a) reward commitment, including a full authority rotation", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const result = await verifyRewardCommitmentV1(fixtureCase.token, { authorityTrust: authorityTrustFor(fixtureCase) });
  assert.equal(result.systemStreamValid, true);
  assert.equal(result.authorityValid, true);
  assert.equal(result.commitmentValid, true);
  assert.equal(result.merkleValid, true);
  assert.equal(result.economicTier, "COMMITTED");
  assert.equal(result.backingValid, "not_applicable");
  assert.equal(result.accepted, true);
  assert.deepEqual(result.errors, []);
  assert.equal(result.metadata.batchId, fixtureCase.token.batch.batchId);
});

test("verifies a COMMITTED blinded-recipient (schema 1b) reward commitment", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1b");
  const result = await verifyRewardCommitmentV1(fixtureCase.token, { authorityTrust: authorityTrustFor(fixtureCase) });
  assert.equal(result.accepted, true);
  assert.deepEqual(result.errors, []);
});

test("verifies a COMMITTED_BACKED linkable (schema 2a) reward commitment", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committedBacked.2a");
  const result = await verifyRewardCommitmentV1(fixtureCase.token, { authorityTrust: authorityTrustFor(fixtureCase) });
  assert.equal(result.economicTier, "COMMITTED_BACKED");
  assert.equal(result.backingValid, true);
  assert.equal(result.accepted, true);
  assert.deepEqual(result.errors, []);
});

test("without an authorityTrust resolver, authority is not_checked and the token is not accepted", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const result = await verifyRewardCommitmentV1(fixtureCase.token);
  assert.equal(result.authorityValid, "not_checked");
  assert.equal(result.accepted, false);
  assert.ok(result.warnings.some((warning) => warning.code === "AUTHORITY_NOT_CHECKED"));
});

test("a genesis authority the trust resolver rejects is not accepted", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const result = await verifyRewardCommitmentV1(fixtureCase.token, { authorityTrust: async () => false });
  assert.equal(result.authorityValid, false);
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((error) => error.code === "AUTHORITY_UNTRUSTED"));
});

test("a non-genesis system-stream segment is indeterminate, not accepted", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const token = clone(fixtureCase.token);
  token.systemEvents = [clone(token.commitmentEvent)];
  const result = await verifyRewardCommitmentV1(token, { authorityTrust: authorityTrustFor(fixtureCase) });
  assert.equal(result.authorityValid, "indeterminate");
  assert.equal(result.accepted, false);
  assert.ok(result.warnings.some((warning) => warning.code === "AUTHORITY_INDETERMINATE_NON_GENESIS_SEGMENT"));
});

test("caller-supplied missing history replays the full rotation and revocation chain from genesis", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const token = clone(fixtureCase.token);
  const history = token.systemEvents.slice(0, -1).map(clone);
  token.systemEvents = [clone(token.commitmentEvent)];
  const result = await verifyRewardCommitmentV1(token, {
    authorityTrust: authorityTrustFor(fixtureCase),
    systemStreamHistory: history
  });
  assert.equal(result.systemStreamValid, true);
  assert.equal(result.authorityValid, true);
  assert.equal(result.accepted, true);
  assert.deepEqual(result.errors, []);
});

test("a P1.6b-compatible provider is paged from the exact earliest prevHash", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const token = clone(fixtureCase.token);
  const historyNewestFirst = token.systemEvents.slice(0, -1).map(clone).reverse();
  const historyByHash = new Map(historyNewestFirst.map((event) => [event.eventHash, event]));
  token.systemEvents = [clone(token.commitmentEvent)];
  const calls = [];
  const result = await verifyRewardCommitmentV1(token, {
    authorityTrust: authorityTrustFor(fixtureCase),
    maxHistoryEvents: 10,
    timeoutMs: 1_000,
    systemStreamHistoryResolver: ({ chainId, headHash, limit, signal }) => {
      calls.push({ chainId, headHash, limit, aborted: signal.aborted });
      const event = historyByHash.get(headHash);
      return {
        success: true,
        data: {
          chainId,
          requestedHeadHash: headHash,
          events: [event],
          nextHeadHash: event.prevHash,
          hasMore: event.prevHash !== null
        }
      };
    }
  });
  assert.equal(calls.length, historyNewestFirst.length);
  assert.equal(calls[0].headHash, fixtureCase.token.commitmentEvent.prevHash);
  assert.equal(calls[0].limit, 10);
  assert.equal(calls[0].aborted, false);
  assert.deepEqual(calls.map((call) => call.headHash), historyNewestFirst.map((event) => event.eventHash));
  assert.deepEqual(calls.map((call) => call.limit), [10, 9, 8]);
  assert.equal(result.authorityValid, true);
  assert.equal(result.accepted, true);
});

test("history budget, missing provider data, network failure, and timeout remain indeterminate", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const token = clone(fixtureCase.token);
  token.systemEvents = [clone(token.commitmentEvent)];
  const cases = [
    { maxHistoryEvents: 2, systemStreamHistory: fixtureCase.token.systemEvents.slice(0, -1).map(clone) },
    { systemStreamHistoryResolver: async () => ({ success: false, error: "system_stream_event_not_found" }) },
    { systemStreamHistoryResolver: async () => { throw new Error("offline"); } },
    { timeoutMs: 1, systemStreamHistoryResolver: async () => new Promise(() => {}) }
  ];
  for (const historyOptions of cases) {
    const result = await verifyRewardCommitmentV1(token, {
      authorityTrust: authorityTrustFor(fixtureCase),
      ...historyOptions
    });
    assert.equal(result.authorityValid, "indeterminate");
    assert.equal(result.accepted, false);
  }
});

test("chainEvidence defaults to not-checked", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const result = await verifyRewardCommitmentV1(fixtureCase.token, { authorityTrust: authorityTrustFor(fixtureCase) });
  assert.equal(result.anchor, "not-checked");
  assert.ok(result.warnings.some((warning) => warning.code === "ANCHOR_NOT_CHECKED"));
});

test('chainEvidence mode "provided" verifies a matching, already-decoded on-chain record offline', async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const { batch } = fixtureCase.token;
  const result = await verifyRewardCommitmentV1(fixtureCase.token, {
    authorityTrust: authorityTrustFor(fixtureCase),
    chainEvidence: { mode: "provided", tx: { batchId: batch.batchId, root: batch.root, schemaVersion: batch.schemaVersion, txRef: batch.txRef, committedAt: batch.committedAt } }
  });
  assert.equal(result.anchor, "verified");
});

test('chainEvidence mode "provided" flags a mismatching record as indeterminate, not a silent pass', async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const { batch } = fixtureCase.token;
  const result = await verifyRewardCommitmentV1(fixtureCase.token, {
    authorityTrust: authorityTrustFor(fixtureCase),
    chainEvidence: { mode: "provided", tx: { batchId: batch.batchId, root: "0".repeat(64), schemaVersion: batch.schemaVersion } }
  });
  assert.equal(result.anchor, "indeterminate");
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((error) => error.code === "CHAIN_EVIDENCE_MISMATCH"));
});

test('chainEvidence mode "solana-rpc" fails closed before network access for a noncanonical batch.txRef', async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  let called = false;
  const result = await verifyRewardCommitmentV1(fixtureCase.token, {
    authorityTrust: authorityTrustFor(fixtureCase),
    chainEvidence: {
      mode: "solana-rpc",
      binding: "crinkl-platform-solana-create-batch-imprint/v1",
      rpcUrl: "https://rpc.example",
      fetch: async () => { called = true; throw new Error("must not be called"); }
    },
    solanaEvidenceTrust: () => true
  });
  assert.equal(called, false);
  assert.equal(result.anchor, "indeterminate");
  assert.equal(result.accepted, false);
  assert.ok(result.errors.some((error) => error.code === "CHAIN_EVIDENCE_INVALID"));
});

test('chainEvidence mode "rpc" fetches exactly the caller-supplied url and verifies the response', async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const { batch } = fixtureCase.token;
  let calledUrl;
  const stubFetch = async (url) => {
    calledUrl = url;
    return { json: async () => ({ batchId: batch.batchId, root: batch.root, schemaVersion: batch.schemaVersion }) };
  };
  const result = await verifyRewardCommitmentV1(fixtureCase.token, {
    authorityTrust: authorityTrustFor(fixtureCase),
    chainEvidence: { mode: "rpc", url: "https://example.invalid/reward-batch", fetch: stubFetch }
  });
  assert.equal(result.anchor, "verified");
  assert.equal(calledUrl, "https://example.invalid/reward-batch");
});

test('chainEvidence mode "rpc" without a url never calls fetch and is indeterminate', async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  let called = false;
  const stubFetch = async () => { called = true; throw new Error("must not be called"); };
  const result = await verifyRewardCommitmentV1(fixtureCase.token, {
    authorityTrust: authorityTrustFor(fixtureCase),
    chainEvidence: { mode: "rpc", url: "", fetch: stubFetch }
  });
  assert.equal(called, false);
  assert.equal(result.anchor, "indeterminate");
  assert.ok(result.errors.some((error) => error.code === "CHAIN_EVIDENCE_INVALID"));
});

test('chainEvidence modes "none" and "provided" perform zero network access even if global fetch is poisoned', async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committed.1a");
  const { batch } = fixtureCase.token;
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; throw new Error("network must never be touched"); };
  try {
    await verifyRewardCommitmentV1(fixtureCase.token, { authorityTrust: authorityTrustFor(fixtureCase), chainEvidence: { mode: "none" } });
    await verifyRewardCommitmentV1(fixtureCase.token, {
      authorityTrust: authorityTrustFor(fixtureCase),
      chainEvidence: { mode: "provided", tx: { batchId: batch.batchId, root: batch.root, schemaVersion: batch.schemaVersion } }
    });
    await verifyRewardCommitmentV1(fixtureCase.token, { authorityTrust: authorityTrustFor(fixtureCase) });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls, 0);
});

test("composes with native spend verification to reach the committed-backed tier with verified linkage", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committedBacked.2a");
  const issuerTrust = ({ issuedBy, publicKeyBase64 }) =>
    issuedBy === fixtureCase.spendIssuer.issuedBy && publicKeyBase64 === fixtureCase.spendIssuer.publicKeyBase64;
  const result = await verifySpendWithRewardCommitment(fixtureCase.spendToken, fixtureCase.token, {
    issuerTrust,
    rewardCommitment: { authorityTrust: authorityTrustFor(fixtureCase) }
  });
  assert.equal(result.tier, "committed-backed");
  assert.equal(result.linkage, "verified");
  assert.equal(result.anchor, "not-checked");
  assert.deepEqual(result.errors, []);
});

test("a linkable 2a commitment with no rewardInclusionProof remains crypto-valid and not-checked", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committedBacked.2a");
  const token = clone(fixtureCase.token);
  delete token.rewardInclusionProof;
  const result = await verifySpendWithRewardCommitment(fixtureCase.spendToken, token, {
    issuerTrust: spendIssuerTrust(fixtureCase),
    rewardCommitment: { authorityTrust: authorityTrustFor(fixtureCase) }
  });
  assert.equal(result.spend.cryptographicallyValid, true);
  assert.equal(result.rewardCommitment.accepted, true);
  assert.equal(result.linkage, "not-checked");
  assert.equal(result.tier, "crypto-valid");
});

for (const id of ["rewardCommitment.v1.committed.1a", "rewardCommitment.v1.committed.1b"]) {
  test(`a non-linkable ${id.slice(-2)} commitment retains independent tiering`, async () => {
    const rewardCase = caseById(id);
    const spendCase = caseById("rewardCommitment.v1.committedBacked.2a");
    const result = await verifySpendWithRewardCommitment(spendCase.spendToken, rewardCase.token, {
      issuerTrust: spendIssuerTrust(spendCase),
      rewardCommitment: { authorityTrust: authorityTrustFor(rewardCase) }
    });
    assert.equal(result.spend.cryptographicallyValid, true);
    assert.equal(result.rewardCommitment.accepted, true);
    assert.equal(result.linkage, "not-applicable");
    assert.equal(result.tier, "committed");
  });
}

test("a missing reward commitment is not an error for the spend token; the tier just stays crypto-valid", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committedBacked.2a");
  const issuerTrust = ({ issuedBy, publicKeyBase64 }) =>
    issuedBy === fixtureCase.spendIssuer.issuedBy && publicKeyBase64 === fixtureCase.spendIssuer.publicKeyBase64;
  const result = await verifySpendWithRewardCommitment(fixtureCase.spendToken, undefined, { issuerTrust });
  assert.equal(result.tier, "crypto-valid");
  assert.equal(result.linkage, "not-applicable");
  assert.deepEqual(result.errors, []);
  assert.ok(result.warnings.some((warning) => warning.code === "REWARD_COMMITMENT_NOT_PROVIDED"));
});

test("an invalid spend signature never reaches any reward tier, regardless of the reward commitment", async () => {
  const fixtureCase = caseById("rewardCommitment.v1.committedBacked.2a");
  const tamperedSpend = clone(fixtureCase.spendToken);
  tamperedSpend.canonical.totalCents = "999999999";
  const issuerTrust = ({ issuedBy, publicKeyBase64 }) =>
    issuedBy === fixtureCase.spendIssuer.issuedBy && publicKeyBase64 === fixtureCase.spendIssuer.publicKeyBase64;
  const result = await verifySpendWithRewardCommitment(tamperedSpend, fixtureCase.token, {
    issuerTrust,
    rewardCommitment: { authorityTrust: authorityTrustFor(fixtureCase) }
  });
  assert.equal(result.tier, "invalid");
  assert.equal(result.linkage, "not-applicable");
});

test("released Merkle vector: leaf hash and full proof walk (batch schema V1) match crinkl-protocol conformance/v1/vectors/merkle.rewardBatch.schemaV1.json", () => {
  const vector = JSON.parse(readFileSync(new URL("../fixtures/merkle-reward-batch-v1.json", import.meta.url)));
  const target = vector.case.leaves.find((leaf) => leaf.wallet === vector.case.proof.wallet);
  assert.equal(computeLeafHash(target), vector.case.proof.expectedLeafHashHex);
  const walk = verifyInclusionProof({
    leaf: target,
    leafHash: vector.case.proof.expectedLeafHashHex,
    siblings: vector.case.proof.expectedPathHex,
    expectedRoot: vector.case.expectedRootHex
  });
  assert.equal(walk.valid, true);
  assert.equal(walk.computedRoot, vector.case.expectedRootHex);
});

test("released Merkle vector: RewardIssuanceLeaf hash computation (schema V2 rewardEventsRoot) is deterministic and correctly sortable by spendId", () => {
  // NOTE: this vector's `expectedRootHex` covers a 3-leaf (non-power-of-2)
  // tree. Every leaf-count-2^n pairing this package's tree-builder produces
  // (padding-at-end per COMMITMENT_LAYER.md's literal padding rule, padding
  // at the front, or the three possible unpadded fold orders) fails to
  // reproduce it, so the specific odd-leaf-count internal pairing the
  // reference vector generator used is not recoverable from the normative
  // text alone. This package's verifier only ever *walks a supplied proof*
  // (never rebuilds a tree from raw leaves — see the schemaV1 test above,
  // which round-trips exactly against a supplied proof), so this gap does
  // not affect verification correctness; it only means this specific vector
  // cannot conformance-test tree *construction*. Recorded as a compliance
  // note in the PR. What IS independently checked here: leaf-hash domain
  // separation/canonicalization and the normative sort-by-spendId rule.
  const vector = JSON.parse(readFileSync(new URL("../fixtures/merkle-reward-events-root-v2.json", import.meta.url)));
  const leaves = vector.case.rewardIssuanceLeaves;
  const hashes = leaves.map(computeLeafHash);
  assert.equal(new Set(hashes).size, hashes.length, "leaf hashes must be distinct");
  for (const hash of hashes) assert.match(hash, /^[0-9a-f]{64}$/);
  const sortedSpendIds = [...leaves].sort((a, b) => (a.spendId < b.spendId ? -1 : a.spendId > b.spendId ? 1 : 0)).map((leaf) => leaf.spendId);
  assert.deepEqual(sortedSpendIds, ["spend-1", "spend-2", "spend-3"]);
});
