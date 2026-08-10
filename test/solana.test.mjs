import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1,
  verifySolanaBatchAnchor
} from "../dist/index.js";

const rawFixture = JSON.parse(readFileSync(new URL("../fixtures/solana-platform-create-batch-imprint-v1.json", import.meta.url)));
const clone = (value) => JSON.parse(JSON.stringify(value));
const expected = rawFixture.expected;
const signature = rawFixture.signature;

function batch(overrides = {}) {
  return {
    // Platform's application binding stores only this UUID's first 64 bits.
    batchId: `${expected.batchIdPrefixU64Hex.slice(0, 8)}-${expected.batchIdPrefixU64Hex.slice(8, 12)}-${expected.batchIdPrefixU64Hex.slice(12, 16)}-8000-000000000000`,
    root: expected.root,
    leafCount: expected.leafCount,
    totalPoints: "800",
    schemaVersion: "2b",
    txRef: `solana:${expected.cluster}:${expected.programId}:${rawFixture.slot}:${rawFixture.transactionIndex}:${rawFixture.instructionIndex}:${signature}`,
    committedAt: "2026-08-01T23:23:04.000Z",
    ...overrides
  };
}

function rpcFetch(mutate = {}) {
  const calls = [];
  const responses = clone(rawFixture.responses);
  for (const [method, replacement] of Object.entries(mutate)) responses[method].result = replacement;
  const fetch = async (url, init) => {
    const request = JSON.parse(init.body);
    calls.push({ url, request });
    const response = clone(responses[request.method]);
    response.id = request.id;
    return { ok: true, status: 200, json: async () => response };
  };
  return { fetch, calls, responses };
}

const trust = ({ binding, sourceCommit, cluster, rpcUrl, programId, instructionDiscriminatorHex, requiredFinality }) =>
  binding === PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1.binding &&
  sourceCommit === PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1.sourceCommit &&
  cluster === expected.cluster && rpcUrl === "https://rpc.example" && programId === expected.programId &&
  instructionDiscriminatorHex === expected.discriminatorHex && requiredFinality === "finalized";

function options(fetch) {
  return {
    mode: "solana-rpc",
    binding: PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1.binding,
    rpcUrl: "https://rpc.example",
    fetch
  };
}

test("decodes the pinned real finalized Platform Solana JSON-RPC fixture", async () => {
  const { fetch, calls } = rpcFetch();
  const result = await verifySolanaBatchAnchor(batch(), "solana:devnet", options(fetch), trust);
  assert.deepEqual(result, { valid: true });
  assert.deepEqual(calls.map(({ request }) => request.method), ["getTransaction", "getSignatureStatuses", "getBlock"]);
  assert.equal(calls[0].request.params[1].commitment, "finalized");
  assert.equal(calls[2].request.params[0], rawFixture.slot);
});

test("does not call RPC until the caller authorizes binding, source, cluster, endpoint, program and discriminator", async () => {
  const { fetch, calls } = rpcFetch();
  const result = await verifySolanaBatchAnchor(batch(), "solana:devnet", options(fetch), () => false);
  assert.equal(result.valid, false);
  assert.equal(result.cause, "trust");
  assert.equal(calls.length, 0);
});

test("a throwing Solana trust resolver fails closed before network access", async () => {
  const { fetch, calls } = rpcFetch();
  const result = await verifySolanaBatchAnchor(batch(), "solana:devnet", options(fetch), () => { throw new Error("trust registry unavailable"); });
  assert.equal(result.valid, false);
  assert.equal(result.cause, "trust");
  assert.equal(calls.length, 0);
});

test("rejects an unknown application binding before network access", async () => {
  const { fetch, calls } = rpcFetch();
  const result = await verifySolanaBatchAnchor(batch(), "solana:devnet", { ...options(fetch), binding: "unknown-binding" }, trust);
  assert.equal(result.valid, false);
  assert.equal(calls.length, 0);
});

for (const [name, mutate, message] of [
  ["finality", { getSignatureStatuses: { ...rawFixture.responses.getSignatureStatuses.result, value: [{ ...rawFixture.responses.getSignatureStatuses.result.value[0], confirmationStatus: "confirmed" }] } }, "not finalized"],
  ["transaction position", { getBlock: { ...rawFixture.responses.getBlock.result, signatures: [signature, "other"] } }, "block position"],
  ["program", { getTransaction: { ...rawFixture.responses.getTransaction.result, transaction: { ...rawFixture.responses.getTransaction.result.transaction, message: { ...rawFixture.responses.getTransaction.result.transaction.message, accountKeys: rawFixture.responses.getTransaction.result.transaction.message.accountKeys.map((key, index) => index === 3 ? "11111111111111111111111111111111" : key) } } } }, "program or position"]
]) {
  test(`fails closed on ${name} mismatch`, async () => {
    const { fetch } = rpcFetch(mutate);
    const result = await verifySolanaBatchAnchor(batch(), "solana:devnet", options(fetch), trust);
    assert.equal(result.valid, false);
    assert.match(result.message, new RegExp(message));
  });
}

test("fails closed when the signed batch root differs from the pinned instruction", async () => {
  const { fetch } = rpcFetch();
  const result = await verifySolanaBatchAnchor(batch({ root: "cd".repeat(32) }), "solana:devnet", options(fetch), trust);
  assert.equal(result.valid, false);
  assert.match(result.message, /root mismatch/);
});

test("fails closed when any ordered Platform instruction account differs", async () => {
  const transaction = clone(rawFixture.responses.getTransaction.result);
  transaction.transaction.message.instructions[0].accounts = [0, 1, 4, 2];
  const { fetch } = rpcFetch({ getTransaction: transaction });
  const result = await verifySolanaBatchAnchor(batch(), "solana:devnet", options(fetch), trust);
  assert.equal(result.valid, false);
  assert.match(result.message, /account ABI mismatch/);
});

test("fails closed for a Protocol-legal opaque batchId outside the pinned Platform UUID binding", async () => {
  const { fetch } = rpcFetch();
  const result = await verifySolanaBatchAnchor(batch({ batchId: "batch-fixture-spend-v2-reward-2b" }), "solana:devnet", options(fetch), trust);
  assert.equal(result.valid, false);
  assert.match(result.message, /batchId mismatch/);
});
