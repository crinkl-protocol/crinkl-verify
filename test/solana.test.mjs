import assert from "node:assert/strict";
import test from "node:test";
import { verifySolanaBatchAnchor } from "../dist/index.js";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DISCRIMINATOR = "f5f3194de5a7ac64";
const PROGRAM_ID = "8143e1svTP4sceDiFGDtTHAwfxnZMiH8XuWgsFTmiT9M";
const SIGNATURE = "1".repeat(64);

function encodeBase58(input) {
  if (input.length === 0) return "";
  const digits = [0];
  for (const byte of input) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      const next = digits[i] * 256 + carry;
      digits[i] = next % 58;
      carry = Math.floor(next / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let leadingZeroes = 0;
  while (leadingZeroes < input.length && input[leadingZeroes] === 0) leadingZeroes += 1;
  return "1".repeat(leadingZeroes) + digits.reverse().map((digit) => BASE58[digit]).join("");
}

function instructionData(batch) {
  const bytes = new Uint8Array(61);
  bytes.set(Buffer.from(DISCRIMINATOR, "hex"), 0);
  const batchNumber = BigInt(`0x${batch.batchId.replace(/-/g, "").slice(0, 16)}`);
  new DataView(bytes.buffer).setBigUint64(8, batchNumber, true);
  bytes.set(Buffer.from(batch.root, "hex"), 16);
  new DataView(bytes.buffer).setUint32(48, batch.leafCount, true);
  new DataView(bytes.buffer).setBigInt64(52, 1_786_320_000n, true);
  bytes[60] = Number(batch.schemaVersion[0]);
  return encodeBase58(bytes);
}

function fixture(overrides = {}) {
  const batch = {
    batchId: "01234567-89ab-4def-8123-456789abcdef",
    root: "ab".repeat(32),
    leafCount: 2,
    totalPoints: "800",
    schemaVersion: "2b",
    txRef: `solana:devnet:${PROGRAM_ID}:123:1:0:${SIGNATURE}`,
    committedAt: "2026-08-10T00:00:00.000Z",
    ...overrides
  };
  return batch;
}

function rpcFetch(batch, mutate = {}) {
  const calls = [];
  const responses = {
    getTransaction: {
      slot: 123,
      blockTime: 1_786_320_000,
      meta: { err: null },
      transaction: {
        signatures: [SIGNATURE],
        message: {
          accountKeys: [PROGRAM_ID],
          instructions: [{ programIdIndex: 0, accounts: [1, 2, 3, 4], data: instructionData(batch) }]
        }
      }
    },
    getSignatureStatuses: { context: { slot: 130 }, value: [{ slot: 123, confirmations: null, err: null, confirmationStatus: "finalized" }] },
    getBlock: { blockhash: "block", previousBlockhash: "previous", parentSlot: 122, signatures: ["other", SIGNATURE] }
  };
  Object.assign(responses, mutate);
  const fetch = async (url, init) => {
    const request = JSON.parse(init.body);
    calls.push({ url, request });
    return {
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: "2.0", id: request.id, result: responses[request.method] })
    };
  };
  return { fetch, calls };
}

const trust = ({ cluster, rpcUrl, programId, instructionDiscriminatorHex, requiredFinality }) =>
  cluster === "devnet" && rpcUrl === "https://rpc.example" && programId === PROGRAM_ID &&
  instructionDiscriminatorHex === DISCRIMINATOR && requiredFinality === "finalized";

test("decodes and verifies exact finalized Solana JSON-RPC transaction evidence", async () => {
  const batch = fixture();
  const { fetch, calls } = rpcFetch(batch);
  const result = await verifySolanaBatchAnchor(batch, "solana:devnet", {
    mode: "solana-rpc",
    rpcUrl: "https://rpc.example",
    instructionDiscriminatorHex: DISCRIMINATOR,
    fetch
  }, trust);
  assert.deepEqual(result, { valid: true });
  assert.deepEqual(calls.map(({ request }) => request.method), ["getTransaction", "getSignatureStatuses", "getBlock"]);
  assert.equal(calls[0].request.params[1].commitment, "finalized");
  assert.equal(calls[2].request.params[0], 123);
});

test("does not call RPC until the caller authorizes cluster, endpoint, program and discriminator", async () => {
  const batch = fixture();
  const { fetch, calls } = rpcFetch(batch);
  const result = await verifySolanaBatchAnchor(batch, "solana:devnet", {
    mode: "solana-rpc",
    rpcUrl: "https://rpc.example",
    instructionDiscriminatorHex: DISCRIMINATOR,
    fetch
  }, () => false);
  assert.equal(result.valid, false);
  assert.equal(result.cause, "trust");
  assert.equal(calls.length, 0);
});

test("a throwing Solana trust resolver fails closed before network access", async () => {
  const batch = fixture();
  const { fetch, calls } = rpcFetch(batch);
  const result = await verifySolanaBatchAnchor(batch, "solana:devnet", {
    mode: "solana-rpc", rpcUrl: "https://rpc.example", instructionDiscriminatorHex: DISCRIMINATOR, fetch
  }, () => { throw new Error("trust registry unavailable"); });
  assert.equal(result.valid, false);
  assert.equal(result.cause, "trust");
  assert.equal(calls.length, 0);
});

for (const [name, mutate, message] of [
  ["finality", { getSignatureStatuses: { value: [{ slot: 123, err: null, confirmationStatus: "confirmed" }] } }, "not finalized"],
  ["transaction position", { getBlock: { signatures: [SIGNATURE, "other"] } }, "block position"],
  ["program", { getTransaction: { slot: 123, meta: { err: null }, transaction: { signatures: [SIGNATURE], message: { accountKeys: ["11111111111111111111111111111111"], instructions: [{ programIdIndex: 0, data: instructionData(fixture()) }] } } } }, "program or position"]
]) {
  test(`fails closed on ${name} mismatch`, async () => {
    const batch = fixture();
    const { fetch } = rpcFetch(batch, mutate);
    const result = await verifySolanaBatchAnchor(batch, "solana:devnet", {
      mode: "solana-rpc", rpcUrl: "https://rpc.example", instructionDiscriminatorHex: DISCRIMINATOR, fetch
    }, trust);
    assert.equal(result.valid, false);
    assert.match(result.message, new RegExp(message));
  });
}

test("fails closed when instruction root differs from the signed batch root", async () => {
  const batch = fixture();
  const encodedForOtherRoot = instructionData({ ...batch, root: "cd".repeat(32) });
  const { fetch } = rpcFetch(batch, {
    getTransaction: { slot: 123, meta: { err: null }, transaction: { signatures: [SIGNATURE], message: { accountKeys: [PROGRAM_ID], instructions: [{ programIdIndex: 0, data: encodedForOtherRoot }] } } }
  });
  const result = await verifySolanaBatchAnchor(batch, "solana:devnet", {
    mode: "solana-rpc", rpcUrl: "https://rpc.example", instructionDiscriminatorHex: DISCRIMINATOR, fetch
  }, trust);
  assert.equal(result.valid, false);
  assert.match(result.message, /root mismatch/);
});
