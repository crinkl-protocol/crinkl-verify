import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as ed25519 from "@noble/ed25519";
import { computeNativeSpendAttestationTokenHash, verifyNativeSpendAttestation } from "../dist/index.js";

const fixture = JSON.parse(readFileSync(new URL("../fixtures/native-v1.json", import.meta.url)));
const seed = Uint8Array.from(Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex"));
const trust = ({ issuedBy, publicKeyBase64 }) =>
  issuedBy === fixture.case.token.signatures.issuedBy &&
  publicKeyBase64 === fixture.case.token.signatures.publicKey;

async function sign(token) {
  token.signatures.tokenHash = computeNativeSpendAttestationTokenHash(token);
  token.signatures.signature = Buffer.from(
    await ed25519.signAsync(Buffer.from(token.signatures.tokenHash, "hex"), seed)
  ).toString("base64");
  return token;
}

test("defaults to the released native protocol version", async () => {
  const token = structuredClone(fixture.case.token);
  token.protocol.protocolVersion = "999.0.0-unreleased";
  await sign(token);
  const result = await verifyNativeSpendAttestation(token, { issuerTrust: trust });
  assert.equal(result.cryptographicallyValid, false);
  assert.equal(result.errors[0].code, "UNSUPPORTED_PROTOCOL_VERSION");
});

test("takes one immutable inert snapshot before issuer trust", async () => {
  const original = structuredClone(fixture.case.token);
  const result = await verifyNativeSpendAttestation(original, {
    issuerTrust: ({ token }) => {
      assert.notEqual(token, original);
      assert.equal(Object.isFrozen(token), true);
      assert.equal(Object.isFrozen(token.canonical), true);
      assert.throws(() => { token.canonical.totalCents = "9999"; }, TypeError);
      original.canonical.totalCents = "9999";
      return true;
    }
  });
  assert.equal(result.cryptographicallyValid, true);
  assert.equal(result.issuerAuthorized, true);
  assert.deepEqual(result.errors, []);
});

test("rejects getters and proxies before they can change the signed view", async () => {
  const getterToken = structuredClone(fixture.case.token);
  Object.defineProperty(getterToken.canonical, "totalCents", {
    enumerable: true,
    get: () => "1234"
  });
  const getterResult = await verifyNativeSpendAttestation(getterToken, { issuerTrust: trust });
  assert.equal(getterResult.errors[0].code, "SCHEMA_INVALID");

  const proxyResult = await verifyNativeSpendAttestation(new Proxy(fixture.case.token, {}), { issuerTrust: trust });
  assert.equal(proxyResult.errors[0].code, "SCHEMA_INVALID");
});

for (const [name, mutate] of [
  ["undefined", (token) => { token.canonical.totalCents = undefined; }],
  ["function", (token) => { token.canonical.totalCents = () => "1234"; }],
  ["symbol", (token) => { token.canonical.totalCents = Symbol("amount"); }],
  ["bigint", (token) => { token.canonical.totalCents = 1n; }],
  ["NaN", (token) => { token.lineage.eventCount = Number.NaN; }],
  ["Infinity", (token) => { token.lineage.eventCount = Number.POSITIVE_INFINITY; }],
  ["sparse array", (token) => { token.zk = { commitments: ["x", , "y"] }; }],
  ["custom prototype", (token) => { token.canonical = Object.assign(Object.create({ inherited: true }), token.canonical); }],
  ["unpaired surrogate", (token) => { token.spendId = "bad\ud800"; }]
]) {
  test(`rejects ${name} as non-inert JSON`, async () => {
    const token = structuredClone(fixture.case.token);
    mutate(token);
    const result = await verifyNativeSpendAttestation(token, { issuerTrust: trust });
    assert.equal(result.cryptographicallyValid, false);
    assert.equal(result.errors[0].code, "SCHEMA_INVALID");
  });
}

test("rejects cycles as non-inert JSON", async () => {
  const token = structuredClone(fixture.case.token);
  token.canonical.self = token.canonical;
  const result = await verifyNativeSpendAttestation(token, { issuerTrust: trust });
  assert.equal(result.errors[0].code, "SCHEMA_INVALID");
});

test("enforces exact unsigned signatures and all present V1 optional fields", async () => {
  const signatureExtra = structuredClone(fixture.case.token);
  signatureExtra.signatures.debug = "not-signed";
  const extraResult = await verifyNativeSpendAttestation(signatureExtra, { issuerTrust: trust });
  assert.equal(extraResult.errors[0].code, "SCHEMA_INVALID");

  for (const [path, mutate] of [
    ["wallet", (token) => { token.wallet = ""; }],
    ["storeHash", (token) => { token.canonical.storeHash = "sha256:UPPER"; }],
    ["date", (token) => { token.canonical.date = "2024-02-30"; }],
    ["totalCents", (token) => { token.canonical.totalCents = "-1"; }],
    ["currency", (token) => { token.canonical.currency = "usd"; }],
    ["timestamp", (token) => { token.canonical.timestamp = "2024-01-01T00:00:00Z"; }],
    ["geoRegion", (token) => { token.canonical.geoRegion = "california"; }],
    ["cbsaCode", (token) => { token.canonical.cbsaCode = "UNKNOWN"; }],
    ["verificationVersion", (token) => { token.canonical.verificationVersion = "version-one"; }],
    ["zk commitments", (token) => { token.zk = { commitments: { C_store: "opaque" } }; }]
  ]) {
    const token = structuredClone(fixture.case.token);
    mutate(token);
    const result = await verifyNativeSpendAttestation(token, { issuerTrust: trust });
    assert.equal(result.errors[0].code, "SCHEMA_INVALID", path);
  }

  const extended = structuredClone(fixture.case.token);
  extended.canonical.geoRegion = "US-CA";
  extended.canonical.cbsaCode = "Unknown";
  extended.zk = { commitments: { C_store: "opaque", C_total: "opaque", C_dayIndex: "opaque", C_geoRegion: "opaque" } };
  await sign(extended);
  const extendedResult = await verifyNativeSpendAttestation(extended, { issuerTrust: trust });
  assert.equal(extendedResult.cryptographicallyValid, true);
  assert.equal(extendedResult.issuerAuthorized, true);
});

test("rejects noncanonical RFC 4648 Base64 aliases", async () => {
  const whitespaceKey = structuredClone(fixture.case.token);
  whitespaceKey.signatures.publicKey = ` ${whitespaceKey.signatures.publicKey}`;
  const whitespaceResult = await verifyNativeSpendAttestation(whitespaceKey, { issuerTrust: trust });
  assert.equal(whitespaceResult.errors[0].code, "SCHEMA_INVALID");

  const unpaddedSignature = structuredClone(fixture.case.token);
  unpaddedSignature.signatures.signature = unpaddedSignature.signatures.signature.slice(0, -2);
  const unpaddedResult = await verifyNativeSpendAttestation(unpaddedSignature, { issuerTrust: trust });
  assert.equal(unpaddedResult.errors[0].code, "SCHEMA_INVALID");

  const alteredPadBits = structuredClone(fixture.case.token);
  alteredPadBits.signatures.signature = `${alteredPadBits.signatures.signature.slice(0, -3)}h==`;
  const alteredPadBitsResult = await verifyNativeSpendAttestation(alteredPadBits, { issuerTrust: trust });
  assert.equal(alteredPadBitsResult.errors[0].code, "SCHEMA_INVALID");
});

test("keeps unknown signed extensions hash-bound while rejecting unsigned signature extras", async () => {
  const token = structuredClone(fixture.case.token);
  token.extension = { future: "signed" };
  token.canonical.futureCanonicalField = "signed";
  token.lineage.futureLineageField = "signed";
  token.protocol.futureProtocolField = "signed";
  token.zk = { witness: "signed-but-not-interpreted" };
  await sign(token);
  const result = await verifyNativeSpendAttestation(token, { issuerTrust: trust });
  assert.equal(result.cryptographicallyValid, true);
  assert.equal(result.issuerAuthorized, true);
});

test("fixture provenance rejects local fixture substitution", () => {
  const directory = mkdtempSync(join(tmpdir(), "crinkl-verify-fixture-test-"));
  try {
    for (const file of ["provenance.json", "native-v1.json", "native-v1-additional.json"]) {
      writeFileSync(join(directory, file), readFileSync(new URL(`../fixtures/${file}`, import.meta.url)));
    }
    const substituted = JSON.parse(readFileSync(join(directory, "native-v1.json")));
    substituted.case.token.spendId = "substituted";
    writeFileSync(join(directory, "native-v1.json"), JSON.stringify(substituted));
    assert.throws(() => execFileSync("node", ["scripts/verify-fixture-provenance.mjs"], {
      env: { ...process.env, CRINKL_PROTOCOL_DIR: "/home/azureuser/crinkl-protocol", CRINKL_VERIFY_FIXTURES_DIR: directory },
      stdio: "pipe"
    }), /Fixture selection mismatch/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
