import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  computeNativeSpendAttestationTokenHash,
  verifyNativeSpendAttestation
} from "../dist/index.js";

const fixture = JSON.parse(readFileSync(new URL("../fixtures/native-v1.json", import.meta.url)));
const additional = JSON.parse(readFileSync(new URL("../fixtures/native-v1-additional.json", import.meta.url)));
const trust = ({ issuedBy, publicKeyBase64, protocolVersion }) =>
  issuedBy === "crinkl-authority" &&
  publicKeyBase64 === fixture.case.token.signatures.publicKey &&
  protocolVersion === "1.0.0-rc.1";

test("accepts the pinned released native V1 vector cryptographically and by issuer trust", async () => {
  const result = await verifyNativeSpendAttestation(fixture.case.token, {
    issuerTrust: trust,
    supportedProtocolVersions: ["1.0.0-rc.1"]
  });
  assert.equal(result.cryptographicallyValid, true);
  assert.equal(result.issuerAuthorized, true);
  assert.equal(result.current, "unknown");
  assert.equal(result.accepted, false, "offline verification must not assert freshness/currentness");
  assert.deepEqual(result.errors, []);
});

for (const hashCase of fixture.hashOnlyCases) {
  test(`matches released native V1 hash vector ${hashCase.id}`, () => {
    assert.equal(
      computeNativeSpendAttestationTokenHash(hashCase.unsignedToken),
      hashCase.expectedTokenHashHex
    );
  });
}

for (const vectorCase of additional.cases) {
  test(`verifies released native V1 vector ${vectorCase.id}`, async () => {
    const result = await verifyNativeSpendAttestation(vectorCase.token, {
      issuerTrust: trust,
      supportedProtocolVersions: ["1.0.0-rc.1"]
    });
    assert.equal(result.cryptographicallyValid, true);
    assert.equal(result.issuerAuthorized, true);
    if (vectorCase.token.canonical.status === "INVALIDATED") {
      assert.equal(result.current, false);
      assert.equal(result.errors.at(-1).code, "POLICY_REJECTED");
    }
  });
}

test("rejects a tampered native claim", async () => {
  const token = structuredClone(fixture.case.token);
  token.canonical.totalCents = "9999";
  const result = await verifyNativeSpendAttestation(token, { issuerTrust: trust });
  assert.equal(result.cryptographicallyValid, false);
  assert.equal(result.errors[0].code, "TOKEN_HASH_MISMATCH");
});

test("rejects a cryptographically valid token from an untrusted issuer key", async () => {
  const result = await verifyNativeSpendAttestation(fixture.case.token, { issuerTrust: () => false });
  assert.equal(result.cryptographicallyValid, true);
  assert.equal(result.issuerAuthorized, false);
  assert.equal(result.errors.at(-1).code, "UNTRUSTED_ISSUER");
});
