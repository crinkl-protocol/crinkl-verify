import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { detectArtifactFormat, verify, verifyNativeSpendAttestation, verifyW3cSpendAttestation } from "../dist/index.js";

const fixture = JSON.parse(readFileSync(new URL("../fixtures/native-v1.json", import.meta.url)));

test("detects a native V1 token", () => {
  assert.equal(detectArtifactFormat(fixture.case.token), "crinkl-native-spend-attestation/v1");
});

test("rejects unsupported input without throwing", async () => {
  const result = await verify({ hello: "world" });
  assert.equal(result.accepted, false);
  assert.equal(result.errors[0].code, "UNSUPPORTED_FORMAT");
});

test("exposes no hidden-network W3C fail-closed boundary", async () => {
  const result = await verifyW3cSpendAttestation({ type: ["VerifiableCredential", "SpendAttestationCredential"] });
  assert.equal(result.cryptographicallyValid, false);
  assert.equal(result.errors[0].code, "UNSUPPORTED_PROFILE_VERSION");
  assert.equal(result.warnings[0].code, "EXPERIMENTAL_W3C_PROFILE");
});

test("fails closed for an unsupported native protocol version", async () => {
  const token = structuredClone(fixture.case.token);
  token.protocol.protocolVersion = "9.9.9";
  const result = await verifyNativeSpendAttestation(token, { supportedProtocolVersions: ["1.0.0-rc.1"] });
  assert.equal(result.errors[0].code, "UNSUPPORTED_PROTOCOL_VERSION");
});
