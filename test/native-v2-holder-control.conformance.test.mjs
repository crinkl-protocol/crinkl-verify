import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as ed25519 from "@noble/ed25519";
import {
  computeNativeSpendAttestationTokenHash,
  detectArtifactFormat,
  verify,
  verifyNativeSpendAttestation,
  verifySpendHolderControl
} from "../dist/index.js";

const fixture = JSON.parse(readFileSync(new URL("../fixtures/spend-attestation-holder-binding-v2.json", import.meta.url))).vector;
const { valid } = fixture;
const issuerSeed = Uint8Array.from(Buffer.from(fixture.issuerKeyMaterial.privateKeySeedHex, "hex"));

function completeToken(unsigned = valid.unsignedToken) {
  return {
    ...structuredClone(unsigned),
    signatures: {
      issuedBy: valid.issuerSignature.issuedBy,
      publicKey: valid.issuerSignature.publicKeyBase64,
      tokenHash: valid.issuerSignature.tokenHashHex,
      signature: valid.issuerSignature.signatureBase64
    }
  };
}

const trust = ({ issuedBy, publicKeyBase64, protocolVersion }) =>
  issuedBy === valid.issuerSignature.issuedBy &&
  publicKeyBase64 === valid.issuerSignature.publicKeyBase64 && protocolVersion === "1.0.0-rc.1";

function options(overrides = {}) {
  return {
    issuerTrust: trust,
    expectedContext: {
      spendTokenHash: valid.challenge.spendTokenHash,
      scopeId: valid.challenge.scopeId,
      requestContextHash: valid.challenge.requestContextHash,
      purpose: valid.challenge.purpose,
      verifierId: valid.challenge.verifierId
    },
    now: valid.verificationTime,
    authenticateChallenge: () => true,
    consumeChallenge: () => true,
    ...overrides
  };
}

async function signV2(unsigned) {
  const token = structuredClone(unsigned);
  const tokenHash = computeNativeSpendAttestationTokenHash(token);
  return {
    ...token,
    signatures: {
      issuedBy: valid.issuerSignature.issuedBy,
      publicKey: valid.issuerSignature.publicKeyBase64,
      tokenHash,
      signature: Buffer.from(await ed25519.signAsync(Buffer.from(tokenHash, "hex"), issuerSeed)).toString("base64")
    }
  };
}

test("verifies the pinned SpendAttestationTokenV2 holder-control vector", async () => {
  const token = completeToken();
  assert.equal(detectArtifactFormat(token), "crinkl-native-spend-attestation/v2");
  assert.equal(computeNativeSpendAttestationTokenHash(valid.unsignedToken), valid.issuerSignature.tokenHashHex);
  const spend = await verifyNativeSpendAttestation(token, { issuerTrust: trust });
  assert.equal(spend.cryptographicallyValid, true);
  assert.equal(spend.issuerAuthorized, true);
  assert.equal(spend.current, "unknown");
  assert.deepEqual(spend.errors, []);
  const holder = await verifySpendHolderControl(token, valid.challenge, valid.holderProof, options());
  assert.deepEqual({ accepted: holder.accepted, code: holder.code }, valid.expectedDecision);
});

test("matches all released holder-binding negative decisions", async () => {
  for (const vectorCase of fixture.negativeCases) {
    const token = completeToken();
    const challenge = structuredClone(valid.challenge);
    const proof = structuredClone(valid.holderProof);
    let inputOptions = options();
    if (vectorCase.id === "holder-binding-wrong-key") proof.holderPublicKeyBase64 = fixture.keyMaterial.wrongPublicKeyBase64;
    if (vectorCase.id === "holder-binding-wrong-signature") {
      const bytes = Buffer.from(proof.signatureBase64, "base64");
      bytes[0] ^= 1;
      proof.signatureBase64 = bytes.toString("base64");
    }
    if (vectorCase.id === "holder-binding-changed-scope") {
      challenge.scopeId = `sha256:${"c".repeat(64)}`;
      inputOptions = options({ expectedContext: { ...options().expectedContext, scopeId: challenge.scopeId } });
    }
    if (vectorCase.id === "holder-binding-changed-request") {
      challenge.requestContextHash = `sha256:${"e".repeat(64)}`;
      inputOptions = options({ expectedContext: { ...options().expectedContext, requestContextHash: challenge.requestContextHash } });
    }
    if (vectorCase.id === "holder-binding-expired") inputOptions = options({ now: "2026-07-28T00:05:00.000Z" });
    if (vectorCase.id === "holder-binding-replayed") inputOptions = options({ consumeChallenge: () => false });
    if (vectorCase.id === "holder-binding-absent") {
      const unsigned = structuredClone(valid.unsignedToken);
      delete unsigned.holderBinding;
      const absentResult = await verifySpendHolderControl(await signV2(unsigned), challenge, proof, inputOptions);
      assert.deepEqual(
        { accepted: absentResult.tokenVerification.cryptographicallyValid && absentResult.tokenVerification.issuerAuthorized === true, code: absentResult.code },
        { accepted: true, code: vectorCase.expectedHolderDecision.code },
        vectorCase.id
      );
      continue;
    }
    const holder = await verifySpendHolderControl(token, challenge, proof, inputOptions);
    assert.deepEqual({ accepted: holder.accepted, code: holder.code }, vectorCase.expectedDecision, vectorCase.id);
  }
});

test("fails closed for malformed V2 binding, unknown native schema, and expected-context mismatch", async () => {
  const malformed = completeToken();
  malformed.holderBinding = { scheme: "crinkl.holder.v2", commitment: "sha256:UPPER" };
  const malformedResult = await verifyNativeSpendAttestation(malformed, { issuerTrust: trust });
  assert.equal(malformedResult.errors[0].code, "SCHEMA_INVALID");

  const unknown = structuredClone(completeToken());
  unknown.schemaVersion = 3;
  const unknownResult = await verify(unknown, { issuerTrust: trust });
  assert.equal(unknownResult.errors[0].code, "UNKNOWN_SCHEMA_VERSION");

  let consumed = 0;
  const mismatch = await verifySpendHolderControl(completeToken(), valid.challenge, valid.holderProof, options({
    expectedContext: { ...options().expectedContext, verifierId: "another-verifier" },
    consumeChallenge: () => { consumed += 1; return true; }
  }));
  assert.equal(mismatch.code, "holder_expected_context_mismatch");
  assert.equal(consumed, 0);
});

test("consumes only after every holder check and treats an atomic consume race as replay", async () => {
  let calls = 0;
  const invalidProof = structuredClone(valid.holderProof);
  const invalidSignature = Buffer.from(invalidProof.signatureBase64, "base64");
  invalidSignature[0] ^= 1;
  invalidProof.signatureBase64 = invalidSignature.toString("base64");
  const invalid = await verifySpendHolderControl(completeToken(), valid.challenge, invalidProof, options({
    consumeChallenge: () => { calls += 1; return true; }
  }));
  assert.equal(invalid.code, "holder_signature_invalid");
  assert.equal(calls, 0);

  const raced = await verifySpendHolderControl(completeToken(), valid.challenge, valid.holderProof, options({
    consumeChallenge: () => { calls += 1; return false; }
  }));
  assert.equal(raced.code, "holder_challenge_replayed");
  assert.equal(calls, 1);
});

test("fails closed for challenge time boundaries and callback exceptions", async () => {
  const overlong = structuredClone(valid.challenge);
  overlong.expiresAt = "2026-07-28T00:05:00.001Z";
  assert.equal(
    (await verifySpendHolderControl(completeToken(), overlong, valid.holderProof, options())).code,
    "holder_challenge_expired"
  );

  const future = structuredClone(valid.challenge);
  future.issuedAt = "2026-07-28T00:02:00.001Z";
  future.expiresAt = "2026-07-28T00:05:00.000Z";
  assert.equal(
    (await verifySpendHolderControl(completeToken(), future, valid.holderProof, options())).code,
    "holder_challenge_expired"
  );

  let consumed = 0;
  const authenticationError = await verifySpendHolderControl(completeToken(), valid.challenge, valid.holderProof, options({
    authenticateChallenge: () => { throw new Error("store unavailable"); },
    consumeChallenge: () => { consumed += 1; return true; }
  }));
  assert.equal(authenticationError.code, "holder_challenge_invalid");
  assert.equal(consumed, 0);

  const consumeError = await verifySpendHolderControl(completeToken(), valid.challenge, valid.holderProof, options({
    consumeChallenge: () => { throw new Error("store unavailable"); }
  }));
  assert.equal(consumeError.code, "holder_challenge_replayed");
});

test("retains signed V2 extensions in the native token hash preimage", async () => {
  const unsigned = structuredClone(valid.unsignedToken);
  unsigned.extension = { future: "signed" };
  unsigned.canonical.futureCanonicalField = "signed";
  const result = await verifyNativeSpendAttestation(await signV2(unsigned), { issuerTrust: trust });
  assert.equal(result.cryptographicallyValid, true);
  assert.equal(result.issuerAuthorized, true);
  assert.deepEqual(result.errors, []);
});

test("accepts the V2 commitment shape without changing holderBinding or legacy geography behavior", async () => {
  const required = { C_store: "opaque-store", C_total: "opaque-total", C_dayIndex: "opaque-day" };
  for (const [name, optional] of [
    ["none", {}],
    ["currency", { C_currency: "opaque-currency" }],
    ["geo region", { C_geoRegion: "opaque-geo" }],
    ["CBSA code", { C_cbsaCode: "opaque-cbsa" }]
  ]) {
    const commitmentToken = structuredClone(valid.unsignedToken);
    commitmentToken.zk = { commitments: { ...required, ...optional } };
    const commitmentResult = await verifyNativeSpendAttestation(await signV2(commitmentToken), { issuerTrust: trust });
    assert.equal(commitmentResult.cryptographicallyValid, true, name);
    assert.equal(commitmentResult.issuerAuthorized, true, name);
    assert.deepEqual(commitmentResult.errors, [], name);
  }

  const legacyGeography = structuredClone(valid.unsignedToken);
  legacyGeography.canonical.geoRegion = "US-CA";
  legacyGeography.canonical.cbsaCode = "12420";
  const legacyResult = await verifyNativeSpendAttestation(await signV2(legacyGeography), { issuerTrust: trust });
  assert.equal(legacyResult.cryptographicallyValid, true);
  assert.equal(legacyResult.issuerAuthorized, true);
  assert.equal(legacyResult.errors.length, 0);
});

test("independent signed-token tamper probe rejects a changed holder commitment before control verification", async () => {
  const token = completeToken();
  token.holderBinding.commitment = `sha256:${"0".repeat(64)}`;
  const result = await verifyNativeSpendAttestation(token, { issuerTrust: trust });
  assert.equal(result.errors[0].code, "TOKEN_HASH_MISMATCH");
});
