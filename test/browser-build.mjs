import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import test from "node:test";
import { build } from "esbuild";

const fixture = JSON.parse(readFileSync(new URL("../fixtures/reward-commitment-v1.json", import.meta.url)));
const fixtureCase = fixture.cases.find((candidate) => candidate.id === "rewardCommitment.v1.committedBacked.2a");

test("browser bundle verifies reward commitments and linked spends without Node runtime modules", async () => {
  const source = `
    import { verifyRewardCommitmentV1, verifySpendWithRewardCommitment } from "../dist/index.js";
    const fixture = ${JSON.stringify(fixtureCase)};
    const authorityTrust = async ({ chainId, authorityId, publicKeyBase64 }) =>
      chainId === fixture.token.chainId &&
      authorityId === fixture.genesisAuthorityId &&
      publicKeyBase64 === fixture.genesisPublicKeyBase64;
    const issuerTrust = ({ issuedBy, publicKeyBase64 }) =>
      issuedBy === fixture.spendIssuer.issuedBy && publicKeyBase64 === fixture.spendIssuer.publicKeyBase64;
    globalThis.browserVerification = Promise.all([
      verifyRewardCommitmentV1(fixture.token, { authorityTrust }),
      verifySpendWithRewardCommitment(fixture.spendToken, fixture.token, {
        issuerTrust,
        rewardCommitment: { authorityTrust }
      })
    ]);
  `;
  const result = await build({
    absWorkingDir: new URL("..", import.meta.url).pathname,
    bundle: true,
    format: "iife",
    platform: "browser",
    stdin: { contents: source, resolveDir: "test", sourcefile: "browser-entry.mjs" },
    write: false
  });
  const bundle = result.outputFiles[0].text;
  assert.doesNotMatch(bundle, /node:(?:util|assert|buffer|crypto|fs|path|os|child_process)/);

  const context = vm.createContext({
    TextDecoder,
    TextEncoder,
    atob,
    btoa,
    crypto: globalThis.crypto,
    structuredClone
  });
  vm.runInContext(bundle, context, { filename: "crinkl-verify.browser.js" });
  const [reward, composite] = await context.browserVerification;
  assert.equal(reward.accepted, true);
  assert.equal(composite.tier, "committed-backed");
  assert.equal(composite.linkage, "verified");
});
