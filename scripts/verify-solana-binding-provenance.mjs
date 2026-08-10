import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const fixture = JSON.parse(readFileSync(new URL("fixtures/solana-platform-create-batch-imprint-v1.json", root)));
const provenance = JSON.parse(readFileSync(new URL("fixtures/solana-platform-create-batch-imprint-v1.provenance.json", root)));
const repositories = {
  "crinkl-platform": process.env.CRINKL_PLATFORM_DIR ?? "../crinkl-platform",
  "crinkl-onchain-processor": process.env.CRINKL_ONCHAIN_PROCESSOR_DIR ?? "../crinkl-onchain-processor"
};

if (fixture.binding !== provenance.binding) throw new Error("Solana binding identity mismatch");
for (const source of provenance.sources) {
  const repository = repositories[source.repository];
  if (!repository) throw new Error(`Unknown source repository: ${source.repository}`);
  const blob = execFileSync("git", ["-C", repository, "rev-parse", `${source.commit}:${source.path}`], { encoding: "utf8" }).trim();
  if (blob !== source.gitBlob) throw new Error(`Source blob mismatch: ${source.repository}@${source.commit}:${source.path}`);
}
for (const [method, expected] of Object.entries(provenance.rpcEvidence.sha256Json)) {
  const digest = createHash("sha256").update(JSON.stringify(fixture.responses[method])).digest("hex");
  if (digest !== expected) throw new Error(`RPC fixture digest mismatch: ${method}`);
}
if (fixture.signature !== provenance.rpcEvidence.signature || fixture.slot !== provenance.rpcEvidence.slot) {
  throw new Error("RPC fixture transaction identity mismatch");
}
console.log("[solana-binding] source blobs and raw RPC fixture digests OK");
