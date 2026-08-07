import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const provenance = JSON.parse(readFileSync(new URL("../fixtures/provenance.json", import.meta.url)));
for (const artifact of provenance.artifacts) {
  const content = execFileSync(
    "git",
    ["-C", process.env.CRINKL_PROTOCOL_DIR ?? "../crinkl-protocol", "show", `${provenance.source.commit}:${artifact.path}`],
    { encoding: "utf8" }
  );
  const digest = createHash("sha256").update(content).digest("hex");
  if (digest !== artifact.sha256) {
    throw new Error(`Fixture provenance mismatch for ${artifact.path}: expected ${artifact.sha256}, got ${digest}`);
  }
}
console.log("[fixtures] provenance OK");
