import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";

const root = new URL("../", import.meta.url);
const fixtureDirectory = process.env.CRINKL_VERIFY_FIXTURES_DIR;
const fixtureFile = (path) => fixtureDirectory
  ? resolve(fixtureDirectory, basename(path))
  : new URL(path, root);
const provenance = JSON.parse(readFileSync(fixtureFile("fixtures/provenance.json")));
const protocolDir = process.env.CRINKL_PROTOCOL_DIR ?? "../crinkl-protocol";
const sourceArtifacts = new Map();

function atPath(value, path, label) {
  let current = value;
  for (const part of path) {
    if (current === null || typeof current !== "object" || !(part in current)) {
      throw new Error(`Fixture provenance path is absent: ${label}.${String(part)}`);
    }
    current = current[part];
  }
  return current;
}

// Each artifact/binding defaults to `source.commit` (the legacy single pin)
// but MAY override it with its own `commit`, so fixtures reused from
// different points in crinkl-protocol history can coexist in one provenance
// file. Artifacts are keyed by `${commit}:${path}` since the same path can
// legitimately be pinned at more than one commit.
for (const artifact of provenance.artifacts) {
  const commit = artifact.commit ?? provenance.source.commit;
  const content = execFileSync(
    "git",
    ["-C", protocolDir, "show", `${commit}:${artifact.path}`],
    { encoding: "utf8" }
  );
  const digest = createHash("sha256").update(content).digest("hex");
  if (digest !== artifact.sha256) {
    throw new Error(`Fixture provenance mismatch for ${commit}:${artifact.path}: expected ${artifact.sha256}, got ${digest}`);
  }
  sourceArtifacts.set(`${commit}:${artifact.path}`, content);
}

const fixtures = new Map();
for (const binding of provenance.fixtureBindings) {
  const commit = binding.commit ?? provenance.source.commit;
  if (!fixtures.has(binding.fixture)) {
    const fixture = JSON.parse(readFileSync(fixtureFile(binding.fixture)));
    fixtures.set(binding.fixture, fixture);
  }
  const fixture = fixtures.get(binding.fixture);
  if (fixture.sourceCommit !== commit) {
    throw new Error(`Fixture source commit mismatch for ${binding.fixture}: expected ${commit}, got ${fixture.sourceCommit}`);
  }
  const sourceContent = sourceArtifacts.get(`${commit}:${binding.sourceArtifact}`);
  if (!sourceContent) throw new Error(`Fixture binding references an unpinned source artifact: ${commit}:${binding.sourceArtifact}`);
  const source = JSON.parse(sourceContent);
  const sourceCase = binding.sourceCaseId === undefined
    ? source
    : source.cases?.find((candidate) => candidate.id === binding.sourceCaseId);
  if (!sourceCase) throw new Error(`Fixture binding source case not found: ${binding.sourceCaseId}`);
  let expected = atPath(sourceCase, binding.sourcePath, `source:${binding.sourceCaseId ?? "root"}`);
  if (binding.sourceEncoding === "json") expected = JSON.parse(expected);
  const actual = atPath(fixture, binding.fixturePath, `fixture:${binding.fixture}`);
  if (!isDeepStrictEqual(actual, expected)) {
    throw new Error(`Fixture selection mismatch: ${binding.fixture} does not match ${binding.sourceCaseId}`);
  }
}

console.log("[fixtures] provenance and fixture bindings OK");
