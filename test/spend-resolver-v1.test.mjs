import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { verifyPwaSpendResolverBundleV1 } from "../dist/index.js";

const fixture=JSON.parse(readFileSync(new URL("../fixtures/pwa-spend-resolver-v1.json",import.meta.url)));
const verify=(bundle=fixture.bundle, options={})=>verifyPwaSpendResolverBundleV1(bundle,{bootstrapAuthority:fixture.bootstrapAuthority,...options});

test("verifies a fixture-only P3.1h resolver bundle without current reliance",async()=>{
 const result=await verify();
 assert.equal(result.verified,true);assert.equal(result.currentReliance,false);
 assert.equal(result.facts.expectedIssuer,"crinkl-authority");
});
test("uses distinct fixture authorities, the exact source signer tuple, and a cutoff-valid ended issuer key",async()=>{
 const {manifest,issuerSetSnapshot,headSetSnapshot,spendToken}=fixture.bundle;
 assert.notEqual(fixture.bootstrapAuthority.publicKey,issuerSetSnapshot.signatures.publicKey);
 assert.notEqual(issuerSetSnapshot.signatures.publicKey,spendToken.signatures.publicKey);
 assert.equal(manifest.publisherAuthorityPolicy.authorizedSigners[0].issuedBy,"fixture.publisher.decoy");
 assert.equal(issuerSetSnapshot.signatures.issuedBy,"fixture.publisher.distinct");
 assert.ok(Date.parse(headSetSnapshot.generatedAt)>=Date.parse(headSetSnapshot.asOf));
 const cutoffKey=issuerSetSnapshot.keys.find(key=>key.issuerId==="crinkl-authority");
 assert.equal(cutoffKey.validUntil,"2026-09-01T00:00:00.000Z");
 assert.ok(cutoffKey.terminationRef);
 assert.equal((await verify()).verified,true);
 const wrongTuple=structuredClone(fixture.bundle);wrongTuple.issuerSetSnapshot.signatures.issuedBy="fixture.publisher.decoy";
 assert.equal((await verify(wrongTuple)).error,"RESOLVER_SOURCE_AUTHORITY_MISMATCH");
});
test("derives the expected issuer from the sole accepted issuer in single-issuer mode",async()=>{
 const single=structuredClone(fixture.bundle);single.manifest=fixture.singleIssuerManifest;
 const result=await verify(single);
 assert.equal(result.verified,true);
 assert.equal(result.facts.expectedIssuer,"crinkl-authority");
});
test("fails closed for altered signed bytes, proof tuple, stale UX, and caller-free issuer selection",async()=>{
 const signed=structuredClone(fixture.bundle);signed.manifest.freshness.maximumAgeSeconds=901;
 assert.equal((await verify(signed)).error,"RESOLVER_MANIFEST_HASH_MISMATCH");
 const proof=structuredClone(fixture.bundle);proof.headInclusionProof.leaf.spendId="other";
 assert.equal((await verify(proof)).error,"RESOLVER_LEAF_PROOF_INVALID");
 assert.equal((await verify(fixture.bundle,{now:"2026-08-31T00:16:00.001Z"})).error,"RESOLVER_STALE");
 const caller=structuredClone(fixture.bundle);caller.manifest.issuerPolicy.expectedIssuerBinding="CALLER_EXACT_ACCEPTED_MEMBER";
 assert.equal((await verify(caller)).verified,false);
});
test("rejects rollback, predecessor gap, and equivocation from caller-held accepted state",async()=>{
 const ref=`sha256:${fixture.bundle.manifest.signatures.tokenHash}`;
 const state=[{manifestSeriesId:"fixture-main",sequence:1,manifestRef:ref}];
 assert.equal((await verify(fixture.bundle,{acceptedManifestState:state})).error,"RESOLVER_CONTINUITY_REJECTED");
 const same=[{manifestSeriesId:"fixture-main",sequence:0,manifestRef:"sha256:"+"d".repeat(64)}];
 assert.equal((await verify(fixture.bundle,{acceptedManifestState:same})).error,"RESOLVER_CONTINUITY_REJECTED");
});
test("requires exact verified predecessors and rejects cached manifest/source equivocation",async()=>{
 const manifest=structuredClone(fixture.bundle);manifest.manifest=fixture.manifestSequenceOne;
 assert.equal((await verify(manifest)).error,"RESOLVER_CONTINUITY_REJECTED");
 const manifestRef=`sha256:${fixture.bundle.manifest.signatures.tokenHash}`;
 assert.equal((await verify(manifest,{acceptedManifestState:[{manifestSeriesId:"fixture-main",sequence:0,manifestRef}]})).verified,true);
 assert.equal((await verify(manifest,{acceptedManifestState:[{manifestSeriesId:"fixture-main",sequence:0,manifestRef},{manifestSeriesId:"fixture-main",sequence:0,manifestRef:"sha256:"+"f".repeat(64)}]})).error,"RESOLVER_CONTINUITY_REJECTED");
 const source=fixture.sourceSequenceOneBundle;
 assert.equal((await verify(source)).error,"RESOLVER_CONTINUITY_REJECTED");
 const issuerRef=`sha256:${fixture.bundle.issuerSetSnapshot.signatures.tokenHash}`,headRef=`sha256:${fixture.bundle.headSetSnapshot.signatures.tokenHash}`;
 const sourceState={acceptedIssuerSetSnapshotState:[{issuerSetId:"fixture-issuers",sequence:0,issuerSetSnapshotRef:issuerRef}],acceptedHeadSetSnapshotState:[{headSetId:"fixture-heads",sequence:0,headSetSnapshotRef:headRef}]};
 assert.equal((await verify(source,sourceState)).verified,true);
 assert.equal((await verify(source,{...sourceState,acceptedHeadSetSnapshotState:[...sourceState.acceptedHeadSetSnapshotState,{headSetId:"fixture-heads",sequence:0,headSetSnapshotRef:"sha256:"+"e".repeat(64)}]})).error,"RESOLVER_CONTINUITY_REJECTED");
});
test("rejects malformed nested source members, noncanonical source order, cutoff gaps, and invalid proof/time inputs",async()=>{
 const malformed=structuredClone(fixture.bundle);malformed.manifest.publisherAuthorityPolicy.authorizedSigners[1].artifactTypes.push("EXTRA");
 assert.equal((await verify(malformed)).error,"RESOLVER_BUNDLE_SCHEMA_INVALID");
 const unsorted=structuredClone(fixture.bundle);unsorted.issuerSetSnapshot.keys.reverse();
 assert.equal((await verify(unsorted)).error,"RESOLVER_BUNDLE_SCHEMA_INVALID");
 const paired=structuredClone(fixture.bundle);paired.issuerSetSnapshot.keys[0].terminationRef=null;
 assert.equal((await verify(paired)).error,"RESOLVER_BUNDLE_SCHEMA_INVALID");
 const coverage=structuredClone(fixture.bundle);coverage.headSetSnapshot.coveredIssuerIds.reverse();
 assert.equal((await verify(coverage)).error,"RESOLVER_ISSUER_POLICY_REJECTED");
 const inactive=structuredClone(fixture.bundle);inactive.issuerSetSnapshot.keys[1].validFrom="2026-09-01T00:00:00.000Z";
 assert.equal((await verify(inactive)).error,"RESOLVER_ISSUER_POLICY_REJECTED");
 const late=structuredClone(fixture.bundle);late.headInclusionProof.leaf.headAdmittedAt="2026-09-01T00:00:00.000Z";
 assert.equal((await verify(late)).error,"RESOLVER_LEAF_PROOF_INVALID");
 const wrongIssuer=structuredClone(fixture.bundle);wrongIssuer.headInclusionProof.leaf.issuerId="issuer.unknown";
 assert.equal((await verify(wrongIssuer)).error,"RESOLVER_LEAF_PROOF_INVALID");
 const deep=structuredClone(fixture.bundle);deep.headInclusionProof.siblings.push("a".repeat(64));
 assert.equal((await verify(deep)).error,"RESOLVER_LEAF_PROOF_INVALID");
 assert.equal((await verify(fixture.bundle,{now:"not-a-clock"})).error,"RESOLVER_BUNDLE_SCHEMA_INVALID");
});
