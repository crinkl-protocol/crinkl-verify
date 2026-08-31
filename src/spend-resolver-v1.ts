import { base64ToBytes, canonicalizeJcs, hexToBytes, sha256HexUtf8, verifyEd25519 } from "./crypto.js";
import { createInertJsonSnapshot, type JsonValue } from "./json.js";
import { verifyInclusionProof } from "./merkle.js";
import { verifyNativeSpendAttestationSnapshot } from "./native-v1.js";
import type {
  PwaSpendResolverErrorCode, PwaSpendResolverVerificationOptions,
  PwaSpendResolverVerificationResult
} from "./types.js";

type Obj = Record<string, JsonValue>;
type PublisherSigner = { issuedBy:string; keyId:string; publicKey:string; artifactTypes:readonly string[] };
type IssuerKey = { issuerId:string; keyId:string; publicKey:string; validFrom:string; validUntil:string|null; terminationRef:string|null };
type SeriesState = { series:string; sequence:number; ref:string };
const HASH=/^[0-9a-f]{64}$/; const REF=/^sha256:[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const B64=/^[A-Za-z0-9+/]+={0,2}$/;
class Reject extends Error { constructor(readonly code:PwaSpendResolverErrorCode){super(code);} }
const fail=(code:PwaSpendResolverErrorCode):never=>{throw new Reject(code);};
function obj(v:JsonValue|undefined):Obj|undefined{return v!==null&&typeof v==="object"&&!Array.isArray(v)?v as Obj:undefined;}
function exact(v:JsonValue|undefined, keys:readonly string[], code:PwaSpendResolverErrorCode):Obj { const r=obj(v); if(!r||Object.keys(r).length!==keys.length||!keys.every(k=>Object.prototype.hasOwnProperty.call(r,k))) return fail(code); return r; }
function str(v:JsonValue|undefined, pattern:RegExp=/.+/):string { if(typeof v!=="string"||!pattern.test(v)) return fail("RESOLVER_BUNDLE_SCHEMA_INVALID"); return v; }
function b64(v:JsonValue|undefined):string { return str(v,B64); }
function integer(v:JsonValue|undefined):number { if(typeof v!=="number"||!Number.isSafeInteger(v)||v<0)return fail("RESOLVER_BUNDLE_SCHEMA_INVALID");return v; }
function timestamp(v:JsonValue|undefined):string { const s=str(v,/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);if(new Date(s).toISOString()!==s)fail("RESOLVER_BUNDLE_SCHEMA_INVALID");return s; }
function ref(v:JsonValue|undefined):string{return str(v,REF);} function hash(v:JsonValue|undefined):string{return str(v,HASH);}
function exactStrings(value:JsonValue|undefined, expected:readonly string[]):boolean{return Array.isArray(value)&&value.length===expected.length&&expected.every((item,index)=>value[index]===item);}
function canonicalIds(value:JsonValue|undefined, code:PwaSpendResolverErrorCode):string[] { if(!Array.isArray(value))fail(code);const ids=(value as readonly JsonValue[]).map((item:JsonValue)=>str(item,ID));if(!ids.length||new Set(ids).size!==ids.length||ids.some((id,index)=>index>0&&ids[index-1]!>=id))fail(code);return ids; }
function unsigned(value:Obj):Obj { const r:Obj=Object.create(null);for(const k of Object.keys(value))if(k!=="signatures")r[k]=value[k]!;return r; }
function contentRef(value:Obj):string{return `sha256:${sha256HexUtf8(canonicalizeJcs(unsigned(value)))}`;}
async function signature(value:Obj, pin:{issuedBy:string;keyId:string;publicKey:string}, code:PwaSpendResolverErrorCode):Promise<void>{
 const s=exact(value.signatures,["issuedBy","keyId","publicKey","tokenHash","signature"],"RESOLVER_BUNDLE_SCHEMA_INVALID");
 if(str(s.issuedBy,ID)!==pin.issuedBy||str(s.keyId,ID)!==pin.keyId||b64(s.publicKey)!==pin.publicKey)fail(code);
 const actual=sha256HexUtf8(canonicalizeJcs(unsigned(value)));if(hash(s.tokenHash)!==actual)fail("RESOLVER_MANIFEST_HASH_MISMATCH");
 const sig=base64ToBytes(b64(s.signature));const key=base64ToBytes(b64(s.publicKey));const digest=hexToBytes(actual);
 if(!sig||sig.length!==64||!key||key.length!==32||!digest||!(await verifyEd25519(sig,digest,key)))fail("RESOLVER_SIGNATURE_INVALID");
}
function publisherSigners(policy:Obj):PublisherSigner[]{
 if(policy.policyType!=="PWA_SPEND_SOURCE_PUBLISHER_AUTHORITY"||policy.schemaVersion!==1||!ID.test(str(policy.authorityId,ID)))fail("RESOLVER_BUNDLE_SCHEMA_INVALID");
 const raw=policy.authorizedSigners;if(!Array.isArray(raw)||!raw.length)fail("RESOLVER_BUNDLE_SCHEMA_INVALID");const entries=raw as readonly JsonValue[];
 return entries.map((item:JsonValue)=>{const signer=exact(item,["issuedBy","keyId","publicKey","artifactTypes"],"RESOLVER_BUNDLE_SCHEMA_INVALID");if(!exactStrings(signer.artifactTypes,["SPEND_HEAD_SET_SNAPSHOT","SPEND_ISSUER_SET_SNAPSHOT"]))fail("RESOLVER_BUNDLE_SCHEMA_INVALID");return {issuedBy:str(signer.issuedBy,ID),keyId:str(signer.keyId,ID),publicKey:b64(signer.publicKey),artifactTypes:["SPEND_HEAD_SET_SNAPSHOT","SPEND_ISSUER_SET_SNAPSHOT"]};});
}
function signer(signers:readonly PublisherSigner[], value:Obj, artifactType:string):PublisherSigner{
 const signed=exact(value.signatures,["issuedBy","keyId","publicKey","tokenHash","signature"],"RESOLVER_BUNDLE_SCHEMA_INVALID");
 const issuedBy=str(signed.issuedBy,ID),keyId=str(signed.keyId,ID),publicKey=b64(signed.publicKey);
 const selected=signers.find(item=>item.issuedBy===issuedBy&&item.keyId===keyId&&item.publicKey===publicKey&&item.artifactTypes.includes(artifactType));
 return selected??fail("RESOLVER_SOURCE_AUTHORITY_MISMATCH");
}
function issuerKeys(snapshot:Obj):IssuerKey[]{
 const raw=snapshot.keys;if(!Array.isArray(raw)||!raw.length)fail("RESOLVER_BUNDLE_SCHEMA_INVALID");const entries=raw as readonly JsonValue[];
 const keys=entries.map((item:JsonValue)=>{const key=exact(item,["issuerId","keyId","publicKey","validFrom","validUntil","terminationRef","authorizedArtifactTypes"],"RESOLVER_BUNDLE_SCHEMA_INVALID");const validFrom=timestamp(key.validFrom),validUntil=key.validUntil===null?null:timestamp(key.validUntil),terminationRef=key.terminationRef===null?null:ref(key.terminationRef);if((validUntil===null)!==(terminationRef===null)||validUntil!==null&&validFrom>=validUntil||!exactStrings(key.authorizedArtifactTypes,["SPEND_ATTESTATION_TOKEN"]))fail("RESOLVER_BUNDLE_SCHEMA_INVALID");return {issuerId:str(key.issuerId,ID),keyId:str(key.keyId,ID),publicKey:b64(key.publicKey),validFrom,validUntil,terminationRef};});
 const tuple=(key:IssuerKey)=>`${key.issuerId}\u0000${key.keyId}\u0000${key.validFrom}\u0000${key.publicKey}`;
 if(keys.some((key,index)=>index>0&&tuple(keys[index-1]!)>=tuple(key)))fail("RESOLVER_BUNDLE_SCHEMA_INVALID");
 const issuerKey=new Set<string>(), issuerPublic=new Set<string>(), publicIssuer=new Map<string,string>();
 for(const key of keys){const byKey=`${key.issuerId}\u0000${key.keyId}`,byPublic=`${key.issuerId}\u0000${key.publicKey}`;if(issuerKey.has(byKey)||issuerPublic.has(byPublic)||(publicIssuer.has(key.publicKey)&&publicIssuer.get(key.publicKey)!==key.issuerId))fail("RESOLVER_BUNDLE_SCHEMA_INVALID");issuerKey.add(byKey);issuerPublic.add(byPublic);publicIssuer.set(key.publicKey,key.issuerId);}
 return keys;
}
function activeAt(key:IssuerKey, at:string):boolean{return key.validFrom<=at&&(key.validUntil===null||at<key.validUntil);}
function activeIssuer(keys:readonly IssuerKey[], issuer:string, publicKey:string, at:string):boolean{return keys.some(key=>key.issuerId===issuer&&key.publicKey===publicKey&&activeAt(key,at));}
function stateRecords(input:unknown, seriesField:string, refField:string):SeriesState[]{
 if(input===undefined)return [];
 if(!Array.isArray(input))fail("RESOLVER_CONTINUITY_REJECTED");const entries=input as readonly unknown[];
 return entries.map((item:unknown)=>{if(item===null||typeof item!=="object"||Array.isArray(item))fail("RESOLVER_CONTINUITY_REJECTED");const entry=item as Record<string,unknown>,series=entry[seriesField],sequence=entry.sequence,reference=entry[refField];if(Object.keys(entry).length!==3||typeof series!=="string"||!ID.test(series)||typeof sequence!=="number"||!Number.isSafeInteger(sequence)||sequence<0||typeof reference!=="string"||!REF.test(reference))fail("RESOLVER_CONTINUITY_REJECTED");return {series:series as string,sequence:sequence as number,ref:reference as string};});
}
function continuity(series:string, sequence:number, previous:string|null, current:string, state:readonly SeriesState[]):void{
 const known=state.filter(item=>item.series===series), refs=new Map<number,string>();
 for(const item of known){const prior=refs.get(item.sequence);if(prior!==undefined&&prior!==item.ref)fail("RESOLVER_CONTINUITY_REJECTED");refs.set(item.sequence,item.ref);}
 const same=refs.get(sequence);if(same!==undefined&&same!==current)fail("RESOLVER_CONTINUITY_REJECTED");
 const high=known.reduce((maximum,item)=>Math.max(maximum,item.sequence),-1);
 if(sequence===0){if(previous!==null||high>0)fail("RESOLVER_CONTINUITY_REJECTED");return;}
 if(previous===null||refs.get(sequence-1)!==previous||high>sequence)fail("RESOLVER_CONTINUITY_REJECTED");
}
function proofDepth(leafCount:number):number { let capacity=1,depth=0;while(capacity<leafCount){capacity*=2;depth+=1;}return depth; }

/** Pure, fetch-free verifier for the additive P3.1h resolver bundle. */
export async function verifyPwaSpendResolverBundleV1(input:unknown, options:PwaSpendResolverVerificationOptions):Promise<PwaSpendResolverVerificationResult>{
 try {
  const snap=createInertJsonSnapshot(input);if(snap.error||!snap.value)fail("RESOLVER_BUNDLE_SCHEMA_INVALID");const bundle=exact(snap.value,["manifest","issuerSetSnapshot","headSetSnapshot","headInclusionProof","spendToken"],"RESOLVER_BUNDLE_SCHEMA_INVALID");
  const manifest=exact(bundle.manifest,["tokenType","schemaVersion","protocol","manifestSeriesId","sequence","previousManifestRef","resolverProfile","bootstrapAuthorityRef","publisherAuthorityPolicy","issuerPolicy","artifacts","freshness","signatures"],"RESOLVER_BUNDLE_SCHEMA_INVALID");
  if(manifest.tokenType!=="PWA_SPEND_RESOLVER_MANIFEST"||manifest.schemaVersion!==1)fail("RESOLVER_BUNDLE_SCHEMA_INVALID");
  const manifestSeriesId=str(manifest.manifestSeriesId,ID),manifestSequence=integer(manifest.sequence),manifestPrevious=manifest.previousManifestRef===null?null:ref(manifest.previousManifestRef);
  const protocol=exact(manifest.protocol,["protocolVersion"],"RESOLVER_BUNDLE_SCHEMA_INVALID"), profile=exact(manifest.resolverProfile,["profileId","profileVersion","sourceProfile"],"RESOLVER_BUNDLE_SCHEMA_INVALID");if(protocol.protocolVersion!=="1.0.0-rc.1"||profile.profileId!=="PWA_SPEND_RESOLVER_V1"||profile.profileVersion!==1||profile.sourceProfile!=="BUYER_STATE_ISSUER_AND_HEAD_SOURCES_V1")fail("RESOLVER_BUNDLE_SCHEMA_INVALID");
  const policy=exact(manifest.publisherAuthorityPolicy,["policyType","schemaVersion","authorityId","authorizedSigners"],"RESOLVER_BUNDLE_SCHEMA_INVALID"), signers=publisherSigners(policy), policyRef=contentRef(policy);
  const issuePolicy=exact(manifest.issuerPolicy,["acceptedIssuerIds","expectedIssuerBinding","authorizationTimeBasis","retainedKeyAuthorization"],"RESOLVER_BUNDLE_SCHEMA_INVALID"), ids=canonicalIds(issuePolicy.acceptedIssuerIds,"RESOLVER_ISSUER_POLICY_REJECTED"), mode=str(issuePolicy.expectedIssuerBinding);
  if(issuePolicy.authorizationTimeBasis!=="EVALUATION_CUTOFF"||issuePolicy.retainedKeyAuthorization!=="ACTIVE_AT_CUTOFF_ONLY"||(mode!=="SINGLE_ACCEPTED_ISSUER"&&mode!=="VERIFIED_HEAD_LEAF")||(mode==="SINGLE_ACCEPTED_ISSUER"&&ids.length!==1))fail("RESOLVER_ISSUER_POLICY_REJECTED");
  const artifacts=exact(manifest.artifacts,["issuerSetSnapshotRef","headSetSnapshotRef","spendStreamNamespaceRef","snapshotAsOf"],"RESOLVER_BUNDLE_SCHEMA_INVALID"), asOf=timestamp(artifacts.snapshotAsOf), namespace=ref(artifacts.spendStreamNamespaceRef), issuerRef=ref(artifacts.issuerSetSnapshotRef), headRef=ref(artifacts.headSetSnapshotRef);
  const fresh=exact(manifest.freshness,["resultScope","currentReliance","maximumAgeSeconds","clockTrust","staleTreatment","missingTreatment","conflictTreatment"],"RESOLVER_BUNDLE_SCHEMA_INVALID");if(fresh.resultScope!=="AS_OF_ONLY"||fresh.currentReliance!==false||fresh.clockTrust!=="LOCAL_CLOCK_NOT_AUTHORITY"||fresh.staleTreatment!=="INDETERMINATE"||fresh.missingTreatment!=="INDETERMINATE"||fresh.conflictTreatment!=="INDETERMINATE")fail("RESOLVER_BUNDLE_SCHEMA_INVALID");const maximumAgeSeconds=integer(fresh.maximumAgeSeconds);if(maximumAgeSeconds>31536000)fail("RESOLVER_BUNDLE_SCHEMA_INVALID");
  if(ref(manifest.bootstrapAuthorityRef)!==options.bootstrapAuthority.authorityRef)fail("RESOLVER_BOOTSTRAP_UNAUTHORIZED");await signature(manifest,options.bootstrapAuthority,"RESOLVER_BOOTSTRAP_UNAUTHORIZED");const manifestRef=contentRef(manifest);continuity(manifestSeriesId,manifestSequence,manifestPrevious,manifestRef,stateRecords(options.acceptedManifestState,"manifestSeriesId","manifestRef"));
  const issuer=exact(bundle.issuerSetSnapshot,["tokenType","schemaVersion","protocol","issuerSetId","sequence","asOf","previousSnapshotRef","authorityScope","authorizationTimeBasis","keys","publisherAuthorityRef","signatures"],"RESOLVER_BUNDLE_SCHEMA_INVALID"), head=exact(bundle.headSetSnapshot,["tokenType","schemaVersion","protocol","headSetId","sequence","asOf","generatedAt","previousSnapshotRef","spendStreamNamespaceRef","coveredIssuerIds","spendIssuerSetSnapshotRef","publisherAuthorityRef","assurance","headClaim","universeCompleteness","leafSchema","leafCount","headsRoot","signatures"],"RESOLVER_BUNDLE_SCHEMA_INVALID");
  const issuerSetId=str(issuer.issuerSetId,ID),issuerSequence=integer(issuer.sequence),issuerPrevious=issuer.previousSnapshotRef===null?null:ref(issuer.previousSnapshotRef),keys=issuerKeys(issuer);
  const headSetId=str(head.headSetId,ID),headSequence=integer(head.sequence),headPrevious=head.previousSnapshotRef===null?null:ref(head.previousSnapshotRef),covered=canonicalIds(head.coveredIssuerIds,"RESOLVER_ISSUER_POLICY_REJECTED"),headLeafCount=integer(head.leafCount);
  if(!headLeafCount||issuer.tokenType!=="SPEND_ISSUER_SET_SNAPSHOT"||head.tokenType!=="SPEND_HEAD_SET_SNAPSHOT"||issuer.schemaVersion!==1||head.schemaVersion!==1||issuer.authorityScope!=="SPEND_ATTESTATION_TOKEN_ISSUANCE"||issuer.authorizationTimeBasis!=="EVALUATION_CUTOFF"||head.assurance!=="PUBLISHER_ATTESTED"||head.headClaim!=="CANONICAL_HEAD_FOR_INCLUDED_STREAM_KEY_AS_OF"||head.universeCompleteness!=="NOT_CLAIMED"||head.leafSchema!=="SPEND_CANONICAL_HEAD_LEAF_V1"||exact(issuer.protocol,["protocolVersion"],"RESOLVER_BUNDLE_SCHEMA_INVALID").protocolVersion!=="1.0.0-rc.1"||exact(head.protocol,["protocolVersion"],"RESOLVER_BUNDLE_SCHEMA_INVALID").protocolVersion!=="1.0.0-rc.1"||timestamp(issuer.asOf)!==asOf||timestamp(head.asOf)!==asOf||Date.parse(timestamp(head.generatedAt))<Date.parse(asOf)||ref(head.spendStreamNamespaceRef)!==namespace||ref(head.spendIssuerSetSnapshotRef)!==issuerRef||ref(issuer.publisherAuthorityRef)!==policyRef||ref(head.publisherAuthorityRef)!==policyRef||!ids.every(id=>covered.includes(id))||!ids.every(id=>keys.some(key=>key.issuerId===id&&activeAt(key,asOf)))||!HASH.test(hash(head.headsRoot)))fail("RESOLVER_ISSUER_POLICY_REJECTED");
  await signature(issuer,signer(signers,issuer,"SPEND_ISSUER_SET_SNAPSHOT"),"RESOLVER_SOURCE_AUTHORITY_MISMATCH");const verifiedIssuerRef=contentRef(issuer);if(issuerRef!==verifiedIssuerRef)fail("RESOLVER_ARTIFACT_REF_MISMATCH");continuity(issuerSetId,issuerSequence,issuerPrevious,verifiedIssuerRef,stateRecords(options.acceptedIssuerSetSnapshotState,"issuerSetId","issuerSetSnapshotRef"));
  await signature(head,signer(signers,head,"SPEND_HEAD_SET_SNAPSHOT"),"RESOLVER_SOURCE_AUTHORITY_MISMATCH");const verifiedHeadRef=contentRef(head);if(headRef!==verifiedHeadRef)fail("RESOLVER_ARTIFACT_REF_MISMATCH");continuity(headSetId,headSequence,headPrevious,verifiedHeadRef,stateRecords(options.acceptedHeadSetSnapshotState,"headSetId","headSetSnapshotRef"));
  const spend=obj(bundle.spendToken)??fail("RESOLVER_SPEND_REJECTED");const spendIssuer=exact(spend.signatures,["issuedBy","publicKey","tokenHash","signature"],"RESOLVER_SPEND_REJECTED");const native=await verifyNativeSpendAttestationSnapshot(bundle.spendToken,{issuerTrust:({issuedBy,publicKeyBase64})=>activeIssuer(keys,issuedBy,publicKeyBase64,asOf)});if(!native.cryptographicallyValid||native.issuerAuthorized!==true||native.errors.length)fail("RESOLVER_SPEND_REJECTED");
  const proof=exact(bundle.headInclusionProof,["proofType","schemaVersion","snapshotRef","leaf","leafHash","siblings"],"RESOLVER_BUNDLE_SCHEMA_INVALID"), leaf=exact(proof.leaf,["leafType","schemaVersion","spendStreamNamespaceRef","issuerId","spendId","spendTokenHash","canonicalHeadEventHash","eventCount","headEffectiveAt","headAdmittedAt","status"],"RESOLVER_BUNDLE_SCHEMA_INVALID");
  const siblingValues=proof.siblings;if(!Array.isArray(siblingValues))fail("RESOLVER_BUNDLE_SCHEMA_INVALID");const siblings=(siblingValues as readonly JsonValue[]).map((item:JsonValue)=>hash(item));const leafIssuer=str(leaf.issuerId,ID),effectiveAt=timestamp(leaf.headEffectiveAt),admittedAt=timestamp(leaf.headAdmittedAt),leafStatus=str(leaf.status);
  if(proof.proofType!=="SPEND_HEAD_INCLUSION"||proof.schemaVersion!==1||ref(proof.snapshotRef)!==verifiedHeadRef||leaf.leafType!=="SPEND_CANONICAL_HEAD"||leaf.schemaVersion!==1||ref(leaf.spendStreamNamespaceRef)!==namespace||!ids.includes(leafIssuer)||!covered.includes(leafIssuer)||effectiveAt>admittedAt||admittedAt>asOf||!["CORRECTED","HARD_VERIFIED","INVALIDATED"].includes(leafStatus)||siblings.length!==proofDepth(headLeafCount)||str(leaf.spendId,ID)!==native.metadata.spendId||hash(leaf.spendTokenHash)!==native.metadata.tokenHash)fail("RESOLVER_LEAF_PROOF_INVALID");
  const lineage=obj(spend.lineage), canonical=obj(spend.canonical);if(!lineage||!canonical||hash(leaf.canonicalHeadEventHash)!==hash(lineage.headEventHash)||integer(leaf.eventCount)!==lineage.eventCount||leafStatus!==canonical.status)fail("RESOLVER_LEAF_PROOF_INVALID");const walk=verifyInclusionProof({leaf,leafHash:hash(proof.leafHash),siblings,expectedRoot:hash(head.headsRoot)});if(!walk.valid)fail("RESOLVER_LEAF_PROOF_INVALID");
  const expected=mode==="SINGLE_ACCEPTED_ISSUER"?ids[0]!:leafIssuer;if(expected!==leafIssuer||expected!==native.metadata.issuer||!activeIssuer(keys,expected,b64(spendIssuer.publicKey),asOf))fail("RESOLVER_ISSUER_POLICY_REJECTED");
  if(options.now!==undefined){const now=timestamp(options.now);if(Date.parse(now)-Date.parse(asOf)>maximumAgeSeconds*1000)fail("RESOLVER_STALE");}
  return {verified:true,currentReliance:false,facts:{manifestRef,manifestSeriesId,manifestSequence,issuerSetSnapshotRef:verifiedIssuerRef,issuerSetId,issuerSetSequence:issuerSequence,headSetSnapshotRef:verifiedHeadRef,headSetId,headSetSequence:headSequence,spendId:native.metadata.spendId!,tokenHash:native.metadata.tokenHash!,expectedIssuer:expected,snapshotAsOf:asOf}};
 } catch(error){return {verified:false,currentReliance:false,error:error instanceof Reject?error.code:"RESOLVER_BUNDLE_SCHEMA_INVALID"};}
}
