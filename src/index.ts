export { detectArtifactFormat } from "./format.js";
export {
  computeNativeSpendAttestationTokenHash,
  verifyNativeSpendAttestation
} from "./native-v1.js";
export { verifySpendHolderControl } from "./holder-control-v2.js";
export { verifyW3cSpendAttestation } from "./w3c-v1.js";
export { verifyRewardCommitmentV1 } from "./reward-commitment-v1.js";
export { PLATFORM_SOLANA_CREATE_BATCH_IMPRINT_V1, verifySolanaBatchAnchor } from "./solana.js";
export { verifySpendWithRewardCommitment } from "./spend-reward-commitment.js";
export { EMPTY_LEAF_HASH_HEX, combineSorted, computeLeafHash, verifyInclusionProof } from "./merkle.js";
export { computeSystemEventHash } from "./system-stream.js";
export type * from "./types.js";

import { detectArtifactFormatFromSnapshot } from "./format.js";
import { createInertJsonSnapshot } from "./json.js";
import { finalize, resultFor, addError } from "./result.js";
import { verifyNativeSpendAttestationSnapshot } from "./native-v1.js";
import { verifyW3cSpendAttestation } from "./w3c-v1.js";
import type { VerificationOptions, VerificationResult } from "./types.js";

export async function verify(input: unknown, options: VerificationOptions = {}): Promise<VerificationResult> {
  const snapshot = createInertJsonSnapshot(input);
  if (snapshot.error || snapshot.value === undefined) {
    const result = resultFor("unknown", "unknown");
    addError(result, "SCHEMA_INVALID", `Verification input must be inert JSON: ${snapshot.error ?? "missing JSON value"}`, "input", "$");
    return finalize(result);
  }
  const format = detectArtifactFormatFromSnapshot(snapshot.value);
  if (format === "crinkl-native-spend-attestation/v1" || format === "crinkl-native-spend-attestation/v2") return verifyNativeSpendAttestationSnapshot(snapshot.value, options);
  if (snapshot.value !== null && typeof snapshot.value === "object" && !Array.isArray(snapshot.value) &&
    (snapshot.value as Record<string, unknown>).tokenType === "SPEND_ATTESTATION") {
    return verifyNativeSpendAttestationSnapshot(snapshot.value, options);
  }
  if (format === "w3c-vc-crinkl-spend-attestation/v1") return verifyW3cSpendAttestation(snapshot.value, options);
  const result = resultFor("unknown", "unknown");
  addError(result, "UNSUPPORTED_FORMAT", "Input is not a supported Crinkl verification artifact.", "input");
  return finalize(result);
}
