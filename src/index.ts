export { detectArtifactFormat } from "./format.js";
export {
  computeNativeSpendAttestationTokenHash,
  verifyNativeSpendAttestation
} from "./native-v1.js";
export { verifyW3cSpendAttestation } from "./w3c-v1.js";
export type * from "./types.js";

import { detectArtifactFormat } from "./format.js";
import { finalize, resultFor, addError } from "./result.js";
import { verifyNativeSpendAttestation } from "./native-v1.js";
import { verifyW3cSpendAttestation } from "./w3c-v1.js";
import type { VerificationOptions, VerificationResult } from "./types.js";

export async function verify(input: unknown, options: VerificationOptions = {}): Promise<VerificationResult> {
  const format = detectArtifactFormat(input);
  if (format === "crinkl-native-spend-attestation/v1") return verifyNativeSpendAttestation(input, options);
  if (format === "w3c-vc-crinkl-spend-attestation/v1") return verifyW3cSpendAttestation(input, options);
  const result = resultFor("unknown", "unknown");
  addError(result, "UNSUPPORTED_FORMAT", "Input is not a supported Crinkl verification artifact.", "input");
  return finalize(result);
}
