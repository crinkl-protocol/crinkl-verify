import { addError, finalize, resultFor } from "./result.js";
import type { VerificationResult, W3cVerificationOptions } from "./types.js";

/**
 * The public W3C profile is intentionally not implemented until the adopted
 * protocol head supplies its final context, schemas, vectors, issuer-key
 * history, and status/refresh contracts. This function makes the boundary
 * explicit and performs no network I/O.
 */
export async function verifyW3cSpendAttestation(
  _input: unknown,
  _options: W3cVerificationOptions = {}
): Promise<VerificationResult> {
  const result = resultFor("w3c-vc-crinkl-spend-attestation/v1", "1");
  result.warnings.push({
    code: "EXPERIMENTAL_W3C_PROFILE",
    message: "The Crinkl W3C VC profile is experimental and no released, pinned profile bundle is available in this package."
  });
  addError(result, "UNSUPPORTED_PROFILE_VERSION", "W3C verification fails closed until a released Crinkl profile bundle is pinned.", "policy");
  return finalize(result);
}
