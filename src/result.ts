import type {
  ArtifactFormat,
  VerificationCause,
  VerificationErrorCode,
  VerificationResult
} from "./types.js";

export function resultFor(format: ArtifactFormat | "unknown", profileVersion: string | "unknown"): VerificationResult {
  return {
    format,
    profileVersion,
    cryptographicallyValid: false,
    issuerAuthorized: "not_checked",
    current: "not_checked",
    accepted: false,
    errors: [],
    warnings: [],
    metadata: {}
  };
}

export function addError(
  result: VerificationResult,
  code: VerificationErrorCode,
  message: string,
  cause: VerificationCause,
  path?: string
): VerificationResult {
  result.errors.push({ code, message, cause, path });
  return result;
}

export function finalize(result: VerificationResult): VerificationResult {
  result.accepted = result.cryptographicallyValid && result.issuerAuthorized === true && result.current === true;
  return result;
}
