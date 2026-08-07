import type { ArtifactFormat } from "./types.js";

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

export function detectArtifactFormat(input: unknown): ArtifactFormat | undefined {
  const value = object(input);
  if (!value) return undefined;
  if (value.tokenType === "SPEND_ATTESTATION" && value.schemaVersion === 1) {
    return "crinkl-native-spend-attestation/v1";
  }
  const types = Array.isArray(value.type) ? value.type : [];
  if (types.includes("VerifiableCredential") && types.includes("SpendAttestationCredential")) {
    return "w3c-vc-crinkl-spend-attestation/v1";
  }
  return undefined;
}
