import { createInertJsonSnapshot, type JsonValue } from "./json.js";
import { verifyNativeSpendAttestation } from "./native-v1.js";
import { verifyRewardCommitmentV2 } from "./reward-commitment-v2.js";
import type {
  SpendRewardClaimTier,
  SpendRewardCommitmentV2Options,
  SpendRewardCommitmentV2Result,
  VerificationError,
  VerificationWarning
} from "./types.js";

function object(value: JsonValue | undefined): { readonly [key: string]: JsonValue } | undefined {
  return value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value)
    ? value as { readonly [key: string]: JsonValue }
    : undefined;
}

/**
 * Composes native Spend verification with the checkpoint-backed V2 reward
 * profile. It deliberately does not reuse the V1 composite: V2 requires a
 * verified reward inclusion proof and binds both of that proof leaf's exact
 * references to the independently verified Spend Token.
 */
export async function verifySpendRewardCommitmentV2(
  spendToken: unknown,
  rewardCommitmentToken: unknown | undefined,
  options: SpendRewardCommitmentV2Options = {}
): Promise<SpendRewardCommitmentV2Result> {
  const spend = await verifyNativeSpendAttestation(spendToken, options);
  const errors: VerificationError[] = [...spend.errors];
  const warnings: VerificationWarning[] = [...spend.warnings];
  const spendCryptoValid = spend.cryptographicallyValid && spend.issuerAuthorized === true;
  if (!spendCryptoValid) {
    return { tier: "invalid", spend, linkage: "not-applicable", anchor: "not-checked", errors, warnings };
  }

  if (rewardCommitmentToken === undefined) {
    warnings.push({ code: "REWARD_COMMITMENT_NOT_PROVIDED", message: "No checkpoint-backed reward commitment was supplied; the composite result stays at the crypto-valid tier." });
    return { tier: "crypto-valid", spend, linkage: "not-checked", anchor: "not-checked", errors, warnings };
  }

  const rewardSnapshot = createInertJsonSnapshot(rewardCommitmentToken);
  const spendSnapshot = createInertJsonSnapshot(spendToken);
  const reward = await verifyRewardCommitmentV2(rewardCommitmentToken, options.rewardCommitment);
  errors.push(...reward.errors);
  warnings.push(...reward.warnings);
  if (!reward.accepted || rewardSnapshot.error || rewardSnapshot.value === undefined || spendSnapshot.error || spendSnapshot.value === undefined) {
    return { tier: "crypto-valid", spend, rewardCommitment: reward, linkage: "mismatch", anchor: reward.anchor, errors, warnings };
  }

  const rewardToken = object(rewardSnapshot.value);
  const inclusion = object(rewardToken?.rewardInclusionProof);
  const inclusionLeaf = object(inclusion?.leaf);
  const spendObject = object(spendSnapshot.value);
  const lineage = object(spendObject?.lineage);
  const spendId = spend.metadata.spendId;
  const exactLinkage = typeof spendId === "string"
    && typeof lineage?.headEventHash === "string"
    && inclusionLeaf?.spendId === spendId
    && inclusionLeaf.rewardEventHash === lineage.headEventHash;
  if (!exactLinkage) {
    errors.push({
      code: "SPEND_REWARD_LINKAGE_MISMATCH",
      message: "The checkpoint-backed reward inclusion proof does not bind this exact verified spendId and rewardEventHash.",
      cause: "crypto",
      path: "$.rewardInclusionProof.leaf"
    });
    return { tier: "crypto-valid", spend, rewardCommitment: reward, linkage: "mismatch", anchor: reward.anchor, errors, warnings };
  }

  const tier: SpendRewardClaimTier = reward.economicTier === "COMMITTED_BACKED" ? "committed-backed" : "committed";
  return { tier, spend, rewardCommitment: reward, linkage: "verified", anchor: reward.anchor, errors, warnings };
}
