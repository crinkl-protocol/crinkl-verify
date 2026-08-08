import { verifyInclusionProof } from "./merkle.js";
import { verifyNativeSpendAttestation } from "./native-v1.js";
import { verifyRewardCommitmentV1 } from "./reward-commitment-v1.js";
import type {
  RewardCommitmentTokenV1,
  SpendAttestationTokenV1,
  SpendRewardClaimTier,
  SpendRewardLinkageStatus,
  SpendWithRewardCommitmentOptions,
  SpendWithRewardCommitmentResult,
  VerificationError
} from "./types.js";

/**
 * Composes native spend-attestation verification with reward-commitment
 * verification and, when the batch leaf schema is linkable (`2a`/`2b`), the
 * optional spend↔reward linkage proof (COMMITMENT_LAYER.md#spend-reward-link-proofs).
 *
 * A missing `rewardCommitmentToken` is not an error for the spend token: the
 * result simply stays at the `"crypto-valid"` tier. This function proves an
 * issuer signed the canonical claim and, when a reward commitment is
 * supplied and verifies, that the issuer additionally attached and anchored
 * an economic (reward) liability to it. It never proves the underlying
 * purchase occurred.
 */
export async function verifySpendWithRewardCommitment(
  spendToken: unknown,
  rewardCommitmentToken: unknown | undefined,
  options: SpendWithRewardCommitmentOptions = {}
): Promise<SpendWithRewardCommitmentResult> {
  const spend = await verifyNativeSpendAttestation(spendToken, options);
  const errors: VerificationError[] = [];
  const warnings = [...spend.warnings];

  const spendCryptoValid = spend.cryptographicallyValid && spend.issuerAuthorized === true;
  if (!spendCryptoValid) {
    return { tier: "invalid", spend, linkage: "not-applicable", anchor: "not-checked", errors: [...spend.errors], warnings };
  }

  if (rewardCommitmentToken === undefined) {
    warnings.push({ code: "REWARD_COMMITMENT_NOT_PROVIDED", message: "No reward commitment token was supplied; the composite result stays at the crypto-valid tier." });
    return { tier: "crypto-valid", spend, linkage: "not-applicable", anchor: "not-checked", errors, warnings };
  }

  const rewardCommitment = await verifyRewardCommitmentV1(rewardCommitmentToken, options.rewardCommitment);
  errors.push(...rewardCommitment.errors);
  warnings.push(...rewardCommitment.warnings);

  if (!rewardCommitment.accepted) {
    return { tier: "crypto-valid", spend, rewardCommitment, linkage: "not-applicable", anchor: rewardCommitment.anchor, errors, warnings };
  }

  const tier: SpendRewardClaimTier = rewardCommitment.economicTier === "COMMITTED_BACKED" ? "committed-backed" : "committed";

  let linkage: SpendRewardLinkageStatus = "not-applicable";
  const schemaVersion = rewardCommitment.metadata.batchId !== undefined ? (rewardCommitmentToken as RewardCommitmentTokenV1).batch?.schemaVersion : undefined;
  const linkable = schemaVersion === "2a" || schemaVersion === "2b";
  const rewardInclusionProof = (rewardCommitmentToken as RewardCommitmentTokenV1).rewardInclusionProof;

  if (linkable) {
    if (!rewardInclusionProof) {
      linkage = "not-checked";
    } else {
      const spendId = (spendToken as SpendAttestationTokenV1 | undefined)?.spendId;
      const token = rewardCommitmentToken as RewardCommitmentTokenV1;
      const leaf = token.leaf as { rewardEventsRoot?: unknown };

      const recipientMatches = rewardInclusionProof.recipientId === token.recipientId;
      const batchMatches = rewardInclusionProof.batchId === token.batch.batchId;
      const rootMatches = rewardInclusionProof.rewardEventsRoot === leaf.rewardEventsRoot;
      const spendIdMatches = rewardInclusionProof.leaf.spendId === spendId;

      const inclusion = verifyInclusionProof({
        leaf: rewardInclusionProof.leaf,
        leafHash: rewardInclusionProof.leafHash,
        siblings: rewardInclusionProof.siblings,
        expectedRoot: rewardInclusionProof.rewardEventsRoot
      });

      if (recipientMatches && batchMatches && rootMatches && spendIdMatches && inclusion.valid) {
        linkage = "verified";
      } else {
        linkage = "mismatch";
        errors.push({
          code: "SPEND_REWARD_LINKAGE_MISMATCH",
          message: "rewardInclusionProof does not consistently bind this spendId to the reward commitment's aggregated leaf.",
          cause: inclusion.valid ? "input" : "crypto",
          path: "$.rewardInclusionProof"
        });
      }
    }
  }

  return { tier, spend, rewardCommitment, linkage, anchor: rewardCommitment.anchor, errors, warnings };
}
