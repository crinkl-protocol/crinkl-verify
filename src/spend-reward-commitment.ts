import { createInertJsonSnapshot, type JsonValue } from "./json.js";
import { verifyInclusionProof } from "./merkle.js";
import { verifyNativeSpendAttestation } from "./native-v1.js";
import { verifyRewardCommitmentV1 } from "./reward-commitment-v1.js";
import type {
  SpendRewardClaimTier,
  SpendRewardLinkageStatus,
  SpendWithRewardCommitmentOptions,
  SpendWithRewardCommitmentResult,
  VerificationError
} from "./types.js";

function object(value: JsonValue | undefined): { readonly [key: string]: JsonValue } | undefined {
  return value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value)
    ? (value as { readonly [key: string]: JsonValue })
    : undefined;
}

function hasOwn(value: { readonly [key: string]: JsonValue } | undefined, key: string): boolean {
  return value !== undefined && Object.prototype.hasOwnProperty.call(value, key);
}

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

  // Read linkage inputs only from this inert copy. In particular, never use
  // the caller's original spend object after its verification completed.
  const rewardSnapshot = createInertJsonSnapshot(rewardCommitmentToken);
  const rewardToken = rewardSnapshot.error || rewardSnapshot.value === undefined ? undefined : object(rewardSnapshot.value);
  const batch = object(rewardToken?.batch);
  const schemaVersion = batch?.schemaVersion;
  const linkable = schemaVersion === "2a" || schemaVersion === "2b";
  const hasSuppliedLinkageProof = hasOwn(rewardToken, "rewardInclusionProof");

  const rewardCommitment = await verifyRewardCommitmentV1(rewardCommitmentToken, options.rewardCommitment);
  errors.push(...rewardCommitment.errors);
  warnings.push(...rewardCommitment.warnings);

  if (!rewardCommitment.accepted) {
    if (linkable && hasSuppliedLinkageProof) {
      errors.push({
        code: "SPEND_REWARD_LINKAGE_MISMATCH",
        message: "A supplied linkable rewardInclusionProof could not establish an exact Spend-to-reward linkage.",
        cause: "input",
        path: "$.rewardInclusionProof"
      });
      return { tier: "crypto-valid", spend, rewardCommitment, linkage: "mismatch", anchor: rewardCommitment.anchor, errors, warnings };
    }
    return { tier: "crypto-valid", spend, rewardCommitment, linkage: linkable ? "not-checked" : "not-applicable", anchor: rewardCommitment.anchor, errors, warnings };
  }

  const rewardTier: SpendRewardClaimTier = rewardCommitment.economicTier === "COMMITTED_BACKED" ? "committed-backed" : "committed";

  let linkage: SpendRewardLinkageStatus = "not-applicable";
  let tier: SpendRewardClaimTier = rewardTier;

  if (linkable) {
    const rewardInclusionProof = object(rewardToken?.rewardInclusionProof);
    if (!hasSuppliedLinkageProof) {
      linkage = "not-checked";
      tier = "crypto-valid";
    } else {
      const proofLeaf = object(rewardInclusionProof?.leaf);
      const siblings = rewardInclusionProof?.siblings;
      const aggregateLeaf = object(rewardToken?.leaf);
      const spendId = spend.metadata.spendId;
      const proofWellFormed =
        rewardInclusionProof !== undefined &&
        proofLeaf !== undefined &&
        Array.isArray(siblings) && siblings.every((sibling) => typeof sibling === "string") &&
        typeof rewardInclusionProof.recipientId === "string" &&
        typeof rewardInclusionProof.batchId === "string" &&
        typeof rewardInclusionProof.rewardEventsRoot === "string" &&
        typeof rewardInclusionProof.leafHash === "string" &&
        typeof proofLeaf.spendId === "string" &&
        typeof batch?.batchId === "string" &&
        typeof rewardToken?.recipientId === "string" &&
        typeof aggregateLeaf?.rewardEventsRoot === "string" &&
        typeof spendId === "string";

      let inclusionValid = false;
      if (proofWellFormed) {
        try {
          inclusionValid = verifyInclusionProof({
            leaf: proofLeaf,
            leafHash: rewardInclusionProof.leafHash as string,
            siblings: siblings as readonly string[],
            expectedRoot: rewardInclusionProof.rewardEventsRoot as string
          }).valid;
        } catch {
          inclusionValid = false;
        }
      }

      const recipientMatches = proofWellFormed && rewardInclusionProof!.recipientId === rewardToken!.recipientId;
      const batchMatches = proofWellFormed && rewardInclusionProof!.batchId === batch!.batchId;
      const rootMatches = proofWellFormed && rewardInclusionProof!.rewardEventsRoot === aggregateLeaf!.rewardEventsRoot;
      const spendIdMatches = proofWellFormed && proofLeaf!.spendId === spendId;

      if (recipientMatches && batchMatches && rootMatches && spendIdMatches && inclusionValid) {
        linkage = "verified";
      } else {
        linkage = "mismatch";
        tier = "crypto-valid";
        errors.push({
          code: "SPEND_REWARD_LINKAGE_MISMATCH",
          message: "rewardInclusionProof does not consistently bind the verified spendId to the reward commitment's aggregated leaf.",
          cause: inclusionValid ? "input" : "crypto",
          path: "$.rewardInclusionProof"
        });
      }
    }
  }

  return { tier, spend, rewardCommitment, linkage, anchor: rewardCommitment.anchor, errors, warnings };
}
