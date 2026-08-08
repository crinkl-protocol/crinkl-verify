import { canonicalizeJcs, concatBytes, hexToBytes, sha256Hex } from "./crypto.js";

const encoder = new TextEncoder();
const LEAF_PREFIX = Uint8Array.of(0x00);
const INTERNAL_PREFIX = Uint8Array.of(0x01);
const HASH = /^[0-9a-f]{64}$/;

/**
 * `emptyLeafHash = SHA-256(0x00 || "")`, per COMMITMENT_LAYER.md#merkle-tree.
 * Padding-only; MUST NOT be treated as an admissible real leaf.
 */
export const EMPTY_LEAF_HASH_HEX = sha256Hex(LEAF_PREFIX);

/**
 * Leaf hash per COMMITMENT_LAYER.md#merkle-tree: `SHA-256(0x00 || canonicalize(leaf))`.
 * `leaf` MUST already be an inert JSON snapshot value; this function does not
 * re-validate that property (callers are expected to have taken an inert
 * snapshot of the whole token before reaching leaf hashing).
 */
export function computeLeafHash(leaf: unknown): string {
  const canonical = canonicalizeJcs(leaf);
  return sha256Hex(concatBytes(LEAF_PREFIX, encoder.encode(canonical)));
}

/**
 * Internal node hash per COMMITMENT_LAYER.md#merkle-tree: sorted-pair hashing
 * with `0x01` domain separation: `SHA-256(0x01 || left || right)` where
 * `left < right` as raw bytes (equivalently, as same-length lowercase hex
 * strings).
 */
export function combineSorted(a: string, b: string): string {
  const [lo, hi] = a < b ? [a, b] : [b, a];
  const loBytes = hexToBytes(lo);
  const hiBytes = hexToBytes(hi);
  if (!loBytes || !hiBytes) throw new TypeError("combineSorted requires 64-hex-character SHA-256 hashes.");
  return sha256Hex(concatBytes(INTERNAL_PREFIX, loBytes, hiBytes));
}

export interface MerkleProofWalkInput {
  /** The already-hashed leaf per {@link computeLeafHash}. */
  leafHash: string;
  /** Sibling hashes from leaf to root, per COMMITMENT_LAYER.md `InclusionProof.siblings`. */
  siblings: readonly string[];
}

/**
 * Recomputes a Merkle proof per COMMITMENT_LAYER.md#verification-algorithm:
 * walk `siblings` from leaf to root using {@link combineSorted}. Does not
 * recompute the leaf hash itself (callers must have already derived
 * `leafHash` via {@link computeLeafHash} and compared it against any
 * pre-computed value asserted by the artifact).
 */
export function walkMerkleProof(input: MerkleProofWalkInput): string {
  let hash = input.leafHash;
  for (const sibling of input.siblings) {
    if (!HASH.test(sibling)) throw new TypeError("Merkle proof siblings must be lowercase 64-hex-character SHA-256 hashes.");
    hash = combineSorted(hash, sibling);
  }
  return hash;
}

/**
 * Full inclusion-proof verification: recomputes the leaf hash from `leaf`,
 * confirms it matches `leafHash` (when provided, per `InclusionProof.leafHash`
 * being "pre-computed for convenience" — COMMITMENT_LAYER.md#proof-structure),
 * walks the sibling path, and compares the result against `expectedRoot`.
 */
export function verifyInclusionProof(options: {
  leaf: unknown;
  leafHash?: string;
  siblings: readonly string[];
  expectedRoot: string;
}): { valid: boolean; computedLeafHash: string; computedRoot: string; leafHashMismatch: boolean } {
  const computedLeafHash = computeLeafHash(options.leaf);
  const leafHashMismatch = options.leafHash !== undefined && options.leafHash !== computedLeafHash;
  const computedRoot = walkMerkleProof({ leafHash: computedLeafHash, siblings: options.siblings });
  return {
    valid: !leafHashMismatch && computedRoot === options.expectedRoot,
    computedLeafHash,
    computedRoot,
    leafHashMismatch
  };
}

export function isHash(value: unknown): value is string {
  return typeof value === "string" && HASH.test(value);
}
