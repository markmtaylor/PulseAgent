import { createHash } from "node:crypto";
import {
  DigestServiceRequestSchema,
  digestOf,
  serviceRequestDigest,
  sha256Hex,
  type DigestServiceResult,
} from "@pulseagent/core";

/**
 * The deterministic service this milestone sells: the SHA-256 of a bounded
 * input.
 *
 * Deterministic on purpose, and labelled as such. The point of the milestone is
 * to prove that a payment settled and that the buyer got exactly the result it
 * paid for; a service whose output the buyer can recompute makes that check
 * trivial and removes the model, its credentials and its nondeterminism from the
 * evidence entirely. A real agent can sell anything through the same SDK later.
 */

export const SERVICE_NAME = "sha256-digest";

/**
 * Digest that binds a quote to the exact request body it prices.
 *
 * Delegates to the shared definition in core so the buyer derives the same value
 * from its own input rather than reading the seller's.
 */
export function requestDigestFor(resourcePath: string, input: string): string {
  return serviceRequestDigest({ service: SERVICE_NAME, resourcePath, input });
}

/** Computes the service result for `input`. */
export function computeDigestResult(input: string): DigestServiceResult {
  const parsed = DigestServiceRequestSchema.parse({ input });
  const sha256 = createHash("sha256").update(parsed.input, "utf8").digest("hex");
  const result = {
    service: SERVICE_NAME,
    deterministic: true,
    inputDigest: sha256Hex(parsed.input),
    outputDigest: sha256Hex(sha256),
    sha256,
  } as const;
  return result;
}

/** Digest of a delivered result, for the buyer's independent check. */
export function resultDigest(result: DigestServiceResult): string {
  return digestOf(result);
}
