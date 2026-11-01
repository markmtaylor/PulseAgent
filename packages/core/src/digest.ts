import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { canonicalize } from "./canonical.js";

/** Lowercase hex sha-256 of a UTF-8 string, prefixed `sha256:`. */
export function sha256Hex(input: string): string {
  return `sha256:${createHash("sha256").update(input, "utf8").digest("hex")}`;
}

/** Lowercase hex sha-256 of raw bytes, prefixed `sha256:`. */
export function sha256Bytes(input: Uint8Array): string {
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
}

/** Digest of a structure under {@link canonicalize}. Used for quote, intent and event hashes. */
export function digestOf(value: unknown): string {
  return sha256Hex(canonicalize(value));
}

/** URL-safe random identifier. Not a secret; appears in audit records. */
export function randomId(prefix: string, bytes = 16): string {
  return `${prefix}_${randomBytes(bytes).toString("hex")}`;
}

/** Constant-time comparison of two short ASCII tokens. */
export function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
