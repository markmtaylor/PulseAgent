import { sha256Hex } from "../digest.js";

/**
 * Audit payload safety.
 *
 * Two layers, in order of authority:
 *
 * 1. {@link assertAllowlistedPayload} is the real control. At a key-bearing
 *    boundary — the signer above all — every field a record may contain is named
 *    in advance with the shape its value must take. A field that is not on the
 *    list is a thrown error, not a redacted value. This is the only approach
 *    that works, because a 32-byte private key and a 32-byte transaction hash
 *    are the same length and the same alphabet: nothing can tell them apart by
 *    inspection, so the decision has to be made by field, up front.
 * 2. {@link redact} is defense in depth for everything else. It assumes the
 *    payload is already minimal and only limits the damage of a careless call
 *    site: no arbitrary upstream text, no hex long enough to be a signature, and
 *    bounded strings and arrays.
 */

/**
 * Keys whose values never reach an audit record, a log line or an MCP response,
 * at any nesting depth. Matching is on a lowercased, separator-free form of the
 * key, so `private_key`, `privateKey` and `PRIVATE-KEY` all match.
 */
const FORBIDDEN_KEY_FRAGMENTS = [
  "privatekey",
  "secretkey",
  "mnemonic",
  "seedphrase",
  "keystore",
  "passphrase",
  "password",
  "credential",
  "bearer",
  "apikey",
  "authtoken",
  "signertoken",
  "sessiontoken",
  "secret",
];

/**
 * Keys reduced to a digest rather than dropped. A raw signature or a complete
 * authorization is replayable value, so a record keeps only enough to say which
 * one it was.
 */
const DIGEST_ONLY_KEY_FRAGMENTS = ["signature", "authorizationpayload", "rawauthorization", "signedtx"];

const MAX_STRING_LENGTH = 240;
const MAX_ARRAY_LENGTH = 64;
const MAX_DEPTH = 8;

/**
 * Hex runs long enough to be key or signature material, prefixed or bare, found
 * anywhere in a string rather than only as the whole of one. A 65-byte ECDSA
 * signature is 130 hex characters and is caught by either pattern.
 *
 * The threshold is "longer than 32 bytes" on purpose. An address (40 hex) and a
 * bytes32 hash or nonce (64 hex) are legitimate audit values, and a 32-byte
 * private key is exactly as long as a transaction hash and drawn from the same
 * alphabet — no pattern can separate them. That case is handled by
 * {@link assertAllowlistedPayload} at the boundary that holds keys, which is the
 * only place the distinction can actually be made.
 */
const LONG_PREFIXED_HEX = /0x[0-9a-fA-F]{65,}/g;
const LONG_BARE_HEX = /[0-9a-fA-F]{65,}/g;

const SHAPE_PATTERNS = {
  address: /^0x[0-9a-fA-F]{40}$/,
  bytes32: /^0x[0-9a-fA-F]{64}$/,
  digest: /^sha256:[0-9a-f]{64}$/,
  atomic: /^(0|[1-9][0-9]{0,77})$/,
  code: /^[A-Za-z0-9._:-]{1,128}$/,
  origin: /^https?:\/\/[A-Za-z0-9.:[\]-]{1,128}$/,
  path: /^\/[^\s?#]{0,256}$/,
  timestamp: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/,
  prose: /^[A-Za-z0-9 ,.;:()'"/_@+-]{1,240}$/,
} as const;

/** The shape an allowlisted audit field's value must take. */
export type AuditFieldShape =
  | keyof typeof SHAPE_PATTERNS
  | "boolean"
  | "integer"
  | { readonly list: AuditFieldShape }
  | { readonly object: Readonly<Record<string, AuditFieldShape>> };

/** Field name to required shape, for one kind of audit record. */
export type AuditPayloadSpec = Readonly<Record<string, AuditFieldShape>>;

export class AuditPayloadError extends Error {
  readonly field: string;

  constructor(where: string, field: string, detail: string) {
    super(`${where}: field ${field} ${detail}`);
    this.name = "AuditPayloadError";
    this.field = field;
  }
}

/**
 * Checks a payload against an explicit field allowlist, throwing on anything
 * unexpected.
 *
 * Use this wherever a process holds key material. A field absent from `spec` is
 * rejected rather than redacted, so adding a new field to a record is a
 * deliberate edit to the allowlist and not something a call site can do by
 * accident.
 *
 * @param payload The record payload.
 * @param spec Allowed field names and the shape each value must match.
 * @param where Caller label used in error messages.
 * @returns The payload, unchanged, when every field is allowed.
 */
export function assertAllowlistedPayload<T extends Record<string, unknown>>(
  payload: T,
  spec: AuditPayloadSpec,
  where: string,
): T {
  for (const [field, value] of Object.entries(payload)) {
    if (value === undefined) continue;
    const shape = spec[field];
    if (shape === undefined) {
      throw new AuditPayloadError(where, field, "is not on this record's allowlist");
    }
    assertShape(value, shape, where, field);
  }
  return payload;
}

function assertShape(value: unknown, shape: AuditFieldShape, where: string, field: string): void {
  if (typeof shape === "object") {
    if ("list" in shape) {
      if (!Array.isArray(value)) throw new AuditPayloadError(where, field, "must be an array");
      if (value.length > MAX_ARRAY_LENGTH) throw new AuditPayloadError(where, field, "has too many entries");
      value.forEach((item, index) => assertShape(item, shape.list, where, `${field}[${String(index)}]`));
      return;
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new AuditPayloadError(where, field, "must be an object");
    }
    for (const [childField, childValue] of Object.entries(value as Record<string, unknown>)) {
      if (childValue === undefined) continue;
      const childShape = shape.object[childField];
      if (childShape === undefined) {
        throw new AuditPayloadError(where, `${field}.${childField}`, "is not on this record's allowlist");
      }
      assertShape(childValue, childShape, where, `${field}.${childField}`);
    }
    return;
  }

  if (shape === "boolean") {
    if (typeof value !== "boolean") throw new AuditPayloadError(where, field, "must be a boolean");
    return;
  }
  if (shape === "integer") {
    if (typeof value !== "number" || !Number.isSafeInteger(value)) {
      throw new AuditPayloadError(where, field, "must be a safe integer");
    }
    return;
  }
  if (typeof value !== "string") {
    throw new AuditPayloadError(where, field, `must be a string matching ${shape}`);
  }
  if (containsLongHex(value)) {
    throw new AuditPayloadError(where, field, "contains hex long enough to be a signature or key");
  }
  if (!SHAPE_PATTERNS[shape].test(value)) {
    throw new AuditPayloadError(where, field, `does not match the ${shape} shape`);
  }
}

/** True when a string holds a hex run long enough to be key or signature material. */
export function containsLongHex(value: string): boolean {
  LONG_PREFIXED_HEX.lastIndex = 0;
  LONG_BARE_HEX.lastIndex = 0;
  return LONG_PREFIXED_HEX.test(value) || LONG_BARE_HEX.test(value);
}

/**
 * Produces a value safe to persist or return.
 *
 * Defense in depth only; see the module comment. Notably it never keeps an
 * upstream exception's message: those can be unbounded and can quote request
 * bodies or signed payloads verbatim, so only the error class name survives and
 * callers are expected to supply their own bounded, stable code instead.
 *
 * @param value Any JSON-like value.
 * @returns A redacted copy.
 */
export function redact(value: unknown): unknown {
  return redactInner(value, 0);
}

/** {@link redact} for an object payload, which is what audit records carry. */
export function redactPayload(value: Record<string, unknown>): Record<string, unknown> {
  const result = redactInner(value, 0);
  return typeof result === "object" && result !== null && !Array.isArray(result)
    ? (result as Record<string, unknown>)
    : { redacted: true };
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replaceAll(/[^a-z0-9]/g, "");
}

function redactInner(value: unknown, depth: number): unknown {
  if (depth > MAX_DEPTH) return "[truncated_nesting]";
  if (value === null) return null;

  switch (typeof value) {
    case "undefined":
      return undefined;
    case "boolean":
      return value;
    case "bigint":
      return value.toString(10);
    case "number":
      return Number.isSafeInteger(value) ? value : "[redacted_non_integer]";
    case "string":
      return redactString(value);
    case "function":
    case "symbol":
      return "[redacted_non_data]";
    default:
      break;
  }

  if (value instanceof Error) {
    // The message is dropped, not truncated. An upstream message is arbitrary
    // text that has already been observed to carry an embedded signature.
    return { errorName: redactString(value.name) };
  }
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY_LENGTH).map((item) => redactInner(item, depth + 1));
    if (value.length > MAX_ARRAY_LENGTH) items.push(`[truncated_${String(value.length - MAX_ARRAY_LENGTH)}_more]`);
    return items;
  }

  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const normalized = normalizeKey(key);
    if (FORBIDDEN_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment))) {
      out[key] = "[redacted]";
      continue;
    }
    if (DIGEST_ONLY_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment))) {
      // An already-computed digest is passed through. Hashing it again would
      // produce a value that no longer matches the digest recorded elsewhere,
      // silently breaking the linkage these fields exist to provide.
      if (typeof child === "string") {
        out[key] = SHAPE_PATTERNS.digest.test(child) ? child : sha256Hex(child);
      } else {
        out[key] = "[redacted]";
      }
      continue;
    }
    const redacted = redactInner(child, depth + 1);
    if (redacted !== undefined) out[key] = redacted;
  }
  return out;
}

/**
 * Replaces every embedded hex run long enough to be key or signature material
 * with its digest, then bounds the length. Anchored matching is not enough: a
 * signature inside a sentence is still a signature.
 */
function redactString(value: string): string {
  const withoutHex = value
    .replace(LONG_PREFIXED_HEX, (match) => sha256Hex(match))
    .replace(LONG_BARE_HEX, (match) => sha256Hex(match));
  return withoutHex.length > MAX_STRING_LENGTH
    ? `${withoutHex.slice(0, MAX_STRING_LENGTH)}[truncated]`
    : withoutHex;
}

/**
 * Throws when a value still contains something that must never be persisted.
 * Runs immediately before an audit record is written, and in tests.
 */
export function assertNoSecretMaterial(value: unknown, where: string): void {
  walk(value, 0);

  function walk(node: unknown, depth: number): void {
    if (depth > MAX_DEPTH + 4) return;
    if (typeof node === "string") {
      if (containsLongHex(node)) {
        throw new Error(`${where}: value contains hex long enough to be a signature or key`);
      }
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    if (typeof node !== "object" || node === null) return;
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      const normalized = normalizeKey(key);
      const forbidden = FORBIDDEN_KEY_FRAGMENTS.find((fragment) => normalized.includes(fragment));
      if (forbidden !== undefined && child !== "[redacted]") {
        throw new Error(`${where}: value carries a ${forbidden} field that must be redacted`);
      }
      const digestOnly = DIGEST_ONLY_KEY_FRAGMENTS.find((fragment) => normalized.includes(fragment));
      if (
        digestOnly !== undefined &&
        child !== "[redacted]" &&
        !(typeof child === "string" && child.startsWith("sha256:"))
      ) {
        throw new Error(`${where}: field ${key} must be reduced to a sha256 digest`);
      }
      walk(child, depth + 1);
    }
  }
}
