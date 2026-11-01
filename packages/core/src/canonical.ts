/**
 * Canonical JSON encoding used for every hash and digest in the system.
 *
 * Rules, all of which exist so two processes agree byte-for-byte:
 * - object keys sorted by code unit
 * - `undefined` properties dropped
 * - non-integer and non-finite numbers rejected (money never passes through a float)
 * - bigint encoded as a base-10 string
 */
export function canonicalize(value: unknown): string {
  return encode(value, 0);
}

const MAX_DEPTH = 32;

function encode(value: unknown, depth: number): string {
  if (depth > MAX_DEPTH) {
    throw new Error("canonicalize: value nested deeper than 32 levels");
  }
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "bigint":
      return JSON.stringify(value.toString(10));
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isInteger(value)) {
        throw new Error("canonicalize: non-integer number rejected");
      }
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new Error(`canonicalize: unsupported type ${typeof value}`);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => encode(item, depth + 1)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${encode(v, depth + 1)}`).join(",")}}`;
}
