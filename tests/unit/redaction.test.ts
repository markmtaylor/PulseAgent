import { describe, expect, it } from "vitest";
import {
  AuditPayloadError,
  assertAllowlistedPayload,
  assertNoSecretMaterial,
  containsLongHex,
  redact,
  redactPayload,
  sha256Hex,
} from "@pulseagent/core";

/** A synthetic 65-byte marker. Not a real key, signature or credential. */
const SYNTHETIC_SIGNATURE = `0x${"ab".repeat(65)}`;
const SYNTHETIC_BEARER = "ey".padEnd(200, "x");

describe("redaction", () => {
  it("detects a long hex run anywhere in a string, not only as the whole of it", () => {
    expect(containsLongHex(SYNTHETIC_SIGNATURE)).toBe(true);
    // The executed review finding: an embedded marker inside prose.
    expect(containsLongHex(`upstream authorization: ${SYNTHETIC_SIGNATURE}`)).toBe(true);
    expect(containsLongHex(`${"ab".repeat(65)} trailing`)).toBe(true);
    // Legitimate values of these shapes stay.
    expect(containsLongHex("0x1111111111111111111111111111111111111111")).toBe(false);
    expect(containsLongHex(`0x${"cd".repeat(32)}`)).toBe(false);
    expect(containsLongHex(`sha256:${"a".repeat(64)}`)).toBe(false);
  });

  it("digests an embedded signature rather than keeping it", () => {
    const redacted = redact({ note: `upstream authorization: ${SYNTHETIC_SIGNATURE}` }) as { note: string };
    expect(redacted.note).not.toContain("abab");
    expect(redacted.note).toContain("sha256:");
  });

  it("drops an upstream error message entirely", () => {
    // Truncation is not redaction: a 65-byte marker is 132 characters and
    // survives any slice long enough to be useful.
    const redacted = redact(new Error(`boom ${SYNTHETIC_SIGNATURE}`)) as Record<string, unknown>;
    expect(redacted).toEqual({ errorName: "Error" });
    expect(JSON.stringify(redacted)).not.toContain("abab");
  });

  it("removes a field whose name marks it as secret, however it is spelled", () => {
    for (const key of ["privateKey", "private_key", "PRIVATE-KEY", "mnemonic", "apiKey", "bearerToken", "secret"]) {
      const redacted = redactPayload({ [key]: SYNTHETIC_BEARER }) as Record<string, string>;
      expect(redacted[key], key).toBe("[redacted]");
    }
  });

  it("digests a raw signature field but preserves an already-computed digest", () => {
    const fromRaw = redactPayload({ signature: SYNTHETIC_SIGNATURE }) as { signature: string };
    expect(fromRaw.signature).toBe(sha256Hex(SYNTHETIC_SIGNATURE));

    // Re-hashing a digest would break the linkage these fields exist to provide.
    const digest = sha256Hex(SYNTHETIC_SIGNATURE);
    const fromDigest = redactPayload({ signatureDigest: digest }) as { signatureDigest: string };
    expect(fromDigest.signatureDigest).toBe(digest);
  });

  it("bounds strings and arrays", () => {
    const long = redact({ note: "x".repeat(5000) }) as { note: string };
    expect(long.note.length).toBeLessThan(300);
    const many = redact({ items: Array.from({ length: 500 }, (_, i) => i) }) as { items: unknown[] };
    expect(many.items.length).toBeLessThanOrEqual(65);
  });

  it("fails the secret-material assertion on an embedded marker", () => {
    expect(() => assertNoSecretMaterial({ note: `x ${SYNTHETIC_SIGNATURE}` }, "test")).toThrow(/signature or key/);
    expect(() => assertNoSecretMaterial({ privateKey: "anything" }, "test")).toThrow(/privatekey/);
    expect(() => assertNoSecretMaterial({ signature: SYNTHETIC_SIGNATURE }, "test")).toThrow(/sha256 digest/);
    // What redaction produces must pass.
    expect(() => assertNoSecretMaterial(redactPayload({ note: `x ${SYNTHETIC_SIGNATURE}` }), "test")).not.toThrow();
  });
});

describe("field allowlist at a key-bearing boundary", () => {
  const spec = {
    payer: "address",
    amountAtomic: "atomic",
    signatureDigest: "digest",
    nonce: "bytes32",
    code: "code",
    replayed: "boolean",
    legs: { list: { object: { asset: "code", amountAtomic: "atomic" } } },
  } as const;

  it("accepts only the named fields in the stated shapes", () => {
    expect(() =>
      assertAllowlistedPayload(
        {
          payer: "0x1111111111111111111111111111111111111111",
          amountAtomic: "1500",
          signatureDigest: sha256Hex("x"),
          nonce: `0x${"ab".repeat(32)}`,
          code: "budget_exhausted",
          replayed: false,
          legs: [{ asset: "native:gas", amountAtomic: "1000" }],
        },
        spec,
        "test",
      ),
    ).not.toThrow();
  });

  it("refuses a field that is not on the list", () => {
    // A 32-byte key and a 32-byte hash are the same length and alphabet, so the
    // decision has to be made by field name, in advance.
    expect(() => assertAllowlistedPayload({ someKey: `0x${"ab".repeat(32)}` }, spec, "test")).toThrow(
      AuditPayloadError,
    );
    expect(() => assertAllowlistedPayload({ someKey: "x" }, spec, "test")).toThrow(/not on this record's allowlist/);
  });

  it("refuses an allowed field whose value is the wrong shape", () => {
    expect(() => assertAllowlistedPayload({ payer: "not-an-address" }, spec, "test")).toThrow(/address shape/);
    expect(() => assertAllowlistedPayload({ amountAtomic: "1.5" }, spec, "test")).toThrow(/atomic shape/);
    expect(() => assertAllowlistedPayload({ amountAtomic: 1500 }, spec, "test")).toThrow(/must be a string/);
    expect(() => assertAllowlistedPayload({ replayed: "yes" }, spec, "test")).toThrow(/must be a boolean/);
    expect(() => assertAllowlistedPayload({ signatureDigest: "deadbeef" }, spec, "test")).toThrow(/digest shape/);
  });

  it("refuses signature-length hex even in an allowed field", () => {
    expect(() => assertAllowlistedPayload({ code: SYNTHETIC_SIGNATURE }, spec, "test")).toThrow(
      /signature or key/,
    );
  });

  it("refuses an unexpected field nested inside an allowed object", () => {
    expect(() =>
      assertAllowlistedPayload({ legs: [{ asset: "native:gas", amountAtomic: "1", extra: "x" }] }, spec, "test"),
    ).toThrow(/legs\[0\]\.extra/);
  });
});
