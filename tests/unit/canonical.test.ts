import { describe, expect, it } from "vitest";
import { canonicalize, digestOf, paymentCorrelationId, serviceRequestDigest, sha256Hex } from "@pulseagent/core";

describe("canonical encoding", () => {
  it("orders keys so two processes agree byte for byte", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ a: 2, b: 1 })).toBe(canonicalize({ b: 1, a: 2 }));
  });

  it("drops undefined properties rather than encoding them", () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it("refuses a non-integer number, so money cannot pass through a float", () => {
    expect(() => canonicalize({ amount: 1.5 })).toThrow(/non-integer/);
    expect(() => canonicalize({ amount: Number.NaN })).toThrow(/non-integer/);
    expect(() => canonicalize({ amount: Number.POSITIVE_INFINITY })).toThrow(/non-integer/);
  });

  it("encodes a bigint as a base-10 string", () => {
    expect(canonicalize({ amount: 10n ** 30n })).toBe('{"amount":"1000000000000000000000000000000"}');
  });

  it("refuses runaway nesting", () => {
    let nested: unknown = 1;
    for (let i = 0; i < 40; i += 1) nested = { nested };
    expect(() => canonicalize(nested)).toThrow(/nested deeper/);
  });

  it("produces stable digests regardless of key order", () => {
    expect(digestOf({ a: 1, b: 2 })).toBe(digestOf({ b: 2, a: 1 }));
    expect(digestOf({ a: 1 })).not.toBe(digestOf({ a: 2 }));
    expect(sha256Hex("")).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe("request and payment identity", () => {
  it("binds a request digest to the service, path and body together", () => {
    const base = { service: "sha256-digest", resourcePath: "/digest", input: "hello" };
    expect(serviceRequestDigest(base)).toBe(serviceRequestDigest({ ...base }));
    expect(serviceRequestDigest({ ...base, input: "hello " })).not.toBe(serviceRequestDigest(base));
    expect(serviceRequestDigest({ ...base, resourcePath: "/other" })).not.toBe(serviceRequestDigest(base));
    expect(serviceRequestDigest({ ...base, service: "other" })).not.toBe(serviceRequestDigest(base));
  });

  it("derives one correlation id from facts both parties hold", () => {
    const base = {
      quoteId: "quote_1",
      requestDigest: `sha256:${"a".repeat(64)}`,
      payer: "0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa",
      authorizationNonce: `0x${"bb".repeat(32)}`,
    };
    // Address and nonce casing must not change the id: the two sides may render
    // them differently and still be describing the same payment.
    expect(paymentCorrelationId(base)).toBe(
      paymentCorrelationId({
        ...base,
        payer: base.payer.toLowerCase(),
        authorizationNonce: base.authorizationNonce.toUpperCase().replace("0X", "0x"),
      }),
    );
    expect(paymentCorrelationId({ ...base, quoteId: "quote_2" })).not.toBe(paymentCorrelationId(base));
    expect(paymentCorrelationId({ ...base, authorizationNonce: `0x${"cc".repeat(32)}` })).not.toBe(
      paymentCorrelationId(base),
    );
  });
});
