import { describe, expect, it } from "vitest";
import { evaluateQuote, type NormalizedQuote, type PaymentPolicy } from "@pulseagent/core";

const ASSET = "0x1111111111111111111111111111111111111111";
const PAYEE = "0x2222222222222222222222222222222222222222";
const NOW = 1_800_000_000;

const policy: PaymentPolicy = {
  principalId: "buyer-a",
  policyRevision: "rev-1",
  network: "eip155:31337",
  allowedServiceOrigins: ["http://127.0.0.1:8080"],
  allowedResourcePaths: ["/digest"],
  allowedPayees: [PAYEE],
  allowedAssets: [
    {
      address: ASSET,
      symbol: "PAVT",
      decimals: 6,
      eip712Name: "Test Token",
      eip712Version: "1",
      assetTransferMethod: "eip3009",
      valuelessTestFixture: true,
    },
  ],
  maxAmountPerPayment: "2000",
  totalBudget: "10000",
  maxGasReservationWei: "1000",
  totalGasBudgetWei: "100000",
  maxQuoteTtlSeconds: 300,
  maxRequestBodyBytes: 4096,
};

const quote: NormalizedQuote = {
  quoteId: "quote_abcdef123456",
  serviceOrigin: "http://127.0.0.1:8080",
  resourcePath: "/digest",
  requestDigest: `sha256:${"a".repeat(64)}`,
  network: "eip155:31337",
  asset: ASSET,
  assetDecimals: 6,
  payTo: PAYEE,
  amount: "1500",
  expiresAt: NOW + 120,
  eip712Name: "Test Token",
  eip712Version: "1",
  assetTransferMethod: "eip3009",
  maxTimeoutSeconds: 120,
};

const context = {
  nowSeconds: NOW,
  expectedRequestDigest: quote.requestDigest,
  requestBodyBytes: 64,
  committedSpendAtomic: 0n,
};

/** Asserts a specific denial code, so a test cannot pass on the wrong refusal. */
function expectDenial(
  overrides: Partial<NormalizedQuote>,
  code: string,
  contextOverrides: Partial<typeof context> = {},
): void {
  const decision = evaluateQuote(policy, { ...quote, ...overrides }, { ...context, ...contextOverrides });
  expect(decision.allowed, `expected ${code} but the quote was allowed`).toBe(false);
  if (!decision.allowed) expect(decision.code).toBe(code);
}

describe("policy engine", () => {
  it("allows a quote that satisfies every configured constraint", () => {
    const decision = evaluateQuote(policy, quote, context);
    expect(decision.allowed).toBe(true);
    if (decision.allowed) {
      expect(decision.asset.address).toBe(ASSET);
      expect(decision.chain.caip2).toBe("eip155:31337");
      expect(decision.committedSpendAfterAtomic).toBe(1500n);
    }
  });

  it("refuses a chain the policy does not pay on, and one with no profile", () => {
    expectDenial({ network: "eip155:943" }, "chain_mismatch");
    expectDenial({ network: "eip155:369" }, "chain_mismatch");
    const other = evaluateQuote({ ...policy, network: "eip155:1" }, { ...quote, network: "eip155:1" }, context);
    expect(other.allowed).toBe(false);
    if (!other.allowed) expect(other.code).toBe("chain_not_configured");
  });

  it("refuses a chain this build may not broadcast to", () => {
    const publicQuote = { ...quote, network: "eip155:943" as const };
    const decision = evaluateQuote({ ...policy, network: "eip155:943" }, publicQuote, context);
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.code).toBe("broadcast_not_authorized");
  });

  it("refuses an origin, path or payee outside configuration", () => {
    expectDenial({ serviceOrigin: "http://127.0.0.1:9999" }, "service_origin_not_allowed");
    expectDenial({ serviceOrigin: "https://evil.example" }, "service_origin_not_allowed");
    expectDenial({ resourcePath: "/other" }, "resource_path_not_allowed");
    expectDenial({ payTo: "0x3333333333333333333333333333333333333333" }, "payee_not_allowed");
  });

  it("accepts a payee that differs only in checksum casing", () => {
    const decision = evaluateQuote(policy, { ...quote, payTo: PAYEE.toUpperCase().replace("0X", "0x") }, context);
    expect(decision.allowed).toBe(true);
  });

  it("refuses an unapproved asset and any disagreement about it", () => {
    expectDenial({ asset: "0x4444444444444444444444444444444444444444" }, "asset_not_allowed");
    expectDenial({ assetDecimals: 18 }, "asset_decimals_mismatch");
    expectDenial({ eip712Name: "Other Token" }, "asset_domain_mismatch");
    expectDenial({ eip712Version: "2" }, "asset_domain_mismatch");
  });

  it("refuses amounts that are not a positive integer within the limits", () => {
    expectDenial({ amount: "0" }, "amount_not_positive");
    expectDenial({ amount: "2001" }, "amount_over_per_payment_limit");
    // The per-payment limit binds before the budget does.
    expectDenial({ amount: "20000" }, "amount_over_per_payment_limit");
    expectDenial({}, "budget_exhausted", { committedSpendAtomic: 9000n });
    // An amount that exactly fills the remaining budget is allowed.
    expect(evaluateQuote(policy, quote, { ...context, committedSpendAtomic: 8500n }).allowed).toBe(true);
  });

  it("refuses a huge amount without overflowing, since amounts are bigints", () => {
    const huge = (2n ** 256n - 1n).toString(10);
    expectDenial({ amount: huge }, "amount_over_per_payment_limit");
  });

  it("refuses an expired quote and one valid for too long", () => {
    expectDenial({ expiresAt: NOW }, "quote_expired");
    expectDenial({ expiresAt: NOW - 1 }, "quote_expired");
    expectDenial({ expiresAt: NOW + 301 }, "quote_ttl_too_long");
    expectDenial({ maxTimeoutSeconds: 301 }, "payment_timeout_too_long");
  });

  it("refuses a quote that prices a different body than the one to be sent", () => {
    expectDenial({}, "request_digest_mismatch", { expectedRequestDigest: `sha256:${"b".repeat(64)}` });
    expectDenial({}, "request_body_too_large", { requestBodyBytes: 4097 });
  });

  it("skips the budget check when no committed total is supplied", () => {
    // The signer omits it deliberately: its authoritative check is the
    // reservation transaction, which recognizes an exact replay first.
    const decision = evaluateQuote(policy, quote, {
      nowSeconds: NOW,
      expectedRequestDigest: quote.requestDigest,
    });
    expect(decision.allowed).toBe(true);
    if (decision.allowed) expect(decision.committedSpendAfterAtomic).toBeUndefined();
  });
});
