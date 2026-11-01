import { describe, expect, it } from "vitest";
import { validateAuthorizationRequest } from "@pulseagent/signer";
import type { PaymentPolicy, SignerAuthorizationRequest } from "@pulseagent/core";

const ASSET = "0x1111111111111111111111111111111111111111";
const PAYEE = "0x2222222222222222222222222222222222222222";
const SIGNER = "0x3333333333333333333333333333333333333333" as const;
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

const request: SignerAuthorizationRequest = {
  intentId: "int_abcdef123456",
  idempotencyKey: "idem_abcdef123456",
  principalId: "buyer-a",
  quote: {
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
  },
  typedData: {
    primaryType: "TransferWithAuthorization",
    domain: { name: "Test Token", version: "1", chainId: 31_337, verifyingContract: ASSET },
    message: {
      from: SIGNER,
      to: PAYEE,
      value: "1500",
      validAfter: "0",
      validBefore: String(NOW + 120),
      nonce: `0x${"cc".repeat(32)}`,
    },
  },
};

const context = { nowSeconds: NOW, signerAddress: SIGNER, clockSkewSeconds: 60 };

function expectDenial(mutate: (draft: SignerAuthorizationRequest) => SignerAuthorizationRequest, code: string): void {
  const result = validateAuthorizationRequest(policy, mutate(structuredClone(request)), context);
  expect(result.ok, `expected ${code} but the request was authorized`).toBe(false);
  if (!result.ok) expect(result.code).toBe(code);
}

describe("signer validation", () => {
  it("authorizes a request that matches policy, rebuilding the typed data itself", () => {
    const result = validateAuthorizationRequest(policy, request, context);
    expect(result.ok).toBe(true);
    if (result.ok) {
      // Rebuilt from policy, not adopted from the request.
      expect(result.typedData.domain.verifyingContract).toBe(ASSET);
      expect(result.typedData.domain.chainId).toBe(31_337);
      expect(result.typedData.message.value).toBe(1500n);
      expect(result.typedData.message.validAfter).toBe(0n);
      expect(result.typedData.primaryType).toBe("TransferWithAuthorization");
    }
  });

  it("refuses a request for another principal", () => {
    expectDenial((draft) => ({ ...draft, principalId: "buyer-b" }), "principal_mismatch");
  });

  it("refuses a message paying from an account it does not control", () => {
    expectDenial(
      (draft) => ({
        ...draft,
        typedData: {
          ...draft.typedData,
          message: { ...draft.typedData.message, from: "0x9999999999999999999999999999999999999999" },
        },
      }),
      "wrong_payer",
    );
  });

  it("refuses a tampered EIP-712 domain", () => {
    expectDenial(
      (draft) => ({ ...draft, typedData: { ...draft.typedData, domain: { ...draft.typedData.domain, name: "Other" } } }),
      "domain_name_mismatch",
    );
    expectDenial(
      (draft) => ({ ...draft, typedData: { ...draft.typedData, domain: { ...draft.typedData.domain, version: "2" } } }),
      "domain_version_mismatch",
    );
    // A signature for another chain must never be produced here.
    expectDenial(
      (draft) => ({ ...draft, typedData: { ...draft.typedData, domain: { ...draft.typedData.domain, chainId: 1 } } }),
      "domain_chain_mismatch",
    );
    expectDenial(
      (draft) => ({
        ...draft,
        typedData: {
          ...draft.typedData,
          domain: { ...draft.typedData.domain, verifyingContract: "0x8888888888888888888888888888888888888888" },
        },
      }),
      "verifying_contract_mismatch",
    );
  });

  it("refuses a message that redirects the payee or changes the amount", () => {
    expectDenial(
      (draft) => ({
        ...draft,
        typedData: {
          ...draft.typedData,
          message: { ...draft.typedData.message, to: "0x7777777777777777777777777777777777777777" },
        },
      }),
      "message_payee_mismatch",
    );
    expectDenial(
      (draft) => ({
        ...draft,
        typedData: { ...draft.typedData, message: { ...draft.typedData.message, value: "1501" } },
      }),
      "message_value_mismatch",
    );
  });

  it("refuses an authorization whose validity window is wrong", () => {
    expectDenial(
      (draft) => ({
        ...draft,
        typedData: { ...draft.typedData, message: { ...draft.typedData.message, validAfter: "1" } },
      }),
      "valid_after_not_zero",
    );
    expectDenial(
      (draft) => ({
        ...draft,
        typedData: { ...draft.typedData, message: { ...draft.typedData.message, validBefore: String(NOW) } },
      }),
      "valid_before_in_past",
    );
    expectDenial(
      (draft) => ({
        ...draft,
        typedData: {
          ...draft.typedData,
          message: { ...draft.typedData.message, validBefore: String(NOW + 1000) },
        },
      }),
      "valid_before_too_far",
    );
  });

  it("refuses anything but a transfer authorization", () => {
    expectDenial(
      (draft) =>
        ({
          ...draft,
          // Deliberately not a shape the schema allows: the signer must refuse
          // it at runtime, not merely be unable to express it.
          typedData: { ...draft.typedData, primaryType: "Permit" },
        }) as unknown as SignerAuthorizationRequest,
      "primary_type_not_allowed",
    );
  });

  it("applies the whole policy, so a bad quote is refused before any signing", () => {
    expectDenial((draft) => ({ ...draft, quote: { ...draft.quote, serviceOrigin: "https://evil.example" } }), "service_origin_not_allowed");
    expectDenial((draft) => ({ ...draft, quote: { ...draft.quote, asset: "0x5555555555555555555555555555555555555555" } }), "asset_not_allowed");
    expectDenial((draft) => ({ ...draft, quote: { ...draft.quote, expiresAt: NOW - 1 } }), "quote_expired");
  });

  it("refuses to sign for a chain this build may not broadcast to", () => {
    const publicPolicy: PaymentPolicy = { ...policy, network: "eip155:943" };
    const publicRequest = {
      ...structuredClone(request),
      quote: { ...request.quote, network: "eip155:943" },
      typedData: { ...request.typedData, domain: { ...request.typedData.domain, chainId: 943 } },
    };
    const result = validateAuthorizationRequest(publicPolicy, publicRequest, context);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("broadcast_not_authorized");
  });

  it("does not evaluate the budget, leaving that to the reservation transaction", () => {
    // Checking the budget here as well would refuse the exact retry of a payment
    // that already filled it, even though the retry adds no new spend.
    const atLimit: PaymentPolicy = { ...policy, totalBudget: "1500", maxAmountPerPayment: "1500" };
    expect(validateAuthorizationRequest(atLimit, request, context).ok).toBe(true);
  });
});
