import {
  assertBroadcastAllowed,
  chainIdForCaip2,
  requireChainProfile,
  type ChainProfile,
} from "../chain/profiles.js";
import type { AssetProfile, NormalizedQuote, PaymentPolicy } from "../types.js";

/**
 * Stable denial codes. These appear in audit records and tests, so they are part
 * of the contract: add new ones rather than repurposing an existing one.
 */
export type PolicyDenialCode =
  | "chain_not_configured"
  | "chain_mismatch"
  | "broadcast_not_authorized"
  | "service_origin_not_allowed"
  | "resource_path_not_allowed"
  | "payee_not_allowed"
  | "asset_not_allowed"
  | "asset_decimals_mismatch"
  | "asset_domain_mismatch"
  | "asset_transfer_method_not_allowed"
  | "amount_not_positive"
  | "amount_over_per_payment_limit"
  | "budget_exhausted"
  | "quote_expired"
  | "quote_ttl_too_long"
  | "payment_timeout_too_long"
  | "request_digest_mismatch"
  | "request_body_too_large";

export interface PolicyDecisionContext {
  /** Current time in unix seconds. Injected so tests are not clock-dependent. */
  readonly nowSeconds: number;
  /**
   * Digest of the request body the caller actually intends to submit, where the
   * caller sees that body. The isolated signer never does — it binds chain,
   * asset, payee, amount and domain instead — so it omits this and the
   * request-to-quote binding is enforced by the buyer and the seller.
   */
  readonly expectedRequestDigest?: string | undefined;
  /** Byte length of that request body, where the caller has it. */
  readonly requestBodyBytes?: number | undefined;
  /**
   * Atomic units already committed under this policy: settled plus in flight.
   *
   * Optional, and omitted by the isolated signer on purpose. The signer's
   * authoritative limit check happens inside the reservation transaction, which
   * recognizes an exact replay *before* evaluating any limit. Running an
   * incremental budget check here as well would reject the exact retry of a
   * payment that already filled the budget — the retry adds no new spend, so
   * refusing it would strand a legitimate recovery.
   */
  readonly committedSpendAtomic?: bigint | undefined;
}

export type PolicyDecision =
  | {
      readonly allowed: true;
      readonly asset: AssetProfile;
      readonly chain: ChainProfile;
      /**
       * Committed spend after this payment, when the caller supplied the current
       * total. Undefined where the budget check was left to the reservation
       * transaction.
       */
      readonly committedSpendAfterAtomic: bigint | undefined;
    }
  | {
      readonly allowed: false;
      readonly code: PolicyDenialCode;
      /** Operator-facing reason. Contains no upstream text and no secrets. */
      readonly reason: string;
    };

function deny(code: PolicyDenialCode, reason: string): PolicyDecision {
  return { allowed: false, code, reason };
}

const sameAddress = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/**
 * Decides whether a normalized quote may be paid under `policy`.
 *
 * Every check runs against operator configuration or locally derived facts. The
 * quote supplies values to compare, never values to adopt: a seller cannot widen
 * a limit, pick an asset, choose a domain or extend an expiry by what it sends.
 *
 * @param policy Operator-authored policy. The signer holds its own copy.
 * @param quote Normalized seller quote.
 * @param context Locally derived facts: clock, request digest, committed spend.
 * @returns An allow decision carrying the resolved asset and chain, or a denial.
 */
export function evaluateQuote(
  policy: PaymentPolicy,
  quote: NormalizedQuote,
  context: PolicyDecisionContext,
): PolicyDecision {
  if (quote.network !== policy.network) {
    return deny(
      "chain_mismatch",
      `quote is for ${quote.network} but the policy pays only on ${policy.network}`,
    );
  }

  let chain: ChainProfile;
  try {
    chain = requireChainProfile(quote.network);
  } catch {
    return deny("chain_not_configured", `chain ${quote.network} has no configured profile`);
  }

  try {
    assertBroadcastAllowed(chain);
  } catch (error) {
    return deny("broadcast_not_authorized", error instanceof Error ? error.message : "broadcast refused");
  }

  if (!policy.allowedServiceOrigins.includes(quote.serviceOrigin)) {
    return deny("service_origin_not_allowed", `service origin ${quote.serviceOrigin} is not allowed`);
  }
  if (!policy.allowedResourcePaths.includes(quote.resourcePath)) {
    return deny("resource_path_not_allowed", `resource path ${quote.resourcePath} is not allowed`);
  }
  if (!policy.allowedPayees.some((payee) => sameAddress(payee, quote.payTo))) {
    return deny("payee_not_allowed", "quoted payee is not an allowed recipient");
  }

  const asset = policy.allowedAssets.find((candidate) => sameAddress(candidate.address, quote.asset));
  if (!asset) {
    return deny("asset_not_allowed", "quoted asset is not an approved asset");
  }
  if (asset.decimals !== quote.assetDecimals) {
    return deny(
      "asset_decimals_mismatch",
      `quote claims ${String(quote.assetDecimals)} decimals; configuration says ${String(asset.decimals)}`,
    );
  }
  if (asset.eip712Name !== quote.eip712Name || asset.eip712Version !== quote.eip712Version) {
    return deny("asset_domain_mismatch", "quoted EIP-712 domain does not match the configured asset");
  }
  if (asset.assetTransferMethod !== quote.assetTransferMethod) {
    return deny(
      "asset_transfer_method_not_allowed",
      `asset transfer method ${quote.assetTransferMethod} is not configured for this asset`,
    );
  }

  const amount = BigInt(quote.amount);
  if (amount <= 0n) {
    return deny("amount_not_positive", "a payment amount must be a positive integer of atomic units");
  }
  const perPaymentLimit = BigInt(policy.maxAmountPerPayment);
  if (amount > perPaymentLimit) {
    return deny(
      "amount_over_per_payment_limit",
      `amount exceeds the per-payment limit of ${policy.maxAmountPerPayment} atomic units`,
    );
  }

  let committedAfter: bigint | undefined;
  if (context.committedSpendAtomic !== undefined) {
    committedAfter = context.committedSpendAtomic + amount;
    if (committedAfter > BigInt(policy.totalBudget)) {
      return deny(
        "budget_exhausted",
        `payment would commit ${committedAfter.toString(10)} against a total budget of ${policy.totalBudget}`,
      );
    }
  }

  if (quote.expiresAt <= context.nowSeconds) {
    return deny("quote_expired", "quote expiry is not in the future");
  }
  if (quote.expiresAt - context.nowSeconds > policy.maxQuoteTtlSeconds) {
    return deny(
      "quote_ttl_too_long",
      `quote is valid for longer than the permitted ${String(policy.maxQuoteTtlSeconds)}s`,
    );
  }
  if (quote.maxTimeoutSeconds > policy.maxQuoteTtlSeconds) {
    return deny(
      "payment_timeout_too_long",
      `quoted payment timeout exceeds the permitted ${String(policy.maxQuoteTtlSeconds)}s`,
    );
  }

  if (context.requestBodyBytes !== undefined && context.requestBodyBytes > policy.maxRequestBodyBytes) {
    return deny(
      "request_body_too_large",
      `request body of ${String(context.requestBodyBytes)} bytes exceeds the configured maximum`,
    );
  }
  if (context.expectedRequestDigest !== undefined && quote.requestDigest !== context.expectedRequestDigest) {
    return deny("request_digest_mismatch", "quote prices a different request body than the one to be sent");
  }

  // Cross-check that the CAIP-2 id and the profile agree on the numeric chain id,
  // so a malformed profile cannot make a signature land on another chain.
  if (chainIdForCaip2(quote.network) !== chain.chainId) {
    return deny("chain_mismatch", "CAIP-2 chain id disagrees with the configured profile");
  }

  return { allowed: true, asset, chain, committedSpendAfterAtomic: committedAfter };
}
