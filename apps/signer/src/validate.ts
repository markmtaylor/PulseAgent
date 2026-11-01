import { authorizationTypes } from "@x402/evm";
import {
  assertBroadcastAllowed,
  chainIdForCaip2,
  evaluateQuote,
  requireChainProfile,
  type PaymentPolicy,
  type PolicyDenialCode,
  type SignerAuthorizationRequest,
} from "@pulseagent/core";

/**
 * Signer-side validation, independent of whatever the buyer claims.
 *
 * This is the part that has to hold even if everything calling it is
 * compromised. A model, an SDK or a seller can ask for a signature; none of them
 * can widen a limit, choose an asset, redirect a payee, pick a chain, or hand in
 * an "already approved" flag that means anything. Every value below is compared
 * against the signer's own policy copy or recomputed locally, and the request's
 * typed data is rebuilt from scratch and compared field by field — so a crafted
 * domain, a wrong verifying contract, a different primary type or a foreign
 * chain id is a rejection rather than a signature.
 */

export type SignerDenialCode =
  | PolicyDenialCode
  | "principal_mismatch"
  | "wrong_payer"
  | "primary_type_not_allowed"
  | "domain_name_mismatch"
  | "domain_version_mismatch"
  | "domain_chain_mismatch"
  | "verifying_contract_mismatch"
  | "message_payee_mismatch"
  | "message_value_mismatch"
  | "valid_after_not_zero"
  | "valid_before_in_past"
  | "valid_before_too_far"
  | "typed_data_field_set_unexpected";

export interface SignerValidationContext {
  readonly nowSeconds: number;
  /** The signer's own address. The message must pay from exactly this account. */
  readonly signerAddress: `0x${string}`;

  /** Tolerance for clock disagreement between buyer, seller and signer, in seconds. */
  readonly clockSkewSeconds: number;
}

export type SignerValidation =
  | {
      readonly ok: true;
      /** The typed data the signer will sign, rebuilt locally rather than adopted. */
      readonly typedData: {
        readonly domain: {
          readonly name: string;
          readonly version: string;
          readonly chainId: number;
          readonly verifyingContract: `0x${string}`;
        };
        readonly types: typeof authorizationTypes;
        readonly primaryType: "TransferWithAuthorization";
        readonly message: {
          readonly from: `0x${string}`;
          readonly to: `0x${string}`;
          readonly value: bigint;
          readonly validAfter: bigint;
          readonly validBefore: bigint;
          readonly nonce: `0x${string}`;
        };
      };
      readonly amountAtomic: string;
      readonly assetAddress: `0x${string}`;
    }
  | { readonly ok: false; readonly code: SignerDenialCode; readonly reason: string };

const sameAddress = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

const deny = (code: SignerDenialCode, reason: string): SignerValidation => ({ ok: false, code, reason });

/**
 * Decides whether the signer will authorize `request`.
 *
 * @param policy The signer's own policy copy, loaded at startup.
 * @param request The authorization request, already schema-validated.
 * @param context Locally held facts: clock, signer address, committed spend.
 * @returns Locally rebuilt typed data to sign, or a denial.
 */
export function validateAuthorizationRequest(
  policy: PaymentPolicy,
  request: SignerAuthorizationRequest,
  context: SignerValidationContext,
): SignerValidation {
  if (request.principalId !== policy.principalId) {
    return deny("principal_mismatch", "request names a principal this signer does not act for");
  }

  const profile = requireChainProfile(policy.network);
  try {
    // A public chain fails here, loudly, rather than being signed for.
    assertBroadcastAllowed(profile);
  } catch (error) {
    return deny("broadcast_not_authorized", error instanceof Error ? error.message : "broadcast refused");
  }

  // No budget argument: the limit is enforced inside the reservation
  // transaction, which recognizes an exact replay before evaluating it. Checking
  // the budget here too would refuse the exact retry of a payment that already
  // filled it, even though the retry adds no new spend.
  const decision = evaluateQuote(policy, request.quote, { nowSeconds: context.nowSeconds });
  if (!decision.allowed) {
    return deny(decision.code, decision.reason);
  }
  const { asset } = decision;

  const { typedData } = request;
  if (typedData.primaryType !== "TransferWithAuthorization") {
    return deny("primary_type_not_allowed", "only a TransferWithAuthorization message may be signed");
  }
  if (typedData.domain.name !== asset.eip712Name) {
    return deny("domain_name_mismatch", "domain name does not match the configured asset");
  }
  if (typedData.domain.version !== asset.eip712Version) {
    return deny("domain_version_mismatch", "domain version does not match the configured asset");
  }
  const expectedChainId = chainIdForCaip2(policy.network);
  if (typedData.domain.chainId !== expectedChainId) {
    return deny(
      "domain_chain_mismatch",
      `domain chain id ${String(typedData.domain.chainId)} is not ${String(expectedChainId)}`,
    );
  }
  if (!sameAddress(typedData.domain.verifyingContract, asset.address)) {
    return deny("verifying_contract_mismatch", "verifying contract is not the configured asset address");
  }

  const { message } = typedData;
  if (!sameAddress(message.from, context.signerAddress)) {
    return deny("wrong_payer", "message pays from an account this signer does not control");
  }
  if (!sameAddress(message.to, request.quote.payTo)) {
    return deny("message_payee_mismatch", "message payee does not match the quoted payee");
  }
  if (!policy.allowedPayees.some((payee) => sameAddress(payee, message.to))) {
    return deny("payee_not_allowed", "message payee is not an allowed recipient");
  }
  if (BigInt(message.value) !== BigInt(request.quote.amount)) {
    return deny("message_value_mismatch", "message value does not match the quoted amount");
  }
  if (BigInt(message.validAfter) !== 0n) {
    return deny("valid_after_not_zero", "this build signs only authorizations valid from the epoch");
  }

  const validBefore = BigInt(message.validBefore);
  if (validBefore <= BigInt(context.nowSeconds)) {
    return deny("valid_before_in_past", "authorization would already be expired when signed");
  }
  const latestAllowed = BigInt(context.nowSeconds + policy.maxQuoteTtlSeconds + context.clockSkewSeconds);
  if (validBefore > latestAllowed) {
    return deny(
      "valid_before_too_far",
      `authorization validity extends past the permitted ${String(policy.maxQuoteTtlSeconds)}s window`,
    );
  }

  return {
    ok: true,
    amountAtomic: request.quote.amount,
    assetAddress: asset.address as `0x${string}`,
    typedData: {
      // Rebuilt from policy and quote, not copied from the request. The checks
      // above are what make this equal to what was asked for.
      domain: {
        name: asset.eip712Name,
        version: asset.eip712Version,
        chainId: expectedChainId,
        verifyingContract: asset.address as `0x${string}`,
      },
      types: authorizationTypes,
      primaryType: "TransferWithAuthorization",
      message: {
        from: context.signerAddress,
        to: request.quote.payTo as `0x${string}`,
        value: BigInt(request.quote.amount),
        validAfter: 0n,
        validBefore,
        nonce: message.nonce as `0x${string}`,
      },
    },
  };
}
