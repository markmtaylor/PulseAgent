import { digestOf } from "./digest.js";

/**
 * The request digest that binds a quote to the exact body it prices.
 *
 * It lives here, in shared code, because the buyer and the seller must derive it
 * independently and get the same answer. If the buyer took the digest from the
 * quote it would be comparing the seller's value to itself, which checks
 * nothing: a seller could price one body and be paid for another. The buyer
 * computes this from the input it is about to send and refuses a quote whose
 * digest does not match.
 */
export function serviceRequestDigest(input: {
  readonly service: string;
  readonly resourcePath: string;
  readonly input: string;
}): string {
  return digestOf({ service: input.service, resourcePath: input.resourcePath, input: input.input });
}

/**
 * The shared id for one payment, derived from facts both parties hold.
 *
 * A payment's lifecycle is recorded by several processes, and the buyer's own
 * intent id means nothing to the seller. Rather than have one side assert an id
 * the other must trust — which a different buyer could simply claim — both derive
 * this from the quote, the exact request, the payer and the authorization nonce.
 * Those are fixed by the signature and the chain's `AuthorizationUsed` event, so
 * the id cannot be chosen, only computed.
 */
export function paymentCorrelationId(input: {
  readonly quoteId: string;
  readonly requestDigest: string;
  readonly payer: string;
  readonly authorizationNonce: string;
}): string {
  const digest = digestOf({
    quoteId: input.quoteId,
    requestDigest: input.requestDigest,
    payer: input.payer.toLowerCase(),
    authorizationNonce: input.authorizationNonce.toLowerCase(),
  });
  return `pay_${digest.replace("sha256:", "").slice(0, 40)}`;
}
