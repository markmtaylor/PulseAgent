import { createPublicClient, http, type Hex, type PublicClient } from "viem";
import { x402Client } from "@x402/core/client";
import { wrapFetchWithPayment } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { createHash } from "node:crypto";
import {
  AuditLog,
  canonicalize,
  DigestServiceResultSchema,
  DurableStore,
  NormalizedQuoteSchema,
  PaymentPolicySchema,
  assertChainIdMatches,
  assertRpcAllowed,
  createViemSettlementReader,
  digestOf,
  evaluateQuote,
  randomId,
  paymentCorrelationId,
  requireChainProfile,
  serviceRequestDigest,
  verifySettlement,
  type AuditEvent,
  type ChainProfile,
  type DigestServiceResult,
  type IntentState,
  type NormalizedQuote,
  type PaymentIntent,
  type PaymentPolicy,
  type PolicyDenialCode,
  type SettlementFacts,
} from "@pulseagent/core";
import { connectRemoteSigner, withSigningContext, type RemoteSigner, type SigningContext } from "./remote-signer.js";

/**
 * Buyer-side SDK.
 *
 * The operations an agent — or the MCP server in front of it — can perform:
 * list configured services, request a quote, request a payment under policy,
 * read an intent's status, verify a settlement, and read the redacted audit
 * trail. That list is the whole surface. There is deliberately no operation for
 * approving a budget, editing a policy, choosing an RPC endpoint, signing
 * arbitrary data, or reaching a key, because a caller holding those could make
 * every other control here decorative.
 *
 * Nothing in this process can authorize spending. The policy is loaded from
 * operator configuration and the signer holds its own copy; this class's checks
 * exist to fail early and explain why, not to be the thing that stands between a
 * request and a payment.
 */

export class PolicyDeniedError extends Error {
  readonly code: PolicyDenialCode;

  constructor(code: PolicyDenialCode, reason: string) {
    super(`policy refused this payment (${code}): ${reason}`);
    this.name = "PolicyDeniedError";
    this.code = code;
  }
}

export interface PulseAgentClientOptions {
  readonly policy: PaymentPolicy;
  readonly rpcUrl: string;
  readonly ownedLocalOrigins?: readonly string[];
  /** Shared platform state and audit log. */
  readonly databasePath: string;
  readonly signerUrl: string;
  readonly signerToken: string;
}

export interface QuoteResult {
  readonly quote: NormalizedQuote;
  readonly service: { readonly name: string; readonly deterministic: boolean };
}

/** The default deterministic service this build buys. */
export const DEFAULT_SERVICE_NAME = "sha256-digest";

export interface PaymentResult {
  readonly intentId: string;
  /** Id the seller and the verifier record this payment under. */
  readonly correlationId: string;
  readonly state: IntentState;
  readonly result: DigestServiceResult;
  readonly resultDigest: string;
  /** True when the seller returned a previously delivered result. */
  readonly replayed: boolean;
  readonly settlement: SettlementFacts;
  readonly receipt: Record<string, unknown>;
}

export class PulseAgentClient {
  private readonly policy: PaymentPolicy;
  private readonly profile: ChainProfile;
  private readonly store: DurableStore;
  private readonly audit: AuditLog;
  private readonly publicClient: PublicClient;
  private readonly signer: RemoteSigner;
  private readonly rpcUrl: string;

  private constructor(init: {
    policy: PaymentPolicy;
    profile: ChainProfile;
    store: DurableStore;
    audit: AuditLog;
    publicClient: PublicClient;
    signer: RemoteSigner;
    rpcUrl: string;
  }) {
    this.policy = init.policy;
    this.profile = init.profile;
    this.store = init.store;
    this.audit = init.audit;
    this.publicClient = init.publicClient;
    this.signer = init.signer;
    this.rpcUrl = init.rpcUrl;
  }

  /**
   * Connects to the configured chain and signer.
   *
   * @param options Policy, RPC, state path and signer transport.
   * @returns A ready client.
   */
  static async connect(options: PulseAgentClientOptions): Promise<PulseAgentClient> {
    const policy = PaymentPolicySchema.parse(options.policy);
    const profile = requireChainProfile(policy.network);
    assertRpcAllowed(profile, options.rpcUrl, {
      ...(options.ownedLocalOrigins === undefined ? {} : { ownedLocalOrigins: options.ownedLocalOrigins }),
    });

    const publicClient = createPublicClient({ transport: http(options.rpcUrl) }) as PublicClient;
    // Checked at startup, and again by the signer before it authorizes anything.
    assertChainIdMatches(profile, await publicClient.getChainId());

    const signer = await connectRemoteSigner({ url: options.signerUrl, authToken: options.signerToken });
    if (signer.principalId !== policy.principalId) {
      throw new Error("the signer acts for a different principal than this policy names");
    }
    if (signer.policyRevision !== policy.policyRevision) {
      throw new Error("the signer loaded a different policy revision than this client was given");
    }

    const store = DurableStore.open(options.databasePath);
    return new PulseAgentClient({
      policy,
      profile,
      store,
      audit: new AuditLog(store),
      publicClient,
      signer,
      rpcUrl: options.rpcUrl,
    });
  }

  /** The payer address. Public only; the key is in the signer process. */
  get payerAddress(): `0x${string}` {
    return this.signer.address;
  }

  /** Services this policy is configured to buy from. */
  listServices(): readonly { readonly origin: string; readonly resourcePaths: readonly string[] }[] {
    return this.policy.allowedServiceOrigins.map((origin) => ({
      origin,
      resourcePaths: this.policy.allowedResourcePaths,
    }));
  }

  /**
   * Requests a quote and normalizes it.
   *
   * The response is parsed into the one shape the policy engine accepts; a quote
   * carrying an unknown field is rejected rather than partially understood. The
   * origin is checked against configuration before the request is made, so a
   * caller cannot point this at an arbitrary host.
   */
  async requestQuote(input: { serviceOrigin: string; input: string }): Promise<QuoteResult> {
    if (!this.policy.allowedServiceOrigins.includes(input.serviceOrigin)) {
      throw new PolicyDeniedError("service_origin_not_allowed", `${input.serviceOrigin} is not a configured service`);
    }
    const bodyBytes = Buffer.byteLength(input.input, "utf8");
    if (bodyBytes > this.policy.maxRequestBodyBytes) {
      throw new PolicyDeniedError("request_body_too_large", "input exceeds the configured maximum body size");
    }

    const response = await fetch(`${input.serviceOrigin}/quote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input: input.input }),
      // A quote endpoint that redirects is refused: following it would send this
      // request, and later a payment, to a host configuration never approved.
      redirect: "error",
    });
    if (!response.ok) {
      throw new Error(`quote request failed with status ${String(response.status)}`);
    }
    const payload = (await response.json()) as { quote?: unknown; service?: unknown };
    const quote = NormalizedQuoteSchema.parse(payload.quote);
    const service = payload.service as { name?: unknown; deterministic?: unknown } | undefined;
    const serviceName = typeof service?.name === "string" ? service.name : DEFAULT_SERVICE_NAME;

    // Derived from the input this client is about to send, not read from the
    // quote. Comparing the seller's digest to itself would check nothing: a
    // seller could price one body and be paid for another.
    const expectedRequestDigest = serviceRequestDigest({
      service: serviceName,
      resourcePath: quote.resourcePath,
      input: input.input,
    });
    if (expectedRequestDigest !== quote.requestDigest) {
      throw new PolicyDeniedError(
        "request_digest_mismatch",
        "the quote does not price the request this client is about to send",
      );
    }
    if (quote.serviceOrigin !== input.serviceOrigin) {
      throw new PolicyDeniedError(
        "service_origin_not_allowed",
        "the quote names a different service origin than the one it came from",
      );
    }

    this.audit.append({
      actor: "buyer",
      kind: "quote.received",
      policyRevision: this.policy.policyRevision,
      // No state: a quote precedes the intent, so there is nothing to advance.
      payload: {
        quoteId: quote.quoteId,
        serviceOrigin: quote.serviceOrigin,
        requestDigest: quote.requestDigest,
        amountAtomic: quote.amount,
        asset: quote.asset,
        payTo: quote.payTo,
        network: quote.network,
      },
    });

    return {
      quote,
      service: {
        name: typeof service?.name === "string" ? service.name : "unknown",
        deterministic: service?.deterministic === true,
      },
    };
  }

  /**
   * Pays for a quote and returns the verified result.
   *
   * The order matters, and it is: evaluate policy, persist the intent, then
   * authorize. The intent is durable before any signature exists, so a crash or
   * a timeout after this point leaves a record to reconcile against instead of
   * an invisible payment that looks safe to retry.
   *
   * Afterwards the settlement is re-read from the chain by this process too. The
   * seller verified it before delivering; a buyer that took the seller's word
   * for it would be trusting the counterparty about whether it got paid.
   */
  async requestPayment(input: {
    quote: NormalizedQuote;
    input: string;
    /** Supply the same key to retry a payment rather than make a second one. */
    idempotencyKey?: string;
    /** Service identifier used to derive the request digest independently. */
    serviceName?: string;
  }): Promise<PaymentResult> {
    const quote = NormalizedQuoteSchema.parse(input.quote);
    const serviceName = input.serviceName ?? DEFAULT_SERVICE_NAME;
    // Derived locally; see requestQuote for why it is not taken from the quote.
    const expectedRequestDigest = serviceRequestDigest({
      service: serviceName,
      resourcePath: quote.resourcePath,
      input: input.input,
    });
    const idempotencyKey = input.idempotencyKey ?? randomId("idem");

    // Order matters here and is the subject of two fixed defects.
    //
    // First the quote must price the body about to be sent — derived locally, so
    // a caller that edits both the body and the quote's digest is caught.
    if (quote.requestDigest !== expectedRequestDigest) {
      throw new PolicyDeniedError(
        "request_digest_mismatch",
        "the quote does not price the request this call is about to send",
      );
    }

    // The same idempotency key must mean the same payment, so the intent id is
    // derived from it rather than being fresh on every call.
    const intentId = `int_${digestOf({ idempotencyKey, quoteId: quote.quoteId }).replace("sha256:", "").slice(0, 32)}`;
    const existing = this.store.getIntent(intentId);

    // Then, before anything cached is handed back, the immutable terms are
    // compared. Returning a cached result first would answer a *different*
    // request with an earlier request's result: same ids, changed body.
    if (existing) {
      this.assertIntentBinding(existing, quote, expectedRequestDigest);
    }

    // Then recovery, which must come before the expiry and budget checks. A
    // payment that already settled has been made; refusing its retry because the
    // quote has since lapsed, or because the budget it already consumed is now
    // full, would take the money and withhold the result.
    const recovered = await this.tryRecoverDelivery(intentId, quote, input.input);
    if (recovered) return recovered;

    // An intent that already holds an authorization may already have paid. If
    // its delivery cannot be recovered right now — the seller is unreachable,
    // its receipt endpoint is failing, the settlement has not finalized — the
    // answer is "still pending", never "authorize again". The signer would also
    // refuse a second authorization, but relying on that alone would make this
    // client's correctness depend on a different process catching its mistake.
    if (existing?.authorizationNonce !== undefined && existing.state !== "DELIVERED") {
      this.store.updateIntent(intentId, (current) => ({
        ...current,
        state: current.state === "DELIVERED" ? current.state : "RECONCILING",
        terminalReason: "an authorization exists for this intent but its delivery could not be recovered yet",
      }));
      this.audit.append({
        actor: "buyer",
        kind: "payment.pending",
        intentId,
        policyRevision: this.policy.policyRevision,
        state: "RECONCILING",
        payload: {
          quoteId: quote.quoteId,
          code: "authorization_outstanding_delivery_unavailable",
          authorizationNonce: existing.authorizationNonce,
        },
      });
      throw new Error(
        "this intent already holds an authorization, so it may already have paid. Its result could not " +
          "be recovered yet; retry with the same idempotency key. No new authorization will be issued.",
      );
    }

    // Only now, for a genuinely new payment, do expiry and budget apply.
    const decision = evaluateQuote(this.policy, quote, {
      nowSeconds: Math.floor(Date.now() / 1000),
      expectedRequestDigest,
      requestBodyBytes: Buffer.byteLength(input.input, "utf8"),
      committedSpendAtomic: this.store.readCommittedSpend({
        principalId: this.policy.principalId,
        policyRevision: this.policy.policyRevision,
        asset: quote.asset,
      }),
    });
    if (!decision.allowed) {
      this.audit.append({
        actor: "buyer",
        kind: "policy.denied",
        policyRevision: this.policy.policyRevision,
        state: "DENIED",
        payload: { quoteId: quote.quoteId, code: decision.code },
      });
      throw new PolicyDeniedError(decision.code, decision.reason);
    }

    const intent: PaymentIntent = existing ?? {
      intentId,
      idempotencyKey,
      principalId: this.policy.principalId,
      policyRevision: this.policy.policyRevision,
      quote,
      createdAt: Math.floor(Date.now() / 1000),
      state: "POLICY_APPROVED",
    };
    if (!existing) {
      this.store.putIntent(intent);
      this.audit.append({
        actor: "buyer",
        kind: "intent.created",
        intentId,
        policyRevision: this.policy.policyRevision,
        state: "POLICY_APPROVED",
        payload: {
          quoteId: quote.quoteId,
          requestDigest: quote.requestDigest,
          amountAtomic: quote.amount,
          asset: quote.asset,
          payTo: quote.payTo,
          network: quote.network,
        },
      });
    }

    const client = new x402Client();
    client.register(
      this.policy.network as `${string}:${string}`,
      new ExactEvmScheme(this.signer, { rpcUrl: this.rpcUrl }),
    );
    // Upstream's default spend controls only recognize its own default assets and
    // cap in dollars. The asset here is a valueless test fixture, so the cap is
    // stated in atomic units of exactly the approved assets and nothing else.
    client.setSpendControls({
      allowedAssets: this.policy.allowedAssets.map((asset) => ({
        network: this.policy.network as `${string}:${string}`,
        asset: asset.address,
        maxAmountPerPayment: this.policy.maxAmountPerPayment,
      })),
    });

    const context: SigningContext = {
      intentId,
      idempotencyKey,
      principalId: this.policy.principalId,
      quote,
      // Runs while the signature is still inside the signer call, before the
      // paid request is sent. A lost response then still leaves the
      // authorization's identity on disk to reconcile against.
      onAuthorized: (identity) => {
        this.store.updateIntent(intentId, (current) => ({
          ...current,
          state: "AUTHORIZED",
          authorizationNonce: identity.authorizationNonce,
          authorizationSignatureDigest: identity.signatureDigest,
          reservationId: identity.reservationId,
        }));
        this.audit.append({
          actor: "buyer",
          kind: "payment.authorized",
          intentId,
          policyRevision: this.policy.policyRevision,
          state: "AUTHORIZED",
          payload: {
            quoteId: quote.quoteId,
            authorizationNonce: identity.authorizationNonce,
            signatureDigest: identity.signatureDigest,
            reservationId: identity.reservationId,
          },
        });
      },
    };

    const paidFetch = wrapFetchWithPayment(fetch, client);
    let response: Response;
    try {
      response = await withSigningContext(context, async () =>
        paidFetch(`${quote.serviceOrigin}${quote.resourcePath}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ quoteId: quote.quoteId, input: input.input }),
          redirect: "error",
        }),
      );
    } catch (error) {
      // A concurrent duplicate may have bound this intent's one authorization
      // first. That is the correct outcome, not a failure: wait for the winner
      // to finish and take its delivery, rather than authorizing again.
      const afterRace = await this.awaitConcurrentDelivery(intentId, quote, input.input);
      if (afterRace) return afterRace;
      // A transport failure after an authorization was issued is an unknown
      // outcome: the payment may have settled. It must stay reconcilable, never
      // terminal, and must never license a fresh authorization.
      if (context.authorizationNonce !== undefined) {
        this.store.updateIntent(intentId, (current) => ({
          ...current,
          state: "RECONCILING",
          terminalReason: "the paid request failed in transit after an authorization was issued",
        }));
        this.audit.append({
          actor: "buyer",
          kind: "payment.unresolved",
          intentId,
          policyRevision: this.policy.policyRevision,
          state: "RECONCILING",
          payload: { quoteId: quote.quoteId, code: "transport_failed_outcome_unknown" },
        });
      }
      throw error;
    }

    if (context.authorizationNonce !== undefined) {
      this.store.updateIntent(intentId, (current) => ({ ...current, state: "SUBMITTED" }));
      this.audit.append({
        actor: "buyer",
        kind: "payment.submitted",
        intentId,
        policyRevision: this.policy.policyRevision,
        state: "SUBMITTED",
        payload: { quoteId: quote.quoteId, authorizationNonce: context.authorizationNonce },
      });
    }

    if (response.status === 202) {
      // Accepted but not final. `response.ok` is true for 202, so this has to be
      // handled here rather than on the failure path below. A hash the seller
      // already knows is saved now: without it, a settlement that later
      // finalizes has no local identity to reconcile against.
      const pending = (await safeJson(response)) as { transactionHash?: unknown };
      const knownHash = typeof pending.transactionHash === "string" ? pending.transactionHash : undefined;
      this.store.updateIntent(intentId, (current) => ({
        ...current,
        state: "RECONCILING",
        ...(knownHash === undefined ? {} : { settlementTxHash: knownHash as `0x${string}` }),
        terminalReason: "seller reported the settlement as not yet final",
      }));
      this.audit.append({
        actor: "buyer",
        kind: "payment.pending",
        intentId,
        policyRevision: this.policy.policyRevision,
        state: "RECONCILING",
        payload: {
          quoteId: quote.quoteId,
          httpStatus: 202,
          code: codeOf(pending),
          ...(knownHash === undefined ? {} : { transactionHash: knownHash }),
        },
      });
      throw new Error(
        "the seller accepted the payment but reports settlement as not yet final. Retry with the same " +
          "idempotency key; the recorded authorization means the retry collects the result rather than paying again.",
      );
    }

    if (!response.ok) {
      const failure = (await safeJson(response)) as { transactionHash?: unknown };
      const knownHash = typeof failure.transactionHash === "string" ? failure.transactionHash : undefined;
      // Once an authorization has been issued, the payment may have settled no
      // matter what the seller's status code says. DENIED is terminal and would
      // invite a fresh authorization, so an ambiguous refusal stays RECONCILING.
      const authorized = context.authorizationNonce !== undefined;
      const state: IntentState = authorized ? "RECONCILING" : "DENIED";
      this.store.updateIntent(intentId, (current) => ({
        ...current,
        state,
        ...(knownHash === undefined ? {} : { settlementTxHash: knownHash as `0x${string}` }),
        terminalReason: authorized
          ? `outcome unknown after status ${String(response.status)} with an authorization already issued`
          : `seller refused with status ${String(response.status)} before any authorization`,
      }));
      this.audit.append({
        actor: "buyer",
        kind: "payment.unresolved",
        intentId,
        policyRevision: this.policy.policyRevision,
        state,
        payload: {
          quoteId: quote.quoteId,
          httpStatus: response.status,
          code: codeOf(failure),
          ...(knownHash === undefined ? {} : { transactionHash: knownHash }),
        },
      });
      throw new Error(
        `the seller did not deliver a result (status ${String(response.status)}, ${codeOf(failure)}).` +
          (authorized
            ? " An authorization was already issued, so this payment may have settled: retry with the same" +
              " idempotency key to reconcile rather than paying again."
            : " No authorization was issued, so nothing was paid."),
      );
    }

    const body = (await response.json()) as {
      result?: unknown;
      receipt?: { transactionHash?: string };
      replayed?: boolean;
    };
    const receipt = body.receipt ?? {};
    const txHash = receipt.transactionHash;
    if (typeof txHash !== "string") {
      throw new Error("the seller delivered a result without a settlement receipt");
    }

    const nonce = context.authorizationNonce ?? this.store.getIntent(intentId)?.authorizationNonce;
    if (nonce === undefined) {
      throw new Error("no authorization nonce is recorded for this intent, so settlement cannot be verified");
    }

    // Independent verification, on this side too. The seller verified before
    // delivering; a buyer that took the seller's word for it would be trusting
    // the counterparty about whether it had been paid.
    const verdict = await verifySettlement(createViemSettlementReader(this.publicClient), this.profile, {
      txHash: txHash as Hex,
      asset: quote.asset as `0x${string}`,
      from: this.signer.address,
      to: quote.payTo as `0x${string}`,
      amountAtomic: quote.amount,
      authorizationNonce: nonce as Hex,
    });
    if (verdict.status !== "final") {
      this.audit.append({
        actor: "buyer",
        kind: "settlement.unverified",
        intentId,
        policyRevision: this.policy.policyRevision,
        state: "RECONCILING",
        payload: { quoteId: quote.quoteId, transactionHash: txHash, code: verdict.status },
      });
      throw new Error(
        `the seller delivered a result but this buyer could not verify its settlement (${verdict.status}). ` +
          "The result is being discarded.",
      );
    }

    const correlationId = paymentCorrelationId({
      quoteId: quote.quoteId,
      requestDigest: quote.requestDigest,
      payer: this.signer.address,
      authorizationNonce: nonce,
    });

    // Settlement first, as its own record, so this log shows the verification
    // that licensed the delivery rather than jumping straight to it.
    this.audit.append({
      actor: "buyer",
      kind: "settlement.verified",
      intentId,
      policyRevision: this.policy.policyRevision,
      state: "FINALIZED",
      payload: {
        quoteId: quote.quoteId,
        correlationId,
        transactionHash: verdict.facts.txHash,
        blockNumber: verdict.facts.blockNumber,
        blockHash: verdict.facts.blockHash,
        amountAtomic: verdict.facts.amountAtomic,
        authorizationNonce: verdict.facts.authorizationNonce,
        confirmations: verdict.facts.confirmations,
        finalityRule: verdict.facts.finalityRule,
      },
    });

    // Validated and recomputed, not cast. A delivered object of the right shape
    // is not the same thing as the correct answer, and the whole point of a
    // deterministic service is that the buyer can check it.
    const result = DigestServiceResultSchema.parse(body.result);
    this.assertResultMatchesInput(intentId, quote, result, input.input);

    const delivered = digestOf(result);
    this.store.updateIntent(intentId, (current) => ({
      ...current,
      state: "DELIVERED",
      settlementTxHash: verdict.facts.txHash as `0x${string}`,
      settlement: {
        chainId: verdict.facts.chainId,
        txHash: verdict.facts.txHash as `0x${string}`,
        blockNumber: verdict.facts.blockNumber,
        blockHash: verdict.facts.blockHash as `0x${string}`,
        asset: verdict.facts.asset,
        from: verdict.facts.from,
        to: verdict.facts.to,
        amount: verdict.facts.amountAtomic,
        gasUsed: verdict.facts.gasUsed,
        effectiveGasPriceWei: verdict.facts.effectiveGasPriceWei,
        finality: verdict.facts.finalityRule,
        confirmations: verdict.facts.confirmations,
        verifiedAt: verdict.facts.verifiedAtUnix,
      },
      resultDigest: delivered,
    }));
    this.audit.append({
      actor: "buyer",
      kind: "result.verified",
      intentId,
      policyRevision: this.policy.policyRevision,
      state: "DELIVERED",
      payload: {
        quoteId: quote.quoteId,
        resultDigest: delivered,
        transactionHash: verdict.facts.txHash,
        blockNumber: verdict.facts.blockNumber,
        amountAtomic: verdict.facts.amountAtomic,
        authorizationNonce: verdict.facts.authorizationNonce,
        asset: verdict.facts.asset,
        payTo: verdict.facts.to,
        replayed: body.replayed === true,
      },
    });

    const payment: PaymentResult = {
      intentId,
      correlationId,
      state: "DELIVERED",
      result,
      resultDigest: delivered,
      replayed: body.replayed === true,
      settlement: verdict.facts,
      receipt: receipt as Record<string, unknown>,
    };
    // Cached locally so a later retry with the same idempotency key answers from
    // the record instead of touching the seller at all.
    this.store.claimOnce("buyer-delivery", intentId, JSON.stringify(payment));
    return payment;
  }

  /**
   * Waits, briefly, for a concurrent attempt on this intent to deliver.
   *
   * Only one attempt can hold an intent's single authorization; the others are
   * refused at the signer, which is the behaviour that prevents a double spend.
   * From the caller's side that refusal is not an answer though — the payment it
   * asked for is being made by someone else — so the losers poll for the
   * winner's delivery instead of failing or, far worse, authorizing again.
   *
   * Bounded on purpose: if the winner has not delivered within this window the
   * outcome is genuinely unknown, and the caller is told so rather than left
   * waiting.
   */
  private async awaitConcurrentDelivery(
    intentId: string,
    quote: NormalizedQuote,
    paidForInput: string,
  ): Promise<PaymentResult | undefined> {
    const deadline = Date.now() + 15_000;
    for (;;) {
      const recovered = await this.tryRecoverDelivery(intentId, quote, paidForInput);
      if (recovered) return recovered;
      if (Date.now() >= deadline) return undefined;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }

  /**
   * Refuses a retry whose immutable terms differ from the intent's.
   *
   * An intent is bound to one set of terms: the quote, byte for byte, and the
   * digest of the body it prices. A caller reusing the ids while changing the
   * body — even one that helpfully recomputes the quote's digest to match — is
   * asking for a different payment under an identity that already belongs to
   * another one, and must be told no rather than handed the earlier result.
   */
  private assertIntentBinding(
    intent: PaymentIntent,
    quote: NormalizedQuote,
    expectedRequestDigest: string,
  ): void {
    if (intent.quote.requestDigest !== expectedRequestDigest) {
      throw new PolicyDeniedError(
        "request_digest_mismatch",
        "this intent is bound to a different request body; use a new idempotency key for a new request",
      );
    }
    if (canonicalize(intent.quote) !== canonicalize(quote)) {
      throw new PolicyDeniedError(
        "request_digest_mismatch",
        "this intent is bound to different quote terms; use a new idempotency key for a new quote",
      );
    }
  }

  /**
   * Collects a delivery this intent already paid for, if there is one.
   *
   * Two places to look, cheapest first: this client's own cache, then the
   * seller's record for the authorization this intent is bound to. Either way the
   * settlement is re-verified on chain and the result rechecked before it is
   * accepted, because a stored record is still only a record.
   *
   * Returns undefined when nothing has been delivered yet, which is the signal
   * that a fresh authorization is legitimate. Callers must have validated the
   * intent's immutable terms first; this function trusts that it is being asked
   * about the same payment.
   */
  private async tryRecoverDelivery(
    intentId: string,
    quote: NormalizedQuote,
    paidForInput: string,
  ): Promise<PaymentResult | undefined> {
    const cached = this.store.readClaim("buyer-delivery", intentId);
    if (cached !== undefined) {
      const previous = JSON.parse(cached) as PaymentResult;
      // Checked again rather than trusted. A stored record is still only a
      // record, and the answer is recomputable, so there is no reason to hand
      // back something that has not been re-checked against the paid-for input.
      this.assertResultMatchesInput(intentId, quote, previous.result, paidForInput);
      const stillFinal = await verifySettlement(createViemSettlementReader(this.publicClient), this.profile, {
        txHash: previous.settlement.txHash as Hex,
        asset: quote.asset as `0x${string}`,
        from: this.signer.address,
        to: quote.payTo as `0x${string}`,
        amountAtomic: quote.amount,
        authorizationNonce: previous.settlement.authorizationNonce as Hex,
      });
      if (stillFinal.status !== "final") {
        throw new Error(
          `a previously delivered result for this intent no longer verifies on chain (${stillFinal.status}); ` +
            "it is being withheld rather than returned",
        );
      }
      return { ...previous, replayed: true };
    }

    const intent = this.store.getIntent(intentId);
    const nonce = intent?.authorizationNonce;
    if (nonce === undefined) return undefined;

    let response: Response;
    try {
      response = await fetch(`${quote.serviceOrigin}/receipt`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          quoteId: quote.quoteId,
          payer: this.signer.address,
          authorizationNonce: nonce,
        }),
        redirect: "error",
      });
    } catch {
      return undefined;
    }
    if (!response.ok) return undefined;

    const body = (await response.json()) as { result?: unknown; receipt?: { transactionHash?: string } };
    const txHash = body.receipt?.transactionHash;
    if (typeof txHash !== "string") return undefined;

    const verdict = await verifySettlement(createViemSettlementReader(this.publicClient), this.profile, {
      txHash: txHash as Hex,
      asset: quote.asset as `0x${string}`,
      from: this.signer.address,
      to: quote.payTo as `0x${string}`,
      amountAtomic: quote.amount,
      authorizationNonce: nonce as Hex,
    });
    if (verdict.status !== "final") return undefined;

    this.audit.append({
      actor: "buyer",
      kind: "settlement.verified",
      intentId,
      policyRevision: this.policy.policyRevision,
      state: "FINALIZED",
      payload: {
        quoteId: quote.quoteId,
        requestDigest: quote.requestDigest,
        transactionHash: verdict.facts.txHash,
        blockNumber: verdict.facts.blockNumber,
        amountAtomic: verdict.facts.amountAtomic,
        authorizationNonce: verdict.facts.authorizationNonce,
        asset: verdict.facts.asset,
        payTo: verdict.facts.to,
        payer: verdict.facts.from,
      },
    });

    const result = DigestServiceResultSchema.parse(body.result);
    // The recovered answer is verified against the input that was paid for. A
    // schema-valid result with the wrong digest is a wrong answer, and returning
    // it as DELIVERED would be worse than returning nothing.
    this.assertResultMatchesInput(intentId, quote, result, paidForInput);

    const recovered: PaymentResult = {
      intentId,
      correlationId: paymentCorrelationId({
        quoteId: quote.quoteId,
        requestDigest: quote.requestDigest,
        payer: this.signer.address,
        authorizationNonce: nonce,
      }),
      state: "DELIVERED",
      result,
      resultDigest: digestOf(result),
      replayed: true,
      settlement: verdict.facts,
      receipt: (body.receipt ?? {}) as Record<string, unknown>,
    };

    this.store.updateIntent(intentId, (current) => ({
      ...current,
      state: "DELIVERED",
      settlementTxHash: verdict.facts.txHash as `0x${string}`,
      resultDigest: recovered.resultDigest,
    }));
    this.audit.append({
      actor: "buyer",
      kind: "result.recovered",
      intentId,
      policyRevision: this.policy.policyRevision,
      state: "DELIVERED",
      payload: {
        quoteId: quote.quoteId,
        correlationId: recovered.correlationId,
        requestDigest: quote.requestDigest,
        resultDigest: recovered.resultDigest,
        transactionHash: verdict.facts.txHash,
        blockNumber: verdict.facts.blockNumber,
        authorizationNonce: verdict.facts.authorizationNonce,
        amountAtomic: verdict.facts.amountAtomic,
        asset: verdict.facts.asset,
        payTo: verdict.facts.to,
        payer: verdict.facts.from,
        // Named for what it is: this delivery was discovered after the fact, not
        // observed. Recording it as an ordinary verified delivery would claim an
        // exchange this client never saw.
        discoveredAfterLoss: true,
      },
    });
    this.store.claimOnce("buyer-delivery", intentId, JSON.stringify(recovered));
    return recovered;
  }

  /**
   * Rejects a result that is not the digest of the input that was paid for.
   *
   * Applied on every path that can return a result: a fresh delivery, a seller
   * receipt during recovery, and this client's own cache. The service is
   * deterministic precisely so this check is possible, so skipping it anywhere
   * would waste the one property that makes the result checkable at all.
   */
  private assertResultMatchesInput(
    intentId: string,
    quote: NormalizedQuote,
    result: DigestServiceResult,
    paidForInput: string,
  ): void {
    const recomputed = createHash("sha256").update(paidForInput, "utf8").digest("hex");
    if (result.sha256 === recomputed) return;
    this.audit.append({
      actor: "buyer",
      kind: "result.rejected",
      intentId,
      policyRevision: this.policy.policyRevision,
      state: "RECONCILING",
      payload: { quoteId: quote.quoteId, code: "result_does_not_match_input" },
    });
    throw new Error(
      "the result on offer is not the digest of the paid-for input; it is being discarded rather than returned",
    );
  }

  /** The stored intent, or undefined when this client has no record of it. */
  getIntentStatus(intentId: string): PaymentIntent | undefined {
    return this.store.getIntent(intentId);
  }

  /**
   * Re-reads the chain for a stored intent.
   *
   * Safe to call repeatedly, and the way a pending settlement is resolved: it
   * reads, it never pays.
   */
  async verifyIntentSettlement(intentId: string): Promise<{
    readonly status: string;
    readonly facts?: SettlementFacts;
    readonly reason?: string;
  }> {
    const intent = this.store.getIntent(intentId);
    if (!intent?.settlementTxHash || intent.authorizationNonce === undefined) {
      return { status: "no-settlement-recorded" };
    }
    const verdict = await verifySettlement(createViemSettlementReader(this.publicClient), this.profile, {
      txHash: intent.settlementTxHash as Hex,
      asset: intent.quote.asset as `0x${string}`,
      from: this.signer.address,
      to: intent.quote.payTo as `0x${string}`,
      amountAtomic: intent.quote.amount,
      authorizationNonce: intent.authorizationNonce as Hex,
    });
    return "facts" in verdict
      ? {
          status: verdict.status,
          facts: verdict.facts,
          ...("reason" in verdict ? { reason: verdict.reason } : {}),
        }
      : { status: verdict.status, reason: verdict.reason };
  }

  /** The redacted audit trail, optionally narrowed to one intent. */
  readAudit(filter: { intentId?: string } = {}): readonly AuditEvent[] {
    const events = this.audit.read();
    return filter.intentId === undefined ? events : events.filter((event) => event.intentId === filter.intentId);
  }

  /** Terminal hash to pin outside this log, so truncation is detectable. */
  get auditTerminalHash(): string {
    return this.audit.terminalHash;
  }

  /** Writes the audit log out as one canonical JSON record per line. */
  async exportAudit(filePath: string): Promise<{ events: number; terminalHash: string; filePath: string }> {
    return this.audit.exportToFile(filePath);
  }

  close(): void {
    this.store.close();
  }
}

async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

function codeOf(body: unknown): string {
  if (typeof body === "object" && body !== null) {
    const detail = body as { error?: unknown; status?: unknown };
    if (typeof detail.error === "string") return detail.error;
    if (typeof detail.status === "string") return detail.status;
  }
  return "unknown";
}
