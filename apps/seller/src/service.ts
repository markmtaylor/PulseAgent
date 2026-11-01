import express, { type NextFunction, type Request, type Response } from "express";
import { createServer, type Server } from "node:http";
import { createPublicClient, http, type Hex, type PublicClient } from "viem";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { decodePaymentSignatureHeader } from "@x402/core/http";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import type { PaymentRequirements, SettleResponse } from "@x402/core/types";
import { z } from "zod";
import {
  AuditLog,
  AssetProfileSchema,
  DurableStore,
  assertChainIdMatches,
  assertRpcAllowed,
  chainIdForCaip2,
  createViemSettlementReader,
  digestOf,
  paymentCorrelationId,
  randomId,
  requireChainProfile,
  verifySettlement,
  type AssetProfile,
  type ChainProfile,
  type DigestServiceResult,
  type NormalizedQuote,
} from "@pulseagent/core";
import { SERVICE_NAME, computeDigestResult, requestDigestFor, resultDigest } from "./digest-service.js";

/**
 * Seller agent.
 *
 * The x402 side is upstream: `@x402/express` runs the 402 challenge, the
 * facilitator call and the settlement. What this file adds is everything that
 * decides whether a result may actually be released:
 *
 * - **Payment before delivery.** The route declares the `upfront` payment flow,
 *   so settlement happens before the handler runs rather than after it. A
 *   handler that ran first would have already produced the thing being sold.
 * - **Independent verification.** The facilitator's `success: true` is not
 *   sufficient. The handler re-reads the chain and insists on the exact
 *   transfer, the exact authorization nonce, a canonical block and the chain's
 *   finality rule before it will answer.
 * - **Request-to-quote binding.** A signed transfer binds token, amount, payee
 *   and chain. It does not bind an HTTP body, so the same quote presented with a
 *   different body is refused here. Nothing in the payment layer does this.
 * - **One result per payment.** Delivery is claimed durably against the quote,
 *   the request digest, the payer and the authorization nonce together, so a
 *   replay or a concurrent duplicate returns the first result and receipt rather
 *   than performing the work again or charging again.
 */

const QuoteRequestSchema = z.strictObject({ input: z.string().min(1).max(4096) });
const PaidRequestSchema = z.strictObject({
  quoteId: z.string().min(8).max(128),
  input: z.string().min(1).max(4096),
});
const ReceiptRequestSchema = z.strictObject({
  quoteId: z.string().min(8).max(128),
  payer: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  authorizationNonce: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
});

const RESOURCE_PATH = "/digest";

export interface SellerOptions {
  readonly network: string;
  readonly rpcUrl: string;
  readonly ownedLocalOrigins?: readonly string[];
  readonly databasePath: string;
  /** Asset this seller prices in. Operator configuration, never taken from a request. */
  readonly asset: AssetProfile;
  readonly payTo: `0x${string}`;
  /** Price of one digest, in atomic units of `asset`. */
  readonly priceAtomic: string;
  readonly facilitatorUrl: string;
  readonly facilitatorToken: string;
  readonly quoteTtlSeconds?: number;
  readonly port?: number;
}

export interface RunningSeller {
  readonly url: string;
  readonly origin: string;
  readonly port: number;
  readonly payTo: `0x${string}`;
  readonly chain: ChainProfile;
  close(): Promise<void>;
}

interface StoredQuote {
  readonly quote: NormalizedQuote;
  readonly input: string;
}

/**
 * Starts the seller on loopback.
 *
 * @param options Chain, asset, price and facilitator wiring.
 * @returns The running service.
 */
export async function startSeller(options: SellerOptions): Promise<RunningSeller> {
  const asset = AssetProfileSchema.parse(options.asset);
  const profile = requireChainProfile(options.network);
  assertRpcAllowed(profile, options.rpcUrl, {
    ...(options.ownedLocalOrigins === undefined ? {} : { ownedLocalOrigins: options.ownedLocalOrigins }),
  });
  const chainId = chainIdForCaip2(options.network);
  const quoteTtlSeconds = options.quoteTtlSeconds ?? 120;

  const publicClient = createPublicClient({
    chain: {
      id: chainId,
      name: profile.displayName,
      nativeCurrency: { name: profile.nativeSymbol, symbol: profile.nativeSymbol, decimals: 18 },
      rpcUrls: { default: { http: [options.rpcUrl] } },
    },
    transport: http(options.rpcUrl),
  }) as PublicClient;
  assertChainIdMatches(profile, await publicClient.getChainId());

  const store = DurableStore.open(options.databasePath);
  const audit = new AuditLog(store);
  const reader = createViemSettlementReader(publicClient);

  /**
   * Settlement results, keyed by the authorization they consumed.
   *
   * Durable, not a `Map`. A restart between upstream settling and this process
   * answering would otherwise lose the only record of which payment paid for
   * which request, leaving a buyer that has paid unable to collect and with no
   * move except paying again.
   */
  const recordSettlement = (key: string, result: SettleResponse): void => {
    store.claimOnce("settlement", key, JSON.stringify(result));
  };
  const readSettlement = (key: string): SettleResponse | undefined => {
    const raw = store.readClaim("settlement", key);
    return raw === undefined ? undefined : (JSON.parse(raw) as SettleResponse);
  };

  const facilitatorClient = new HTTPFacilitatorClient({
    url: options.facilitatorUrl,
    createAuthHeaders: async () => {
      const headers = { authorization: `Bearer ${options.facilitatorToken}` };
      return { verify: headers, settle: headers, supported: headers };
    },
  });

  const resourceServer = new x402ResourceServer(facilitatorClient);
  registerExactEvmScheme(resourceServer, { networks: [options.network as `${string}:${string}`] });
  resourceServer.onAfterSettle(async (context) => {
    const payload = context.paymentPayload.payload as { authorization?: { from?: string; nonce?: string } };
    const key = settlementKey(payload.authorization?.from, payload.authorization?.nonce);
    if (key !== undefined) recordSettlement(key, context.result as SettleResponse);
  });

  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "32kb" }));

  app.post("/quote", (req, res) => {
    const parsed = QuoteRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request", reason: "input must be a bounded non-empty string" });
      return;
    }
    const nowSeconds = Math.floor(Date.now() / 1000);
    const quoteId = randomId("quote");
    const quote: NormalizedQuote = {
      quoteId,
      serviceOrigin: origin(),
      resourcePath: RESOURCE_PATH,
      requestDigest: requestDigestFor(RESOURCE_PATH, parsed.data.input),
      network: options.network,
      asset: asset.address,
      assetDecimals: asset.decimals,
      payTo: options.payTo,
      amount: options.priceAtomic,
      expiresAt: nowSeconds + quoteTtlSeconds,
      eip712Name: asset.eip712Name,
      eip712Version: asset.eip712Version,
      assetTransferMethod: "eip3009",
      maxTimeoutSeconds: quoteTtlSeconds,
    };
    // Durable before it is quoted, so a payment can always be matched back to the
    // exact terms it was offered.
    store.claimOnce("quote", quoteId, JSON.stringify({ quote, input: parsed.data.input } satisfies StoredQuote));
    audit.append({
      actor: "seller",
      kind: "quote.issued",
      payload: {
        quoteId,
        requestDigest: quote.requestDigest,
        amountAtomic: quote.amount,
        asset: quote.asset,
        payTo: quote.payTo,
        network: quote.network,
        expiresAt: new Date(quote.expiresAt * 1000).toISOString(),
        service: SERVICE_NAME,
      },
    });
    res.status(200).json({
      quote,
      service: {
        name: SERVICE_NAME,
        deterministic: true,
        note: "Deterministic SHA-256 digest service. The payment asset is a valueless test fixture.",
      },
    });
  });

  /**
   * Returns a result that was already delivered for a given authorization.
   *
   * This is what makes a buyer's recovery possible without a second payment. A
   * buyer that crashed after its payment settled, or that lost a race to a
   * concurrent duplicate, holds the authorization nonce but cannot re-present
   * its signature — the signer issues one authorization per intent and never
   * hands back a second. Without this endpoint such a buyer has paid and cannot
   * collect, and its only other move is to pay again.
   *
   * Nothing new is computed and nothing is charged: this only replays a stored
   * record. It is also deliberately unauthenticated in M1a, which is acceptable
   * only because the authorization nonce is already public in the chain's
   * `AuthorizationUsed` event and this service's output is recomputable by
   * anyone. A service selling anything confidential must authenticate the buyer
   * here, and this build does not implement that.
   */
  app.post("/receipt", (req, res) => {
    const parsed = ReceiptRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    const stored = readQuote(parsed.data.quoteId);
    if (!stored) {
      res.status(404).json({ error: "unknown_quote" });
      return;
    }
    const delivered = store.readClaim(
      "delivery",
      deliveryKeyFor(stored, parsed.data.payer, parsed.data.authorizationNonce),
    );
    if (delivered === undefined) {
      res.status(404).json({ error: "no_delivery_for_this_authorization" });
      return;
    }
    const record = JSON.parse(delivered) as DeliveredRecord;
    audit.append({
      actor: "seller",
      kind: "result.redelivered",
      intentId: record.intentId,
      payload: {
        quoteId: stored.quote.quoteId,
        resultDigest: record.resultDigest,
        transactionHash: record.settlementTxHash,
      },
    });
    res.status(200).json({ result: record.result, receipt: record.receipt, replayed: true });
  });

  /**
   * Rejects or short-circuits a paid request before the payment layer sees it.
   *
   * Order matters here, and it is: body binding, then an existing delivery, then
   * expiry.
   *
   * - Binding the HTTP request to the quote is something the signed transfer
   *   cannot do by itself, so an unknown quote or the same quote with a
   *   different body must never reach a 402 challenge.
   * - An authorization that has already been delivered for is answered from the
   *   stored record *here*, in front of the payment middleware. Behind it, a
   *   replay would be met with a fresh 402 and charged a second time.
   * - Expiry is checked last, and only for a request that has not already been
   *   paid. A buyer recovering a payment that settled before its quote lapsed
   *   has paid; refusing it as expired would take the money and withhold the
   *   result.
   */
  const bindRequestToQuote = (req: Request, res: Response, next: NextFunction): void => {
    const parsed = PaidRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request", reason: "quoteId and input are required" });
      return;
    }
    const stored = readQuote(parsed.data.quoteId);
    if (!stored) {
      res.status(404).json({ error: "unknown_quote" });
      return;
    }
    const digest = requestDigestFor(RESOURCE_PATH, parsed.data.input);
    if (digest === stored.quote.requestDigest) {
      const replay = findExistingDelivery(req, stored);
      if (replay) {
        audit.append({
          actor: "seller",
          kind: "result.redelivered",
          intentId: replay.intentId,
          payload: {
            quoteId: stored.quote.quoteId,
            resultDigest: replay.resultDigest,
            transactionHash: replay.settlementTxHash,
          },
        });
        res.status(200).json({ result: replay.result, receipt: replay.receipt, replayed: true });
        return;
      }
      if (stored.quote.expiresAt <= Math.floor(Date.now() / 1000)) {
        audit.append({
          actor: "seller",
          kind: "quote.expired",
          payload: { quoteId: stored.quote.quoteId, requestDigest: stored.quote.requestDigest },
        });
        res.status(410).json({ error: "quote_expired" });
        return;
      }
    }
    if (digest !== stored.quote.requestDigest) {
      // Same quote id, different body. The payment would have been valid and the
      // work would have been the wrong work.
      audit.append({
        actor: "seller",
        kind: "request.binding.rejected",
        payload: {
          quoteId: stored.quote.quoteId,
          requestDigest: digest,
          code: "request_digest_mismatch",
        },
      });
      res.status(409).json({ error: "request_digest_mismatch" });
      return;
    }
    next();
  };

  const routes = {
    [`POST ${RESOURCE_PATH}`]: {
      accepts: [
        {
          scheme: "exact",
          network: options.network as `${string}:${string}`,
          payTo: options.payTo,
          price: (context: { adapter: { getBody?: () => unknown } }) => {
            const quoteId = readQuoteIdFromBody(context.adapter.getBody?.());
            const stored = quoteId === undefined ? undefined : readQuote(quoteId);
            if (!stored) throw new Error("price requested for an unknown quote");
            // The amount comes from the stored quote, in atomic units. There is
            // no dollar string anywhere in this path and no conversion step.
            return { asset: stored.quote.asset, amount: stored.quote.amount };
          },
          maxTimeoutSeconds: quoteTtlSeconds,
          extra: {
            name: asset.eip712Name,
            version: asset.eip712Version,
            assetTransferMethod: "eip3009",
            // Settle before the handler. The result must not exist until paid.
            paymentFlow: "upfront",
          },
        },
      ],
      description: "Deterministic SHA-256 digest of a bounded input",
      mimeType: "application/json",
      serviceName: SERVICE_NAME,
    },
  };

  app.post(
    RESOURCE_PATH,
    bindRequestToQuote,
    paymentMiddleware(routes, resourceServer),
    (req: Request, res: Response) => {
      void handlePaidRequest(req, res).catch(() => {
        res.status(500).json({ error: "internal_error" });
      });
    },
  );

  async function handlePaidRequest(req: Request, res: Response): Promise<void> {
    const parsed = PaidRequestSchema.parse(req.body);
    const stored = readQuote(parsed.quoteId);
    if (!stored) {
      res.status(404).json({ error: "unknown_quote" });
      return;
    }

    const header = req.header("payment-signature") ?? req.header("x-payment");
    if (header === undefined) {
      res.status(402).json({ error: "payment_required" });
      return;
    }
    let payer: string | undefined;
    let nonce: string | undefined;
    let requirements: PaymentRequirements | undefined;
    try {
      const payload = decodePaymentSignatureHeader(header);
      const authorization = (payload.payload as { authorization?: { from?: string; nonce?: string } }).authorization;
      payer = authorization?.from;
      nonce = authorization?.nonce;
      requirements = payload.accepted;
    } catch {
      res.status(400).json({ error: "invalid_payment_header" });
      return;
    }
    const key = settlementKey(payer, nonce);
    if (key === undefined || payer === undefined || nonce === undefined) {
      res.status(400).json({ error: "invalid_payment_header" });
      return;
    }

    // One result per payment. The claim binds the quote, the exact body, the
    // payer and the authorization together, so a replay or a concurrent
    // duplicate gets the first answer rather than new work or a second charge.
    const deliveryKey = deliveryKeyFor(stored, payer, nonce);
    const alreadyDelivered = store.readClaim("delivery", deliveryKey);
    if (alreadyDelivered !== undefined) {
      const previous = JSON.parse(alreadyDelivered) as DeliveredRecord;
      audit.append({
        actor: "seller",
        kind: "result.redelivered",
        intentId: previous.intentId,
        payload: {
          quoteId: stored.quote.quoteId,
          resultDigest: previous.resultDigest,
          transactionHash: previous.settlementTxHash,
        },
      });
      res.status(200).json({ result: previous.result, receipt: previous.receipt, replayed: true });
      return;
    }

    const settlement = readSettlement(key);
    if (!settlement || settlement.success !== true || settlement.transaction === "") {
      // Upstream settles before this handler under the upfront flow, so no
      // settlement here means the payment did not complete.
      res.status(402).json({ error: "settlement_not_completed" });
      return;
    }

    // The id both parties derive independently, so these records join the
    // buyer's and the signer's without either side asserting the other's id.
    const intentId = paymentCorrelationId({
      quoteId: stored.quote.quoteId,
      requestDigest: stored.quote.requestDigest,
      payer,
      authorizationNonce: nonce,
    });
    const expectedAmount = requirements?.amount ?? stored.quote.amount;
    if (expectedAmount !== stored.quote.amount) {
      res.status(409).json({ error: "amount_mismatch" });
      return;
    }

    // The facilitator said it settled. That claim is now checked against the chain.
    const verdict = await verifySettlement(reader, profile, {
      txHash: settlement.transaction as Hex,
      asset: stored.quote.asset as `0x${string}`,
      from: payer as `0x${string}`,
      to: stored.quote.payTo as `0x${string}`,
      amountAtomic: stored.quote.amount,
      authorizationNonce: nonce as Hex,
    });

    if (verdict.status !== "final") {
      audit.append({
        actor: "verifier",
        kind: "settlement.unverified",
        intentId,
        state: verdict.status === "pending-finality" || verdict.status === "pending-inclusion" ? "RECONCILING" : "DENIED",
        policyRevision: "seller-rev-1",
        payload: {
          quoteId: stored.quote.quoteId,
          transactionHash: settlement.transaction,
          code: verdict.status,
        },
      });
      // A pending settlement is not a failure and must stay resumable: the buyer
      // can ask again, and the delivery claim above means it will not pay twice.
      // The hash goes back even on a refusal: a buyer told only "not verified"
      // has no identity to reconcile against, and the settlement may still
      // finalize.
      res.status(verdict.status === "pending-finality" || verdict.status === "pending-inclusion" ? 202 : 409).json({
        error: "settlement_not_verified",
        status: verdict.status,
        reason: verdict.reason,
        transactionHash: settlement.transaction,
      });
      return;
    }

    audit.append({
      actor: "verifier",
      kind: "settlement.verified",
      intentId,
      state: "FINALIZED",
      policyRevision: "seller-rev-1",
      payload: {
        quoteId: stored.quote.quoteId,
        transactionHash: verdict.facts.txHash,
        blockNumber: verdict.facts.blockNumber,
        blockHash: verdict.facts.blockHash,
        asset: verdict.facts.asset,
        payer: verdict.facts.from,
        payTo: verdict.facts.to,
        amountAtomic: verdict.facts.amountAtomic,
        authorizationNonce: verdict.facts.authorizationNonce,
        confirmations: verdict.facts.confirmations,
        finalityRule: verdict.facts.finalityRule,
        gasUsed: verdict.facts.gasUsed,
      },
    });

    const result = computeDigestResult(stored.input);
    const receipt = {
      network: options.network,
      transactionHash: verdict.facts.txHash,
      blockNumber: verdict.facts.blockNumber,
      blockHash: verdict.facts.blockHash,
      asset: verdict.facts.asset,
      payer: verdict.facts.from,
      payTo: verdict.facts.to,
      amountAtomic: verdict.facts.amountAtomic,
      authorizationNonce: verdict.facts.authorizationNonce,
      confirmations: verdict.facts.confirmations,
      finalityRule: verdict.facts.finalityRule,
      assetIsValuelessTestFixture: asset.valuelessTestFixture,
    };
    const record: DeliveredRecord = {
      intentId,
      result,
      receipt,
      resultDigest: resultDigest(result),
      settlementTxHash: verdict.facts.txHash,
    };

    // Claimed before the result leaves the process. If two requests race, the
    // loser returns the winner's result instead of producing a second one.
    const claim = store.claimOnce("delivery", deliveryKey, JSON.stringify(record));
    if (!claim.claimed) {
      const previous = JSON.parse(claim.existing) as DeliveredRecord;
      res.status(200).json({ result: previous.result, receipt: previous.receipt, replayed: true });
      return;
    }

    audit.append({
      actor: "seller",
      kind: "result.delivered",
      intentId,
      state: "DELIVERED",
      policyRevision: "seller-rev-1",
      payload: {
        quoteId: stored.quote.quoteId,
        resultDigest: record.resultDigest,
        transactionHash: verdict.facts.txHash,
        requestDigest: stored.quote.requestDigest,
        authorizationNonce: verdict.facts.authorizationNonce,
        amountAtomic: verdict.facts.amountAtomic,
        asset: verdict.facts.asset,
        payTo: verdict.facts.to,
        payer: verdict.facts.from,
      },
    });

    res.status(200).json({ result, receipt, replayed: false });
  }

  /** The delivery already made for the authorization in this request, if any. */
  function findExistingDelivery(req: Request, stored: StoredQuote): DeliveredRecord | undefined {
    const header = req.header("payment-signature") ?? req.header("x-payment");
    if (header === undefined) return undefined;
    let payer: string | undefined;
    let nonce: string | undefined;
    try {
      const payload = decodePaymentSignatureHeader(header);
      const authorization = (payload.payload as { authorization?: { from?: string; nonce?: string } }).authorization;
      payer = authorization?.from;
      nonce = authorization?.nonce;
    } catch {
      return undefined;
    }
    if (typeof payer !== "string" || typeof nonce !== "string") return undefined;
    const raw = store.readClaim("delivery", deliveryKeyFor(stored, payer, nonce));
    return raw === undefined ? undefined : (JSON.parse(raw) as DeliveredRecord);
  }

  function deliveryKeyFor(stored: StoredQuote, payer: string, nonce: string): string {
    return digestOf({
      quoteId: stored.quote.quoteId,
      requestDigest: stored.quote.requestDigest,
      payer: payer.toLowerCase(),
      authorizationNonce: nonce.toLowerCase(),
    });
  }

  function readQuote(quoteId: string): StoredQuote | undefined {
    const raw = store.readClaim("quote", quoteId);
    if (raw === undefined) return undefined;
    return JSON.parse(raw) as StoredQuote;
  }

  const server: Server = createServer(app);
  const port = await listen(server, options.port ?? 0);
  function origin(): string {
    return `http://127.0.0.1:${String(port)}`;
  }

  audit.append({
    actor: "seller",
    kind: "seller.started",
    payload: {
      network: options.network,
      payTo: options.payTo,
      asset: asset.address,
      priceAtomic: options.priceAtomic,
      service: SERVICE_NAME,
      assetIsValuelessTestFixture: asset.valuelessTestFixture,
    },
  });

  return {
    url: origin(),
    origin: origin(),
    port,
    payTo: options.payTo,
    chain: profile,
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      store.close();
    },
  };
}

interface DeliveredRecord {
  readonly intentId: string;
  readonly result: DigestServiceResult;
  readonly receipt: Record<string, unknown>;
  readonly resultDigest: string;
  readonly settlementTxHash: string;
}

function settlementKey(from: string | undefined, nonce: string | undefined): string | undefined {
  if (typeof from !== "string" || typeof nonce !== "string") return undefined;
  return `${from.toLowerCase()}:${nonce.toLowerCase()}`;
}

function readQuoteIdFromBody(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const quoteId = (body as { quoteId?: unknown }).quoteId;
  return typeof quoteId === "string" ? quoteId : undefined;
}

function listen(server: Server, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("seller failed to bind a TCP port"));
        return;
      }
      resolve(address.port);
    });
  });
}
