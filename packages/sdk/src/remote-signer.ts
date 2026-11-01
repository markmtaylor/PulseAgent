import { AsyncLocalStorage } from "node:async_hooks";
import {
  SignerAuthorizationResponseSchema,
  type NormalizedQuote,
  type SignerAuthorizationRequest,
} from "@pulseagent/core";

/**
 * Client-side handle on the isolated signer.
 *
 * This satisfies the upstream x402 client's signer interface — an address and
 * `signTypedData` — without ever holding a key. The typed data the scheme built
 * is forwarded to the signer process, which rebuilds it from its own policy,
 * compares it field by field and refuses anything it did not expect. From this
 * side the only possible outcomes are "a signature for exactly what policy
 * allows" and "a denial"; there is no third option this process can reach for.
 */

/** Per-payment context the signer needs to bind an authorization to an intent. */
export interface SigningContext {
  readonly intentId: string;
  readonly idempotencyKey: string;
  readonly principalId: string;
  readonly quote: NormalizedQuote;
  /** Filled in once the signer has signed, so the caller learns the nonce used. */
  authorizationNonce?: `0x${string}`;
  signatureDigest?: string;
  reservationId?: string;
  /**
   * Called with the authorization's identity before the signature is handed back
   * to the payment scheme, so the caller can persist it before the request that
   * spends it leaves the process.
   *
   * This ordering is the point. If the nonce were recorded after the paid
   * request returned, a lost response would leave a payment that settled and no
   * local record of which authorization settled it — nothing to reconcile with,
   * and nothing to stop a second payment.
   */
  onAuthorized?: (identity: {
    readonly authorizationNonce: `0x${string}`;
    readonly signatureDigest: string;
    readonly reservationId: string;
  }) => void;
}

const signingContext = new AsyncLocalStorage<SigningContext>();

/** Runs `work` with the context every signature request inside it belongs to. */
export function withSigningContext<T>(context: SigningContext, work: () => Promise<T>): Promise<T> {
  return signingContext.run(context, work);
}

export class SignerDeniedError extends Error {
  readonly code: string;
  readonly httpStatus: number;

  constructor(httpStatus: number, code: string, reason: string) {
    super(`signer refused the authorization (${code}): ${reason}`);
    this.name = "SignerDeniedError";
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

export interface RemoteSignerOptions {
  /** Loopback base URL of the signer process. */
  readonly url: string;
  readonly authToken: string;
  readonly requestTimeoutMs?: number;
}

export interface RemoteSigner {
  /** The signer's public address. */
  readonly address: `0x${string}`;
  readonly principalId: string;
  readonly policyRevision: string;
  signTypedData(message: {
    domain: Record<string, unknown>;
    types: Record<string, unknown>;
    primaryType: string;
    message: Record<string, unknown>;
  }): Promise<`0x${string}`>;
}

/**
 * Connects to a running signer and reports its public identity.
 *
 * @param options Signer URL and transport token.
 * @returns A signer handle usable as an x402 client signer.
 */
export async function connectRemoteSigner(options: RemoteSignerOptions): Promise<RemoteSigner> {
  const timeoutMs = options.requestTimeoutMs ?? 10_000;
  const health = await request<{
    address: `0x${string}`;
    principalId: string;
    policyRevision: string;
  }>(`${options.url}/health`, { method: "GET" }, options.authToken, timeoutMs);

  return {
    address: health.address,
    principalId: health.principalId,
    policyRevision: health.policyRevision,
    async signTypedData(typedData) {
      const context = signingContext.getStore();
      if (!context) {
        throw new Error("a signature was requested outside a payment with an established intent");
      }
      const authorizationRequest: SignerAuthorizationRequest = {
        intentId: context.intentId,
        idempotencyKey: context.idempotencyKey,
        principalId: context.principalId,
        quote: context.quote,
        typedData: {
          primaryType: "TransferWithAuthorization",
          domain: {
            name: String(typedData.domain["name"]),
            version: String(typedData.domain["version"]),
            chainId: Number(typedData.domain["chainId"]),
            verifyingContract: String(typedData.domain["verifyingContract"]),
          },
          // Values arrive as bigints from the scheme; sent as base-10 strings so
          // no float ever represents an amount on the wire.
          message: {
            from: String(typedData.message["from"]),
            to: String(typedData.message["to"]),
            value: toAtomicString(typedData.message["value"]),
            validAfter: toAtomicString(typedData.message["validAfter"]),
            validBefore: toAtomicString(typedData.message["validBefore"]),
            nonce: String(typedData.message["nonce"]),
          },
        },
      };

      const response = SignerAuthorizationResponseSchema.parse(
        await request<unknown>(
          `${options.url}/authorize`,
          { method: "POST", body: JSON.stringify(authorizationRequest) },
          options.authToken,
          timeoutMs,
        ),
      );

      const authorizationNonce = authorizationRequest.typedData.message.nonce as `0x${string}`;
      context.authorizationNonce = authorizationNonce;
      context.signatureDigest = response.signatureDigest;
      context.reservationId = response.reservationId;
      // Persisted before the signature is returned, so the authorization can be
      // reconciled even if everything after this point is lost.
      context.onAuthorized?.({
        authorizationNonce,
        signatureDigest: response.signatureDigest,
        reservationId: response.reservationId,
      });
      return response.signature as `0x${string}`;
    },
  };
}

function toAtomicString(value: unknown): string {
  if (typeof value === "bigint") return value.toString(10);
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return value.toString(10);
  throw new Error("an authorization amount was not an integer");
}

async function request<T>(
  url: string,
  init: { method: string; body?: string },
  authToken: string,
  timeoutMs: number,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetch(url, {
      method: init.method,
      ...(init.body === undefined ? {} : { body: init.body }),
      headers: {
        authorization: `Bearer ${authToken}`,
        ...(init.body === undefined ? {} : { "content-type": "application/json" }),
      },
      signal: controller.signal,
      // No redirects: the signer is at a fixed loopback address, and following a
      // redirect would mean sending an authorization request somewhere else.
      redirect: "error",
    });
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = {};
  }
  if (!response.ok) {
    const detail = body as { code?: string; reason?: string; error?: string };
    throw new SignerDeniedError(
      response.status,
      detail.code ?? detail.error ?? "signer_error",
      detail.reason ?? "no reason supplied",
    );
  }
  return body as T;
}
