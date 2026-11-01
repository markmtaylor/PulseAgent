import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { PrivateKeyAccount } from "viem";
import {
  AuditLog,
  DurableStore,
  PaymentPolicySchema,
  SignerAuthorizationRequestSchema,
  assertAllowlistedPayload,
  constantTimeEquals,
  digestOf,
  randomId,
  sha256Hex,
  type AuditPayloadSpec,
  type PaymentPolicy,
  type SignerAuthorizationResponse,
} from "@pulseagent/core";
import { validateAuthorizationRequest, type SignerValidation } from "./validate.js";

/**
 * The isolated signer process.
 *
 * Custody rules this service exists to enforce:
 *
 * - The key is generated here, in this process, and never leaves it. There is no
 *   endpoint that returns it, no field that carries it, and it is never written
 *   to disk, an argument, an environment variable, a log line or an audit record.
 *   Only the public address is ever emitted.
 * - There is no generic signing endpoint. The only thing this service will sign
 *   is an EIP-3009 `TransferWithAuthorization` that its own policy approves.
 *   Arbitrary calldata, raw digests, raw transactions and unrecognized methods
 *   have no code path.
 * - Budget is enforced here, atomically, before signing. A caller cannot raise a
 *   limit, and an "approved" flag from a caller carries no authority.
 *
 * Process separation on one user account is a real improvement over signing
 * in-process, and it is not a defense against a compromised host. Production
 * custody needs a separate OS identity or container at minimum, and an external
 * signer, KMS or HSM for anything that matters.
 */

const MAX_REQUEST_BYTES = 16 * 1024;
const DEFAULT_CLOCK_SKEW_SECONDS = 60;

/**
 * Field allowlists for this process's audit records.
 *
 * The signer is the only process holding key material, so its records are
 * allowlisted by field rather than filtered by pattern. A 32-byte private key
 * and a 32-byte transaction hash are indistinguishable by inspection, so the
 * decision about what may be written has to be made here, in advance, per field.
 * Adding a field to a record means editing one of these specs on purpose.
 */
const AUDIT_SPECS = {
  started: {
    principalId: "code",
    network: "code",
    signerAddress: "address",
    allowedPayees: { list: "address" },
    allowedAssets: { list: "address" },
    maxAmountPerPayment: "atomic",
    totalBudget: "atomic",
    maxGasReservationWei: "atomic",
    totalGasBudgetWei: "atomic",
  },
  rejected: {
    code: "code",
    quoteId: "code",
    boundTo: "code",
    issues: { list: "code" },
  },
  reservation: {
    reservationId: "code",
    replayed: "boolean",
    legs: { list: { object: { asset: "code", amountAtomic: "atomic" } } },
    authorizationNonce: "bytes32",
    authorizationDigest: "digest",
    payTo: "address",
    amountAtomic: "atomic",
    asset: "address",
  },
  signed: {
    reservationId: "code",
    payer: "address",
    signatureDigest: "digest",
    authorizationDigest: "digest",
    replayed: "boolean",
  },
  failed: {
    reservationId: "code",
    code: "code",
  },
} as const satisfies Record<string, AuditPayloadSpec>;

export interface SignerOptions {
  readonly policy: PaymentPolicy;
  /** Path to the signer's own SQLite state. Holds its budget ledger and audit log. */
  readonly databasePath: string;
  /** Shared secret for the loopback transport, supplied by the process that starts this one. */
  readonly authToken: string;
  /** Port to bind on 127.0.0.1. 0 picks an ephemeral port. */
  readonly port?: number;
  readonly clockSkewSeconds?: number;
}

export interface RunningSigner {
  /** `http://127.0.0.1:<port>`. */
  readonly url: string;
  readonly port: number;
  /** Public address only. The key behind it never leaves this process. */
  readonly address: `0x${string}`;
  readonly principalId: string;
  readonly policyRevision: string;
  close(): Promise<void>;
}

/**
 * Starts the signer on loopback.
 *
 * @param options Policy, state path and transport token.
 * @returns The running service, identified by its public address.
 */
export async function startSigner(options: SignerOptions): Promise<RunningSigner> {
  const policy = PaymentPolicySchema.parse(options.policy);
  if (options.authToken.length < 32) {
    throw new Error("signer auth token must be at least 32 characters");
  }
  const clockSkewSeconds = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  // The only place a key exists. `generatePrivateKey` is called here rather than
  // read from configuration precisely so no key can be handed in from outside,
  // and the hex is never bound to a name that outlives this expression.
  const account: PrivateKeyAccount = privateKeyToAccount(generatePrivateKey());

  const store = DurableStore.open(options.databasePath);
  const audit = new AuditLog(store);

  audit.append({
    actor: "signer",
    kind: "signer.started",
    policyRevision: policy.policyRevision,
    payload: assertAllowlistedPayload(
      {
        principalId: policy.principalId,
        network: policy.network,
        signerAddress: account.address,
        allowedPayees: policy.allowedPayees,
        allowedAssets: policy.allowedAssets.map((asset) => asset.address),
        maxAmountPerPayment: policy.maxAmountPerPayment,
        totalBudget: policy.totalBudget,
        maxGasReservationWei: policy.maxGasReservationWei,
        totalGasBudgetWei: policy.totalGasBudgetWei,
      },
      AUDIT_SPECS.started,
      "signer.started",
    ),
  });

  const server = createServer((req, res) => {
    void handle(req, res).catch(() => {
      // A handler that throws must not leak upstream text to the caller.
      sendJson(res, 500, { error: "internal_error" });
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!isAuthorized(req, options.authToken)) {
      sendJson(res, 401, { error: "unauthorized" });
      return;
    }
    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    if (req.method === "GET" && url.pathname === "/health") {
      sendJson(res, 200, {
        ok: true,
        // Public address only. There is no endpoint that exposes anything else.
        address: account.address,
        principalId: policy.principalId,
        policyRevision: policy.policyRevision,
        network: policy.network,
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/authorize") {
      await handleAuthorize(req, res);
      return;
    }

    // Anything else, including any shape of generic signing or key management, is
    // simply absent.
    sendJson(res, 404, { error: "unsupported_method" });
  }

  async function handleAuthorize(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: unknown;
    try {
      body = JSON.parse(await readBody(req));
    } catch (error) {
      sendJson(res, 400, {
        error: "invalid_request",
        reason: error instanceof Error && error.message.includes("too large") ? "body_too_large" : "invalid_json",
      });
      return;
    }

    const parsed = SignerAuthorizationRequestSchema.safeParse(body);
    if (!parsed.success) {
      // Strict schemas mean an unknown field lands here rather than being ignored.
      audit.append({
        actor: "signer",
        kind: "signer.authorization.rejected",
        policyRevision: policy.policyRevision,
        state: "DENIED",
        payload: assertAllowlistedPayload(
          {
            code: "schema_rejected",
            // Field paths only, never the rejected values, and normalized to the
            // allowlist's shape: a top-level unknown key has an empty path.
            issues: parsed.error.issues.map((issue) =>
              issue.path.length === 0 ? "root" : issue.path.join(".").replaceAll(/[^A-Za-z0-9._:-]/g, "_").slice(0, 128),
            ),
          },
          AUDIT_SPECS.rejected,
          "signer.rejected",
        ),
      });
      sendJson(res, 400, { error: "invalid_request", reason: "schema_rejected" });
      return;
    }
    const request = parsed.data;

    const validation = validateAuthorizationRequest(policy, request, {
      nowSeconds: Math.floor(Date.now() / 1000),
      signerAddress: account.address,
      clockSkewSeconds,
    });
    if (!validation.ok) {
      audit.append({
        actor: "signer",
        kind: "signer.authorization.rejected",
        intentId: request.intentId,
        policyRevision: policy.policyRevision,
        state: "DENIED",
        // The reason is returned to the caller but not persisted: audit records
        // carry stable codes, never free text that could embed foreign material.
        payload: assertAllowlistedPayload(
          { code: validation.code, quoteId: request.quote.quoteId },
          AUDIT_SPECS.rejected,
          "signer.rejected",
        ),
      });
      sendJson(res, 403, { error: "policy_denied", code: validation.code, reason: validation.reason });
      return;
    }

    // Everything that determines this authorization's spending power is digested
    // and bound to the intent. Reserving by idempotency key alone is not enough:
    // a caller that repeats an intent with a fresh nonce keeps one reservation
    // while collecting a second independently spendable signature.
    const authorizationDigest = authorizationDigestOf(request, validation, policy.policyRevision);

    const bound = store.bindAuthorization({
      principalId: policy.principalId,
      policyRevision: policy.policyRevision,
      intentId: request.intentId,
      idempotencyKey: request.idempotencyKey,
      reservationId: randomId("rsv"),
      authorizationDigest,
      payer: account.address,
      authorizationNonce: validation.typedData.message.nonce,
      legs: [
        {
          asset: validation.assetAddress,
          amountAtomic: validation.amountAtomic,
          maxAmountPerPayment: policy.maxAmountPerPayment,
          totalBudget: policy.totalBudget,
        },
        {
          // Gas a sponsor may spend is a separate bounded resource with its own
          // ceiling, committed in the same transaction as the token amount.
          asset: GAS_BUDGET_ASSET,
          amountAtomic: policy.maxGasReservationWei,
          maxAmountPerPayment: policy.maxGasReservationWei,
          totalBudget: policy.totalGasBudgetWei,
        },
      ],
    });
    if (!bound.ok) {
      audit.append({
        actor: "signer",
        kind: "signer.authorization.rejected",
        intentId: request.intentId,
        policyRevision: policy.policyRevision,
        state: "DENIED",
        payload: assertAllowlistedPayload({ code: bound.code }, AUDIT_SPECS.rejected, "signer.rejected"),
      });
      // A conflict means these ids already belong to another authorization; a
      // limit refusal means policy said no. Different problems, different codes.
      const conflict =
        bound.code === "authorization_already_bound" ||
        bound.code === "nonce_bound_to_other_intent" ||
        bound.code === "idempotency_key_bound_to_other_intent" ||
        bound.code === "reservation_binding_changed";
      sendJson(res, conflict ? 409 : 403, { error: "policy_denied", code: bound.code, reason: bound.reason });
      return;
    }

    audit.append({
      actor: "signer",
      kind: "signer.reservation.held",
      intentId: request.intentId,
      policyRevision: policy.policyRevision,
      state: "RESERVED",
      payload: assertAllowlistedPayload(
        {
          reservationId: bound.reservationId,
          replayed: bound.replayed,
          legs: bound.legs.map((leg) => ({ asset: leg.asset, amountAtomic: leg.amountAtomic })),
          // The nonce is public and is exactly what a replay check needs. The
          // signature over it is never recorded.
          authorizationNonce: validation.typedData.message.nonce,
          authorizationDigest,
          payTo: validation.typedData.message.to,
          amountAtomic: validation.amountAtomic,
          asset: validation.assetAddress,
        },
        AUDIT_SPECS.reservation,
        "signer.reservation",
      ),
    });

    let signature: `0x${string}`;
    try {
      // ECDSA signing here is deterministic (RFC 6979), so an exact retry of a
      // bound authorization reproduces the same bytes and confers no new
      // spending capability. The equality check below is what enforces that
      // rather than assuming it.
      signature = await account.signTypedData(validation.typedData);
    } catch {
      // The reservation deliberately stays held. Releasing budget on an error
      // path is how a double spend happens.
      audit.append({
        actor: "signer",
        kind: "signer.authorization.failed",
        intentId: request.intentId,
        policyRevision: policy.policyRevision,
        state: "RECONCILING",
        payload: assertAllowlistedPayload(
          { reservationId: bound.reservationId, code: "signing_failed" },
          AUDIT_SPECS.failed,
          "signer.failed",
        ),
      });
      sendJson(res, 500, { error: "signing_failed" });
      return;
    }

    const signatureDigest = sha256Hex(signature);
    const recorded = store.claimOnce("authorization-signature", authorizationDigest, signatureDigest);
    if (!recorded.claimed && recorded.existing !== signatureDigest) {
      // A bound authorization produced different bytes than the first time. That
      // should be impossible with deterministic signing; if it happens, handing
      // the caller a second distinct signature would hand it a second spendable
      // authorization, so refuse and leave the intent to be reconciled.
      audit.append({
        actor: "signer",
        kind: "signer.authorization.failed",
        intentId: request.intentId,
        policyRevision: policy.policyRevision,
        state: "RECONCILING",
        payload: assertAllowlistedPayload(
          { reservationId: bound.reservationId, code: "nondeterministic_signature" },
          AUDIT_SPECS.failed,
          "signer.failed",
        ),
      });
      sendJson(res, 500, { error: "signing_failed", code: "nondeterministic_signature" });
      return;
    }

    audit.append({
      actor: "signer",
      kind: "signer.authorization.signed",
      intentId: request.intentId,
      policyRevision: policy.policyRevision,
      state: "AUTHORIZED",
      payload: assertAllowlistedPayload(
        {
          reservationId: bound.reservationId,
          payer: account.address,
          // Digests only. A raw EIP-3009 authorization plus its signature is
          // replayable value, so neither is ever persisted.
          signatureDigest,
          authorizationDigest,
          replayed: bound.replayed,
        },
        AUDIT_SPECS.signed,
        "signer.signed",
      ),
    });

    const response: SignerAuthorizationResponse = {
      intentId: request.intentId,
      reservationId: bound.reservationId,
      signature,
      signatureDigest,
      payer: account.address,
      policyRevision: policy.policyRevision,
    };
    sendJson(res, 200, response);
  }

  const port = await listen(server, options.port ?? 0);

  return {
    url: `http://127.0.0.1:${String(port)}`,
    port,
    address: account.address,
    principalId: policy.principalId,
    policyRevision: policy.policyRevision,
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      store.close();
    },
  };
}

/** Budget key for native gas a sponsor may spend, kept separate from the token budget. */
export const GAS_BUDGET_ASSET = "native:gas";

/**
 * Digests everything that gives an authorization spending power.
 *
 * Anything omitted from this digest becomes a field a caller may change while
 * keeping its reservation, so the nonce, the validity window, the domain, the
 * payer, the payee, the amount, the quote and request identity and the policy
 * revision are all in it. Two requests that differ in any of them are two
 * different authorizations and the second is refused.
 */
export function authorizationDigestOf(
  request: { intentId: string; idempotencyKey: string; principalId: string; quote: { quoteId: string; requestDigest: string; serviceOrigin: string; resourcePath: string; network: string; asset: string; payTo: string; amount: string; expiresAt: number } },
  validation: Extract<SignerValidation, { ok: true }>,
  policyRevision: string,
): string {
  const { typedData } = validation;
  return digestOf({
    intentId: request.intentId,
    idempotencyKey: request.idempotencyKey,
    principalId: request.principalId,
    policyRevision,
    quote: {
      quoteId: request.quote.quoteId,
      requestDigest: request.quote.requestDigest,
      serviceOrigin: request.quote.serviceOrigin,
      resourcePath: request.quote.resourcePath,
      network: request.quote.network,
      asset: request.quote.asset.toLowerCase(),
      payTo: request.quote.payTo.toLowerCase(),
      amount: request.quote.amount,
      expiresAt: request.quote.expiresAt,
    },
    authorization: {
      primaryType: typedData.primaryType,
      domain: {
        name: typedData.domain.name,
        version: typedData.domain.version,
        chainId: typedData.domain.chainId,
        verifyingContract: typedData.domain.verifyingContract.toLowerCase(),
      },
      message: {
        from: typedData.message.from.toLowerCase(),
        to: typedData.message.to.toLowerCase(),
        value: typedData.message.value.toString(10),
        validAfter: typedData.message.validAfter.toString(10),
        validBefore: typedData.message.validBefore.toString(10),
        nonce: typedData.message.nonce.toLowerCase(),
      },
    },
  });
}

/** A token suitable for the loopback transport. Generated by the caller, never logged. */
export function generateSignerToken(): string {
  return randomBytes(32).toString("hex");
}

function isAuthorized(req: IncomingMessage, expected: string): boolean {
  const header = req.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  return constantTimeEquals(header.slice("Bearer ".length), expected);
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    total += buffer.byteLength;
    if (total > MAX_REQUEST_BYTES) {
      throw new Error("request body too large");
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(payload)),
    "cache-control": "no-store",
  });
  res.end(payload);
}

function listen(server: Server, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    // Loopback only. The signer is never reachable from another host.
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("signer failed to bind a TCP port"));
        return;
      }
      resolve(address.port);
    });
  });
}
