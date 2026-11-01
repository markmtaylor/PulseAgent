import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createPublicClient, createWalletClient, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { x402Facilitator } from "@x402/core/facilitator";
import { registerExactEvmScheme } from "@x402/evm/exact/facilitator";
import { toFacilitatorEvmSigner } from "@x402/evm";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";
import {
  AuditLog,
  DurableStore,
  AddressSchema,
  assertBroadcastAllowed,
  assertChainIdMatches,
  assertRpcAllowed,
  chainIdForCaip2,
  constantTimeEquals,
  requireChainProfile,
  sha256Hex,
  type ChainProfile,
} from "@pulseagent/core";
import {
  BroadcastRefusedError,
  createConstrainedWriter,
  withSettlementConstraint,
  type BroadcastLimits,
} from "./constrained-signer.js";

/**
 * Self-hosted x402 v2 facilitator.
 *
 * The protocol work — verifying an EIP-3009 authorization and submitting the
 * settlement — is the upstream `@x402/evm` exact scheme, not a reimplementation.
 * Copying the wire format while claiming interoperability would prove nothing,
 * so this process is a thin, policy-constrained host around upstream code.
 *
 * What is ours:
 *
 * - the chain is one an operator configured, its RPC origin is on an allowlist,
 *   and its self-reported chain id is checked before the first settlement
 * - broadcasting is refused outright unless the profile permits it, so pointing
 *   this at a public chain fails loudly instead of quietly paying
 * - the gas account is generated in this process and never leaves it
 * - every verify and settle attempt is recorded before and after the fact, so a
 *   timeout leaves evidence to reconcile against
 *
 * A hosted facilitator is not used: none has been shown to support the target
 * chain, and depending on one would put settlement outside the operator's
 * control.
 */

const MAX_REQUEST_BYTES = 64 * 1024;

export interface FacilitatorOptions {
  /** CAIP-2 chain to settle on. Must have a profile permitting broadcast. */
  readonly network: string;
  readonly rpcUrl: string;
  /** Exact origins of loopback nodes this process tree started. */
  readonly ownedLocalOrigins?: readonly string[];
  /** Shared platform state and audit log. */
  readonly databasePath: string;
  readonly authToken: string;
  readonly port?: number;
  /** Receipt-wait bound. Below it, settle reports pending with the broadcast hash. */
  readonly confirmationTimeoutMs?: number;
  /**
   * Assets this facilitator may ever submit a transfer for. A payment naming
   * anything else is refused at the broadcast boundary.
   */
  readonly allowedAssets: readonly `0x${string}`[];
  /**
   * Payees this facilitator may settle to. Operator configuration; a payment
   * requirement naming anything else is refused at the broadcast boundary.
   */
  readonly allowedPayees: readonly `0x${string}`[];
  /** Gas, fee and lifetime-fee ceilings for this account. */
  readonly limits: BroadcastLimits;
  /** Identity the fee budget is tracked under. */
  readonly facilitatorId?: string;
  readonly policyRevision?: string;
}

export interface RunningFacilitator {
  readonly url: string;
  readonly port: number;
  readonly network: string;
  /** Public address of the gas account. The key behind it stays in this process. */
  readonly signerAddress: `0x${string}`;
  readonly chain: ChainProfile;
  close(): Promise<void>;
}

/**
 * Starts the facilitator on loopback.
 *
 * @param options Chain, RPC, state path and transport token.
 * @returns The running service.
 */
export async function startFacilitator(options: FacilitatorOptions): Promise<RunningFacilitator> {
  if (options.authToken.length < 32) {
    throw new Error("facilitator auth token must be at least 32 characters");
  }
  const profile = requireChainProfile(options.network);
  // Refused before anything is wired up: a facilitator aimed at a chain this
  // build may not broadcast to must not start at all.
  assertBroadcastAllowed(profile);
  assertRpcAllowed(profile, options.rpcUrl, {
    ...(options.ownedLocalOrigins === undefined ? {} : { ownedLocalOrigins: options.ownedLocalOrigins }),
  });

  const chainId = chainIdForCaip2(options.network);
  const chain = {
    id: chainId,
    name: profile.displayName,
    nativeCurrency: { name: profile.nativeSymbol, symbol: profile.nativeSymbol, decimals: 18 },
    rpcUrls: { default: { http: [options.rpcUrl] } },
  } as const;

  const publicClient = createPublicClient({ chain, transport: http(options.rpcUrl) });
  // The node is not trusted to be the chain it was configured as.
  assertChainIdMatches(profile, await publicClient.getChainId());

  // Gas account: generated here, used only to submit settlements, never exported.
  const account = privateKeyToAccount(generateLocalKey());
  const walletClient = createWalletClient({ account, chain, transport: http(options.rpcUrl) });

  const store = DurableStore.open(options.databasePath);
  const audit = new AuditLog(store);

  const allowedAssets = options.allowedAssets.map((asset) => AddressSchema.parse(asset) as `0x${string}`);
  if (allowedAssets.length === 0) {
    throw new Error("a facilitator must be configured with at least one allowed asset");
  }
  const allowedPayees = options.allowedPayees.map((payee) => AddressSchema.parse(payee) as `0x${string}`);
  if (allowedPayees.length === 0) {
    throw new Error("a facilitator must be configured with at least one allowed payee");
  }

  // Every write goes through the constrained boundary rather than straight to
  // the wallet client; see constrained-signer.ts for what it enforces.
  const writer = createConstrainedWriter({
    publicClient,
    walletClient,
    address: account.address,
    chainId,
    network: options.network,
    allowedAssets,
    allowedPayees,
    limits: options.limits,
    store,
    audit,
    facilitatorId: options.facilitatorId ?? "facilitator-local",
    policyRevision: options.policyRevision ?? "facilitator-rev-1",
  });

  const signer = toFacilitatorEvmSigner(
    {
      address: account.address,
      readContract: (args) => publicClient.readContract(args as never) as Promise<unknown>,
      verifyTypedData: (args) => publicClient.verifyTypedData(args as never),
      writeContract: writer.writeContract,
      sendTransaction: writer.sendTransaction,
      waitForTransactionReceipt: writer.waitForTransactionReceipt,
      getCode: (args) => publicClient.getCode({ address: args.address }),
    },
    { confirmationTimeoutMs: options.confirmationTimeoutMs ?? 30_000 },
  );

  const facilitator = new x402Facilitator();
  registerExactEvmScheme(facilitator, { signer, networks: options.network as `${string}:${string}` });
  audit.append({
    actor: "facilitator",
    kind: "facilitator.started",
    payload: {
      network: options.network,
      chainId,
      facilitatorAddress: account.address,
      finalityRule: profile.finality.kind,
      mode: profile.mode,
      allowedAssets,
      allowedPayees,
      maxGasLimit: options.limits.maxGasLimit.toString(10),
      maxFeePerGasWei: options.limits.maxFeePerGasWei.toString(10),
      totalFeeBudgetWei: options.limits.totalFeeBudgetWei.toString(10),
    },
  });

  const server = createServer((req, res) => {
    void handle(req, res).catch(() => {
      sendJson(res, 500, { error: "internal_error" });
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!isAuthorized(req, options.authToken)) {
      sendJson(res, 401, { error: "unauthorized" });
      return;
    }
    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    if (req.method === "GET" && (url.pathname === "/supported" || url.pathname === "/health")) {
      sendJson(res, 200, facilitator.getSupported());
      return;
    }
    if (req.method === "POST" && url.pathname === "/verify") {
      await handleVerify(req, res);
      return;
    }
    if (req.method === "POST" && url.pathname === "/settle") {
      await handleSettle(req, res);
      return;
    }
    sendJson(res, 404, { error: "unsupported_method" });
  }

  async function handleVerify(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req);
    if (!body) {
      sendJson(res, 400, { error: "invalid_request" });
      return;
    }
    const { paymentPayload, paymentRequirements } = body;
    const payloadDigest = sha256Hex(JSON.stringify(paymentPayload));
    try {
      const result = await facilitator.verify(paymentPayload, paymentRequirements);
      audit.append({
        actor: "facilitator",
        kind: "facilitator.verify.result",
        payload: {
          isValid: result.isValid,
          invalidReason: result.invalidReason ?? "none",
          payer: result.payer ?? "unknown",
          payloadDigest,
        },
      });
      sendJson(res, 200, result);
    } catch {
      audit.append({
        actor: "facilitator",
        kind: "facilitator.verify.error",
        payload: { payloadDigest, code: "verify_threw" },
      });
      sendJson(res, 502, { isValid: false, invalidReason: "facilitator_error" });
    }
  }

  async function handleSettle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson(req);
    if (!body) {
      sendJson(res, 400, { error: "invalid_request" });
      return;
    }
    const { paymentPayload, paymentRequirements } = body;
    const payloadDigest = sha256Hex(JSON.stringify(paymentPayload));

    // Recorded durably *before* the broadcast. If the process dies between here
    // and a receipt, the attempt is on disk to reconcile against rather than
    // being invisible and retried as a fresh payment.
    audit.append({
      actor: "facilitator",
      kind: "facilitator.settle.attempt",
      payload: { payloadDigest, network: options.network },
    });

    try {
      // The constraint the broadcast boundary checks every submission against.
      const result = await withSettlementConstraint(
        {
          asset: paymentRequirements.asset as `0x${string}`,
          payTo: paymentRequirements.payTo as `0x${string}`,
          amountAtomic: paymentRequirements.amount,
          network: options.network,
        },
        () => facilitator.settle(paymentPayload, paymentRequirements),
      );
      audit.append({
        actor: "facilitator",
        kind: "facilitator.settle.result",
        payload: {
          payloadDigest,
          success: result.success,
          transaction: result.transaction === "" ? "none" : result.transaction,
          errorReason: result.errorReason ?? "none",
          payer: result.payer ?? "unknown",
        },
      });
      sendJson(res, 200, result);
    } catch (error) {
      if (error instanceof BroadcastRefusedError) {
        // A refusal is definite: nothing was broadcast, so nothing is pending.
        audit.append({
          actor: "facilitator",
          kind: "facilitator.settle.refused",
          payload: { payloadDigest, code: error.code },
        });
        sendJson(res, 400, {
          success: false,
          errorReason: `broadcast_refused:${error.code}`,
          transaction: "",
          network: options.network,
        });
        return;
      }
      // Anything else is an unknown outcome, not a failure: the transaction may
      // already be in the mempool. Reported so the caller reconciles against the
      // recorded hash rather than paying again.
      audit.append({
        actor: "facilitator",
        kind: "facilitator.settle.unknown",
        payload: { payloadDigest, code: "settle_threw_outcome_unknown" },
      });
      sendJson(res, 502, {
        success: false,
        errorReason: "settlement_outcome_unknown",
        transaction: "",
        network: options.network,
      });
    }
  }

  const port = await listen(server, options.port ?? 0);
  return {
    url: `http://127.0.0.1:${String(port)}`,
    port,
    network: options.network,
    signerAddress: account.address,
    chain: profile,
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      store.close();
    },
  };
}

/** A fresh key for this process's gas account. Never written down anywhere. */
function generateLocalKey(): Hex {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function isAuthorized(req: IncomingMessage, expected: string): boolean {
  const header = req.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  return constantTimeEquals(header.slice("Bearer ".length), expected);
}

async function readJson(
  req: IncomingMessage,
): Promise<{ paymentPayload: PaymentPayload; paymentRequirements: PaymentRequirements } | undefined> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    total += buffer.byteLength;
    if (total > MAX_REQUEST_BYTES) return undefined;
    chunks.push(buffer);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
      paymentPayload?: PaymentPayload;
      paymentRequirements?: PaymentRequirements;
    };
    if (!parsed.paymentPayload || !parsed.paymentRequirements) return undefined;
    return { paymentPayload: parsed.paymentPayload, paymentRequirements: parsed.paymentRequirements };
  } catch {
    return undefined;
  }
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
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("facilitator failed to bind a TCP port"));
        return;
      }
      resolve(address.port);
    });
  });
}
