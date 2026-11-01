import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { NormalizedQuoteSchema, type NormalizedQuote } from "@pulseagent/core";
import { DEFAULT_SERVICE_NAME, PolicyDeniedError, SignerDeniedError, type PulseAgentClient } from "@pulseagent/sdk";

/**
 * MCP server exposing the bounded buyer operations.
 *
 * MCP is an interaction boundary, not an authorization boundary. A model can ask
 * for a payment under a policy an operator wrote; it cannot approve its own
 * budget, change a policy, reach a key, choose an RPC endpoint or ask for a
 * signature over anything of its choosing. Those are not guarded here by a flag
 * the model could set — they are simply not registered as tools, so there is
 * nothing to call. Every request below goes through the same policy engine and
 * the same isolated signer as a direct SDK call.
 *
 * Tool names that deliberately do not exist, and must not be added: approving
 * spending, loading or editing a policy, importing or exporting a key, signing
 * arbitrary data or raw transactions, choosing an RPC, and anything that would
 * let a caller widen a limit.
 */

export const ABSENT_BY_DESIGN = [
  "approve_spending",
  "approve_budget",
  "set_policy",
  "load_policy",
  "sign_typed_data",
  "sign_transaction",
  "sign_message",
  "export_key",
  "import_key",
  "set_rpc_url",
] as const;

export interface McpServerOptions {
  readonly client: PulseAgentClient;
  readonly serverName?: string;
  readonly serverVersion?: string;
}

/**
 * Builds the MCP server around a connected buyer client.
 *
 * @param options The client to expose and optional server identity.
 * @returns A server ready to connect to a transport.
 */
export function createPulseAgentMcpServer(options: McpServerOptions): McpServer {
  const { client } = options;
  const server = new McpServer({
    name: options.serverName ?? "pulseagent",
    version: options.serverVersion ?? "0.1.0",
  });

  // Quotes seen in this session, so a payment can name a quote by id rather than
  // the model restating its terms — which would let it restate them differently.
  const quotes = new Map<string, { quote: NormalizedQuote; input: string; serviceName: string }>();

  server.registerTool(
    "list_services",
    {
      title: "List configured services",
      description:
        "Lists the service origins and resource paths this agent's operator policy permits. " +
        "The list is configuration; it cannot be extended from here.",
      inputSchema: {},
    },
    safeTool(() => jsonResult({ services: client.listServices(), payer: client.payerAddress })),
  );

  server.registerTool(
    "request_quote",
    {
      title: "Request a quote",
      description:
        "Asks a configured service to price one request. The quote is checked against the policy's " +
        "allowed origin and is verified to price exactly the input given here.",
      inputSchema: {
        serviceOrigin: z.string().describe("Origin of a service the policy allows"),
        input: z.string().min(1).max(4096).describe("The bounded input to be priced"),
      },
    },
    safeTool(async ({ serviceOrigin, input }: { serviceOrigin: string; input: string }) => {
      {
        const result = await client.requestQuote({ serviceOrigin, input });
        quotes.set(result.quote.quoteId, {
          quote: result.quote,
          input,
          serviceName: result.service.name,
        });
        return jsonResult({
          quote: result.quote,
          service: result.service,
          note:
            "The amount is in atomic units of the quoted asset. Paying requires a separate " +
            "request_payment call, which the operator policy and the isolated signer both evaluate.",
        });
      }
    }),
  );

  server.registerTool(
    "request_payment",
    {
      title: "Request a payment under policy",
      description:
        "Pays a quote obtained from request_quote and returns the verified result. The policy engine " +
        "and the isolated signer each evaluate the request independently; this tool carries no " +
        "authority to approve spending, and a denial here is final.",
      inputSchema: {
        quoteId: z.string().describe("Quote id returned by request_quote in this session"),
        idempotencyKey: z
          .string()
          .min(8)
          .max(128)
          .optional()
          .describe("Reuse the same key to retry a payment instead of making a second one"),
      },
    },
    safeTool(async ({ quoteId, idempotencyKey }: { quoteId: string; idempotencyKey?: string | undefined }) => {
      const remembered = quotes.get(quoteId);
      if (!remembered) {
        return codeResult("quote_not_in_session");
      }
      {
        const payment = await client.requestPayment({
          quote: NormalizedQuoteSchema.parse(remembered.quote),
          input: remembered.input,
          serviceName: remembered.serviceName || DEFAULT_SERVICE_NAME,
          ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
        });
        return jsonResult({
          intentId: payment.intentId,
          correlationId: payment.correlationId,
          state: payment.state,
          replayed: payment.replayed,
          result: payment.result,
          resultDigest: payment.resultDigest,
          settlement: payment.settlement,
        });
      }
    }),
  );

  server.registerTool(
    "get_intent_status",
    {
      title: "Get a payment intent's status",
      description: "Reads the durable record for one payment intent. Read-only.",
      inputSchema: { intentId: z.string().describe("Intent id from request_payment") },
    },
    safeTool(({ intentId }: { intentId: string }) => {
      const intent = client.getIntentStatus(intentId);
      return intent === undefined ? jsonResult({ found: false, intentId }) : jsonResult({ found: true, intent });
    }),
  );

  server.registerTool(
    "verify_settlement",
    {
      title: "Verify a settlement on chain",
      description:
        "Re-reads the chain for a stored intent and reports whether its settlement is final. " +
        "Read-only, and the way a pending settlement is resolved: it never pays.",
      inputSchema: { intentId: z.string().describe("Intent id from request_payment") },
    },
    safeTool(async ({ intentId }: { intentId: string }) =>
      jsonResult(await client.verifyIntentSettlement(intentId)),
    ),
  );

  server.registerTool(
    "read_audit",
    {
      title: "Read the redacted audit trail",
      description:
        "Returns audit records, optionally for one intent. Payloads are redacted: signatures appear " +
        "only as digests and no key material is present. A locally rewritable log is not " +
        "independently tamper-proof.",
      inputSchema: {
        intentId: z.string().optional().describe("Narrow the trail to one intent"),
        limit: z.number().int().min(1).max(500).optional().describe("Most recent records to return"),
      },
    },
    safeTool(({ intentId, limit }: { intentId?: string | undefined; limit?: number | undefined }) => {
      const events = client.readAudit(intentId === undefined ? {} : { intentId });
      const slice = limit === undefined ? events : events.slice(-limit);
      return jsonResult({
        events: slice,
        terminalHash: client.auditTerminalHash,
        note:
          "Pin the terminal hash outside this log. Hash chaining detects edits to earlier records; " +
          "it does not detect a wholesale rewrite or a removed tail.",
      });
    }),
  );

  return server;
}

/** The one shape every tool returns, success or refusal. */
type ToolOutput = { content: { type: "text"; text: string }[]; isError?: true };

/**
 * Wraps a tool handler so no failure can escape as raw text.
 *
 * Every registered tool goes through this, including the ones that only read a
 * property or call a synchronous method. A handler without it reports whatever
 * its dependency threw, and an executed review of this boundary found exactly
 * that: three read-only tools echoed a synthetic 65-byte marker from an error
 * message straight into tool output. There is no handler here that is "too
 * simple to throw".
 */
function safeTool<TArgs>(handler: (args: TArgs) => ToolOutput | Promise<ToolOutput>) {
  return async (args: TArgs): Promise<ToolOutput> => {
    try {
      return await handler(args);
    } catch (error) {
      return errorResult(error);
    }
  };
}

function jsonResult(value: unknown): { content: { type: "text"; text: string }[] } {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

/**
 * Stable codes this boundary may emit, each with a description written here.
 *
 * Tool output crosses into a model's context, so nothing arbitrary may ride along
 * with it. Truncating an upstream message is not redaction: a 65-byte signature
 * is 132 characters and survives any slice generous enough to be useful. So no
 * upstream text is forwarded at all — a failure becomes one of these codes, and
 * the words the caller reads are the ones below.
 */
const FAILURE_DESCRIPTIONS: Readonly<Record<string, string>> = {
  // Policy engine denials.
  chain_not_configured: "The quoted chain has no configured profile, so it is disabled.",
  chain_mismatch: "The quote is for a different chain than the policy pays on.",
  broadcast_not_authorized: "This build may not broadcast to the quoted chain.",
  service_origin_not_allowed: "The service origin is not one the policy permits.",
  resource_path_not_allowed: "The resource path is not one the policy permits.",
  payee_not_allowed: "The quoted payee is not an allowed recipient.",
  asset_not_allowed: "The quoted asset is not an approved asset.",
  asset_decimals_mismatch: "The quote's asset decimals disagree with configuration.",
  asset_domain_mismatch: "The quote's EIP-712 domain does not match the configured asset.",
  asset_transfer_method_not_allowed: "The quoted asset transfer method is not configured.",
  amount_not_positive: "A payment amount must be a positive integer of atomic units.",
  amount_over_per_payment_limit: "The amount exceeds the per-payment limit.",
  budget_exhausted: "The payment would exceed the policy's total budget.",
  quote_expired: "The quote has expired.",
  quote_ttl_too_long: "The quote is valid for longer than the policy permits.",
  payment_timeout_too_long: "The quoted payment timeout exceeds the policy's limit.",
  request_digest_mismatch: "The quote does not price this request, or the intent is bound to other terms.",
  request_body_too_large: "The input exceeds the configured maximum body size.",
  // Signer denials.
  principal_mismatch: "The signer acts for a different principal.",
  wrong_payer: "The authorization would pay from an account the signer does not control.",
  primary_type_not_allowed: "The signer signs only EIP-3009 transfer authorizations.",
  domain_name_mismatch: "The typed-data domain name does not match the configured asset.",
  domain_version_mismatch: "The typed-data domain version does not match the configured asset.",
  domain_chain_mismatch: "The typed-data domain names a different chain.",
  verifying_contract_mismatch: "The verifying contract is not the configured asset.",
  message_payee_mismatch: "The authorization payee does not match the quote.",
  message_value_mismatch: "The authorization value does not match the quote.",
  valid_after_not_zero: "This build signs only authorizations valid from the epoch.",
  valid_before_in_past: "The authorization would already have expired when signed.",
  valid_before_too_far: "The authorization's validity window is longer than the policy permits.",
  authorization_already_bound: "This intent is already bound to a different authorization.",
  nonce_bound_to_other_intent: "That authorization nonce belongs to another intent.",
  nonce_already_used: "That authorization nonce has already been issued.",
  reservation_binding_changed: "This intent already holds a reservation for different terms.",
  idempotency_key_bound_to_other_intent: "That idempotency key belongs to another intent.",
  // Boundary-level outcomes.
  quote_not_in_session: "That quote was not issued in this session.",
  request_failed: "The request did not complete. See the operator's logs for the reason.",
};

/** A refusal this boundary itself decided, reported with the same shape. */
function codeResult(code: string): ToolOutput {
  return {
    content: [{ type: "text", text: JSON.stringify({ refused: true, code, description: describe(code) }, null, 2) }],
    isError: true,
  };
}

function describe(code: string): string {
  return FAILURE_DESCRIPTIONS[code] ?? FAILURE_DESCRIPTIONS["request_failed"] ?? "The request did not complete.";
}

/**
 * Reports a failure as tool output rather than a transport error.
 *
 * A policy denial is an answer, not a malfunction, so the caller is told which
 * rule refused it — by code, with a description from the table above. No upstream
 * message, stack, cause or payload is included.
 */
function errorResult(error: unknown): ToolOutput {
  const code =
    error instanceof PolicyDeniedError || error instanceof SignerDeniedError ? error.code : "request_failed";
  const detail = { refused: true, code, description: describe(code) };
  return { content: [{ type: "text", text: JSON.stringify(detail, null, 2) }], isError: true };
}
