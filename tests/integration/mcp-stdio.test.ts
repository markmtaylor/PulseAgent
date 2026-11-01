import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { repositoryRoot, tokenBalance } from "@pulseagent/localchain";
import { startLocalStack, type LocalStack } from "@pulseagent/two-agents";

/**
 * The MCP server as a model would actually reach it: a spawned child process
 * speaking stdio to the official client, driving the live stack.
 *
 * The in-memory transport tests cover the tool surface and the error boundary.
 * This one covers what they cannot: that the server starts as its own process
 * from operator configuration, that stdout carries nothing but the protocol, and
 * that a payment requested through MCP really settles on chain.
 */

let stack: LocalStack;
let client: Client;

beforeAll(async () => {
  stack = await startLocalStack({
    runtimeDir: path.join(mkdtempSync(path.join(tmpdir(), "pa-mcp-")), "runtime"),
    priceAtomic: "1500",
    payerFundingAtomic: "1000000",
  });

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(repositoryRoot(), "packages/mcp/dist/main.js")],
    env: { ...(process.env as Record<string, string>), ...stack.mcpEnvironment },
    // Anything the server writes to stderr is diagnostics; stdout is the protocol.
    stderr: "pipe",
  });
  client = new Client({ name: "pulseagent-stdio-test", version: "0.0.0" });
  await client.connect(transport);
}, 120_000);

afterAll(async () => {
  await client?.close();
  await stack?.stop();
});

function textOf(result: unknown): string {
  const content = (result as { content?: { text?: string }[] }).content ?? [];
  return content.map((entry) => entry.text ?? "").join("\n");
}

describe("MCP over stdio against the live stack", () => {
  it("initializes and lists the bounded operations", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((tool) => tool.name).sort()).toEqual([
      "get_intent_status",
      "list_services",
      "read_audit",
      "request_payment",
      "request_quote",
      "verify_settlement",
    ]);
  });

  it("reports the configured services and the payer's public address", async () => {
    const payload = JSON.parse(textOf(await client.callTool({ name: "list_services", arguments: {} }))) as {
      services: { origin: string }[];
      payer: string;
    };
    expect(payload.services.map((service) => service.origin)).toEqual([stack.sellerOrigin]);
    expect(payload.payer).toBe(stack.payerAddress);
  });

  it("quotes, pays and delivers a verified result, settling once on chain", async () => {
    const input = "mcp stdio payment";
    const quoted = JSON.parse(
      textOf(
        await client.callTool({
          name: "request_quote",
          arguments: { serviceOrigin: stack.sellerOrigin, input },
        }),
      ),
    ) as { quote: { quoteId: string; amount: string } };
    expect(quoted.quote.amount).toBe("1500");

    const payeeBefore = await tokenBalance(stack.chain, stack.token, stack.payeeAddress);
    const paid = JSON.parse(
      textOf(
        await client.callTool({
          name: "request_payment",
          arguments: { quoteId: quoted.quote.quoteId, idempotencyKey: "idem_mcp_stdio_0001" },
        }),
      ),
    ) as {
      intentId: string;
      correlationId: string;
      state: string;
      result: { sha256: string };
      settlement: { txHash: string; amountAtomic: string };
    };

    expect(paid.state).toBe("DELIVERED");
    const { createHash } = await import("node:crypto");
    expect(paid.result.sha256).toBe(createHash("sha256").update(input, "utf8").digest("hex"));
    expect(paid.settlement.amountAtomic).toBe("1500");
    expect((await tokenBalance(stack.chain, stack.token, stack.payeeAddress)) - payeeBefore).toBe(1500n);

    const status = JSON.parse(
      textOf(await client.callTool({ name: "get_intent_status", arguments: { intentId: paid.intentId } })),
    ) as { found: boolean; intent: { state: string } };
    expect(status.found).toBe(true);
    expect(status.intent.state).toBe("DELIVERED");

    const verified = JSON.parse(
      textOf(await client.callTool({ name: "verify_settlement", arguments: { intentId: paid.intentId } })),
    ) as { status: string; facts?: { txHash: string } };
    expect(verified.status).toBe("final");
    expect(verified.facts?.txHash).toBe(paid.settlement.txHash);

    const audit = JSON.parse(
      textOf(await client.callTool({ name: "read_audit", arguments: { intentId: paid.intentId } })),
    ) as { events: { kind: string }[]; terminalHash: string; note: string };
    expect(audit.events.map((event) => event.kind)).toEqual(
      expect.arrayContaining(["intent.created", "payment.authorized", "settlement.verified", "result.verified"]),
    );
    expect(audit.terminalHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    // The limits of the audit trail travel with it.
    expect(audit.note).toMatch(/does not detect a wholesale rewrite/);

    // Nothing that crossed this boundary may carry replayable material.
    const everything = JSON.stringify([quoted, paid, status, verified, audit]);
    expect(everything).not.toMatch(/0x[0-9a-fA-F]{130,}/);
    expect(everything).not.toMatch(/privateKey|mnemonic|Bearer /i);
  });

  it("refuses a payment for a quote it never issued", async () => {
    const refusal = JSON.parse(
      textOf(await client.callTool({ name: "request_payment", arguments: { quoteId: "quote_never_issued" } })),
    ) as { refused: boolean; code: string };
    expect(refusal).toMatchObject({ refused: true, code: "quote_not_in_session" });
  });

  it("refuses a quote from an origin the policy does not allow", async () => {
    const refusal = JSON.parse(
      textOf(
        await client.callTool({
          name: "request_quote",
          arguments: { serviceOrigin: "http://127.0.0.1:1", input: "x" },
        }),
      ),
    ) as { refused: boolean; code: string; description: string };
    expect(refusal.refused).toBe(true);
    expect(refusal.code).toBe("service_origin_not_allowed");
    expect(refusal.description).toMatch(/not one the policy permits/);
  });

  it("has no tool that could approve spending, change policy or sign arbitrarily", async () => {
    const { tools } = await client.listTools();
    for (const name of tools.map((tool) => tool.name)) {
      expect(name).not.toMatch(/approve|budget|policy|sign|key|secret|rpc/i);
    }
    // And calling one that does not exist is reported as an error rather than
    // quietly succeeding.
    const absent = await client.callTool({ name: "approve_spending", arguments: {} });
    expect((absent as { isError?: boolean }).isError).toBe(true);
    expect(textOf(absent)).toMatch(/approve_spending/);
  });
});
