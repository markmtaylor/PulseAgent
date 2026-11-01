import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ABSENT_BY_DESIGN, createPulseAgentMcpServer } from "@pulseagent/mcp";
import type { PulseAgentClient } from "@pulseagent/sdk";

/**
 * The model boundary, driven by the official MCP client.
 *
 * Two things are checked. First, that the tool surface is the bounded one: a
 * model can ask for a payment under a policy and cannot approve its own budget,
 * replace a policy, reach a key or ask for a signature over anything it chooses.
 * Second, that nothing a dependency throws reaches tool output verbatim.
 *
 * The marker below is synthetic. It is not a key, a signature or a credential;
 * it only has the shape of one, which is the property under test.
 */

const SYNTHETIC_SIGNATURE = `0x${"ab".repeat(65)}`;
const SYNTHETIC_BEARER = `Bearer ${"s".repeat(180)}`;
const SENTINEL = "SENTINEL_SECRET_MARKER";
const QUOTE_ID = "quote_session_0001";

/** A quote shaped like a real one, so request_quote can succeed on demand. */
const SESSION_QUOTE = {
  quoteId: QUOTE_ID,
  serviceOrigin: "http://127.0.0.1:8080",
  resourcePath: "/digest",
  requestDigest: `sha256:${"c".repeat(64)}`,
  network: "eip155:31337",
  asset: "0x1111111111111111111111111111111111111111",
  assetDecimals: 6,
  payTo: "0x2222222222222222222222222222222222222222",
  amount: "1500",
  expiresAt: Math.floor(Date.now() / 1000) + 300,
  eip712Name: "Test Token",
  eip712Version: "1",
  assetTransferMethod: "eip3009",
  maxTimeoutSeconds: 120,
} as const;

/** Every tool, and the dependency whose failure that tool must contain. */
const TOOLS = [
  { name: "list_services", member: "listServices", args: {} },
  {
    name: "request_quote",
    member: "requestQuote",
    args: { serviceOrigin: "http://127.0.0.1:8080", input: "hello" },
  },
  { name: "request_payment", member: "requestPayment", args: { quoteId: QUOTE_ID } },
  { name: "get_intent_status", member: "getIntentStatus", args: { intentId: "int_1" } },
  { name: "verify_settlement", member: "verifyIntentSettlement", args: { intentId: "int_1" } },
  { name: "read_audit", member: "readAudit", args: {} },
] as const;

/**
 * A client whose every member throws an error carrying the markers.
 *
 * Synchronous property reads throw too, because a handler that only reads a
 * property was one of the three that leaked.
 */
function throwingClient(message: string): PulseAgentClient {
  const boom = (): never => {
    throw new Error(message);
  };
  return {
    get payerAddress(): `0x${string}` {
      return boom();
    },
    listServices: boom,
    requestQuote: boom,
    requestPayment: boom,
    getIntentStatus: boom,
    verifyIntentSettlement: boom,
    readAudit: boom,
    get auditTerminalHash(): string {
      return boom();
    },
    exportAudit: boom,
    close: () => undefined,
  } as unknown as PulseAgentClient;
}

/**
 * A client that works, except for the one member under test.
 *
 * Needed because some handlers have prerequisites: `request_payment` refuses a
 * quote it has not seen, so a test that only injected an error there never
 * reached the dependency at all and proved nothing.
 */
function clientFailingOn(member: string, message: string): PulseAgentClient {
  const boom = (): never => {
    throw new Error(message);
  };
  const working: Record<string, unknown> = {
    listServices: () => [{ origin: "http://127.0.0.1:8080", resourcePaths: ["/digest"] }],
    requestQuote: async () => ({ quote: SESSION_QUOTE, service: { name: "sha256-digest", deterministic: true } }),
    requestPayment: async () => ({ intentId: "int_1", correlationId: "pay_1", state: "DELIVERED" }),
    getIntentStatus: () => undefined,
    verifyIntentSettlement: async () => ({ status: "no-settlement-recorded" }),
    readAudit: () => [],
    payerAddress: "0x1111111111111111111111111111111111111111",
    auditTerminalHash: `sha256:${"0".repeat(64)}`,
    exportAudit: async () => ({ events: 0, terminalHash: "", filePath: "" }),
    close: () => undefined,
  };
  working[member] = boom;
  return working as unknown as PulseAgentClient;
}

async function connect(client: PulseAgentClient): Promise<Client> {
  const server = createPulseAgentMcpServer({ client });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const mcpClient = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([mcpClient.connect(clientTransport), server.connect(serverTransport)]);
  return mcpClient;
}

function textOf(result: unknown): string {
  const content = (result as { content?: { text?: string }[] }).content ?? [];
  return content.map((entry) => entry.text ?? "").join("\n");
}

describe("MCP tool surface", () => {
  it("initializes and lists exactly the bounded operations", async () => {
    const mcpClient = await connect(throwingClient("unused"));
    const { tools } = await mcpClient.listTools();
    const names = tools.map((tool) => tool.name).sort();
    expect(names).toEqual([
      "get_intent_status",
      "list_services",
      "read_audit",
      "request_payment",
      "request_quote",
      "verify_settlement",
    ]);
    await mcpClient.close();
  });

  it("does not expose spending approval, policy editing or generic signing", async () => {
    const mcpClient = await connect(throwingClient("unused"));
    const { tools } = await mcpClient.listTools();
    const names = new Set(tools.map((tool) => tool.name));
    for (const absent of ABSENT_BY_DESIGN) {
      expect(names.has(absent), `${absent} must not exist`).toBe(false);
    }
    // Nor anything whose name suggests one of those capabilities.
    for (const name of names) {
      expect(name).not.toMatch(/approve|budget|policy|sign|key|secret|rpc/i);
    }
    await mcpClient.close();
  });

  it("describes a tool without leaking configuration", async () => {
    const mcpClient = await connect(throwingClient("unused"));
    const { tools } = await mcpClient.listTools();
    expect(JSON.stringify(tools)).not.toMatch(/0x[0-9a-fA-F]{40,}/);
    await mcpClient.close();
  });
});

describe("MCP error boundary", () => {
  for (const marker of [
    { label: "an embedded signature", value: `upstream authorization: ${SYNTHETIC_SIGNATURE}` },
    { label: "an embedded bearer token", value: `auth failed: ${SYNTHETIC_BEARER}` },
    { label: "a secret sentinel", value: `config error: ${SENTINEL}` },
  ]) {
    it(`never echoes ${marker.label} from any tool`, async () => {
      for (const tool of TOOLS) {
        const mcpClient = await connect(clientFailingOn(tool.member, marker.value));
        // Some handlers have prerequisites. Satisfy them so the call actually
        // reaches the failing dependency rather than being refused early.
        if (tool.name === "request_payment") {
          await mcpClient.callTool({
            name: "request_quote",
            arguments: { serviceOrigin: "http://127.0.0.1:8080", input: "hello" },
          });
        }
        const result = await mcpClient.callTool({ name: tool.name, arguments: tool.args });
        const text = textOf(result);
        // Truncation is not redaction; none of these may appear at all.
        expect(text, `${tool.name} leaked ${marker.label}`).not.toContain("abab");
        expect(text, `${tool.name} leaked ${marker.label}`).not.toContain(SENTINEL);
        expect(text, `${tool.name} leaked ${marker.label}`).not.toContain("ssss");
        expect(text, `${tool.name} leaked ${marker.label}`).not.toMatch(/0x[0-9a-fA-F]{130,}/);
        // The call must have reached the failing dependency and been contained.
        const payload = JSON.parse(text) as { refused?: boolean; code?: unknown; description?: unknown };
        expect(payload, `${tool.name} did not report a refusal`).toMatchObject({ refused: true });
        expect(payload.code).toBe("request_failed");
        expect(payload.description).toBeTypeOf("string");
        await mcpClient.close();
      }
    });
  }

  it("reports a policy denial by its stable code", async () => {
    const { PolicyDeniedError } = await import("@pulseagent/sdk");
    const denying = {
      listServices: () => [],
      requestQuote: () => {
        throw new PolicyDeniedError("service_origin_not_allowed", `not allowed ${SYNTHETIC_SIGNATURE}`);
      },
      payerAddress: "0x1111111111111111111111111111111111111111",
    } as unknown as PulseAgentClient;

    const mcpClient = await connect(denying);
    const result = await mcpClient.callTool({
      name: "request_quote",
      arguments: { serviceOrigin: "https://evil.example", input: "x" },
    });
    const payload = JSON.parse(textOf(result)) as { code: string; description: string };
    expect(payload.code).toBe("service_origin_not_allowed");
    expect(payload.description).toMatch(/not one the policy permits/);
    // Even a denial's own message must not carry the marker through.
    expect(textOf(result)).not.toContain("abab");
    await mcpClient.close();
  });

  it("refuses to pay for a quote that was not issued in this session", async () => {
    // A model must not be able to assemble a quote field by field.
    const mcpClient = await connect(throwingClient("unused"));
    const result = await mcpClient.callTool({ name: "request_payment", arguments: { quoteId: "quote_invented" } });
    expect(JSON.parse(textOf(result))).toMatchObject({ refused: true, code: "quote_not_in_session" });
    await mcpClient.close();
  });
});
