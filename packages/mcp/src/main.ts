import { readFile } from "node:fs/promises";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { PaymentPolicySchema } from "@pulseagent/core";
import { PulseAgentClient } from "@pulseagent/sdk";
import { createPulseAgentMcpServer } from "./server.js";

/**
 * MCP stdio entrypoint.
 *
 * Configuration arrives as paths and a transport token, from an operator:
 *
 * - `PULSEAGENT_POLICY`: the operator-authored policy JSON
 * - `PULSEAGENT_DB`: shared platform state and audit log
 * - `PULSEAGENT_RPC_URL`: RPC endpoint, which must satisfy the chain profile
 * - `PULSEAGENT_SIGNER_URL` / `PULSEAGENT_SIGNER_TOKEN`: the isolated signer
 * - `PULSEAGENT_OWNED_LOCAL_ORIGINS`: comma-separated origins of owned local nodes
 *
 * None of this is reachable through a tool call. Credential loading and operator
 * approval stay outside MCP on purpose: a model that could set them would be
 * approving its own spending.
 */
async function main(): Promise<void> {
  const policy = PaymentPolicySchema.parse(JSON.parse(await readFile(requireEnv("PULSEAGENT_POLICY"), "utf8")));
  const ownedLocalOrigins = (process.env["PULSEAGENT_OWNED_LOCAL_ORIGINS"] ?? "")
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin !== "");

  const client = await PulseAgentClient.connect({
    policy,
    rpcUrl: requireEnv("PULSEAGENT_RPC_URL"),
    ownedLocalOrigins,
    databasePath: requireEnv("PULSEAGENT_DB"),
    signerUrl: requireEnv("PULSEAGENT_SIGNER_URL"),
    signerToken: requireEnv("PULSEAGENT_SIGNER_TOKEN"),
  });

  const server = createPulseAgentMcpServer({ client });
  // stdout belongs to the protocol; nothing else may write to it.
  await server.connect(new StdioServerTransport());

  const shutdown = (): void => {
    client.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

main().catch((error: unknown) => {
  process.stderr.write(
    `${JSON.stringify({
      service: "mcp",
      fatal: true,
      code: "startup_failed",
      // A stable code and the error's class name only. An upstream message is
      // arbitrary text and has been observed carrying embedded signature material.
      errorName: error instanceof Error ? error.name : "Error",
    })}\n`,
  );
  process.exit(1);
});
