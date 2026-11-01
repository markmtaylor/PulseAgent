import { readFile } from "node:fs/promises";
import { z } from "zod";
import { startFacilitator } from "./service.js";

/**
 * Facilitator entrypoint.
 *
 * `PULSEAGENT_FACILITATOR_CONFIG` names a JSON file holding the chain, the RPC,
 * the asset allowlist and the broadcast limits. `PULSEAGENT_FACILITATOR_TOKEN`
 * carries the loopback transport token from the parent process.
 *
 * No key material is accepted: the gas account is generated inside the process
 * and only its address is ever printed.
 */
const ConfigSchema = z.strictObject({
  network: z.string(),
  rpcUrl: z.string(),
  ownedLocalOrigins: z.array(z.string()).default([]),
  databasePath: z.string(),
  port: z.number().int().min(0).max(65_535).default(0),
  allowedAssets: z.array(z.string().regex(/^0x[0-9a-fA-F]{40}$/)).min(1),
  allowedPayees: z.array(z.string().regex(/^0x[0-9a-fA-F]{40}$/)).min(1),
  maxGasLimit: z.string().regex(/^[0-9]+$/),
  maxFeePerGasWei: z.string().regex(/^[0-9]+$/),
  maxPriorityFeePerGasWei: z.string().regex(/^[0-9]+$/),
  totalFeeBudgetWei: z.string().regex(/^[0-9]+$/),
  confirmationTimeoutMs: z.number().int().positive().default(30_000),
  facilitatorId: z.string().default("facilitator-local"),
  policyRevision: z.string().default("facilitator-rev-1"),
});

async function main(): Promise<void> {
  const configPath = requireEnv("PULSEAGENT_FACILITATOR_CONFIG");
  const authToken = requireEnv("PULSEAGENT_FACILITATOR_TOKEN");
  const config = ConfigSchema.parse(JSON.parse(await readFile(configPath, "utf8")));

  const facilitator = await startFacilitator({
    network: config.network,
    rpcUrl: config.rpcUrl,
    ownedLocalOrigins: config.ownedLocalOrigins,
    databasePath: config.databasePath,
    authToken,
    port: config.port,
    confirmationTimeoutMs: config.confirmationTimeoutMs,
    allowedAssets: config.allowedAssets as `0x${string}`[],
    allowedPayees: config.allowedPayees as `0x${string}`[],
    facilitatorId: config.facilitatorId,
    policyRevision: config.policyRevision,
    limits: {
      maxGasLimit: BigInt(config.maxGasLimit),
      maxFeePerGasWei: BigInt(config.maxFeePerGasWei),
      maxPriorityFeePerGasWei: BigInt(config.maxPriorityFeePerGasWei),
      totalFeeBudgetWei: BigInt(config.totalFeeBudgetWei),
    },
  });

  const shutdown = (): void => {
    void facilitator.close().then(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  process.stdout.write(
    `${JSON.stringify({
      ready: true,
      service: "facilitator",
      url: facilitator.url,
      port: facilitator.port,
      network: facilitator.network,
      signerAddress: facilitator.signerAddress,
    })}\n`,
  );
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

main().catch((error: unknown) => {
  process.stderr.write(
    `${JSON.stringify({
      service: "facilitator",
      fatal: true,
      code: "startup_failed",
      // A stable code and the error's class name only. This process handles
      // payment material, and an arbitrary message is arbitrary text: one has
      // already been observed carrying an embedded signature.
      errorName: error instanceof Error ? error.name : "Error",
    })}\n`,
  );
  process.exit(1);
});
