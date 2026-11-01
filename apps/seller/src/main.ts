import { readFile } from "node:fs/promises";
import { z } from "zod";
import { AssetProfileSchema } from "@pulseagent/core";
import { startSeller } from "./service.js";

/**
 * Seller entrypoint.
 *
 * `PULSEAGENT_SELLER_CONFIG` names a JSON file holding the chain, the RPC, the
 * asset it prices in, its payee address and its facilitator.
 * `PULSEAGENT_FACILITATOR_TOKEN` carries the facilitator's transport token.
 *
 * The seller holds no key: it receives payments at a configured address and
 * never signs anything.
 */
const ConfigSchema = z.strictObject({
  network: z.string(),
  rpcUrl: z.string(),
  ownedLocalOrigins: z.array(z.string()).default([]),
  databasePath: z.string(),
  asset: AssetProfileSchema,
  payTo: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  priceAtomic: z.string().regex(/^[1-9][0-9]*$/),
  facilitatorUrl: z.string(),
  quoteTtlSeconds: z.number().int().positive().max(3600).default(120),
  port: z.number().int().min(0).max(65_535).default(0),
});

async function main(): Promise<void> {
  const configPath = requireEnv("PULSEAGENT_SELLER_CONFIG");
  const facilitatorToken = requireEnv("PULSEAGENT_FACILITATOR_TOKEN");
  const config = ConfigSchema.parse(JSON.parse(await readFile(configPath, "utf8")));

  const seller = await startSeller({
    network: config.network,
    rpcUrl: config.rpcUrl,
    ownedLocalOrigins: config.ownedLocalOrigins,
    databasePath: config.databasePath,
    asset: config.asset,
    payTo: config.payTo as `0x${string}`,
    priceAtomic: config.priceAtomic,
    facilitatorUrl: config.facilitatorUrl,
    facilitatorToken,
    quoteTtlSeconds: config.quoteTtlSeconds,
    port: config.port,
  });

  const shutdown = (): void => {
    void seller.close().then(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  process.stdout.write(
    `${JSON.stringify({
      ready: true,
      service: "seller",
      url: seller.url,
      origin: seller.origin,
      port: seller.port,
      payTo: seller.payTo,
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
      service: "seller",
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
