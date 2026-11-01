import { readFile } from "node:fs/promises";
import { PaymentPolicySchema } from "@pulseagent/core";
import { startSigner } from "./service.js";

/**
 * Signer entrypoint.
 *
 * Configuration arrives as paths and a transport token, never as key material:
 *
 * - `PULSEAGENT_SIGNER_POLICY`: path to the operator-authored policy JSON
 * - `PULSEAGENT_SIGNER_DB`: path to this signer's own SQLite state
 * - `PULSEAGENT_SIGNER_TOKEN`: loopback transport token, from the parent process
 * - `PULSEAGENT_SIGNER_PORT`: optional fixed port; 0 or unset picks an ephemeral one
 *
 * On readiness one JSON line goes to stdout carrying the public address and
 * nothing else. There is deliberately no flag, environment variable or argument
 * that imports a private key: a key handed in from outside would already have
 * been exposed to whatever handed it in.
 */
async function main(): Promise<void> {
  const policyPath = requireEnv("PULSEAGENT_SIGNER_POLICY");
  const databasePath = requireEnv("PULSEAGENT_SIGNER_DB");
  const authToken = requireEnv("PULSEAGENT_SIGNER_TOKEN");
  const portRaw = process.env["PULSEAGENT_SIGNER_PORT"];
  const port = portRaw === undefined || portRaw === "" ? 0 : Number(portRaw);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new Error("PULSEAGENT_SIGNER_PORT must be a valid TCP port");
  }

  const policy = PaymentPolicySchema.parse(JSON.parse(await readFile(policyPath, "utf8")));
  const signer = await startSigner({ policy, databasePath, authToken, port });

  const shutdown = (): void => {
    void signer.close().then(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  process.stdout.write(
    `${JSON.stringify({
      ready: true,
      service: "signer",
      url: signer.url,
      port: signer.port,
      address: signer.address,
      principalId: signer.principalId,
      policyRevision: signer.policyRevision,
    })}\n`,
  );
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

main().catch((error: unknown) => {
  // A stable code only. This process holds the key, so an arbitrary error
  // message must never reach a log: messages have been observed carrying
  // embedded signature material, and the environment is never echoed.
  process.stderr.write(
    `${JSON.stringify({
      service: "signer",
      fatal: true,
      code: "startup_failed",
      errorName: error instanceof Error ? error.name : "Error",
    })}\n`,
  );
  process.exit(1);
});
