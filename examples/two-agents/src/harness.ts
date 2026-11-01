import { spawn } from "node:child_process";
import type { ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";

/** A spawned service: no stdin, both output streams piped so we can read readiness. */
type ServiceProcess = ChildProcessByStdio<null, Readable, Readable>;
import { createServer } from "node:http";
import { mkdir, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import {
  deployTestToken,
  fundNative,
  repositoryRoot,
  startLocalChain,
  type ProvisionResult,
  type RunningLocalChain,
} from "@pulseagent/localchain";
import { PulseAgentClient } from "@pulseagent/sdk";
import type { AssetProfile, PaymentPolicy } from "@pulseagent/core";

/**
 * Brings up the whole local stack: a disposable chain, a deployed valueless
 * fixture, and the signer, facilitator and seller as separate OS processes with
 * a buyer SDK client connected to them.
 *
 * Shared by the demo and the integration tests so both exercise the same wiring
 * rather than two approximations of it.
 *
 * Process separation is real here — the signer is another process, and the key it
 * generates exists only inside it. Running under one OS user, that separation
 * limits accidents and does not resist a compromised host; production custody
 * needs a separate identity or container and an external signer, KMS or HSM.
 *
 * {@link LocalStack.stop} is safe to call from a `finally` block and is the only
 * thing that terminates the children. A demo that leaves processes behind has not
 * finished, so it is called unconditionally.
 */

export interface LocalStackOptions {
  /** Directory for runtime state, configs and evidence. Created if absent. */
  readonly runtimeDir: string;
  /** Price of one digest, in atomic units of the fixture token. */
  readonly priceAtomic?: string;
  /** Tokens minted to the payer. */
  readonly payerFundingAtomic?: string;
  readonly maxAmountPerPayment?: string;
  readonly totalBudget?: string;
  readonly quoteTtlSeconds?: number;
}

export interface LocalStack {
  readonly chain: RunningLocalChain;
  readonly token: ProvisionResult;
  readonly asset: AssetProfile;
  readonly policy: PaymentPolicy;
  readonly payeeAddress: `0x${string}`;
  readonly payerAddress: `0x${string}`;
  readonly facilitatorAddress: `0x${string}`;
  readonly sellerOrigin: string;
  readonly signerUrl: string;
  readonly facilitatorUrl: string;
  readonly client: PulseAgentClient;
  /** Environment an MCP server needs to drive this same stack over stdio. */
  readonly mcpEnvironment: Readonly<Record<string, string>>;
  /** Shared state and audit log for buyer, seller and facilitator. */
  readonly platformDatabasePath: string;
  /** The signer's own state and audit log, kept on its side of the boundary. */
  readonly signerDatabasePath: string;
  readonly runtimeDir: string;
  /**
   * Stops and restarts the seller process, keeping its durable state.
   *
   * The chain and the signer stay up, so this is a service restart rather than a
   * fresh system: exactly the case where in-memory settlement records would have
   * been lost and a buyer that had paid could no longer collect.
   */
  restartSeller(): Promise<void>;
  /**
   * Stops and restarts the facilitator process, keeping its durable state.
   *
   * Its broadcast claims and sender-nonce counter live in the shared database,
   * so a restart must not lose them: losing the counter would reuse a nonce, and
   * losing a claim would broadcast an authorization twice.
   */
  restartFacilitator(): Promise<void>;
  /**
   * A new buyer client on the same durable state, as a restarted buyer would be.
   *
   * The returned client replaces {@link LocalStack.client}; the previous one is
   * closed.
   */
  restartBuyer(): Promise<PulseAgentClient>;
  stop(): Promise<void>;
}

const READY_TIMEOUT_MS = 45_000;

/**
 * Starts the stack.
 *
 * @param options Runtime directory and economic parameters.
 * @returns The running stack. Always stop it in a `finally`.
 */
export async function startLocalStack(options: LocalStackOptions): Promise<LocalStack> {
  const runtimeDir = path.resolve(options.runtimeDir);
  await mkdir(runtimeDir, { recursive: true });
  const root = repositoryRoot();

  const priceAtomic = options.priceAtomic ?? "1500";
  const payerFundingAtomic = options.payerFundingAtomic ?? "1000000";
  const quoteTtlSeconds = options.quoteTtlSeconds ?? 120;

  const children: { name: string; child: ServiceProcess }[] = [];
  let chain: RunningLocalChain | undefined;

  const stop = async (): Promise<void> => {
    // Reverse order, and every child gets stopped even if an earlier one throws.
    for (const entry of [...children].reverse()) {
      await terminate(entry.child);
    }
    children.length = 0;
    if (chain) {
      await chain.close();
      chain = undefined;
    }
  };

  try {
    chain = await startLocalChain();
    // A non-optional binding for everything below: `chain` itself has to stay
    // reassignable so `stop` can clear it, which defeats narrowing in closures.
    const runningChain = chain;
    const ownedLocalOrigins = [runningChain.origin];
    const token = await deployTestToken(runningChain);

    const asset: AssetProfile = {
      address: token.token.address,
      symbol: token.token.symbol,
      decimals: token.token.decimals,
      eip712Name: token.token.name,
      eip712Version: token.token.eip712Version,
      assetTransferMethod: "eip3009",
      valuelessTestFixture: true,
    };

    // The seller's payee address. No key is needed to receive, so none is created
    // for it beyond the one this account was generated with, which nothing uses.
    const payeeAddress = privateKeyToAccount(randomHexKey()).address;

    // Ports are reserved before anything starts, because the signer's policy has
    // to name the seller's origin and the seller has to name the facilitator's.
    const sellerPort = await reserveLoopbackPort();
    const facilitatorPort = await reserveLoopbackPort();
    const signerPort = await reserveLoopbackPort();
    const sellerOrigin = `http://127.0.0.1:${String(sellerPort)}`;
    const facilitatorUrl = `http://127.0.0.1:${String(facilitatorPort)}`;
    const signerUrl = `http://127.0.0.1:${String(signerPort)}`;

    const platformDatabasePath = path.join(runtimeDir, "platform.sqlite");
    const signerDatabasePath = path.join(runtimeDir, "signer.sqlite");

    const policy: PaymentPolicy = {
      principalId: "buyer-agent-a",
      policyRevision: "policy-rev-1",
      network: "eip155:31337",
      allowedServiceOrigins: [sellerOrigin],
      allowedResourcePaths: ["/digest"],
      allowedPayees: [payeeAddress],
      allowedAssets: [asset],
      maxAmountPerPayment: options.maxAmountPerPayment ?? "2000",
      totalBudget: options.totalBudget ?? "10000",
      maxGasReservationWei: "2000000000000000",
      totalGasBudgetWei: "100000000000000000",
      maxQuoteTtlSeconds: Math.max(quoteTtlSeconds, 120),
      maxRequestBodyBytes: 4096,
    };

    const policyPath = path.join(runtimeDir, "signer-policy.json");
    await writeFile(policyPath, `${JSON.stringify(policy, null, 2)}\n`, "utf8");

    // Transport tokens are generated here and passed through the environment of
    // the child that needs them. They are never logged or written to evidence.
    const signerToken = randomBytes(32).toString("hex");
    const facilitatorToken = randomBytes(32).toString("hex");

    const signerReady = await startChild(children, "signer", path.join(root, "apps/signer/dist/main.js"), {
      PULSEAGENT_SIGNER_POLICY: policyPath,
      PULSEAGENT_SIGNER_DB: signerDatabasePath,
      PULSEAGENT_SIGNER_TOKEN: signerToken,
      PULSEAGENT_SIGNER_PORT: String(signerPort),
    });
    const payerAddress = signerReady["address"] as `0x${string}`;

    // The payer is funded with valueless fixture tokens only. It never holds
    // native gas: under EIP-3009 the facilitator pays the gas.
    await mintTokens(runningChain, token, payerAddress, BigInt(payerFundingAtomic));

    const facilitatorConfigPath = path.join(runtimeDir, "facilitator-config.json");
    await writeFile(
      facilitatorConfigPath,
      `${JSON.stringify(
        {
          network: "eip155:31337",
          rpcUrl: runningChain.url,
          ownedLocalOrigins,
          databasePath: platformDatabasePath,
          port: facilitatorPort,
          allowedAssets: [asset.address],
          allowedPayees: [payeeAddress],
          maxGasLimit: "300000",
          maxFeePerGasWei: "5000000000",
          maxPriorityFeePerGasWei: "2000000000",
          totalFeeBudgetWei: "100000000000000000",
          confirmationTimeoutMs: 20_000,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    const facilitatorReady = await startChild(
      children,
      "facilitator",
      path.join(root, "apps/facilitator/dist/main.js"),
      {
        PULSEAGENT_FACILITATOR_CONFIG: facilitatorConfigPath,
        PULSEAGENT_FACILITATOR_TOKEN: facilitatorToken,
      },
    );
    const facilitatorAddress = facilitatorReady["signerAddress"] as `0x${string}`;
    // The facilitator sponsors gas, so it is the only account given native funds.
    await fundNative(runningChain, facilitatorAddress, 10n ** 19n);

    const sellerConfigPath = path.join(runtimeDir, "seller-config.json");
    await writeFile(
      sellerConfigPath,
      `${JSON.stringify(
        {
          network: "eip155:31337",
          rpcUrl: runningChain.url,
          ownedLocalOrigins,
          databasePath: platformDatabasePath,
          asset,
          payTo: payeeAddress,
          priceAtomic,
          facilitatorUrl,
          quoteTtlSeconds,
          port: sellerPort,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    await startChild(children, "seller", path.join(root, "apps/seller/dist/main.js"), {
      PULSEAGENT_SELLER_CONFIG: sellerConfigPath,
      PULSEAGENT_FACILITATOR_TOKEN: facilitatorToken,
    });

    // Exposed so tests can drive the MCP server against this same stack.
    const mcpEnvironment = {
      PULSEAGENT_POLICY: policyPath,
      PULSEAGENT_DB: platformDatabasePath,
      PULSEAGENT_RPC_URL: runningChain.url,
      PULSEAGENT_SIGNER_URL: signerUrl,
      PULSEAGENT_SIGNER_TOKEN: signerToken,
      PULSEAGENT_OWNED_LOCAL_ORIGINS: ownedLocalOrigins.join(","),
    };

    const connectBuyer = async (): Promise<PulseAgentClient> =>
      PulseAgentClient.connect({
        policy,
        rpcUrl: runningChain.url,
        ownedLocalOrigins,
        databasePath: platformDatabasePath,
        signerUrl,
        signerToken,
      });

    let client = await connectBuyer();

    const stack: LocalStack = {
      chain: runningChain,
      token,
      asset,
      policy,
      payeeAddress,
      payerAddress,
      facilitatorAddress,
      sellerOrigin,
      signerUrl,
      facilitatorUrl,
      get client() {
        return client;
      },
      mcpEnvironment,
      platformDatabasePath,
      signerDatabasePath,
      runtimeDir,
      async restartSeller() {
        const index = children.findIndex((entry) => entry.name === "seller");
        if (index !== -1) {
          const [existing] = children.splice(index, 1);
          if (existing) await terminate(existing.child);
        }
        await startChild(children, "seller", path.join(root, "apps/seller/dist/main.js"), {
          PULSEAGENT_SELLER_CONFIG: sellerConfigPath,
          PULSEAGENT_FACILITATOR_TOKEN: facilitatorToken,
        });
      },
      async restartFacilitator() {
        const index = children.findIndex((entry) => entry.name === "facilitator");
        if (index !== -1) {
          const [existing] = children.splice(index, 1);
          if (existing) await terminate(existing.child);
        }
        const ready = await startChild(children, "facilitator", path.join(root, "apps/facilitator/dist/main.js"), {
          PULSEAGENT_FACILITATOR_CONFIG: facilitatorConfigPath,
          PULSEAGENT_FACILITATOR_TOKEN: facilitatorToken,
        });
        // A restarted facilitator generates a fresh gas account, so it needs
        // funding again; its key never survives the process.
        await fundNative(runningChain, ready["signerAddress"] as `0x${string}`, 10n ** 19n);
      },
      async restartBuyer() {
        client.close();
        client = await connectBuyer();
        return client;
      },
      async stop() {
        client.close();
        await stop();
      },
    };
    return stack;
  } catch (error) {
    await stop();
    throw error;
  }
}

async function mintTokens(
  chain: RunningLocalChain,
  token: ProvisionResult,
  to: `0x${string}`,
  amount: bigint,
): Promise<void> {
  const { mintTestTokens } = await import("@pulseagent/localchain");
  await mintTestTokens(chain, token, to, amount);
}

/**
 * Spawns a service and waits for its single JSON readiness line.
 *
 * stderr is captured rather than inherited, so a child's diagnostics are
 * available on failure without being interleaved into the demo's own output.
 */
async function startChild(
  children: { name: string; child: ServiceProcess }[],
  name: string,
  script: string,
  env: Record<string, string>,
): Promise<Record<string, unknown>> {
  const child: ServiceProcess = spawn(process.execPath, [script], {
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.push({ name, child });

  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr = `${stderr}${chunk}`.slice(-4000);
  });

  return new Promise<Record<string, unknown>>((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => {
      reject(new Error(`${name} did not report readiness within ${String(READY_TIMEOUT_MS)}ms. stderr: ${stderr}`));
    }, READY_TIMEOUT_MS);

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      const line = buffer.slice(0, newline);
      clearTimeout(timer);
      try {
        resolve(JSON.parse(line) as Record<string, unknown>);
      } catch {
        reject(new Error(`${name} printed a readiness line that is not JSON`));
      }
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`${name} exited with code ${String(code)} before reporting readiness. stderr: ${stderr}`));
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function terminate(child: ServiceProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    const forceTimer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 3000);
    child.once("exit", () => {
      clearTimeout(forceTimer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

/**
 * Picks a free loopback port by binding and releasing one.
 *
 * There is a small window between release and reuse. It is acceptable for a
 * local demo and would not be for anything long-lived; the alternative, letting
 * each service pick its own port, cannot work here because the signer's policy
 * must name the seller's origin before the seller exists.
 */
export async function reserveLoopbackPort(): Promise<number> {
  const server = createServer();
  return new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("could not reserve a loopback port"));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
  });
}

function randomHexKey(): `0x${string}` {
  return `0x${randomBytes(32).toString("hex")}`;
}
