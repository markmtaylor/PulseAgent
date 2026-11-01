import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  assertRpcAllowed,
  listChainProfiles,
  requireChainProfile,
  sha256Hex,
  type ChainProfile,
} from "@pulseagent/core";

/**
 * `npm run verify:pulse`
 *
 * A read-only capability probe against the configured public PulseChain
 * profiles, writing dated machine-readable evidence.
 *
 * Read-only is structural, not a promise: the only JSON-RPC methods issued are
 * reads, there is no account and no key in this process, and a failure is
 * reported rather than retried against a different endpoint. The endpoint is
 * checked against the profile's allowlist before any request goes out.
 *
 * The probes answer the questions that actually gate this project: does the node
 * respond, which chain does it claim to be, does it serve a finalized block, and
 * does it accept the EVM opcodes our fixtures would need. The last of those is
 * why the Permit2 path was abandoned, so it is checked every time rather than
 * assumed to have stayed the same.
 */

const OPCODE_PROBES = {
  legacy_control: "0x60006000f3",
  shanghai_push0: "0x5f5ff3",
  cancun_mcopy: "0x6000600060005e60006000f3",
  cancun_tstore: "0x600060005d60006000f3",
} as const;

/** Addresses whose presence was recorded earlier and is re-checked here. */
const CANONICAL_ADDRESSES = {
  permit2: "0x000000000022D473030F116dDEE9F6B43aC78BA3",
  x402ExactPermit2Proxy: "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
} as const;

interface ProbeOutcome {
  readonly method: string;
  readonly params: readonly unknown[];
  readonly ok: boolean;
  readonly result?: unknown;
  readonly error?: { readonly code: number; readonly message: string };
}

async function main(argv: readonly string[]): Promise<number> {
  const outDirArgIndex = argv.indexOf("--out");
  const outDir = path.resolve(
    outDirArgIndex === -1 ? path.join(process.cwd(), ".runtime", "evidence") : argv[outDirArgIndex + 1] ?? ".",
  );
  const profiles = listChainProfiles().filter((profile) => profile.mode !== "local-ephemeral");

  const observedAt = new Date().toISOString();
  const reports: Record<string, unknown> = {};
  let failures = 0;

  for (const profile of profiles) {
    const endpoint = profile.allowedRpcOrigins[0];
    if (endpoint === undefined) {
      process.stdout.write(`${profile.caip2}: no allowed RPC origin is configured; skipped\n`);
      continue;
    }
    // Refuses anything outside the profile's allowlist before a request is made.
    assertRpcAllowed(profile, endpoint);

    process.stdout.write(`\n${profile.caip2} — ${profile.displayName}\n  endpoint ${endpoint}\n`);
    const probes: ProbeOutcome[] = [];
    const call = async (method: string, params: readonly unknown[] = []): Promise<ProbeOutcome> => {
      const outcome = await rpc(endpoint, method, params);
      probes.push(outcome);
      return outcome;
    };

    const chainId = await call("eth_chainId");
    const expectedChainId = `0x${profile.chainId.toString(16)}`;
    const chainIdMatches = chainId.ok && chainId.result === expectedChainId;
    process.stdout.write(
      `  eth_chainId            ${chainId.ok ? String(chainId.result) : `failed: ${chainId.error?.message ?? ""}`}` +
        ` ${chainIdMatches ? "(matches profile)" : "(DOES NOT MATCH PROFILE)"}\n`,
    );
    if (!chainIdMatches) failures += 1;

    const clientVersion = await call("web3_clientVersion");
    process.stdout.write(
      `  web3_clientVersion     ${clientVersion.ok ? String(clientVersion.result) : "unavailable"} (self-reported)\n`,
    );

    const syncing = await call("eth_syncing");
    process.stdout.write(`  eth_syncing            ${syncing.ok ? JSON.stringify(syncing.result) : "unavailable"}\n`);

    const latest = await call("eth_getBlockByNumber", ["latest", false]);
    const finalized = await call("eth_getBlockByNumber", ["finalized", false]);
    const latestNumber = blockNumberOf(latest.result);
    const finalizedNumber = blockNumberOf(finalized.result);
    process.stdout.write(
      `  latest block           ${latestNumber === undefined ? "unavailable" : String(latestNumber)}\n` +
        `  finalized block        ${finalizedNumber === undefined ? "unavailable" : String(finalizedNumber)}\n`,
    );
    if (latestNumber !== undefined && finalizedNumber !== undefined) {
      const lag = latestNumber - finalizedNumber;
      process.stdout.write(
        `  finality lag           ${String(lag)} blocks — a public settlement must stay resumable across this\n`,
      );
    }

    process.stdout.write("  opcode support (read-only eth_call of tiny programs):\n");
    const opcodes: Record<string, { accepted: boolean; error?: string }> = {};
    for (const [name, data] of Object.entries(OPCODE_PROBES)) {
      const probe = await call("eth_call", [{ data, gas: "0x186a0" }, "latest"]);
      opcodes[name] = probe.ok ? { accepted: true } : { accepted: false, error: probe.error?.message ?? "rejected" };
      process.stdout.write(
        `    ${name.padEnd(16)} ${probe.ok ? "accepted" : `rejected — ${probe.error?.message ?? ""}`}\n`,
      );
    }
    if (opcodes["cancun_mcopy"]?.accepted === true) {
      process.stdout.write(
        "    note: MCOPY now appears to be accepted here. The EIP-3009 choice was made because it was\n" +
          "    not; re-check the Permit2 path's behavior before relying on either conclusion.\n",
      );
    }

    process.stdout.write("  canonical contract code (presence only, not authenticity):\n");
    const code: Record<string, { bytes: number; digest: string }> = {};
    for (const [name, address] of Object.entries(CANONICAL_ADDRESSES)) {
      const probe = await call("eth_getCode", [address, "latest"]);
      const hex = typeof probe.result === "string" ? probe.result : "0x";
      code[name] = { bytes: (hex.length - 2) / 2, digest: sha256Hex(hex) };
      process.stdout.write(`    ${name.padEnd(24)} ${String(code[name]?.bytes ?? 0)} bytes at ${address}\n`);
    }

    reports[profile.caip2] = {
      profile: describeProfile(profile),
      endpoint,
      chainIdMatchesProfile: chainIdMatches,
      latestBlock: latestNumber === undefined ? null : String(latestNumber),
      finalizedBlock: finalizedNumber === undefined ? null : String(finalizedNumber),
      opcodes,
      canonicalCode: code,
      probes,
    };
  }

  const evidence = {
    observedAt,
    tool: "npm run verify:pulse",
    claim: "read-only capability probe",
    notClaimed: [
      "no transaction was signed or submitted",
      "contract presence is not authenticity: matching bytecode and a nonempty account are not provenance",
      "a self-reported client version and chain id are claims by the node, not proofs",
      "no test asset is approved and no public spending plan is authorized",
    ],
    networks: reports,
  };

  await mkdir(outDir, { recursive: true });
  const file = path.join(outDir, `verify-pulse-${observedAt.replaceAll(/[:.]/g, "-")}.json`);
  await writeFile(file, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");

  process.stdout.write(`\nEvidence written to ${file}\n`);
  process.stdout.write(
    failures === 0
      ? "All configured public profiles responded and reported the expected chain id.\n" +
          "This is a capability probe. It authorizes nothing: there is no public broadcast path in this build.\n"
      : `${String(failures)} profile(s) did not report the expected chain id.\n`,
  );
  return failures === 0 ? 0 : 1;
}

function describeProfile(profile: ChainProfile): Record<string, unknown> {
  return {
    caip2: profile.caip2,
    chainId: profile.chainId,
    mode: profile.mode,
    broadcast: profile.broadcast,
    finality: profile.finality,
    evmTarget: profile.evmTarget,
    evidenceDate: profile.evidenceDate,
  };
}

/** One JSON-RPC read. A failure is reported, never retried elsewhere. */
async function rpc(endpoint: string, method: string, params: readonly unknown[]): Promise<ProbeOutcome> {
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      // No redirects: a redirected RPC request is a different endpoint than the
      // one the profile allows.
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok) {
      return { method, params, ok: false, error: { code: response.status, message: `HTTP ${String(response.status)}` } };
    }
    const body = (await response.json()) as { result?: unknown; error?: { code?: number; message?: string } };
    if (body.error) {
      return {
        method,
        params,
        ok: false,
        error: { code: body.error.code ?? -1, message: String(body.error.message ?? "rpc error").slice(0, 240) },
      };
    }
    return { method, params, ok: true, result: body.result };
  } catch (error) {
    return {
      method,
      params,
      ok: false,
      error: { code: -1, message: error instanceof Error ? error.message.slice(0, 240) : "request failed" },
    };
  }
}

function blockNumberOf(block: unknown): bigint | undefined {
  if (typeof block !== "object" || block === null) return undefined;
  const number = (block as { number?: unknown }).number;
  return typeof number === "string" ? BigInt(number) : undefined;
}

// Verify that profiles exist before probing, so a configuration mistake fails here.
requireChainProfile("eip155:943");
requireChainProfile("eip155:369");

process.exitCode = await main(process.argv.slice(2));
