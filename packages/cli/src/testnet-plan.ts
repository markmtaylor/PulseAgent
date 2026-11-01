import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { digestOf, requireChainProfile } from "@pulseagent/core";

/**
 * `npm run demo:testnet:plan`
 *
 * Writes a preparation checklist for the public-test execution that M1b would
 * require, and does nothing else. No key is loaded, no account is created, no
 * transaction is built or signed, and no network write occurs.
 *
 * It is a checklist rather than an approval-ready plan, and it says so in its own
 * machine-readable status and in its exit code: an incomplete document that
 * presents itself as a plan invites someone to approve it. Several values cannot
 * be filled in by this tool and must come from an operator through a channel no
 * model can reach:
 *
 * - which test asset on chain 943 is approved, since none is
 * - the public addresses of the payer, payee and gas sponsor
 * - the maximum spend and gas the operator authorizes
 * - the approval record itself
 *
 * Printing placeholders for those is the honest output. Filling them in with
 * invented values would turn a gate into a formality.
 */

interface PlanInput {
  readonly payerAddress?: string | undefined;
  readonly payeeAddress?: string | undefined;
  readonly gasSponsorAddress?: string | undefined;
  readonly assetAddress?: string | undefined;
  readonly amountAtomic?: string | undefined;
  readonly maxGasWei?: string | undefined;
}

const PLACEHOLDER = "OPERATOR_MUST_SUPPLY";

async function main(argv: readonly string[]): Promise<number> {
  const profile = requireChainProfile("eip155:943");
  const parsed = parseArgs(argv);
  if ("error" in parsed) {
    process.stderr.write(
      `${parsed.error}\n\nUsage: npm run demo:testnet:plan -- [--payer 0x..] [--payee 0x..]\n` +
        "       [--gas-sponsor 0x..] [--asset 0x..] [--amount <atomic>] [--max-gas-wei <wei>]\n" +
        "       [--out <dir>]\n",
    );
    return 2;
  }
  const input = parsed;
  const outDirIndex = argv.indexOf("--out");
  const outDir = path.resolve(
    outDirIndex === -1 ? path.join(process.cwd(), ".runtime", "evidence") : argv[outDirIndex + 1] ?? ".",
  );

  const unresolved: string[] = [];
  const value = (name: string, supplied: string | undefined): string => {
    if (supplied === undefined || supplied === "") {
      unresolved.push(name);
      return PLACEHOLDER;
    }
    return supplied;
  };

  const steps = [
    {
      step: 1,
      action: "confirm the capability probe is current",
      command: "npm run verify:pulse",
      sideEffects: "none (read-only)",
      note: "Re-check the chain id and the MCOPY/TSTORE result before relying on either.",
    },
    {
      step: 2,
      action: "approve a test asset",
      sideEffects: "none; this is a human decision",
      asset: value("assetAddress", input.assetAddress),
      note:
        "No test asset on chain 943 is approved. An EIP-3009 token must be verified for its domain, " +
        "its authorization semantics and its nonce handling before it can be named here. It must be " +
        "described as a test token, never as a redeemable stablecoin.",
    },
    {
      step: 3,
      action: "provision addresses",
      payer: value("payerAddress", input.payerAddress),
      payee: value("payeeAddress", input.payeeAddress),
      gasSponsor: value("gasSponsorAddress", input.gasSponsorAddress),
      sideEffects: "none here; keys are generated inside the signer and sponsor processes",
      note: "This tool never sees or requests a private key. Only public addresses belong in a plan.",
    },
    {
      step: 4,
      action: "fund the gas sponsor with tPLS from the official faucet",
      faucet: "https://faucet.v4.testnet.pulsechain.com/",
      sideEffects: "a human funds an address; no automation here",
      note: "Faucet availability and behavior have not been demonstrated by this project.",
    },
    {
      step: 5,
      action: "record the operator approval",
      maximumSpendAtomic: value("amountAtomic", input.amountAtomic),
      maximumGasWei: value("maxGasWei", input.maxGasWei),
      sideEffects: "none",
      note:
        "The approval must bind this exact plan digest, the spending and gas ceilings and an expiry. " +
        "This build has no verifier for such a record, which is why step 6 cannot run.",
    },
    {
      step: 6,
      action: "execute one payment on chain 943",
      status: "NOT IMPLEMENTED",
      sideEffects: "none; the command fails explicitly",
      note:
        "There is no public broadcast path in this build. The chain profile for 943 declares " +
        "operator approval as required and not implemented, so every signing and broadcast entry point " +
        "refuses before it reaches a network. It does not fall back to local mode.",
    },
  ];

  const plan = {
    generatedAt: new Date().toISOString(),
    milestone: "M1b (public test)",
    // Machine-readable, so a caller does not have to parse prose to find out
    // whether this document is complete.
    status: unresolved.length === 0 ? "prepared_unsigned" : "not_ready",
    approvalReady: false,
    unresolvedCount: unresolved.length,
    network: {
      caip2: profile.caip2,
      chainId: profile.chainId,
      displayName: profile.displayName,
      allowedRpcOrigins: profile.allowedRpcOrigins,
      finality: profile.finality,
      broadcast: profile.broadcast,
      nativeGasCurrency: profile.nativeSymbol,
    },
    scheme: {
      protocol: "x402 v2",
      scheme: "exact",
      assetTransferMethod: "eip3009",
      note:
        "Permit2 is not a candidate on this chain: the canonical x402 exact Permit2 proxy's runtime " +
        "code contains MCOPY, which 943 rejects, and a read-only call to its settlement path fails " +
        "with invalid opcode. Etching a different proxy at the canonical address would not be network " +
        "parity and is not done.",
    },
    steps,
    unresolved,
    sideEffectsPerformedByThisCommand: "none",
    signingPerformedByThisCommand: "none",
  };

  const planDigest = digestOf(plan);
  const document = { ...plan, planDigest };

  await mkdir(outDir, { recursive: true });
  const file = path.join(outDir, `testnet-plan-${document.generatedAt.replaceAll(/[:.]/g, "-")}.json`);
  await writeFile(file, `${JSON.stringify(document, null, 2)}\n`, "utf8");

  process.stdout.write(
    `Public-test preparation checklist for ${profile.caip2} (${profile.displayName})\n` +
      `status: ${document.status}\n\n`,
  );
  for (const step of steps) {
    process.stdout.write(`  ${String(step.step)}. ${step.action}\n`);
    process.stdout.write(`     side effects: ${step.sideEffects}\n`);
  }
  process.stdout.write(`\n  plan digest: ${planDigest}\n  written to:  ${file}\n`);
  process.stdout.write(
    `\n${String(unresolved.length)} value(s) still require an operator: ${
      unresolved.length === 0 ? "none" : unresolved.join(", ")
    }\n` +
      "No transaction was built, signed or sent. Public execution is not implemented in this build and\n" +
      "will fail explicitly rather than running against the local chain instead.\n" +
      (unresolved.length === 0
        ? "Every value is supplied, and this is still only a checklist: it is not an approval, and\n" +
          "nothing in this build can act on it. Approval is a human decision recorded outside any\n" +
          "model's reach.\n"
        : "This checklist is incomplete and is not approval-ready. Exiting nonzero so no automation\n" +
          "treats placeholders as a plan, and nothing here asks for approval of them.\n"),
  );
  // Nonzero while values are missing: CI asserts this, which is what keeps an
  // incomplete checklist from being mistaken for a prepared plan.
  return unresolved.length === 0 ? 0 : 3;
}

const ADDRESS_FLAGS = { "--payer": "payerAddress", "--payee": "payeeAddress", "--gas-sponsor": "gasSponsorAddress", "--asset": "assetAddress" } as const;
const AMOUNT_FLAGS = { "--amount": "amountAtomic", "--max-gas-wei": "maxGasWei" } as const;

/**
 * Parses and validates the plan's inputs.
 *
 * Values are checked here rather than written into the plan as given. A plan
 * that records a malformed address or a fractional amount looks complete and is
 * not, and an operator reading it would have no way to tell.
 */
function parseArgs(argv: readonly string[]): PlanInput | { readonly error: string } {
  const input: Record<string, string> = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === undefined || flag === "--out") {
      index += flag === "--out" ? 1 : 0;
      continue;
    }
    if (!flag.startsWith("--")) continue;

    const addressKey = (ADDRESS_FLAGS as Record<string, string | undefined>)[flag];
    const amountKey = (AMOUNT_FLAGS as Record<string, string | undefined>)[flag];
    if (addressKey === undefined && amountKey === undefined) {
      return { error: `unrecognized option ${flag}` };
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) return { error: `${flag} needs a value` };
    index += 1;

    if (addressKey !== undefined) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
        return { error: `${flag} must be a 0x-prefixed 20-byte address` };
      }
      input[addressKey] = value;
      continue;
    }
    if (!/^(0|[1-9][0-9]{0,77})$/.test(value)) {
      return { error: `${flag} must be a base-10 integer amount in atomic units or wei` };
    }
    input[amountKey as string] = value;
  }
  return input as PlanInput;
}

process.exitCode = await main(process.argv.slice(2));
