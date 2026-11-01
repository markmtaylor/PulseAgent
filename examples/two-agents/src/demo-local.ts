import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  AuditLog,
  DurableStore,
  digestOf,
  verifyLinkedAuditLogs,
  type AuditEvent,
} from "@pulseagent/core";
import { authorizationConsumed, repositoryRoot, tokenBalance } from "@pulseagent/localchain";
import { startLocalStack, type LocalStack } from "./harness.js";

/**
 * M1a: the local rehearsal.
 *
 * Buyer agent A pays seller agent B for one deterministic SHA-256 digest, on a
 * disposable local chain, through the upstream x402 v2 exact scheme using
 * EIP-3009. Every claim it makes is checked against the chain or the durable
 * record rather than against an HTTP status.
 *
 * **This is not M1.** It is a local rehearsal on chain 31337 with a valueless
 * fixture token. It does not demonstrate anything about PulseChain 943, about a
 * token with value, or about production custody. M1b — a finalized transaction
 * on 943 with an operator-approved spending plan — is a separate gate that this
 * build has no code path for.
 */

interface Check {
  readonly name: string;
  readonly passed: boolean;
  readonly detail: string;
}

async function main(): Promise<number> {
  const startedAt = new Date();
  const runtimeDir = path.join(
    repositoryRoot(),
    ".runtime",
    `demo-${startedAt.toISOString().replaceAll(/[:.]/g, "-")}`,
  );
  const evidenceDir = path.join(runtimeDir, "evidence");
  await mkdir(evidenceDir, { recursive: true });

  const checks: Check[] = [];
  const record = (name: string, passed: boolean, detail: string): void => {
    checks.push({ name, passed, detail });
    process.stdout.write(`${passed ? "  pass" : "  FAIL"}  ${name}${detail === "" ? "" : ` — ${detail}`}\n`);
  };

  let stack: LocalStack | undefined;
  try {
    process.stdout.write("Starting the local stack (disposable chain, signer, facilitator, seller)...\n");
    stack = await startLocalStack({ runtimeDir, priceAtomic: "1500", payerFundingAtomic: "1000000" });
    const price = BigInt("1500");

    process.stdout.write(
      [
        `  chain            ${stack.chain.origin} (chain id ${String(stack.chain.chainId)}, ${stack.chain.hardfork})`,
        `  test token       ${stack.asset.address} ${stack.asset.symbol} — VALUELESS TEST FIXTURE`,
        `  token runtime    ${stack.token.token.onChainCodeDigest} (eth_getCode bytes)`,
        `  compiler         ${stack.token.token.solcVersion} target ${stack.token.token.evmVersion}`,
        `  payer (signer)   ${stack.payerAddress}`,
        `  payee (seller)   ${stack.payeeAddress}`,
        `  facilitator gas  ${stack.facilitatorAddress}`,
        `  seller           ${stack.sellerOrigin}`,
        "",
        "Opcode boundary, using the same probes as the PulseChain evidence:",
      ].join("\n") + "\n",
    );

    // The local chain must reject exactly what 943 and 369 reject. Rehearsing on
    // a Cancun chain would hide the class of failure that blocked Permit2.
    for (const [name, data, mustSucceed] of [
      ["legacy control", "0x60006000f3", true],
      ["PUSH0 (Shanghai)", "0x5f5ff3", true],
      ["MCOPY (Cancun)", "0x6000600060005e60006000f3", false],
      ["TSTORE (Cancun)", "0x600060005d60006000f3", false],
    ] as const) {
      let accepted = true;
      try {
        await stack.chain.request("eth_call", [{ data, gas: "0x186a0" }, "latest"]);
      } catch {
        accepted = false;
      }
      record(
        `opcode ${name} ${mustSucceed ? "accepted" : "rejected"}`,
        accepted === mustSucceed,
        accepted ? "accepted" : "rejected as unsupported",
      );
    }

    process.stdout.write("\nHappy path:\n");
    const payerBefore = await tokenBalance(stack.chain, stack.token, stack.payerAddress);
    const payeeBefore = await tokenBalance(stack.chain, stack.token, stack.payeeAddress);

    const serviceInput = "PulseAgent milestone 1a local rehearsal";
    const { quote, service } = await stack.client.requestQuote({
      serviceOrigin: stack.sellerOrigin,
      input: serviceInput,
    });
    record(
      "seller quoted an exact atomic amount",
      quote.amount === price.toString(10) && quote.asset.toLowerCase() === stack.asset.address.toLowerCase(),
      `${quote.amount} atomic units of ${stack.asset.symbol}`,
    );
    record("service is labelled deterministic", service.deterministic, service.name);

    const idempotencyKey = `idem_${digestOf({ quoteId: quote.quoteId }).replace("sha256:", "").slice(0, 24)}`;
    const payment = await stack.client.requestPayment({
      quote,
      input: serviceInput,
      idempotencyKey,
      serviceName: service.name,
    });

    record(
      "settlement verified as final and canonical",
      payment.settlement.finalityRule === "confirmations" && payment.state === "DELIVERED",
      `tx ${payment.settlement.txHash} in block ${payment.settlement.blockNumber}`,
    );
    record(
      "settlement is bound to the signed authorization nonce",
      payment.settlement.authorizationNonce.length === 66,
      payment.settlement.authorizationNonce,
    );

    const expectedDigest = await sha256Of(serviceInput);
    record(
      "delivered result is the digest the buyer can recompute",
      payment.result.sha256 === expectedDigest,
      payment.result.sha256,
    );

    const payerAfter = await tokenBalance(stack.chain, stack.token, stack.payerAddress);
    const payeeAfter = await tokenBalance(stack.chain, stack.token, stack.payeeAddress);
    record(
      "payer balance decreased by exactly the price",
      payerBefore - payerAfter === price,
      `${payerBefore.toString(10)} to ${payerAfter.toString(10)}`,
    );
    record(
      "payee balance increased by exactly the price",
      payeeAfter - payeeBefore === price,
      `${payeeBefore.toString(10)} to ${payeeAfter.toString(10)}`,
    );
    record(
      "authorization nonce is consumed on chain",
      await authorizationConsumed(
        stack.chain,
        stack.token,
        stack.payerAddress,
        payment.settlement.authorizationNonce as `0x${string}`,
      ),
      payment.settlement.authorizationNonce,
    );

    process.stdout.write("\nReplay and concurrency:\n");
    const replay = await stack.client.requestPayment({
      quote,
      input: serviceInput,
      idempotencyKey,
      serviceName: service.name,
    });
    record(
      "replaying the same request returns the same result",
      replay.resultDigest === payment.resultDigest,
      replay.replayed ? "seller reported a replay" : "same digest",
    );
    record(
      "replaying the same request returns the same receipt",
      replay.settlement.txHash === payment.settlement.txHash,
      replay.settlement.txHash,
    );

    const concurrent = await Promise.allSettled([
      stack.client.requestPayment({ quote, input: serviceInput, idempotencyKey, serviceName: service.name }),
      stack.client.requestPayment({ quote, input: serviceInput, idempotencyKey, serviceName: service.name }),
    ]);
    // Both must succeed, and both must name the original settlement. A check that
    // passed when every attempt failed would report "no double spend" for a
    // system that simply stopped working.
    const allSucceeded = concurrent.every((outcome) => outcome.status === "fulfilled");
    const concurrentDigests = new Set(
      concurrent.flatMap((outcome) => (outcome.status === "fulfilled" ? [outcome.value.settlement.txHash] : [])),
    );
    record(
      "concurrent duplicates both succeed against one settlement",
      allSucceeded && concurrentDigests.size === 1 && concurrentDigests.has(payment.settlement.txHash),
      allSucceeded
        ? `${String(concurrentDigests.size)} distinct settlement hashes`
        : `an attempt failed: ${concurrent
            .flatMap((outcome) => (outcome.status === "rejected" ? [String(outcome.reason).slice(0, 80)] : []))
            .join("; ")}`,
    );

    const afterReplays = await tokenBalance(stack.chain, stack.token, stack.payeeAddress);
    record(
      "replays and duplicates charged nothing further",
      afterReplays === payeeAfter,
      `payee still holds ${afterReplays.toString(10)}`,
    );

    let changedBodyRefused = false;
    try {
      await stack.client.requestPayment({
        quote,
        input: `${serviceInput} (different)`,
        idempotencyKey,
        serviceName: service.name,
      });
    } catch {
      changedBodyRefused = true;
    }
    record(
      "a changed body under the same intent ids is refused, not answered from cache",
      changedBodyRefused,
      "the intent stays bound to the body it paid for",
    );

    const forgedQuote = {
      ...quote,
      requestDigest: await recomputeRequestDigest(service.name, quote.resourcePath, `${serviceInput} (different)`),
    };
    let forgedRefused = false;
    try {
      await stack.client.requestPayment({
        quote: forgedQuote,
        input: `${serviceInput} (different)`,
        idempotencyKey,
        serviceName: service.name,
      });
    } catch {
      forgedRefused = true;
    }
    record(
      "a changed body with a recomputed quote digest is still refused",
      forgedRefused,
      "immutable terms are compared before any cached result is returned",
    );

    process.stdout.write("\nNegative cases:\n");
    const tampered = await fetch(`${stack.sellerOrigin}/digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ quoteId: quote.quoteId, input: `${serviceInput} (changed)` }),
    });
    record(
      "a changed body with the same quote id is refused",
      tampered.status === 409,
      `HTTP ${String(tampered.status)}`,
    );

    const unknownQuote = await fetch(`${stack.sellerOrigin}/digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ quoteId: "quote_0000000000000000", input: serviceInput }),
    });
    record("an unknown quote id is refused", unknownQuote.status === 404, `HTTP ${String(unknownQuote.status)}`);

    process.stdout.write("\nAudit trail:\n");
    const platformExport = path.join(evidenceDir, "audit-platform.jsonl");
    const signerExport = path.join(evidenceDir, "audit-signer.jsonl");
    const platform = await stack.client.exportAudit(platformExport);

    const signerStore = DurableStore.open(stack.signerDatabasePath);
    const signerAudit = new AuditLog(signerStore);
    const signerEvents = signerAudit.read();
    const signerManifest = await signerAudit.exportToFile(signerExport);
    signerStore.close();

    const platformEvents = stack.client.readAudit();
    const linkage = verifyLinkedAuditLogs(
      [
        { label: "platform", events: platformEvents, expectedTerminalHash: platform.terminalHash },
        { label: "signer", events: signerEvents, expectedTerminalHash: signerManifest.terminalHash },
      ],
      {
        // Both ids: the buyer's intent and the id the seller derives from the
        // authorization. One lifecycle, two id spaces.
        intentIds: [payment.intentId, payment.correlationId],
        requiredKinds: [
          "intent.created",
          "signer.reservation.held",
          "signer.authorization.signed",
          "payment.authorized",
          // Either the submission was observed, or the ambiguity that replaced
          // it was recorded. A recovered payment legitimately has the latter.
          ["payment.submitted", "payment.unresolved", "payment.pending"],
          "settlement.verified",
          "result.delivered",
          ["result.verified", "result.recovered"],
        ],
        expectedTerminalState: "DELIVERED",
      },
    );
    record(
      "every lifecycle record is present and linked across both logs",
      linkage.ok,
      linkage.ok
        ? `${String(platformEvents.length)} platform and ${String(signerEvents.length)} signer records`
        : linkage.findings.map((finding) => finding.code).join(", "),
    );
    record(
      "no audit record carries a raw signature",
      !containsSignatureMaterial([...platformEvents, ...signerEvents]),
      "signatures appear only as digests",
    );

    const manifest = {
      milestone: "M1a",
      claim: "local rehearsal only",
      notM1: "M1 requires a finalized transaction on PulseChain 943; no public-chain transaction exists",
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      chain: {
        caip2: "eip155:31337",
        chainId: stack.chain.chainId,
        hardfork: stack.chain.hardfork,
        rpcOrigin: stack.chain.origin,
        disposable: true,
      },
      asset: {
        address: stack.asset.address,
        symbol: stack.asset.symbol,
        decimals: stack.asset.decimals,
        valuelessTestFixture: true,
        notAStablecoin: true,
        onChainCodeDigest: stack.token.token.onChainCodeDigest,
        compiledBytecodeDigest: stack.token.token.compiledBytecodeDigest,
        solcVersion: stack.token.token.solcVersion,
        evmVersion: stack.token.token.evmVersion,
      },
      intentId: payment.intentId,
      quoteId: quote.quoteId,
      requestDigest: quote.requestDigest,
      resultDigest: payment.resultDigest,
      policyRevision: stack.policy.policyRevision,
      settlement: payment.settlement,
      balances: {
        payerBefore: payerBefore.toString(10),
        payerAfter: payerAfter.toString(10),
        payeeBefore: payeeBefore.toString(10),
        payeeAfter: payeeAfter.toString(10),
      },
      audit: {
        platform: { file: path.relative(repositoryRoot(), platformExport), ...platform, filePath: undefined },
        signer: { file: path.relative(repositoryRoot(), signerExport), ...signerManifest, filePath: undefined },
        note: "A locally rewritable log is not independently tamper-proof. Pin these terminal hashes elsewhere.",
      },
      checks,
    };
    const manifestPath = path.join(evidenceDir, "manifest.json");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

    const failed = checks.filter((check) => !check.passed);
    process.stdout.write(
      [
        "",
        `Evidence: ${path.relative(repositoryRoot(), evidenceDir)}`,
        `  manifest        ${path.relative(repositoryRoot(), manifestPath)}`,
        `  platform audit  ${path.relative(repositoryRoot(), platformExport)} (${String(platform.events)} records)`,
        `  signer audit    ${path.relative(repositoryRoot(), signerExport)} (${String(signerManifest.events)} records)`,
        "",
        `${String(checks.length - failed.length)}/${String(checks.length)} checks passed.`,
        failed.length === 0
          ? "M1a local rehearsal complete. This says nothing about PulseChain 943; M1b remains open."
          : `FAILED: ${failed.map((check) => check.name).join("; ")}`,
        "",
      ].join("\n"),
    );
    return failed.length === 0 ? 0 : 1;
  } catch (error) {
    process.stderr.write(`\nThe demo did not complete: ${error instanceof Error ? error.message : "unknown error"}\n`);
    return 1;
  } finally {
    // Always, so a failed run does not leave a chain and three services behind.
    if (stack) await stack.stop();
  }
}

/** The shared request-digest definition, used to build a deliberately wrong quote. */
async function recomputeRequestDigest(service: string, resourcePath: string, input: string): Promise<string> {
  const { serviceRequestDigest } = await import("@pulseagent/core");
  return serviceRequestDigest({ service, resourcePath, input });
}

/** Independent digest, so the delivered result is checked rather than trusted. */
async function sha256Of(input: string): Promise<string> {
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** True if any record holds hex long enough to be a reusable signature. */
function containsSignatureMaterial(events: readonly AuditEvent[]): boolean {
  return events.some((event) => /0x[0-9a-fA-F]{130,}/.test(JSON.stringify(event)));
}

process.exitCode = await main();
