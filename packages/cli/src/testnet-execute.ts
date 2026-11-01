import { PublicBroadcastNotImplementedError, assertBroadcastAllowed, requireChainProfile } from "@pulseagent/core";

/**
 * `npm run demo:testnet:execute`
 *
 * Public execution is not implemented. This command exists so that asking for it
 * fails loudly and specifically, which is the whole point: the dangerous failure
 * mode is a public command that quietly runs against the local chain and reports
 * success, producing a transaction hash from chain 31337 that reads like
 * evidence about chain 943.
 *
 * So there is no fallback here, no `--local` flag, and no environment variable
 * that changes the outcome.
 */
function main(): number {
  const profile = requireChainProfile("eip155:943");

  process.stderr.write(
    [
      `Public execution on ${profile.caip2} (${profile.displayName}) is not implemented.`,
      "",
      "What is missing, specifically:",
      "  - a verifier for an operator approval record bound to a plan digest, ceilings and an expiry",
      "  - an approved test asset on this chain; none has been verified",
      "  - a funded gas sponsor address, provisioned outside any model's reach",
      "  - finalized-settlement handling proven against this chain's finality lag",
      "",
      "This command does not fall back to the local chain. Run `npm run demo:local` if a local",
      "rehearsal is what you want, and `npm run demo:testnet:plan` for the unsigned plan.",
      "",
    ].join("\n"),
  );

  try {
    // Reached only to prove the gate is the code path, not this message.
    assertBroadcastAllowed(profile);
  } catch (error) {
    if (error instanceof PublicBroadcastNotImplementedError) {
      process.stderr.write(`Refused by the chain profile: ${error.message}\n`);
      return 3;
    }
    process.stderr.write(`Refused by the chain profile: ${error instanceof Error ? error.message : "unknown"}\n`);
    return 3;
  }

  // Unreachable while 943 declares operator approval required and not implemented.
  process.stderr.write(
    "The chain profile unexpectedly permitted a broadcast, and no execution path exists. Refusing.\n",
  );
  return 4;
}

process.exitCode = main();
