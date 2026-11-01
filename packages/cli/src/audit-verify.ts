import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  readEventsFile,
  verifyAuditEvents,
  verifyLinkedAuditLogs,
  type AuditEvent,
  type AuditFinding,
} from "@pulseagent/core";

/**
 * `npm run audit:verify -- <args>`
 *
 * Two modes:
 *
 * - `--manifest <file>`: acceptance. Reads a demo manifest, verifies every log it
 *   names against the terminal hash recorded there, and requires the payment's
 *   whole lifecycle to be present and terminal across those logs. This is the
 *   mode that can say a run is acceptable.
 * - one or more log files: structural check of each chain on its own. Useful, and
 *   explicitly not acceptance: a single per-process log holds part of a lifecycle
 *   by design, so a pass here says the records are consistent, not that a payment
 *   completed.
 *
 * What verification can and cannot establish is printed either way. Hash
 * chaining detects edits to earlier records; it cannot detect a log rebuilt from
 * scratch or one whose tail was removed, which is why a terminal hash recorded
 * elsewhere matters.
 */

interface ManifestShape {
  intentId?: unknown;
  quoteId?: unknown;
  requestDigest?: unknown;
  resultDigest?: unknown;
  settlement?: {
    txHash?: unknown;
    amountAtomic?: unknown;
    authorizationNonce?: unknown;
    asset?: unknown;
    to?: unknown;
  };
  audit?: {
    platform?: { file?: unknown; terminalHash?: unknown };
    signer?: { file?: unknown; terminalHash?: unknown };
  };
}

async function main(argv: readonly string[]): Promise<number> {
  const args = [...argv];
  if (args.length === 0 || args.includes("--help")) {
    process.stdout.write(usage());
    return args.length === 0 ? 2 : 0;
  }

  const manifestIndex = args.indexOf("--manifest");
  if (manifestIndex !== -1) {
    const manifestPath = args[manifestIndex + 1];
    if (manifestPath === undefined) {
      process.stderr.write("--manifest needs a file path\n");
      return 2;
    }
    return verifyFromManifest(manifestPath);
  }

  // Parsed by walking the arguments rather than by index arithmetic: deriving a
  // value's position from `indexOf` returning -1 silently swallowed the first
  // positional argument, so a single log file reported "no files given".
  let requireComplete = false;
  let expectedTerminalHash: string | undefined;
  let expectedIntentId: string | undefined;
  const files: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;
    if (arg === "--require-complete") {
      requireComplete = true;
      continue;
    }
    if (arg === "--terminal-hash" || arg === "--intent") {
      const value = args[index + 1];
      if (value === undefined || value.startsWith("--")) {
        process.stderr.write(`${arg} needs a value\n`);
        return 2;
      }
      if (arg === "--terminal-hash") expectedTerminalHash = value;
      else expectedIntentId = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--")) {
      process.stderr.write(`unrecognized option ${arg}\n${usage()}`);
      return 2;
    }
    files.push(arg);
  }
  if (files.length === 0) {
    process.stderr.write(`no audit log files were given\n${usage()}`);
    return 2;
  }

  let worst = 0;
  for (const file of files) {
    const events = await readEventsFile(file);
    const report = verifyAuditEvents(events, {
      ...(expectedTerminalHash === undefined ? {} : { expectedTerminalHash }),
      ...(expectedIntentId === undefined ? {} : { expectedIntentIds: [expectedIntentId] }),
      ...(requireComplete ? { requireCompleteLifecycle: true, expectedTerminalState: "DELIVERED" as const } : {}),
    });
    process.stdout.write(`\n${file}\n`);
    process.stdout.write(`  records           ${String(report.events)}\n`);
    process.stdout.write(`  terminal hash     ${report.terminalHash ?? "(empty log)"}\n`);
    process.stdout.write(`  chain and order   ${report.ok ? "consistent" : "FAILED"}\n`);
    for (const intent of report.intents) {
      process.stdout.write(
        `  intent ${intent.intentId}: ${intent.states.join(" -> ") || "(no state records)"}` +
          `${intent.terminalState === undefined ? " (not terminal in this log)" : ""}\n`,
      );
    }
    printFindings(report.findings);
    if (!report.ok) worst = 1;
  }

  process.stdout.write(
    `\n${caveat()}\n` +
      "This was a per-log structural check, not acceptance. Use --manifest to require a complete,\n" +
      "terminal lifecycle across the linked logs of one payment.\n",
  );
  return worst;
}

async function verifyFromManifest(manifestPath: string): Promise<number> {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ManifestShape;
  const base = path.dirname(path.resolve(manifestPath));
  const root = path.resolve(base, "..", "..", "..");

  const intentId = typeof manifest.intentId === "string" ? manifest.intentId : undefined;
  if (intentId === undefined) {
    process.stderr.write("the manifest does not name an intent id\n");
    return 2;
  }

  const logs: { label: string; events: AuditEvent[]; expectedTerminalHash?: string }[] = [];
  for (const label of ["platform", "signer"] as const) {
    const entry = manifest.audit?.[label];
    if (entry === undefined) continue;
    const file = typeof entry.file === "string" ? entry.file : undefined;
    if (file === undefined) continue;
    const resolved = (await exists(path.resolve(root, file)))
      ? path.resolve(root, file)
      : path.resolve(base, path.basename(file));
    logs.push({
      label,
      events: await readEventsFile(resolved),
      ...(typeof entry.terminalHash === "string" ? { expectedTerminalHash: entry.terminalHash } : {}),
    });
    process.stdout.write(`${label.padEnd(9)} ${resolved}\n`);
  }
  if (logs.length === 0) {
    process.stderr.write("the manifest names no audit logs\n");
    return 2;
  }

  // Both ids: a payment is recorded under the buyer's intent id and under the id
  // the seller derives from the authorization.
  const correlationId = findCorrelationId(logs, intentId);
  const ids = new Set(correlationId === undefined ? [intentId] : [intentId, correlationId]);
  const linkage = verifyLinkedAuditLogs(logs, {
    intentIds: [...ids],
    requiredKinds: [
      "intent.created",
      "signer.reservation.held",
      "signer.authorization.signed",
      "payment.authorized",
      // Either the submission was observed, or the ambiguity that replaced it
      // was recorded. A payment whose response was lost has the latter, and
      // writing an unobserved submission to satisfy a checklist would be a lie.
      ["payment.submitted", "payment.unresolved", "payment.pending"],
      "settlement.verified",
      "result.delivered",
      ["result.verified", "result.recovered"],
    ],
    expectedTerminalState: "DELIVERED",
  });

  process.stdout.write(`\nintent      ${intentId}\n`);
  process.stdout.write(`correlation ${correlationId ?? "(not found in these logs)"}\n\n`);
  for (const entry of linkage.perLog) {
    process.stdout.write(
      `${entry.label.padEnd(9)} ${String(entry.report.events)} records, chain ` +
        `${entry.report.ok ? "consistent" : "FAILED"}, terminal hash ${entry.report.terminalHash ?? "none"}\n`,
    );
  }
  // The manifest's own claims are checked against the logs. A manifest is a
  // summary written by the same run, so an unchecked one adds nothing: if it
  // says a payment settled for an amount the logs never record, that is a
  // finding, not a formality.
  const claims: { field: string; expected: string | undefined; found: string | undefined }[] = [
    { field: "quoteId", expected: asString(manifest.quoteId), found: payloadValue(logs, ids, "quoteId") },
    {
      field: "requestDigest",
      expected: asString(manifest.requestDigest),
      found: payloadValue(logs, ids, "requestDigest"),
    },
    {
      field: "resultDigest",
      expected: asString(manifest.resultDigest),
      found: payloadValue(logs, ids, "resultDigest"),
    },
    {
      field: "settlement.txHash",
      expected: asString(manifest.settlement?.txHash),
      found: payloadValue(logs, ids, "transactionHash"),
    },
    {
      field: "settlement.amountAtomic",
      expected: asString(manifest.settlement?.amountAtomic),
      found: payloadValue(logs, ids, "amountAtomic"),
    },
    {
      field: "settlement.authorizationNonce",
      expected: asString(manifest.settlement?.authorizationNonce),
      found: payloadValue(logs, ids, "authorizationNonce"),
    },
  ];
  const claimFindings: AuditFinding[] = [];
  process.stdout.write("\nmanifest claims checked against the logs:\n");
  for (const claim of claims) {
    if (claim.expected === undefined) {
      process.stdout.write(`  absent   ${claim.field} (the manifest does not state it)\n`);
      claimFindings.push({
        severity: "error",
        code: "manifest_claim_absent",
        message: `the manifest does not state ${claim.field}, so it cannot be checked`,
      });
      continue;
    }
    const agrees =
      claim.found !== undefined && claim.found.toLowerCase() === claim.expected.toLowerCase();
    process.stdout.write(`  ${agrees ? "agrees  " : "DISAGREE"} ${claim.field}\n`);
    if (!agrees) {
      claimFindings.push({
        severity: "error",
        code: "manifest_claim_unsupported",
        message:
          `the manifest states ${claim.field} = ${claim.expected} but the logs record ` +
          `${claim.found ?? "nothing"}`,
      });
    }
  }

  process.stdout.write("\nrequired lifecycle records:\n");
  for (const kind of linkage.kinds) {
    process.stdout.write(`  ${kind.label === undefined ? "MISSING " : "found   "} ${kind.kind}${kind.label === undefined ? "" : ` (${kind.label})`}\n`);
  }
  printFindings([...linkage.findings, ...claimFindings]);
  const ok = linkage.ok && claimFindings.length === 0;

  process.stdout.write(
    `\n${caveat()}\n` +
      (ok
        ? "Acceptance check passed: the payment's whole lifecycle is present, ordered within each log,\nand terminal across the linked logs.\n"
        : "Acceptance check FAILED. The lifecycle above is incomplete or inconsistent.\n"),
  );
  return ok ? 0 : 1;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** The single value the logs record for a payload field under these ids. */
function payloadValue(
  logs: readonly { events: readonly AuditEvent[] }[],
  ids: ReadonlySet<string>,
  field: string,
): string | undefined {
  for (const log of logs) {
    for (const event of log.events) {
      if (event.intentId === undefined || !ids.has(event.intentId)) continue;
      const value = (event.payload as Record<string, unknown>)[field];
      if (typeof value === "string" && value !== "") return value;
    }
  }
  return undefined;
}

/** The seller-side id for this payment, read from the buyer's own records. */
function findCorrelationId(
  logs: readonly { events: readonly AuditEvent[] }[],
  intentId: string,
): string | undefined {
  for (const log of logs) {
    for (const event of log.events) {
      if (event.intentId !== intentId) continue;
      const candidate = (event.payload as { correlationId?: unknown }).correlationId;
      if (typeof candidate === "string") return candidate;
    }
  }
  return undefined;
}

function printFindings(findings: readonly AuditFinding[]): void {
  for (const finding of findings) {
    process.stdout.write(
      `  ${finding.severity === "error" ? "ERROR  " : "warning"} ${finding.code}: ${finding.message}\n`,
    );
  }
}

function caveat(): string {
  return (
    "A locally rewritable log is not independently tamper-proof. Hash chaining detects an edited or\n" +
    "removed interior record; it cannot detect a log rebuilt wholesale, and it cannot detect a removed\n" +
    "tail unless the terminal hash was recorded somewhere else. Independent anchoring and write-once\n" +
    "retention are separate controls this build does not provide."
  );
}

function usage(): string {
  return (
    "Usage:\n" +
    "  npm run audit:verify -- --manifest <manifest.json>\n" +
    "      Acceptance: verify every log the manifest names and require the payment's complete,\n" +
    "      terminal lifecycle across them.\n\n" +
    "  npm run audit:verify -- <log.jsonl> [more.jsonl ...] [--terminal-hash <hash>]\n" +
    "                          [--intent <id>] [--require-complete]\n" +
    "      Structural check of each log on its own. Not acceptance.\n"
  );
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await readFile(filePath);
    return true;
  } catch {
    return false;
  }
}

process.exitCode = await main(process.argv.slice(2));
