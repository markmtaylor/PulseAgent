import { execFile } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLog, DurableStore } from "@pulseagent/core";
import { repositoryRoot } from "@pulseagent/localchain";

/**
 * The operator commands, run as commands.
 *
 * Exit codes are the interface here: CI and an operator's shell both act on
 * them, and a command that printed a warning while exiting zero would be
 * reported as success. So each case asserts the code, not only the output.
 */

const run = promisify(execFile);
const CLI = (name: string): string => path.join(repositoryRoot(), "packages/cli/dist", name);

interface Outcome {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

async function cli(script: string, args: readonly string[] = []): Promise<Outcome> {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI(script), ...args], { maxBuffer: 8 * 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return { code: failure.code ?? 1, stdout: failure.stdout ?? "", stderr: failure.stderr ?? "" };
  }
}

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "pa-cli-"));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  dirs.length = 0;
});

/** Builds a complete, valid pair of audit logs plus the manifest naming them. */
async function buildEvidence(dir: string): Promise<{ manifestPath: string; platformPath: string }> {
  const store = DurableStore.open(path.join(dir, "platform.sqlite"));
  const signerStore = DurableStore.open(path.join(dir, "signer.sqlite"));
  const intentId = "int_cli_regression_0001";
  const correlationId = "pay_cli_regression_0001";
  const facts = {
    quoteId: "quote_cli_0001",
    requestDigest: `sha256:${"a".repeat(64)}`,
    authorizationNonce: `0x${"bc".repeat(32)}`,
    amountAtomic: "1500",
    asset: "0x1111111111111111111111111111111111111111",
    payTo: "0x2222222222222222222222222222222222222222",
    payer: "0x3333333333333333333333333333333333333333",
    transactionHash: `0x${"de".repeat(32)}`,
  };
  const resultDigest = `sha256:${"9".repeat(64)}`;

  try {
    const signerLog = new AuditLog(signerStore);
    signerLog.append({
      actor: "signer",
      kind: "signer.reservation.held",
      intentId,
      policyRevision: "rev-1",
      state: "RESERVED",
      payload: { ...facts, authorizationDigest: `sha256:${"f".repeat(64)}`, transactionHash: undefined },
    });
    signerLog.append({
      actor: "signer",
      kind: "signer.authorization.signed",
      intentId,
      policyRevision: "rev-1",
      state: "AUTHORIZED",
      payload: {
        ...facts,
        transactionHash: undefined,
        signatureDigest: `sha256:${"e".repeat(64)}`,
        authorizationDigest: `sha256:${"f".repeat(64)}`,
      },
    });

    const platformLog = new AuditLog(store);
    platformLog.append({
      actor: "buyer",
      kind: "intent.created",
      intentId,
      policyRevision: "rev-1",
      state: "POLICY_APPROVED",
      payload: { quoteId: facts.quoteId, requestDigest: facts.requestDigest, amountAtomic: facts.amountAtomic },
    });
    platformLog.append({
      actor: "buyer",
      kind: "payment.authorized",
      intentId,
      policyRevision: "rev-1",
      state: "AUTHORIZED",
      payload: { ...facts, transactionHash: undefined },
    });
    platformLog.append({
      actor: "buyer",
      kind: "payment.submitted",
      intentId,
      policyRevision: "rev-1",
      state: "SUBMITTED",
      payload: { ...facts, transactionHash: undefined },
    });
    platformLog.append({
      actor: "buyer",
      kind: "settlement.verified",
      intentId,
      policyRevision: "rev-1",
      state: "FINALIZED",
      payload: { ...facts, correlationId },
    });
    platformLog.append({
      actor: "verifier",
      kind: "settlement.verified",
      intentId: correlationId,
      policyRevision: "seller-rev-1",
      state: "FINALIZED",
      payload: { ...facts },
    });
    platformLog.append({
      actor: "seller",
      kind: "result.delivered",
      intentId: correlationId,
      policyRevision: "seller-rev-1",
      state: "DELIVERED",
      payload: { ...facts, resultDigest },
    });
    platformLog.append({
      actor: "buyer",
      kind: "result.verified",
      intentId,
      policyRevision: "rev-1",
      state: "DELIVERED",
      payload: { ...facts, resultDigest },
    });

    const evidenceDir = path.join(dir, "evidence");
    await mkdir(evidenceDir, { recursive: true });
    const platform = await platformLog.exportToFile(path.join(evidenceDir, "audit-platform.jsonl"));
    const signer = await signerLog.exportToFile(path.join(evidenceDir, "audit-signer.jsonl"));

    const manifestPath = path.join(evidenceDir, "manifest.json");
    await writeFile(
      manifestPath,
      `${JSON.stringify(
        {
          milestone: "M1a",
          intentId,
          quoteId: facts.quoteId,
          requestDigest: facts.requestDigest,
          resultDigest,
          settlement: {
            txHash: facts.transactionHash,
            amountAtomic: facts.amountAtomic,
            authorizationNonce: facts.authorizationNonce,
          },
          audit: {
            platform: { file: "audit-platform.jsonl", terminalHash: platform.terminalHash, events: platform.events },
            signer: { file: "audit-signer.jsonl", terminalHash: signer.terminalHash, events: signer.events },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return { manifestPath, platformPath: platform.filePath };
  } finally {
    store.close();
    signerStore.close();
  }
}

describe("audit:verify", () => {
  it("prints usage and exits nonzero with no arguments", async () => {
    const outcome = await cli("audit-verify.js");
    expect(outcome.code).toBe(2);
    expect(`${outcome.stdout}${outcome.stderr}`).toMatch(/Usage/);
  });

  it("accepts a single positional log file", async () => {
    // The defect this covers: deriving a flag's value position from an index of
    // -1 excluded argument zero, so one log file reported "no files given".
    const dir = tempDir();
    const { platformPath } = await buildEvidence(dir);
    const outcome = await cli("audit-verify.js", [platformPath]);
    expect(outcome.code).toBe(0);
    expect(outcome.stdout).toMatch(/chain and order\s+consistent/);
    expect(outcome.stdout).toMatch(/not acceptance/);
  });

  it("warns that a truncated tail is undetectable without an external anchor", async () => {
    const dir = tempDir();
    const { platformPath } = await buildEvidence(dir);
    const outcome = await cli("audit-verify.js", [platformPath]);
    expect(outcome.stdout).toMatch(/no_external_anchor/);
  });

  it("fails against a wrong terminal hash", async () => {
    const dir = tempDir();
    const { platformPath } = await buildEvidence(dir);
    const outcome = await cli("audit-verify.js", [platformPath, "--terminal-hash", `sha256:${"0".repeat(64)}`]);
    expect(outcome.code).toBe(1);
    expect(outcome.stdout).toMatch(/terminal_hash_mismatch/);
  });

  it("rejects an unknown option and a flag with no value", async () => {
    const dir = tempDir();
    const { platformPath } = await buildEvidence(dir);
    expect((await cli("audit-verify.js", [platformPath, "--nope"])).code).toBe(2);
    expect((await cli("audit-verify.js", [platformPath, "--terminal-hash"])).code).toBe(2);
  });

  it("accepts a complete run through its manifest", async () => {
    const dir = tempDir();
    const { manifestPath } = await buildEvidence(dir);
    const outcome = await cli("audit-verify.js", ["--manifest", manifestPath]);
    expect(outcome.code).toBe(0);
    expect(outcome.stdout).toMatch(/Acceptance check passed/);
    expect(outcome.stdout).toMatch(/agrees\s+settlement.txHash/);
    expect(outcome.stdout).toMatch(/found\s+signer.authorization.signed/);
  });

  it("fails when the manifest claims a settlement the logs do not record", async () => {
    // A manifest is a summary written by the same run. An unchecked one adds
    // nothing at all.
    const dir = tempDir();
    const { manifestPath } = await buildEvidence(dir);
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
      settlement: { amountAtomic: string };
    };
    manifest.settlement.amountAtomic = "999999";
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2), "utf8");

    const outcome = await cli("audit-verify.js", ["--manifest", manifestPath]);
    expect(outcome.code).toBe(1);
    expect(outcome.stdout).toMatch(/manifest_claim_unsupported/);
    expect(outcome.stdout).toMatch(/DISAGREE settlement.amountAtomic/);
  });

  it("fails when a log named by the manifest has been tampered with", async () => {
    const dir = tempDir();
    const { manifestPath, platformPath } = await buildEvidence(dir);
    const lines = (await readFile(platformPath, "utf8")).trim().split("\n");
    const first = JSON.parse(lines[0] as string) as { payload: Record<string, unknown> };
    first.payload["quoteId"] = "quote_substituted";
    lines[0] = JSON.stringify(first);
    await writeFile(platformPath, `${lines.join("\n")}\n`, "utf8");

    const outcome = await cli("audit-verify.js", ["--manifest", manifestPath]);
    expect(outcome.code).toBe(1);
    expect(outcome.stdout).toMatch(/event_hash_mismatch|chain_break/);
  });

  it("always states what verification cannot establish", async () => {
    const dir = tempDir();
    const { manifestPath } = await buildEvidence(dir);
    const outcome = await cli("audit-verify.js", ["--manifest", manifestPath]);
    expect(outcome.stdout).toMatch(/not independently tamper-proof/);
    expect(outcome.stdout).toMatch(/cannot detect a log rebuilt wholesale/);
  });
});

describe("demo:testnet:plan", () => {
  it("exits nonzero and reports not_ready while values are unresolved", async () => {
    const dir = tempDir();
    const outcome = await cli("testnet-plan.js", ["--out", dir]);
    expect(outcome.code).toBe(3);
    expect(outcome.stdout).toMatch(/status: not_ready/);
    expect(outcome.stdout).toMatch(/is not approval-ready/);
    expect(outcome.stdout).toMatch(/No transaction was built, signed or sent/);

    const written = (await readdir(dir)).filter((name) => name.startsWith("testnet-plan-"));
    expect(written).toHaveLength(1);
    const plan = JSON.parse(await readFile(path.join(dir, written[0] as string), "utf8")) as {
      status: string;
      approvalReady: boolean;
      unresolved: string[];
      signingPerformedByThisCommand: string;
      planDigest: string;
    };
    expect(plan.status).toBe("not_ready");
    expect(plan.approvalReady).toBe(false);
    // The gas ceiling is an operator value and must be listed as missing.
    expect(plan.unresolved).toEqual(expect.arrayContaining(["maxGasWei", "assetAddress", "amountAtomic"]));
    expect(plan.signingPerformedByThisCommand).toBe("none");
    expect(plan.planDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("exits zero once every operator value is supplied, and is still not an approval", async () => {
    const dir = tempDir();
    const outcome = await cli("testnet-plan.js", [
      "--out",
      dir,
      "--payer",
      "0x1111111111111111111111111111111111111111",
      "--payee",
      "0x2222222222222222222222222222222222222222",
      "--gas-sponsor",
      "0x3333333333333333333333333333333333333333",
      "--asset",
      "0x4444444444444444444444444444444444444444",
      "--amount",
      "1500",
      "--max-gas-wei",
      "1000000000000000",
    ]);
    expect(outcome.code).toBe(0);
    expect(outcome.stdout).toMatch(/status: prepared_unsigned/);
    expect(outcome.stdout).toMatch(/it is not an approval/);
  });

  it("validates its arguments instead of writing them into the plan", async () => {
    expect((await cli("testnet-plan.js", ["--payer", "not-an-address"])).code).toBe(2);
    expect((await cli("testnet-plan.js", ["--amount", "1.5"])).code).toBe(2);
    expect((await cli("testnet-plan.js", ["--amount"])).code).toBe(2);
    expect((await cli("testnet-plan.js", ["--unknown", "x"])).code).toBe(2);
  });
});

describe("demo:testnet:execute", () => {
  it("refuses, names what is missing, and does not fall back to local mode", async () => {
    const outcome = await cli("testnet-execute.js");
    expect(outcome.code).toBe(3);
    expect(outcome.stderr).toMatch(/not implemented/);
    expect(outcome.stderr).toMatch(/operator approval record/);
    expect(outcome.stderr).toMatch(/does not fall back to the local chain/);
    // No evidence of a transaction, a hash or a chain write anywhere in output.
    expect(`${outcome.stdout}${outcome.stderr}`).not.toMatch(/0x[0-9a-fA-F]{64}/);
  });
});
