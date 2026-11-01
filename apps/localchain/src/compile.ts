import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { digestOf, sha256Hex } from "@pulseagent/core";

/**
 * Compiles the valueless test fixture with solc-js, pinned to the Shanghai EVM
 * target.
 *
 * The target is not a preference. PulseChain 943 and 369 both return invalid
 * opcode for MCOPY and TSTORE at the observed finalized blocks, and the
 * canonical x402 exact Permit2 proxy on those chains — compiled for Cancun —
 * reverts on MCOPY in its settlement path. Letting solc default to a newer
 * target would emit bytecode that works locally and cannot run on the chain this
 * project is aimed at.
 *
 * Output is cached on disk, keyed by a digest over the sources, the compiler
 * version and the exact settings, so a changed source or setting recompiles and
 * an unchanged one does not.
 */

const require = createRequire(import.meta.url);

/** The subset of solc-js this module uses. solc-js ships no type declarations. */
interface SolcModule {
  version(): string;
  compile(input: string, callbacks: { import: (requestedPath: string) => { contents: string } | { error: string } }): string;
}

export interface CompiledContract {
  readonly contractName: string;
  readonly abi: readonly unknown[];
  readonly bytecode: `0x${string}`;
  readonly deployedBytecode: `0x${string}`;
  /**
   * Byte ranges in `deployedBytecode` that construction fills in, keyed by the
   * compiler's AST id. Masked out when comparing compiled code to deployed code.
   */
  readonly immutableReferences: Readonly<Record<string, readonly { start: number; length: number }[]>>;
  readonly solcVersion: string;
  readonly evmVersion: "shanghai";
  readonly sourceDigest: string;
  /** Digest of the deployed runtime bytecode, recorded as deployment evidence. */
  readonly deployedBytecodeDigest: string;
}

export interface CompileOptions {
  /** Repository-relative Solidity file, e.g. `contracts/TestTokenEIP3009.sol`. */
  readonly sourcePath?: string;
  readonly contractName?: string;
  /** Where to cache artifacts. Gitignored; regenerated on demand. */
  readonly cacheDir?: string;
}

const DEFAULT_SOURCE = "contracts/TestTokenEIP3009.sol";
const DEFAULT_CONTRACT = "TestTokenEIP3009";

/** Repository root, derived from this file's location rather than the cwd. */
export function repositoryRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
}

/**
 * Compiles (or loads from cache) the fixture contract.
 *
 * @param options Source path, contract name and cache directory.
 * @returns The compiled artifact with its provenance digests.
 */
export async function compileFixture(options: CompileOptions = {}): Promise<CompiledContract> {
  const root = repositoryRoot();
  const sourcePath = path.resolve(root, options.sourcePath ?? DEFAULT_SOURCE);
  const contractName = options.contractName ?? DEFAULT_CONTRACT;
  const cacheDir = path.resolve(root, options.cacheDir ?? path.join("artifacts", "local"));

  const solc = require("solc") as SolcModule;
  const solcVersion = solc.version();
  const sourceText = await readFile(sourcePath, "utf8");
  const sourceName = path.relative(root, sourcePath);

  const settings = {
    optimizer: { enabled: true, runs: 200 },
    // Held at Shanghai on purpose; see the module comment.
    evmVersion: "shanghai" as const,
    outputSelection: {
      "*": {
        "*": [
          "abi",
          "evm.bytecode.object",
          "evm.deployedBytecode.object",
          // Needed to compare deployed code against compiled code: immutables
          // are placeholders until construction substitutes them.
          "evm.deployedBytecode.immutableReferences",
        ],
      },
    },
  };

  const resolvedImports = new Map<string, string>();
  const importCallback = (requested: string): { contents: string } | { error: string } => {
    const cached = resolvedImports.get(requested);
    if (cached !== undefined) return { contents: cached };
    try {
      const resolved = resolveSolidityImport(requested, [moduleDirectory(), path.dirname(sourcePath), root]);
      const contents = readFileSyncUtf8(resolved);
      resolvedImports.set(requested, contents);
      return { contents };
    } catch {
      return { error: `import ${requested} could not be resolved` };
    }
  };

  // First pass resolves the import graph so the cache key covers every source,
  // not just the entry file.
  const input = {
    language: "Solidity",
    sources: { [sourceName]: { content: sourceText } },
    settings,
  };
  const firstPass = JSON.parse(solc.compile(JSON.stringify(input), { import: importCallback })) as SolcOutput;
  assertNoCompileErrors(firstPass, sourceName);

  const sourceDigest = digestOf({
    solcVersion,
    settings,
    sources: Object.fromEntries([
      [sourceName, sha256Hex(sourceText)],
      ...[...resolvedImports.entries()].map(([name, contents]) => [name, sha256Hex(contents)] as const),
    ]),
  });

  const cachePath = path.join(cacheDir, `${contractName}.${sourceDigest.replace("sha256:", "").slice(0, 16)}.json`);
  const cached = await readCachedArtifact(cachePath);
  if (cached) return cached;

  const contract = firstPass.contracts?.[sourceName]?.[contractName];
  if (!contract) {
    throw new Error(`solc output does not contain ${contractName} from ${sourceName}`);
  }
  const bytecode = `0x${contract.evm.bytecode.object}` as const;
  const deployedBytecode = `0x${contract.evm.deployedBytecode.object}` as const;

  assertNoCancunOpcodes(deployedBytecode);

  const artifact: CompiledContract = {
    contractName,
    abi: contract.abi,
    bytecode,
    deployedBytecode,
    immutableReferences: contract.evm.deployedBytecode.immutableReferences ?? {},
    solcVersion,
    evmVersion: "shanghai",
    sourceDigest,
    deployedBytecodeDigest: sha256Hex(deployedBytecode),
  };

  await mkdir(cacheDir, { recursive: true });
  await writeFile(cachePath, `${JSON.stringify(artifact, null, 2)}\n`, "utf8");
  return artifact;
}

/**
 * Rejects bytecode containing a Cancun-only opcode.
 *
 * A scan of raw bytes cannot distinguish an opcode from a byte inside a PUSH
 * immediate, so this is a backstop against a compiler-target mistake, not a
 * proof of chain compatibility. The authoritative check is the local chain
 * itself, which runs at the same Shanghai boundary as the target networks and
 * rejects these opcodes outright.
 */
export function assertNoCancunOpcodes(bytecodeHex: string): void {
  const bytes = Buffer.from(bytecodeHex.replace(/^0x/, ""), "hex");
  for (let index = 0; index < bytes.length; index += 1) {
    const opcode = bytes[index];
    if (opcode === undefined) break;
    if (opcode >= 0x60 && opcode <= 0x7f) {
      // Skip a PUSH immediate so its data cannot be misread as an opcode.
      index += opcode - 0x5f;
      continue;
    }
    if (opcode === 0x5e) throw new Error("compiled bytecode contains MCOPY, which the target chains reject");
    if (opcode === 0x5c) throw new Error("compiled bytecode contains TLOAD, which the target chains reject");
    if (opcode === 0x5d) throw new Error("compiled bytecode contains TSTORE, which the target chains reject");
  }
}

interface SolcOutput {
  errors?: { severity: string; type?: string; formattedMessage?: string; message?: string }[];
  contracts?: Record<
    string,
    Record<
      string,
      {
        abi: readonly unknown[];
        evm: {
          bytecode: { object: string };
          deployedBytecode: {
            object: string;
            immutableReferences?: Record<string, { start: number; length: number }[]>;
          };
        };
      }
    >
  >;
}

function assertNoCompileErrors(output: SolcOutput, sourceName: string): void {
  const errors = (output.errors ?? []).filter((entry) => entry.severity === "error");
  if (errors.length > 0) {
    const detail = errors
      .map((entry) => entry.formattedMessage ?? entry.message ?? entry.type ?? "unknown error")
      .join("\n")
      .slice(0, 4000);
    throw new Error(`solc failed to compile ${sourceName}:\n${detail}`);
  }
}

async function readCachedArtifact(cachePath: string): Promise<CompiledContract | undefined> {
  try {
    return JSON.parse(await readFile(cachePath, "utf8")) as CompiledContract;
  } catch {
    return undefined;
  }
}

function readFileSyncUtf8(filePath: string): string {
  // solc's import callback is synchronous, so this one read cannot be async.
  return readFileSync(filePath, "utf8");
}

/** This module's own directory, the natural base for `node_modules` lookup. */
function moduleDirectory(): string {
  return path.dirname(fileURLToPath(import.meta.url));
}

/**
 * Resolves a Solidity `node_modules` import by walking the directory tree.
 *
 * `require.resolve` is not usable here: a package's `exports` map legitimately
 * refuses arbitrary subpaths, and `.sol` files are never listed in one, so a
 * perfectly present contract fails to resolve. Walking `node_modules` is what
 * every Solidity toolchain does for the same reason.
 *
 * Only `node_modules` subpaths are served. A relative or absolute path from a
 * source file is refused, so a contract cannot make the compiler read something
 * outside the dependency tree.
 */
function resolveSolidityImport(requested: string, fromDirectories: readonly string[]): string {
  if (requested.startsWith(".") || path.isAbsolute(requested)) {
    throw new Error(`import ${requested} is not a node_modules package path`);
  }
  const segments = requested.split("/").filter((segment) => segment !== "");
  if (segments.some((segment) => segment === "." || segment === "..")) {
    throw new Error(`import ${requested} must not traverse directories`);
  }
  const packageSegments = segments[0]?.startsWith("@") ? 2 : 1;
  const packageName = segments.slice(0, packageSegments).join("/");
  const subPath = segments.slice(packageSegments).join("/");
  if (packageName === "" || subPath === "") {
    throw new Error(`import ${requested} does not name a file inside a package`);
  }

  for (const start of fromDirectories) {
    let directory = path.resolve(start);
    for (;;) {
      const candidate = path.join(directory, "node_modules", packageName, subPath);
      if (existsSync(candidate)) return candidate;
      const parent = path.dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
  }
  throw new Error(`import ${requested} was not found in any node_modules directory`);
}

/**
 * Compares deployed runtime code against compiled runtime code, ignoring the
 * ranges construction fills in.
 *
 * Immutable variables — and OpenZeppelin's cached EIP-712 domain fields among
 * them — are zero placeholders in compiled output and real values on chain, so a
 * byte-for-byte comparison would always fail. Masking exactly the compiler's
 * declared immutable ranges keeps the check meaningful: every other byte of
 * executable code must match.
 */
export function deployedCodeMatches(
  artifact: Pick<CompiledContract, "deployedBytecode" | "immutableReferences">,
  onChainCode: string,
): { matches: boolean; reason?: string } {
  const expected = Buffer.from(artifact.deployedBytecode.replace(/^0x/, ""), "hex");
  const actual = Buffer.from(onChainCode.replace(/^0x/, ""), "hex");
  if (expected.length !== actual.length) {
    return {
      matches: false,
      reason: `deployed code is ${String(actual.length)} bytes; the fixture compiles to ${String(expected.length)}`,
    };
  }
  for (const ranges of Object.values(artifact.immutableReferences)) {
    for (const range of ranges) {
      expected.fill(0, range.start, range.start + range.length);
      actual.fill(0, range.start, range.start + range.length);
    }
  }
  return expected.equals(actual)
    ? { matches: true }
    : { matches: false, reason: "deployed code differs from the fixture outside its immutable ranges" };
}
