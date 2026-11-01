import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  ContractDecoder,
  EdrContext,
  l1ProviderFactory,
  MineOrdering,
  type Provider,
  type ProviderConfig,
} from "@nomicfoundation/edr";

/**
 * A disposable local EVM, in this process, served over loopback JSON-RPC.
 *
 * LOCAL ONLY. Nothing here may point at a public chain: there is no fork
 * configuration, no remote URL parameter and no way to reach another node.
 *
 * Two properties are deliberate:
 *
 * - **No well-known keys.** The node starts with no owned accounts at all. Every
 *   account used by a test or the demo is generated at runtime in the process
 *   that needs it and funded through `hardhat_setBalance`. Nothing prints a
 *   startup list of development private keys, because no such list exists.
 * - **Shanghai, not latest.** PulseChain 943 and 369 both reject MCOPY and
 *   TSTORE at the observed finalized blocks. Rehearsing on a Cancun chain would
 *   hide exactly the class of failure that blocked the Permit2 path, so the
 *   local chain is held at the same opcode boundary.
 */

export const LOCAL_CHAIN_ID = 31_337;
export const LOCAL_HARDFORK = "shanghai";

export interface LocalChainOptions {
  /** Port on 127.0.0.1. 0 picks an ephemeral port. */
  readonly port?: number;
  /** Block gas limit for the genesis block. */
  readonly blockGasLimit?: bigint;
  readonly initialBaseFeePerGas?: bigint;
}

export interface RunningLocalChain {
  /** `http://127.0.0.1:<port>`, the only way to reach this node. */
  readonly url: string;
  /** Exact origin, which callers pass to `assertRpcAllowed` as an owned node. */
  readonly origin: string;
  readonly port: number;
  readonly chainId: number;
  readonly hardfork: string;
  /** Issues a JSON-RPC request directly, bypassing HTTP. Used by provisioning. */
  request(method: string, params?: readonly unknown[]): Promise<unknown>;
  close(): Promise<void>;
}

/**
 * Starts the local chain and its loopback JSON-RPC endpoint.
 *
 * @param options Port and genesis parameters.
 * @returns The running node, including the exact origin to authorize.
 */
export async function startLocalChain(options: LocalChainOptions = {}): Promise<RunningLocalChain> {
  const context = new EdrContext();
  await context.registerProviderFactory("L1", l1ProviderFactory());

  const config: ProviderConfig = {
    // Blocks may share a timestamp, so the chain's clock tracks wall time.
    //
    // This matters more than it looks. With auto-mining, one block is produced
    // per transaction, and forcing each to be strictly later than the last makes
    // the chain's clock run ahead of real time by a second per transaction.
    // Deploying, minting and a few payments is enough for an EIP-3009
    // authorization with a short validity window to be rejected as expired by a
    // chain that is "in the future" — a failure a public chain would not produce
    // and which has nothing to teach about the protocol.
    allowBlocksWithSameTimestamp: true,
    allowUnlimitedContractSize: false,
    // Surface a failed `eth_call` as a JSON-RPC error rather than empty data, so
    // an unsupported opcode is observable the way a public node reports it.
    bailOnCallFailure: true,
    bailOnTransactionFailure: false,
    chainId: BigInt(LOCAL_CHAIN_ID),
    coinbase: new Uint8Array(20),
    genesisState: [],
    hardfork: LOCAL_HARDFORK,
    initialBaseFeePerGas: options.initialBaseFeePerGas ?? 1_000_000_000n,
    minGasPrice: 0n,
    mining: { autoMine: true, memPool: { order: MineOrdering.Priority } },
    network: { genesisBlockGasLimit: options.blockGasLimit ?? 30_000_000n },
    networkId: BigInt(LOCAL_CHAIN_ID),
    observability: {},
    // No owned accounts: there is no development key in this process.
    ownedAccounts: [],
    precompileOverrides: [],
  };

  const provider: Provider = await context.createProvider(
    "L1",
    config,
    // The node's own logger stays off. Nothing it might print can reach a log.
    { enable: false, decodeConsoleLogInputsCallback: () => [], printLineCallback: () => undefined },
    { subscriptionCallback: () => undefined },
    new ContractDecoder(),
  );

  let nextId = 1;
  const request = async (method: string, params: readonly unknown[] = []): Promise<unknown> => {
    const response = await provider.handleRequest(
      JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
    );
    const parsed = parseResponse(response.data);
    if ("error" in parsed && parsed.error) {
      throw new LocalChainRpcError(method, parsed.error.code, parsed.error.message);
    }
    return (parsed as { result?: unknown }).result;
  };

  const server = createServer((req, res) => {
    void serveJsonRpc(provider, req, res).catch(() => {
      sendJson(res, 500, { jsonrpc: "2.0", id: null, error: { code: -32_603, message: "internal error" } });
    });
  });
  const port = await listen(server, options.port ?? 0);
  const origin = `http://127.0.0.1:${String(port)}`;

  return {
    url: origin,
    origin,
    port,
    chainId: LOCAL_CHAIN_ID,
    hardfork: LOCAL_HARDFORK,
    request,
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

export class LocalChainRpcError extends Error {
  readonly method: string;
  readonly code: number;

  constructor(method: string, code: number, message: string) {
    super(`${method} failed (${String(code)}): ${message}`);
    this.name = "LocalChainRpcError";
    this.method = method;
    this.code = code;
  }
}

async function serveJsonRpc(provider: Provider, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== "POST") {
    sendJson(res, 405, { jsonrpc: "2.0", id: null, error: { code: -32_600, message: "POST required" } });
    return;
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    total += buffer.byteLength;
    if (total > 8 * 1024 * 1024) {
      sendJson(res, 413, { jsonrpc: "2.0", id: null, error: { code: -32_600, message: "body too large" } });
      return;
    }
    chunks.push(buffer);
  }
  const body = normalizeJsonRpcBody(Buffer.concat(chunks).toString("utf8"));
  if (body === undefined) {
    sendJson(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32_700, message: "parse error" } });
    return;
  }
  const response = await provider.handleRequest(body);
  const data = JSON.stringify(normalizeJsonRpcError(
    typeof response.data === "string" ? (JSON.parse(response.data) as unknown) : response.data,
  ));
  res.writeHead(200, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(data)),
  });
  res.end(data);
}

/**
 * Normalizes a JSON-RPC body before the provider sees it.
 *
 * The provider requires `params` to be present, while clients legitimately omit
 * it for parameterless calls — viem sends a bare `{"method":"eth_gasPrice"}`.
 * Rejecting those would make the local node behave unlike any real one, so the
 * missing field is filled in rather than treated as a client error. Only the
 * envelope is touched; method names and parameters are passed through untouched.
 */
function normalizeJsonRpcBody(body: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  const normalizeOne = (value: unknown): unknown => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return value;
    const request = value as Record<string, unknown>;
    return {
      jsonrpc: typeof request["jsonrpc"] === "string" ? request["jsonrpc"] : "2.0",
      id: request["id"] ?? null,
      method: request["method"],
      params: Array.isArray(request["params"]) ? request["params"] : [],
    };
  };
  return JSON.stringify(Array.isArray(parsed) ? parsed.map(normalizeOne) : normalizeOne(parsed));
}

/**
 * Reshapes a revert into the form clients decode.
 *
 * The provider reports a revert as code -32000 with
 * `error.data = { reason, data, transactionHash }`. Clients expect the standard
 * `execution reverted` shape: code 3, that phrase in the message, and the revert
 * bytes directly in `error.data`. viem in particular maps -32000 to "invalid
 * parameters", so without this a custom error arrives undecodable and a test
 * asserting *which* revert happened cannot be written. The structured detail is
 * preserved alongside rather than discarded.
 */
function normalizeJsonRpcError(response: unknown): unknown {
  if (Array.isArray(response)) return response.map(normalizeJsonRpcError);
  if (typeof response !== "object" || response === null) return response;
  const envelope = response as Record<string, unknown>;
  const error = envelope["error"];
  if (typeof error !== "object" || error === null) return response;
  const errorObject = error as Record<string, unknown>;
  const detail = errorObject["data"];
  if (typeof detail !== "object" || detail === null) return response;
  const revertData = (detail as Record<string, unknown>)["data"];
  if (typeof revertData !== "string") return response;
  const message = typeof errorObject["message"] === "string" ? errorObject["message"] : "";
  return {
    ...envelope,
    error: {
      ...errorObject,
      code: 3,
      message: message.includes("execution reverted") ? message : `execution reverted: ${message}`,
      data: revertData,
      detail,
    },
  };
}

function parseResponse(data: string | unknown): { error?: { code: number; message: string }; result?: unknown } {
  const parsed = typeof data === "string" ? (JSON.parse(data) as unknown) : data;
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("local chain returned a response that is not an object");
  }
  return parsed as { error?: { code: number; message: string }; result?: unknown };
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(payload)),
  });
  res.end(payload);
}

function listen(server: Server, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("local chain failed to bind a TCP port"));
        return;
      }
      resolve(address.port);
    });
  });
}
