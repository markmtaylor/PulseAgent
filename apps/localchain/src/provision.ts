import { createPublicClient, createWalletClient, http, parseEventLogs, type Hex, type PublicClient } from "viem";
import { sha256Hex } from "@pulseagent/core";
import { privateKeyToAccount } from "viem/accounts";
import { compileFixture, deployedCodeMatches, type CompiledContract } from "./compile.js";
import { LOCAL_CHAIN_ID, type RunningLocalChain } from "./node.js";

/**
 * Deploys and funds the valueless fixtures on an owned local chain.
 *
 * LOCAL ONLY, and structurally so: every function here needs a
 * {@link RunningLocalChain} handle, which only exists for a node this process
 * started. There is no URL parameter, so none of this can be aimed at a public
 * chain even by mistake.
 *
 * Native funding goes through `hardhat_setBalance` rather than a prefunded
 * development account, which is what lets the node start with no owned accounts
 * and no well-known keys at all. Every account below is generated at runtime and
 * only its address is ever returned.
 */

export const LOCAL_TEST_TOKEN = {
  name: "PulseAgent Valueless Test Token",
  symbol: "PAVT",
  decimals: 6,
  eip712Version: "1",
} as const;

export interface ProvisionedAccount {
  /** Public address. The key is held only by the process that generated it. */
  readonly address: `0x${string}`;
}

export interface ProvisionResult {
  readonly token: {
    readonly address: `0x${string}`;
    readonly name: string;
    readonly symbol: string;
    readonly decimals: number;
    readonly eip712Version: string;
    /**
     * Digest of the runtime bytes read back from the chain with `eth_getCode`.
     * This is the deployment evidence: the compiler's own output still carries
     * zero placeholders where construction substitutes immutables, so hashing it
     * would describe something that was never deployed.
     */
    readonly onChainCodeDigest: string;
    /** Digest of the compiler's runtime output, for comparison only. */
    readonly compiledBytecodeDigest: string;
    readonly solcVersion: string;
    readonly evmVersion: "shanghai";
    readonly valuelessTestFixture: true;
  };
  readonly deployer: ProvisionedAccount;
  readonly artifact: CompiledContract;
}

/** Gives `address` a native balance on the local chain. Local-only RPC method. */
export async function fundNative(chain: RunningLocalChain, address: `0x${string}`, wei: bigint): Promise<void> {
  await chain.request("hardhat_setBalance", [address, `0x${wei.toString(16)}`]);
}

/** A viem public client bound to the owned local node. */
export function localPublicClient(chain: RunningLocalChain): PublicClient {
  return createPublicClient({
    chain: localChainDefinition(chain),
    transport: http(chain.url),
  }) as PublicClient;
}

/**
 * Compiles and deploys the EIP-3009 test token.
 *
 * @param chain The owned local node.
 * @returns Token metadata, including the runtime bytecode digest as deployment
 *          evidence, and the deployer's public address.
 */
export async function deployTestToken(chain: RunningLocalChain): Promise<ProvisionResult> {
  const artifact = await compileFixture();
  const deployer = privateKeyToAccount(randomLocalKey());
  await fundNative(chain, deployer.address, 10n ** 20n);

  const definition = localChainDefinition(chain);
  const wallet = createWalletClient({ account: deployer, chain: definition, transport: http(chain.url) });
  const publicClient = createPublicClient({ chain: definition, transport: http(chain.url) });

  const hash = await wallet.deployContract({
    abi: artifact.abi as never,
    bytecode: artifact.bytecode,
    args: [LOCAL_TEST_TOKEN.name, LOCAL_TEST_TOKEN.symbol, LOCAL_TEST_TOKEN.decimals, LOCAL_TEST_TOKEN.eip712Version],
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const deployedAt = receipt.contractAddress;
  if (receipt.status !== "success" || deployedAt === null || deployedAt === undefined) {
    throw new Error("test token deployment failed on the local chain");
  }

  // Confirm the code actually on chain is the fixture that was compiled, rather
  // than trusting the receipt. Immutable ranges are masked because construction
  // substitutes them.
  const onChainCode = await publicClient.getCode({ address: deployedAt });
  const deployedCode = onChainCode ?? "0x";
  const comparison = deployedCodeMatches(artifact, deployedCode);
  if (!comparison.matches) {
    throw new Error(`deployed runtime bytecode does not match the compiled fixture: ${comparison.reason ?? ""}`);
  }

  return {
    token: {
      address: deployedAt,
      name: LOCAL_TEST_TOKEN.name,
      symbol: LOCAL_TEST_TOKEN.symbol,
      decimals: LOCAL_TEST_TOKEN.decimals,
      eip712Version: LOCAL_TEST_TOKEN.eip712Version,
      onChainCodeDigest: sha256Hex(deployedCode),
      compiledBytecodeDigest: artifact.deployedBytecodeDigest,
      solcVersion: artifact.solcVersion,
      evmVersion: artifact.evmVersion,
      valuelessTestFixture: true,
    },
    deployer: { address: deployer.address },
    artifact,
  };
}

/**
 * Mints valueless test tokens to `to` using the fixture's open faucet.
 *
 * @returns The recipient's balance afterwards, in atomic units.
 */
export async function mintTestTokens(
  chain: RunningLocalChain,
  provisioned: ProvisionResult,
  to: `0x${string}`,
  amountAtomic: bigint,
): Promise<bigint> {
  const definition = localChainDefinition(chain);
  const minter = privateKeyToAccount(randomLocalKey());
  await fundNative(chain, minter.address, 10n ** 18n);
  const wallet = createWalletClient({ account: minter, chain: definition, transport: http(chain.url) });
  const publicClient = createPublicClient({ chain: definition, transport: http(chain.url) });

  const hash = await wallet.writeContract({
    address: provisioned.token.address,
    abi: provisioned.artifact.abi as never,
    functionName: "mint",
    args: [to, amountAtomic],
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error("minting valueless test tokens failed");

  const minted = parseEventLogs({
    abi: provisioned.artifact.abi as never,
    eventName: "Transfer",
    logs: receipt.logs,
  });
  if (minted.length === 0) throw new Error("mint emitted no Transfer event");

  return (await publicClient.readContract({
    address: provisioned.token.address,
    abi: provisioned.artifact.abi as never,
    functionName: "balanceOf",
    args: [to],
  })) as bigint;
}

/** Reads a token balance in atomic units. */
export async function tokenBalance(
  chain: RunningLocalChain,
  provisioned: ProvisionResult,
  owner: `0x${string}`,
): Promise<bigint> {
  const publicClient = createPublicClient({ chain: localChainDefinition(chain), transport: http(chain.url) });
  return (await publicClient.readContract({
    address: provisioned.token.address,
    abi: provisioned.artifact.abi as never,
    functionName: "balanceOf",
    args: [owner],
  })) as bigint;
}

/** Whether an authorization nonce has been consumed or cancelled. */
export async function authorizationConsumed(
  chain: RunningLocalChain,
  provisioned: ProvisionResult,
  authorizer: `0x${string}`,
  nonce: Hex,
): Promise<boolean> {
  const publicClient = createPublicClient({ chain: localChainDefinition(chain), transport: http(chain.url) });
  return (await publicClient.readContract({
    address: provisioned.token.address,
    abi: provisioned.artifact.abi as never,
    functionName: "authorizationState",
    args: [authorizer, nonce],
  })) as boolean;
}

/** A viem chain definition for the owned local node. */
export function localChainDefinition(chain: RunningLocalChain) {
  return {
    id: LOCAL_CHAIN_ID,
    name: "Local ephemeral EVM",
    nativeCurrency: { name: "Test Ether", symbol: "ETH(test)", decimals: 18 },
    rpcUrls: { default: { http: [chain.url] } },
  } as const;
}

/** A fresh key for a local, valueless account. Returned to nobody. */
function randomLocalKey(): Hex {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return `0x${Buffer.from(bytes).toString("hex")}`;
}
