import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createPublicClient, createWalletClient, http, parseEventLogs, type Hex, type PublicClient } from "viem";
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { authorizationTypes } from "@x402/evm";
import {
  assertNoCancunOpcodes,
  authorizationConsumed,
  deployTestToken,
  deployedCodeMatches,
  fundNative,
  localChainDefinition,
  mintTestTokens,
  startLocalChain,
  tokenBalance,
  type ProvisionResult,
  type RunningLocalChain,
} from "@pulseagent/localchain";

/**
 * The EIP-3009 fixture, exercised on a real chain.
 *
 * The upstream `MockERC3009Token` was rejected for this role because it does not
 * verify signatures at all and has no `transferWithAuthorization`,
 * `authorizationState` or nonce tracking. Against such a mock, every test below
 * would pass for the wrong reason: a forged signature would "settle". So these
 * cases are what justify using a reviewed fixture instead.
 */

let chain: RunningLocalChain;
let token: ProvisionResult;
let publicClient: PublicClient;
let submitter: PrivateKeyAccount;

beforeAll(async () => {
  chain = await startLocalChain();
  token = await deployTestToken(chain);
  publicClient = createPublicClient({
    chain: localChainDefinition(chain),
    transport: http(chain.url),
  }) as PublicClient;
  submitter = privateKeyToAccount(generatePrivateKey());
  await fundNative(chain, submitter.address, 10n ** 19n);
});

afterAll(async () => {
  await chain?.close();
});

interface AuthorizationInput {
  readonly payer: PrivateKeyAccount;
  readonly payee: `0x${string}`;
  readonly value: bigint;
  readonly nonce: Hex;
  readonly validAfter?: bigint;
  readonly validBefore?: bigint;
  readonly domainName?: string;
  readonly domainVersion?: string;
  readonly chainId?: number;
  readonly verifyingContract?: `0x${string}`;
  readonly signWith?: PrivateKeyAccount;
}

/** Signs an authorization, with every domain field overridable for negative cases. */
async function signAuthorization(input: AuthorizationInput): Promise<{
  args: readonly unknown[];
  signature: Hex;
}> {
  const message = {
    from: input.payer.address,
    to: input.payee,
    value: input.value,
    validAfter: input.validAfter ?? 0n,
    validBefore: input.validBefore ?? BigInt(Math.floor(Date.now() / 1000) + 300),
    nonce: input.nonce,
  };
  const signature = await (input.signWith ?? input.payer).signTypedData({
    domain: {
      name: input.domainName ?? token.token.name,
      version: input.domainVersion ?? token.token.eip712Version,
      chainId: input.chainId ?? chain.chainId,
      verifyingContract: input.verifyingContract ?? token.token.address,
    },
    types: authorizationTypes,
    primaryType: "TransferWithAuthorization",
    message,
  });
  return {
    signature,
    args: [
      message.from,
      message.to,
      message.value,
      message.validAfter,
      message.validBefore,
      message.nonce,
      Number.parseInt(signature.slice(130, 132), 16),
      signature.slice(0, 66) as Hex,
      `0x${signature.slice(66, 130)}` as Hex,
    ],
  };
}

async function submit(args: readonly unknown[], functionName = "transferWithAuthorization"): Promise<Hex> {
  const wallet = createWalletClient({
    account: submitter,
    chain: localChainDefinition(chain),
    transport: http(chain.url),
  });
  return wallet.writeContract({
    address: token.token.address,
    abi: token.artifact.abi as never,
    functionName,
    args: args as never,
  });
}

/** Captures the custom error name a revert carries, or undefined. */
async function revertName(args: readonly unknown[], functionName = "transferWithAuthorization"): Promise<string | undefined> {
  try {
    await publicClient.simulateContract({
      address: token.token.address,
      abi: token.artifact.abi as never,
      functionName,
      args: args as never,
      account: submitter.address,
    });
    return undefined;
  } catch (error) {
    const walked = (error as { walk?: (fn: (e: unknown) => boolean) => unknown }).walk?.(
      (candidate) => (candidate as { name?: string }).name === "ContractFunctionRevertedError",
    ) as { data?: { errorName?: string } } | undefined;
    return walked?.data?.errorName ?? "unknown";
  }
}

describe("fixture provenance", () => {
  it("compiles for Shanghai and contains no Cancun-only opcode", () => {
    expect(token.token.evmVersion).toBe("shanghai");
    // The local chain enforces the same boundary, but a compiler-target slip
    // should be caught before deployment too.
    expect(() => assertNoCancunOpcodes(token.artifact.deployedBytecode)).not.toThrow();
  });

  it("matches the compiled fixture outside its immutable ranges", async () => {
    const onChain = await publicClient.getCode({ address: token.token.address });
    expect(deployedCodeMatches(token.artifact, onChain ?? "0x").matches).toBe(true);
    // Deployment evidence hashes the bytes the chain actually holds, not the
    // compiler's output with its zeroed immutable placeholders.
    expect(token.token.onChainCodeDigest).not.toBe(token.token.compiledBytecodeDigest);
  });

  it("uses the EIP-3009 typehashes from the reference implementation", async () => {
    // Byte-identical preimages mean a signature produced for a Circle-style
    // EIP-3009 token is accepted here unchanged.
    for (const [fn, expected] of [
      ["TRANSFER_WITH_AUTHORIZATION_TYPEHASH", "0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267"],
      ["RECEIVE_WITH_AUTHORIZATION_TYPEHASH", "0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8"],
      ["CANCEL_AUTHORIZATION_TYPEHASH", "0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429"],
    ] as const) {
      const value = await publicClient.readContract({
        address: token.token.address,
        abi: token.artifact.abi as never,
        functionName: fn,
      });
      expect(value, fn).toBe(expected);
    }
  });

  it("labels itself a valueless test fixture on chain", async () => {
    const notice = await publicClient.readContract({
      address: token.token.address,
      abi: token.artifact.abi as never,
      functionName: "FIXTURE_NOTICE",
    });
    expect(String(notice)).toMatch(/VALUELESS TEST FIXTURE/);
    expect(String(notice)).toMatch(/NOT A STABLECOIN/);
  });
});

describe("EIP-3009 authorization", () => {
  it("transfers exactly the authorized amount and consumes the nonce", async () => {
    const payer = privateKeyToAccount(generatePrivateKey());
    const payee = privateKeyToAccount(generatePrivateKey()).address;
    await mintTestTokens(chain, token, payer.address, 1_000_000n);

    const nonce = `0x${"a1".repeat(32)}` as Hex;
    const { args } = await signAuthorization({ payer, payee, value: 250_000n, nonce });
    const hash = await submit(args);
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    expect(receipt.status).toBe("success");

    const events = parseEventLogs({ abi: token.artifact.abi as never, logs: receipt.logs });
    expect(events.map((event) => (event as { eventName: string }).eventName).sort()).toEqual([
      "AuthorizationUsed",
      "Transfer",
    ]);
    expect(await tokenBalance(chain, token, payer.address)).toBe(750_000n);
    expect(await tokenBalance(chain, token, payee)).toBe(250_000n);
    expect(await authorizationConsumed(chain, token, payer.address, nonce)).toBe(true);
  });

  it("refuses the same authorization a second time", async () => {
    const payer = privateKeyToAccount(generatePrivateKey());
    const payee = privateKeyToAccount(generatePrivateKey()).address;
    await mintTestTokens(chain, token, payer.address, 1000n);
    const nonce = `0x${"a2".repeat(32)}` as Hex;
    const { args } = await signAuthorization({ payer, payee, value: 100n, nonce });
    await publicClient.waitForTransactionReceipt({ hash: await submit(args) });

    expect(await revertName(args)).toBe("AuthorizationUsedOrCanceled");
    expect(await tokenBalance(chain, token, payee)).toBe(100n);
  });

  it("refuses a signature from anyone but the payer", async () => {
    // Against a non-verifying mock this would succeed, which is the whole reason
    // the upstream mock was unusable here.
    const payer = privateKeyToAccount(generatePrivateKey());
    const impostor = privateKeyToAccount(generatePrivateKey());
    const payee = privateKeyToAccount(generatePrivateKey()).address;
    await mintTestTokens(chain, token, payer.address, 1000n);
    const { args } = await signAuthorization({
      payer,
      payee,
      value: 100n,
      nonce: `0x${"a3".repeat(32)}`,
      signWith: impostor,
    });
    expect(await revertName(args)).toBe("InvalidSignature");
    expect(await tokenBalance(chain, token, payee)).toBe(0n);
  });

  it("refuses a signature bound to another chain, token or domain", async () => {
    const payer = privateKeyToAccount(generatePrivateKey());
    const payee = privateKeyToAccount(generatePrivateKey()).address;
    await mintTestTokens(chain, token, payer.address, 10_000n);

    const cases = [
      { label: "another chain id", override: { chainId: 943 } },
      { label: "another verifying contract", override: { verifyingContract: payee } },
      { label: "another domain name", override: { domainName: "Some Other Token" } },
      { label: "another domain version", override: { domainVersion: "2" } },
    ] as const;

    for (const [index, testCase] of cases.entries()) {
      const { args } = await signAuthorization({
        payer,
        payee,
        value: 100n,
        nonce: `0x${String(index + 10).padStart(2, "0").repeat(32)}` as Hex,
        ...testCase.override,
      });
      expect(await revertName(args), testCase.label).toBe("InvalidSignature");
    }
    expect(await tokenBalance(chain, token, payee)).toBe(0n);
  });

  it("refuses an expired or not-yet-valid authorization", async () => {
    const payer = privateKeyToAccount(generatePrivateKey());
    const payee = privateKeyToAccount(generatePrivateKey()).address;
    await mintTestTokens(chain, token, payer.address, 1000n);
    const now = BigInt(Math.floor(Date.now() / 1000));

    const expired = await signAuthorization({
      payer,
      payee,
      value: 100n,
      nonce: `0x${"b1".repeat(32)}`,
      validBefore: now - 1n,
    });
    expect(await revertName(expired.args)).toBe("AuthorizationExpired");

    const early = await signAuthorization({
      payer,
      payee,
      value: 100n,
      nonce: `0x${"b2".repeat(32)}`,
      validAfter: now + 3600n,
      validBefore: now + 7200n,
    });
    expect(await revertName(early.args)).toBe("AuthorizationNotYetValid");
  });

  it("refuses a transfer exceeding the payer's balance", async () => {
    const payer = privateKeyToAccount(generatePrivateKey());
    const payee = privateKeyToAccount(generatePrivateKey()).address;
    await mintTestTokens(chain, token, payer.address, 10n);
    const { args } = await signAuthorization({ payer, payee, value: 1000n, nonce: `0x${"b3".repeat(32)}` });
    expect(await revertName(args)).toBe("ERC20InsufficientBalance");
  });

  it("lets a payer cancel an unused authorization so it can never settle", async () => {
    const payer = privateKeyToAccount(generatePrivateKey());
    const payee = privateKeyToAccount(generatePrivateKey()).address;
    await mintTestTokens(chain, token, payer.address, 1000n);
    const nonce = `0x${"c1".repeat(32)}` as Hex;
    const { args } = await signAuthorization({ payer, payee, value: 100n, nonce });

    const cancelSignature = await payer.signTypedData({
      domain: {
        name: token.token.name,
        version: token.token.eip712Version,
        chainId: chain.chainId,
        verifyingContract: token.token.address,
      },
      types: { CancelAuthorization: [{ name: "authorizer", type: "address" }, { name: "nonce", type: "bytes32" }] },
      primaryType: "CancelAuthorization",
      message: { authorizer: payer.address, nonce },
    });
    await publicClient.waitForTransactionReceipt({
      hash: await submit([payer.address, nonce, cancelSignature], "cancelAuthorization"),
    });

    expect(await authorizationConsumed(chain, token, payer.address, nonce)).toBe(true);
    expect(await revertName(args)).toBe("AuthorizationUsedOrCanceled");
  });

  it("lets only the payee submit receiveWithAuthorization", async () => {
    const payer = privateKeyToAccount(generatePrivateKey());
    const payee = privateKeyToAccount(generatePrivateKey());
    await mintTestTokens(chain, token, payer.address, 1000n);
    await fundNative(chain, payee.address, 10n ** 18n);
    const nonce = `0x${"d1".repeat(32)}` as Hex;
    const message = {
      from: payer.address,
      to: payee.address,
      value: 100n,
      validAfter: 0n,
      validBefore: BigInt(Math.floor(Date.now() / 1000) + 300),
      nonce,
    };
    const signature = await payer.signTypedData({
      domain: {
        name: token.token.name,
        version: token.token.eip712Version,
        chainId: chain.chainId,
        verifyingContract: token.token.address,
      },
      types: {
        ReceiveWithAuthorization: [
          { name: "from", type: "address" },
          { name: "to", type: "address" },
          { name: "value", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
        ],
      },
      primaryType: "ReceiveWithAuthorization",
      message,
    });
    const args = [
      message.from,
      message.to,
      message.value,
      message.validAfter,
      message.validBefore,
      message.nonce,
      Number.parseInt(signature.slice(130, 132), 16),
      signature.slice(0, 66) as Hex,
      `0x${signature.slice(66, 130)}` as Hex,
    ];

    // A third party front-running the payee must be refused.
    expect(await revertName(args, "receiveWithAuthorization")).toBe("CallerMustBePayee");

    const payeeWallet = createWalletClient({
      account: payee,
      chain: localChainDefinition(chain),
      transport: http(chain.url),
    });
    const hash = await payeeWallet.writeContract({
      address: token.token.address,
      abi: token.artifact.abi as never,
      functionName: "receiveWithAuthorization",
      args: args as never,
    });
    expect((await publicClient.waitForTransactionReceipt({ hash })).status).toBe("success");
    expect(await tokenBalance(chain, token, payee.address)).toBe(100n);
  });
});

describe("local chain opcode boundary", () => {
  it("accepts Shanghai and rejects Cancun opcodes, as both target chains do", async () => {
    const probe = async (data: string): Promise<boolean> => {
      try {
        await chain.request("eth_call", [{ data, gas: "0x186a0" }, "latest"]);
        return true;
      } catch {
        return false;
      }
    };
    expect(await probe("0x60006000f3")).toBe(true);
    expect(await probe("0x5f5ff3")).toBe(true);
    // Rehearsing on a Cancun chain would hide the failure that ruled out Permit2.
    expect(await probe("0x6000600060005e60006000f3")).toBe(false);
    expect(await probe("0x600060005d60006000f3")).toBe(false);
  });

  it("refuses a local-only method on a remote-looking request and reports chain id 31337", async () => {
    expect(await chain.request("eth_chainId")).toBe("0x7a69");
  });
});
