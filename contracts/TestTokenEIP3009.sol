// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title TestTokenEIP3009
 * @notice VALUELESS TEST FIXTURE. This token is not a stablecoin, is not backed by
 *         anything, is not redeemable, and must never be presented as holding value.
 *         It exists so the x402 `exact` EVM scheme's EIP-3009 asset transfer method can
 *         be exercised end to end against a disposable local chain.
 *
 * @dev Provenance of the authorization semantics implemented here:
 *      - EIP-3009 "Transfer With Authorization" (https://eips.ethereum.org/EIPS/eip-3009)
 *        defines the three typed-data structs, the `authorizationState` getter and the
 *        `AuthorizationUsed` / `AuthorizationCanceled` events.
 *      - Circle's reference implementation, circlefin/stablecoin-evm
 *        contracts/v2/EIP3009.sol, is the behavioral model followed for the validity
 *        window (`validAfter` exclusive lower bound, `validBefore` exclusive upper
 *        bound), single-use nonces, payee-bound `receiveWithAuthorization`, and
 *        `cancelAuthorization`. Typehash preimages below are byte-identical to that
 *        implementation's, so a signature produced for a Circle-style EIP-3009 token is
 *        accepted here unchanged. Verified against the published constants
 *        0x7c7c6cdb..., 0xd099cc98... and 0x158b0a9e... in the fixture test suite.
 *      - OpenZeppelin Contracts 5.0.2 supplies the ERC-20, EIP-712 domain and
 *        ECDSA recovery bases rather than hand-rolled cryptography. The pin is
 *        deliberate: from 5.2 onwards `Strings` imports `Bytes`, whose
 *        hand-written `mcopy` assembly makes the whole `EIP712` import graph
 *        Cancun-only, and solc refuses to compile it for Shanghai. 5.0.2's graph
 *        compiles clean at this target, so the audited upstream EIP-712
 *        implementation is reused rather than replaced.
 *
 *      Signature verification is ECDSA only. `SignatureChecker`, which would add
 *      ERC-1271 contract-wallet support, also depends on `mcopy` in current
 *      releases. A contract-wallet payer is consequently out of scope for this
 *      fixture, and the x402 facilitator's ERC-1271 and ERC-6492 paths are
 *      untested by this milestone and must not be described as supported.
 *
 *      Deliberately compiled for the Shanghai EVM target. PulseChain 943 and 369 both
 *      reject MCOPY and TSTORE at the observed finalized blocks, so no Cancun-only
 *      opcode may appear in fixture bytecode. Nothing here uses transient storage.
 *
 *      `mint` is unrestricted on purpose: this contract is only ever deployed to an
 *      owned ephemeral chain, and an unrestricted faucet makes that obvious to a reader.
 *      That property alone disqualifies it from any public deployment.
 */
contract TestTokenEIP3009 is ERC20, EIP712 {
    /// @notice Marker a deployment check can read to confirm this is the test fixture.
    string public constant FIXTURE_NOTICE = "VALUELESS TEST FIXTURE - NOT A STABLECOIN - NOT REDEEMABLE";

    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    // keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    uint8 private immutable _decimals;
    string private _version;

    /// @dev authorizer => nonce => consumed
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    error AuthorizationNotYetValid();
    error AuthorizationExpired();
    error AuthorizationUsedOrCanceled(address authorizer, bytes32 nonce);
    error InvalidSignature();
    error CallerMustBePayee(address caller, address payee);

    /**
     * @param name_ ERC-20 name. Must equal the EIP-712 domain name a payer signs over.
     * @param symbol_ ERC-20 symbol.
     * @param decimals_ Token decimals.
     * @param version_ EIP-712 domain version, exposed as `version()` so an x402
     *        facilitator can cross-check the domain it was told to expect.
     */
    constructor(string memory name_, string memory symbol_, uint8 decimals_, string memory version_)
        ERC20(name_, symbol_)
        EIP712(name_, version_)
    {
        _decimals = decimals_;
        _version = version_;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    /// @notice EIP-712 domain version. Part of the domain separator a payer signs.
    function version() external view returns (string memory) {
        return _version;
    }

    /// @notice The EIP-712 domain separator, from the upstream OpenZeppelin base.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice True once `nonce` has been spent or cancelled by `authorizer`.
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    /// @notice Unrestricted faucet. Local ephemeral chains only; see contract notice.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// @notice EIP-3009 transfer authorized by `from`, submitted by anyone (65-byte ECDSA).
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    /// @notice EIP-3009 transfer authorized by `from`, submitted by anyone (EOA or ERC-1271).
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) public {
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _requireValidSignature(
            from,
            keccak256(
                abi.encode(
                    TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce
                )
            ),
            signature
        );
        _markAuthorizationAsUsed(from, nonce);
        _transfer(from, to, value);
    }

    /// @notice EIP-3009 transfer that only the payee may submit (65-byte ECDSA).
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        receiveWithAuthorization(from, to, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    /// @notice EIP-3009 transfer that only the payee may submit, blocking front-running.
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) public {
        if (to != _msgSender()) revert CallerMustBePayee(_msgSender(), to);
        _requireValidAuthorization(from, nonce, validAfter, validBefore);
        _requireValidSignature(
            from,
            keccak256(
                abi.encode(
                    RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce
                )
            ),
            signature
        );
        _markAuthorizationAsUsed(from, nonce);
        _transfer(from, to, value);
    }

    /// @notice Burn an unused authorization nonce so it can never settle.
    function cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) external {
        _requireUnusedAuthorization(authorizer, nonce);
        _requireValidSignature(
            authorizer, keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce)), signature
        );
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    function _requireValidAuthorization(address authorizer, bytes32 nonce, uint256 validAfter, uint256 validBefore)
        private
        view
    {
        if (block.timestamp <= validAfter) revert AuthorizationNotYetValid();
        if (block.timestamp >= validBefore) revert AuthorizationExpired();
        _requireUnusedAuthorization(authorizer, nonce);
    }

    function _requireUnusedAuthorization(address authorizer, bytes32 nonce) private view {
        if (_authorizationStates[authorizer][nonce]) {
            revert AuthorizationUsedOrCanceled(authorizer, nonce);
        }
    }

    function _requireValidSignature(address signer, bytes32 structHash, bytes memory signature) private view {
        (address recovered, ECDSA.RecoverError error_,) = ECDSA.tryRecover(_hashTypedDataV4(structHash), signature);
        if (error_ != ECDSA.RecoverError.NoError || recovered != signer) {
            revert InvalidSignature();
        }
    }

    function _markAuthorizationAsUsed(address authorizer, bytes32 nonce) private {
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }
}
