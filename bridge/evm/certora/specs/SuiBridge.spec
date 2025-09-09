import "MockTokens.spec";
import "snippet_BridgeUtils.spec";
import "setup/snippet_loopSummaries.spec";
import "setup/snippet_uups.spec";

using BridgeConfig as BridgeConfig;
using BridgeVault as BridgeVault;

methods {
    function BridgeVault.owner() external returns address envfree;

    // Be careful that this doesn't summarize any other calls...
    //function _.balanceOf(address a) external with(env e) => CVL_balanceOf(e, calledContract, a) expect uint256;
    //function _.transfer(address a, uint256 v) external with(env e) => CVL_transferFrom(e, calledContract, e.msg.sender, a, v) expect bool;
    //function _.transferFrom(address src, address a, uint256 v) external with(env e) => CVL_transferFrom(e, calledContract, src, a, v) expect bool;

    function BridgeConfig.chainID() external returns (uint8) envfree;
    function BridgeConfig.isChainSupported(uint8 chainId) external returns (bool) envfree;
    function BridgeConfig.isTokenSupported(uint8 tokenID) external returns (bool) envfree;
    function BridgeConfig.tokenAddressOf(uint8 tokenID) external returns (address) envfree;
    function SuiBridgeHarness.isTransferProcessed(uint64 nonce) external returns (bool) envfree;
}

definition ReentrancyGuard_NOT_ENTERED() returns uint256 = 1;
definition ReentrancyGuard_ENTERED() returns uint256 = 2;

ghost bool unprotectedReentrancy;

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (currentContract.ext_openzeppelin_storage_ReentrancyGuard._status != ReentrancyGuard_ENTERED()) {
        unprotectedReentrancy = true;
    }
}

hook DELEGATECALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (currentContract.ext_openzeppelin_storage_ReentrancyGuard._status != ReentrancyGuard_ENTERED()) {
        unprotectedReentrancy = true;
    }
}

ghost mathint numTokenDepositedLogs;
ghost mathint depositedLogSourceChainID;
ghost mathint depositedLogNonce;
ghost mathint depositedLogDestinationChainID;

hook LOG4(uint offset, uint length, bytes32 t1, bytes32 t2, bytes32 t3, bytes32 t4)
{
    if (t1 == to_bytes32(0xa0f1d54820817ede8517e70a3d0a9197c015471c5360d2119b759f0359858ce6)) {
        numTokenDepositedLogs = numTokenDepositedLogs + 1;
        depositedLogSourceChainID = assert_uint256(t2);
        depositedLogNonce = assert_uint256(t3);
        depositedLogDestinationChainID = assert_uint256(t4);
    }
}


invariant reentrancyguard_not_entered() 
    currentContract.ext_openzeppelin_storage_ReentrancyGuard._status == ReentrancyGuard_NOT_ENTERED();

strong invariant reentrancyguard_valid() 
    currentContract.ext_openzeppelin_storage_ReentrancyGuard._status == ReentrancyGuard_ENTERED()
    || currentContract.ext_openzeppelin_storage_ReentrancyGuard._status == ReentrancyGuard_NOT_ENTERED();

/**
 * Check that nonces will only increase and by at most one per operation.
 * Nonces are used for outgoing transfers to give every transfer a different
 * nonce.  They are also used for messages to ensure they are processed in 
 * the correct order.  If they would ever decrease this would violate both
 * use cases.
 */
rule nonces_only_increase(method f) {
    env e;
    calldataarg args;
    uint8 msgType;
    uint256 nonceBefore = currentContract.nonces[msgType];
    f(e, args);
    uint256 nonceAfter = currentContract.nonces[msgType];

    assert nonceBefore <= nonceAfter, "nonces always increase";
    assert nonceAfter <= nonceBefore + 1, "nonces increase by at most 1 per operation";
}

/**
 * Check that a transfer cannot get unprocessed.  We later check that
 * a transfer is only successful if it hasn't beend processed and that
 * it will set the processed flags.  All three together ensure that every
 * transfer is processed at most once.
 */
rule processed_nonces_monotonic(method f) {
    env e;
    calldataarg args;
    uint64 nonce;

    bool processedBefore = currentContract.isTransferProcessed(nonce);
    f(e, args);
    bool processedAfter = currentContract.isTransferProcessed(nonce);

    assert processedBefore => processedAfter, "nonces never get unprocessed";
}

/**
 * This rule checks all important conditions for successful transfers.
 */
rule transferBridgedTokens_integrity() {
    env e;
    bytes[] signatures;
    BridgeUtils.Message message;
    uint64 nonce = message.nonce;

    bool processedBefore = currentContract.isTransferProcessed(nonce);
    currentContract.transferBridgedTokensWithSignatures(e, signatures, message);
    bool processedAfter = currentContract.isTransferProcessed(nonce);

    //BridgeUtils.TokenTransferPayload tokenTransferPayload =
    //    currentContract.decodeTokenTransferPayloadWrapper@withrevert(message.payload);
    //assert !lastReverted;

    assert !processedBefore;
    assert processedAfter;
    assert BridgeConfig.isChainSupported(message.chainID);
    //assert BridgeConfig.chainID() == tokenTransferPayload.targetChain;
    //assert BridgeConfig.isTokenSupported(tokenTransferPayload.tokenID);
}

rule bridgeERC20_integrity {
    env e;
    uint8 tokenId;
    address token = BridgeConfig.tokenAddressOf(tokenId);
    uint256 amount;
    bytes recipient;
    uint8 destChainId;

    uint64 transferNonceBefore = currentContract.nonces[0];
    currentContract.bridgeERC20(e, tokenId, amount, recipient, destChainId);
    uint64 transferNonceAfter = currentContract.nonces[0];


    assert recipient.length == 32;
    assert BridgeConfig.isChainSupported(destChainId);
    assert BridgeConfig.isTokenSupported(tokenId);
    assert amount > 0;
    assert transferNonceAfter == transferNonceBefore + 1;
}

rule bridgeETH_integrity {
    env e;
    bytes recipient;
    uint8 destChainId;

    uint64 transferNonceBefore = currentContract.nonces[0];
    currentContract.bridgeETH(e, recipient, destChainId);
    uint64 transferNonceAfter = currentContract.nonces[0];


    assert recipient.length == 32;
    assert BridgeConfig.isChainSupported(destChainId);
    assert e.msg.value > 0;
    assert transferNonceAfter == transferNonceBefore + 1;
}



rule tokenDepositedImpliesTokenVaulted(method f) {
    env e;
    calldataarg args;
    address token;

    // reset log counter
    numTokenDepositedLogs = 0;

    // in case native tokens are send (without transfer),
    // the WETH balance should increase
    lastTransferredToken = WETH;

    // prevent overflow in old WETH contract
    require(e.msg.value < 2^128, "It's impossible to own this much ETH");


    uint256 tokenBalanceBefore = CVL_balanceOf(token, BridgeVault);
    f(e, args);
    uint256 tokenBalanceAfter = CVL_balanceOf(token, BridgeVault);

    assert numTokenDepositedLogs <= 1, "At most one token deposited";
    assert numTokenDepositedLogs == 1 && token == lastTransferredToken => 
        tokenBalanceAfter > tokenBalanceBefore, "Tokens should be transferred";
}
