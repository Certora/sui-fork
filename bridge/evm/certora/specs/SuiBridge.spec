import "MockTokens.spec";
import "snippet_BridgeUtils.spec";
import "snippet_loopSummaries.spec";
import "snippet_uups.spec";
import "snippet_verifySignatures.spec";

using BridgeConfig as BridgeConfig;
using BridgeVault as BridgeVault;
using BridgeUtilsHarness as BridgeUtilsHarness;

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
    function BridgeConfig.tokenSuiDecimalOf(uint8 tokenID) external returns (uint8) envfree;
    function SuiBridgeHarness.isTransferProcessed(uint64 nonce) external returns (bool) envfree;

    function BridgeUtilsHarness.ETH() external returns (uint8) envfree;
    function BridgeUtilsHarness.TOKEN_TRANSFER() external returns (uint8) envfree;
    function BridgeUtilsHarness.EMERGENCY_OP() external returns (uint8) envfree;
    function BridgeUtilsHarness.decodeTokenTransferPayloadWrapper(bytes _payload) external returns (BridgeUtils.TokenTransferPayload) envfree;
    function BridgeUtilsHarness.decodeEmergencyOpPayloadWrapper(bytes _payload) external returns (bool) envfree;
    function BridgeUtilsHarness.convertERC20ToSuiDecimalWrapper(uint8 erc20Decimal, uint8 suiDecimal, uint256 amount) external returns (uint64) envfree;
    function BridgeUtilsHarness.convertSuiToERC20DecimalWrapper(uint8 erc20Decimal, uint8 suiDecimal, uint64 amount) external returns (uint256) envfree;

    function BridgeVault.owner() external returns (address) envfree;
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
    if (t1 == to_bytes32(0xa0f1d54820817ede8517e70a3d0a9197c015471c5360d2119b759f0359858ce6)
        && executingContract == currentContract) {
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

rule nonReentrant_status_preserved(method f)
{
    env e;
    calldataarg args;

    requireInvariant reentrancyguard_valid();
    require currentContract.ext_openzeppelin_storage_Initializable._initialized > 0, "Contract is initialized";

    uint256 statusBefore = currentContract.ext_openzeppelin_storage_ReentrancyGuard._status;
    f(e,args);
    uint256 statusAfter = currentContract.ext_openzeppelin_storage_ReentrancyGuard._status;
    assert statusBefore == statusAfter;
}

rule nonReentrant_functions(method f)
filtered {
    f -> f.selector == sig:bridgeERC20(uint8,uint256,bytes,uint8).selector
        || f.selector == sig:bridgeETH(bytes,uint8).selector
        || f.selector == sig:transferBridgedTokensWithSignatures(bytes[],BridgeUtils.Message).selector
}
{
    env e;
    calldataarg args;

    requireInvariant reentrancyguard_valid();

    unprotectedReentrancy = false;
    uint256 statusBefore = currentContract.ext_openzeppelin_storage_ReentrancyGuard._status;
    f(e,args);
    uint256 statusAfter = currentContract.ext_openzeppelin_storage_ReentrancyGuard._status;
    assert statusBefore == ReentrancyGuard_NOT_ENTERED() && statusAfter == statusBefore;
    assert !unprotectedReentrancy;
}

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
    address token;
    address balanceAddress;

    uint256 balanceBefore = CVL_balanceOf(token, balanceAddress);
    uint256 nativeBalanceBefore = nativeBalances[balanceAddress];
    bool pausedBefore = currentContract.ext_openzeppelin_storage_Pausable._paused;
    bool processedBefore = currentContract.isTransferProcessed(nonce);
    currentContract.transferBridgedTokensWithSignatures(e, signatures, message);
    uint256 balanceAfter = CVL_balanceOf(token, balanceAddress);
    uint256 nativeBalanceAfter = nativeBalances[balanceAddress];
    bool processedAfter = currentContract.isTransferProcessed(nonce);

    BridgeUtils.TokenTransferPayload tokenTransferPayload;
    tokenTransferPayload =
        BridgeUtilsHarness.decodeTokenTransferPayloadWrapper@withrevert(message.payload);
    assert !lastReverted;
    
    require token == BridgeConfig.tokenAddressOf(tokenTransferPayload.tokenID),
        "assume we picked right token in the beginning";
    uint256 amount = BridgeUtilsHarness.convertSuiToERC20DecimalWrapper(
        CVL_decimals(token), BridgeConfig.tokenSuiDecimalOf(tokenTransferPayload.tokenID), 
        tokenTransferPayload.amount);
    // check that token balances change correctly
    if (tokenTransferPayload.tokenID == BridgeUtilsHarness.ETH()) {
        // Note that we also assume that the bridge is configured correctly, i.e. WETH is the token for tokenID ETH().
        require token == WETH, "This will always transfer WETH, regardless of BridgeConfig";
        if (tokenTransferPayload.recipientAddress == BridgeVault ||
            tokenTransferPayload.recipientAddress == WETH) {
            // Sending ETH to the vault or to the WETH contract will deposit them as WETH again.
            // Therefore, no balance change.
            assert balanceAfter == balanceBefore;
            assert nativeBalanceAfter == nativeBalanceBefore;
        } else {
            if (balanceAddress == BridgeVault) {
                assert balanceAfter == balanceBefore - amount;
            } else {
                assert balanceAfter == balanceBefore;
            }
            if (balanceAddress == tokenTransferPayload.recipientAddress) {
                assert nativeBalanceAfter == nativeBalanceBefore + amount;
            } else if (balanceAddress == WETH) {
                assert nativeBalanceAfter == nativeBalanceBefore - amount;
            } else {
                assert nativeBalanceAfter == nativeBalanceBefore;
            }        
        }
    } else {
        assert nativeBalanceBefore == nativeBalanceAfter;
        if (BridgeVault == tokenTransferPayload.recipientAddress) {
            assert balanceBefore == balanceAfter;
        } else if (balanceAddress == tokenTransferPayload.recipientAddress) {
            assert balanceAfter == balanceBefore + amount;
        } else if (balanceAddress == BridgeVault) {
            assert balanceAfter == balanceBefore - amount;
        } else {
            assert balanceAfter == balanceBefore;
        }
    }

    assert !pausedBefore;
    assert !processedBefore;
    assert processedAfter;
    assert BridgeConfig.isChainSupported(message.chainID);
    assert BridgeConfig.chainID() == tokenTransferPayload.targetChain;
    assert BridgeConfig.isTokenSupported(tokenTransferPayload.tokenID);
    assert verifySignaturesSuccessful;
    assert verifySignaturesMessageType == BridgeUtilsHarness.TOKEN_TRANSFER();
}

rule bridgeERC20_integrity {
    env e;
    uint8 tokenId;
    address token = BridgeConfig.tokenAddressOf(tokenId);
    uint256 amount;
    bytes recipient;
    uint8 destChainId;

    numTokenDepositedLogs = 0;
    bool pausedBefore = currentContract.ext_openzeppelin_storage_Pausable._paused;
    uint64 transferNonceBefore = currentContract.nonces[0];
    currentContract.bridgeERC20(e, tokenId, amount, recipient, destChainId);
    uint64 transferNonceAfter = currentContract.nonces[0];

    assert !pausedBefore;
    assert recipient.length == 32;
    assert BridgeConfig.isChainSupported(destChainId);
    assert BridgeConfig.isTokenSupported(tokenId);
    assert amount > 0;
    assert transferNonceAfter == transferNonceBefore + 1;
    assert numTokenDepositedLogs == 1, "there should be exactly one TokensDeposited event";
}

rule bridgeETH_integrity {
    env e;
    bytes recipient;
    uint8 destChainId;

    numTokenDepositedLogs = 0;
    bool pausedBefore = currentContract.ext_openzeppelin_storage_Pausable._paused;
    uint64 transferNonceBefore = currentContract.nonces[0];
    currentContract.bridgeETH(e, recipient, destChainId);
    uint64 transferNonceAfter = currentContract.nonces[0];

    assert !pausedBefore;
    assert recipient.length == 32;
    assert BridgeConfig.isChainSupported(destChainId);
    assert e.msg.value > 0;
    assert transferNonceAfter == transferNonceBefore + 1;
    assert numTokenDepositedLogs == 1; 
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


rule only_transferBridgedTokens_can_remove_tokens(method f) 
filtered {
    f -> f.selector != sig:transferBridgedTokensWithSignatures(bytes[],BridgeUtils.Message).selector &&
         f.contract != WETH && // ignore calling transferFrom or transfer on the token directly
         f.contract != BridgeVault // ignore calling the BridgeVault functions that are protected by ownership
}
{
    env e;
    calldataarg args;
    address token;

    // Exclude the counterexamples where someone impersonates the contract and uses the Vault's functions to transfer.
    require e.msg.sender != currentContract, "SuiBridge must not be impersonated";
    require BridgeVault.owner() == currentContract, "Vault must be owned by SuiBridge";

    // prevent overflow in old WETH contract
    require(e.msg.value < 2^128, "It's impossible to own this much ETH");

    uint256 tokenBalanceBefore = CVL_balanceOf(token, BridgeVault);
    f(e, args);
    uint256 tokenBalanceAfter = CVL_balanceOf(token, BridgeVault);

    assert tokenBalanceAfter >= tokenBalanceBefore, "Tokens should stay in the vault";
}

/**
 * This rule checks all important conditions for emergency operations.
 */
rule executeEmergencyOp_integrity() {
    env e;
    bytes[] signatures;
    BridgeUtils.Message message;

    uint64 nonceBefore = currentContract.nonces[BridgeUtilsHarness.EMERGENCY_OP()];

    currentContract.executeEmergencyOpWithSignatures(e, signatures, message);

    bool pausedAfter = currentContract.ext_openzeppelin_storage_Pausable._paused;
    uint64 nonceAfter = currentContract.nonces[BridgeUtilsHarness.EMERGENCY_OP()];

    bool isFreezing = BridgeUtilsHarness.decodeEmergencyOpPayloadWrapper@withrevert(message.payload);
    assert !lastReverted;
    
    assert pausedAfter == isFreezing;
    assert nonceBefore == message.nonce;
    assert nonceAfter > message.nonce;
    assert verifySignaturesSuccessful;
    assert verifySignaturesMessageType == BridgeUtilsHarness.EMERGENCY_OP();
}

rule only_emergency_operation_changes_pause_status(method f)
filtered {
    f -> f.selector != sig:executeEmergencyOpWithSignatures(bytes[],BridgeUtils.Message).selector
}
{
    env e;
    calldataarg args;

    require currentContract.ext_openzeppelin_storage_Initializable._initialized > 0, "Contract is initialized";

    bool pausedBefore = currentContract.ext_openzeppelin_storage_Pausable._paused;
    f(e, args);
    bool pausedAfter = currentContract.ext_openzeppelin_storage_Pausable._paused;

    assert pausedBefore == pausedAfter;
}
