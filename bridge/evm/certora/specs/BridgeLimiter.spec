import "MockTokens.spec";
import "snippet_BridgeUtils.spec";
import "snippet_loopSummaries.spec";
import "snippet_uups.spec";
import "snippet_timestamp.spec";
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

    function BridgeLimiter.chainLimits(uint8 chainID) external returns (uint64) envfree;
    function BridgeLimiter.getChainHourTimestampKey(uint8 chainID, uint32 hourTimestamp) external returns (uint256) envfree;
    function BridgeLimiter.chainHourlyTransferAmount(uint256 timestampKey) external returns (uint256) envfree;
    function BridgeConfig.chainID() external returns (uint8) envfree;
    function BridgeConfig.isChainSupported(uint8 chainId) external returns (bool) envfree;
    function BridgeConfig.isTokenSupported(uint8 tokenID) external returns (bool) envfree;
    function BridgeConfig.tokenAddressOf(uint8 tokenID) external returns (address) envfree;
    function BridgeConfig.tokenSuiDecimalOf(uint8 tokenID) external returns (uint8) envfree;

    function BridgeUtilsHarness.UPDATE_BRIDGE_LIMIT() external returns (uint8) envfree;
    function BridgeUtilsHarness.decodeUpdateLimitPayloadWrapper(bytes _payload) external returns (uint8, uint64) envfree;
    function BridgeUtilsHarness.convertERC20ToSuiDecimalWrapper(uint8 erc20Decimal, uint8 suiDecimal, uint256 amount) external returns (uint64) envfree;
    function BridgeUtilsHarness.convertSuiToERC20DecimalWrapper(uint8 erc20Decimal, uint8 suiDecimal, uint64 amount) external returns (uint256) envfree;

    function BridgeVault.owner() external returns (address) envfree;
}

invariant hourlyTransferAmountsZeroForFuture(uint8 chainId, uint32 hour) 
    hour > lastTimestamp/hour() => currentContract.chainHourlyTransferAmount(currentContract.getChainHourTimestampKey(chainId, hour)) == 0;

invariant chainLimitsNotExceeded(uint8 chainId, uint32 hour)
    CVL_calculateWindowAmountForHour(currentContract, chainId, hour) <= chainLimits(chainId)
/* the intializer can only be called during initialization; we could reason about it, but then we still get 
 * sanity errors, since it cannot be called.  The updateLimitWithSignatures can violate this property, if the
 * validators choose to set the limit too low.  That is not a problem and after 24 hours the property holds again.
 */ 
filtered { f-> f.selector != sig:initialize(address,uint8[],uint64[]).selector &&
               f.selector != sig:updateLimitWithSignatures(bytes[], BridgeUtils.Message).selector }
{
    preserved BridgeLimiter.recordBridgeTransfers(uint8 chainId2, uint8 tokenId, uint256 amount) with (env e) {
        /* Since recordBridgeTransfer only checks the limit for the current hour, not for future hours,
         * we require the invariant that all hourly transfers that lie in the future are 0.
         * We need this invariant for all hours that are accessed by the second calculateWindowAmount call
         * (from hour-23 to hour).
         */
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-1));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-2));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-3));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-4));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-5));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-6));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-7));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-8));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-9));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-10));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-11));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-12));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-13));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-14));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-15));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-16));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-17));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-18));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-19));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-20));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-21));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-22));
        requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(hour-23));
    }
}

rule recordBridgeTransfers_integrity {
    env e;
    uint8 chainId;
    uint8 tokenId;
    uint256 amount;

    uint256 windowBefore = calculateWindowAmount(e, chainId);
    uint256 tokenAmountInUSD = calculateAmountInUSD(e, tokenId, amount);
    recordBridgeTransfers(e, chainId, tokenId, amount);
    uint256 windowAfter = calculateWindowAmount(e, chainId);

    assert windowAfter == windowBefore + tokenAmountInUSD;
    assert windowAfter <= chainLimits(chainId);
}

rule windowAmountCannotDecreaseWithoutPassingTime {
    env e1;
    env e2;
    env e3;
    method f;
    calldataarg args;
    uint8 chainId;
    uint8 tokenId;
    uint256 amount;

    uint256 windowBefore = calculateWindowAmount(e1, chainId);
    f(e2, args);
    uint256 windowAfter = calculateWindowAmount(e3, chainId);

    assert e1.block.timestamp == e3.block.timestamp => windowAfter >= windowBefore;
}

rule windowDecreasesOverTime {
    env e1;
    env e2;
    uint8 chainId;
    /* For this rule, we require the invariant that all hourly transfers that lie in the future are 0.
     * We need this invariant for all hours that are accessed by the second caculateWindowAmount call,
     * which are for the hour of the timestamp in e2 and the previous 24 hours.
     */
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-1));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-2));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-3));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-4));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-5));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-6));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-7));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-8));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-9));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-10));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-11));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-12));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-13));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-14));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-15));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-16));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-17));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-18));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-19));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-20));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-21));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-22));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-23));
    requireInvariant hourlyTransferAmountsZeroForFuture(chainId, require_uint32(e2.block.timestamp/hour()-24));

    uint256 windowBefore = calculateWindowAmount(e1, chainId);
    uint256 windowAfter = calculateWindowAmount(e2, chainId);

    assert windowAfter <= windowBefore;
    satisfy windowAfter < windowBefore;
}

/**
 * This rule checks all important conditions for updating the limit.
 */
rule updateLimit_integrity() {
    env e;
    bytes[] signatures;
    BridgeUtils.Message message;
    uint64 nonce = message.nonce;
    address token;
    address balanceAddress;

    uint8 sourceChainId;
    uint64 newLimit;

    sourceChainId, newLimit = BridgeUtilsHarness.decodeUpdateLimitPayloadWrapper(message.payload);

    uint64 expectedNonce = currentContract.nonces[BridgeUtilsHarness.UPDATE_BRIDGE_LIMIT()];
    currentContract.updateLimitWithSignatures(e, signatures, message);
    uint64 limitAfter = currentContract.chainLimits[sourceChainId];

    assert nonce == expectedNonce;
    assert currentContract.nonces[BridgeUtilsHarness.UPDATE_BRIDGE_LIMIT()] == expectedNonce + 1;
    assert BridgeConfig.isChainSupported(sourceChainId);
    assert newLimit == limitAfter;
    assert chainLimits(sourceChainId) == newLimit;
    assert verifySignaturesSuccessful;
    assert verifySignaturesMessageType == BridgeUtilsHarness.UPDATE_BRIDGE_LIMIT();
}


rule onlyInitializeAndUpdateLimitChangeLimit(method f)
filtered { f-> f.selector != sig:initialize(address,uint8[],uint64[]).selector &&
               f.selector != sig:updateLimitWithSignatures(bytes[], BridgeUtils.Message).selector }
{
    env e;
    calldataarg args;
    uint8 chainID;

    uint64 limitBefore = currentContract.chainLimits(chainID);
    f(e, args);
    uint64 limitAfter = currentContract.chainLimits(chainID);

    assert limitAfter == limitBefore;
}
