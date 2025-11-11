using BridgeLimiter as BridgeLimiter;

methods {
    function BridgeLimiter.chainHourlyTransferAmount(uint256 timestampKey) external returns uint256 envfree;
    function BridgeLimiter.getChainHourTimestampKey(uint8 chainID, uint32 hourTimestamp) external returns uint256 envfree;
    function _.calculateWindowAmount(uint8 chainID) external with(env e) => CVL_calculateWindowAmount(e, executingContract, chainID) expect (uint256);
    function _.calculateWindowAmount(uint8 chainID) internal with(env e) => CVL_calculateWindowAmount(e, executingContract, chainID) expect (uint256);
}

/**
 * The calculateWindowAmount iterates over the last 24 hours. It's not feasible
 * to increase the loop iter to 24, hence we manually unroll it in this summary.
 * Might become obsolete with https://certora.atlassian.net/browse/CERT-8747
 */
function CVL_calculateWindowAmountForHour(address caller, uint8 chainID, uint32 ch) returns uint256 {
    return require_uint256(
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, ch)) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 1))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 2))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 3))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 4))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 5))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 6))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 7))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 8))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 9))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 10))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 11))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 12))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 13))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 14))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 15))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 16))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 17))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 18))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 19))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 20))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 21))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 22))) +
        BridgeLimiter.chainHourlyTransferAmount(BridgeLimiter.getChainHourTimestampKey(chainID, require_uint32(ch - 23)))
    );
}

function CVL_calculateWindowAmount(env e, address caller, uint8 chainID) returns uint256 {
    uint32 ch = BridgeLimiter.currentHour(e);
    return CVL_calculateWindowAmountForHour(caller, chainID, ch);
}
