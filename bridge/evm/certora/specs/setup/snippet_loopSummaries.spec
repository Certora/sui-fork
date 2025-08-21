// summarizes loops that are too long
// Should become obsolete with https://certora.atlassian.net/browse/CERT-8747
methods {

    function _.chainHourlyTransferAmount(uint256 chainHourTimestamp) external envfree;
    function _.getChainHourTimestampKey(uint8 chainID, uint32 hourTimestamp) external envfree;

    function _.calculateWindowAmount(uint8 chainID) external with(env e) => CVL_calculateWindowAmount(e, executingContract, chainID) expect (uint256);
    function _.calculateWindowAmount(uint8 chainID) internal with(env e) => CVL_calculateWindowAmount(e, executingContract, chainID) expect (uint256);
}

function CVL_calculateWindowAmount(env e, address caller, uint8 chainID) returns uint256 {
    uint32 ch = caller.currentHour(e);
    return require_uint256(
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, ch)) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 1))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 2))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 3))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 4))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 5))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 6))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 7))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 8))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 9))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 10))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 11))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 12))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 13))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 14))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 15))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 16))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 17))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 18))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 19))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 20))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 21))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 22))) +
        caller.chainHourlyTransferAmount(e, caller.getChainHourTimestampKey(e, chainID, require_uint32(ch - 23)))
    );
}
