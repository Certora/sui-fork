// summarizes loops that are too long
// Should become obsolete with https://certora.atlassian.net/browse/CERT-8747
methods {

    function chainHourlyTransferAmount(uint256 chainHourTimestamp) external returns (uint256) envfree;
    function getChainHourTimestampKey(uint8 chainID, uint32 hourTimestamp) external returns (uint256) envfree;

    function _.calculateWindowAmount(uint8 chainID) external with(env e) => CVL_calculateWindowAmount(e, chainID) expect (uint256);
    function _.calculateWindowAmount(uint8 chainID) internal with(env e) => CVL_calculateWindowAmount(e, chainID) expect (uint256);
}

function CVL_calculateWindowAmount(env e, uint8 chainID) returns uint256 {
    uint32 ch = currentHour(e);
    return require_uint256(
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, ch)) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 1))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 2))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 3))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 4))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 5))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 6))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 7))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 8))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 9))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 10))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 11))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 12))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 13))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 14))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 15))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 16))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 17))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 18))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 19))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 20))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 21))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 22))) +
        chainHourlyTransferAmount(getChainHourTimestampKey(chainID, require_uint32(ch - 23)))
    );
}
