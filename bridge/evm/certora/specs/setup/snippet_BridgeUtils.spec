// summarizes decoding functions
// we might need to force them to behave like a function instead of a NONDET
methods {
    function BridgeUtils.decodeBlocklistPayload(bytes memory _payload) internal
        returns (bool, address[] memory)
        => CVL_decodedBlocklistPayload();

    function BridgeUtils.decodeTokenTransferPayload(bytes memory _payload) internal
        returns (BridgeUtils.TokenTransferPayload memory)
        => CVL_decodedTokenTransferPayload();
    
    function BridgeUtils.decodeUpgradePayload(bytes memory _payload) internal
        returns (address, address, bytes memory)
        => CVL_decodeUpgradePayload();
}

function CVL_decodedBlocklistPayload() returns (bool, address[]) {
    bool blocklisted;
    address[] members;
    return (blocklisted, members);
}

function CVL_decodedTokenTransferPayload() returns BridgeUtils.TokenTransferPayload {
    BridgeUtils.TokenTransferPayload res;
    return res;
}

function CVL_decodeUpgradePayload() returns (address, address, bytes) {
    address proxy;
    address implementation;
    bytes callData;
    return (proxy, implementation, callData);
}
