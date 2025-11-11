// summarizes decoding functions
// we might need to force them to behave like a function instead of a NONDET
methods {
    function BridgeUtils.decodeBlocklistPayload(bytes memory _payload) internal
        returns (bool, address[] memory)
        => CVL_decodedBlocklistPayload(_payload);

    function BridgeUtils.decodeTokenTransferPayload(bytes memory _payload) internal
        returns (BridgeUtils.TokenTransferPayload memory)
        => CVL_decodedTokenTransferPayload(_payload);
    
    function BridgeUtils.decodeUpgradePayload(bytes memory _payload) internal
        returns (address, address, bytes memory)
        => CVL_decodeUpgradePayload(_payload);

    function BridgeUtils.decodeAddTokensPayload(bytes memory _payload) internal
        returns (bool, uint8[] memory, address[] memory, uint8[] memory, uint64[] memory)
        => CVL_decodeAddTokensPayload(_payload);
}

function CVL_decodedBlocklistPayload(bytes payload) returns (bool, address[]) {
    bool blocklisted;
    address[] members;
    return (blocklisted, members);
}

ghost CVL_decodeTokenTransferReverts(bytes) returns bool;
//ghost CVL_decodeTokenTransferSenderAddress(bytes) returns bytes;
ghost CVL_decodeTokenTransferTargetChain(bytes) returns uint8;
ghost CVL_decodeTokenTransferRecipientAddress(bytes) returns address;
ghost CVL_decodeTokenTransferTokenID(bytes) returns uint8;
ghost CVL_decodeTokenTransferAmount(bytes) returns uint64;
function CVL_decodedTokenTransferPayload(bytes payload) returns BridgeUtils.TokenTransferPayload
{
    BridgeUtils.TokenTransferPayload res;
    if (CVL_decodeTokenTransferReverts(payload)) {
        revert();
    }
    require res.senderAddressLength == 32, "see code";
    //require res.senderAddress == CVL_decodeTokenTransferSenderAddress(payload);
    require res.targetChain == CVL_decodeTokenTransferTargetChain(payload), "make ghost";
    require res.recipientAddressLength == 20, "see code";
    require res.recipientAddress == CVL_decodeTokenTransferRecipientAddress(payload), "make ghost";
    require res.tokenID == CVL_decodeTokenTransferTokenID(payload), "make ghost";
    require res.amount == CVL_decodeTokenTransferAmount(payload), "make ghost";
    return res;
}

function CVL_decodeUpgradePayload(bytes payload) returns (address, address, bytes) {
    address proxy;
    address implementation;
    bytes callData;
    return (proxy, implementation, callData);
}

function CVL_decodeAddTokensPayload(bytes payload) returns (bool, uint8[], address[], uint8[], uint64[]) {
    bool native;
    uint8[] tokenIDs;
    address[] tokenAddresses;
    uint8[] suiDecimals;
    uint64[] tokenPrices;
    return (native, tokenIDs, tokenAddresses, suiDecimals, tokenPrices);
}

// function CVL_decodedBlocklistPayload(bytes) returns (bool, address[]);

// function CVL_decodedTokenTransferPayload(bytes) returns BridgeUtils.TokenTransferPayload;

// function CVL_decodeUpgradePayload(bytes) returns (address, address, bytes);

// function CVL_decodeAddTokenPayload(bytes) returns (bool, uint8[], address[], uint8[], uint64[]);
