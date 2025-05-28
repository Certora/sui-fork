using MockUSDC as MockUSDC;
using WETH as WETH;

methods {
    function _.proxiableUUID() external => NONDET;
}

hook Sload address a BridgeConfig.supportedTokens[KEY uint8 tokenID].tokenAddress {
    if (tokenID == 0) {
        require(a == MockUSDC);
    } else if (tokenID == 1) {
        require(a == WETH);
    }
}
hook Sload uint8 dec BridgeConfig.supportedTokens[KEY uint8 tokenID].suiDecimal {
    if (tokenID == 0) {
        require(dec == MockUSDC.decimals());
    } else if (tokenID == 1) {
        require(dec == WETH.decimals());
    }
}
hook Sload bool native BridgeConfig.supportedTokens[KEY uint8 tokenID].native {
    if (tokenID == 0) {
        require(native == false);
    } else if (tokenID == 1) {
        require(native == false);
    }
}
