using MockWBTC as MockWBTC;
using MockUSDC as MockUSDC;
using MockUSDT as MockUSDT;
using WETH as WETH;
using BridgeUtilsHarness as BridgeUtilsHarness;

methods {
    function BridgeUtilsHarness.SUI() external returns (uint8) envfree;
    function BridgeUtilsHarness.BTC() external returns (uint8) envfree;
    function BridgeUtilsHarness.ETH() external returns (uint8) envfree;
    function BridgeUtilsHarness.USDC() external returns (uint8) envfree;
    function BridgeUtilsHarness.USDT() external returns (uint8) envfree;
    function MockWBTC.decimals() external returns (uint8) envfree;
    function MockUSDC.decimals() external returns (uint8) envfree;
    function MockUSDT.decimals() external returns (uint8) envfree;
    function WETH.decimals() external returns (uint8) envfree;
    function _.proxiableUUID() external => NONDET;
}

hook Sload address a BridgeConfig.supportedTokens[KEY uint8 tokenID].tokenAddress {
    if (tokenID == BridgeUtilsHarness.SUI()) {
    } else if (tokenID == BridgeUtilsHarness.BTC()) {
        require(a == MockWBTC);
    } else if (tokenID == BridgeUtilsHarness.ETH()) {
        require(a == WETH);
    } else if (tokenID == BridgeUtilsHarness.USDC()) {
        require(a == MockUSDC);
    } else if (tokenID == BridgeUtilsHarness.USDT()) {
        require(a == MockUSDT);
    }
}
hook Sload uint8 dec BridgeConfig.supportedTokens[KEY uint8 tokenID].suiDecimal {
    if (tokenID == BridgeUtilsHarness.SUI()) {
    } else if (tokenID == BridgeUtilsHarness.BTC()) {
        require(dec == MockWBTC.decimals());
    } else if (tokenID == BridgeUtilsHarness.ETH()) {
        require(dec == WETH.decimals());
    } else if (tokenID == BridgeUtilsHarness.USDC()) {
        require(dec == MockUSDC.decimals());
    } else if (tokenID == BridgeUtilsHarness.USDT()) {
        require(dec == MockUSDT.decimals());
    }
}
hook Sload bool native BridgeConfig.supportedTokens[KEY uint8 tokenID].native {
    if (tokenID == BridgeUtilsHarness.SUI()) {
    } else if (tokenID == BridgeUtilsHarness.BTC()) {
        require(native == false);
    } else if (tokenID == BridgeUtilsHarness.ETH()) {
        require(native == false);
    } else if (tokenID == BridgeUtilsHarness.USDC()) {
        require(native == false);
    } else if (tokenID == BridgeUtilsHarness.USDT()) {
        require(native == false);
    }
}
