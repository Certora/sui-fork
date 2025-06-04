import "dispatching_BridgeVault.spec";
use builtin rule sanity filtered { f ->
    f.contract == currentContract &&
    f.selector != sig:transferERC20(address,address,uint256).selector
}

rule sanity_transferERC20(env e) {
    address tokenAddress = MockWBTC;
    address recipientAddress;
    uint256 amount;

    transferERC20(e, tokenAddress, recipientAddress, amount);

    satisfy(true);
}