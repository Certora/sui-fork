using MockWBTC as MockWBTC;
using WETH as WETH;

methods {
    // Be careful that this doesn't summarize any other calls...
    function _.transfer(address a, uint256 v) external with(env e) => CVL_transfer(e,calledContract,a,v) expect void;
}

function CVL_transfer(env e, address token, address a, uint256 v) {
    if (token == MockWBTC) {
        MockWBTC.transfer(e, e.msg.sender, a, v);
        return;
    } else if (token == WETH) {
        WETH.transfer(e, e.msg.sender, a, v);
        return;
    } else {
        revert();
    }
}
