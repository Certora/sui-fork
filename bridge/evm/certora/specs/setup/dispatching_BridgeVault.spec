using MockWBTC as MockWBTC;

methods {
    // Be careful that this doesn't summarize any other calls...
    function _.transfer(address a, uint256 v) external with(env e) => CVL_transfer(e,a,v) expect void;
}

function CVL_transfer(env e, address a, uint256 v) {
    MockWBTC.transfer(e, a, v);
}
