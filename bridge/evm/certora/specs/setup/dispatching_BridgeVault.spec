using MockWBTC as MockWBTC;
using WETH as WETH;

methods {
    // Be careful that this doesn't summarize any other calls...
    function _.transfer(address a, uint256 v) external => DISPATCHER(true);
}
