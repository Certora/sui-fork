methods {
    function _.transfer(address a, uint256 v) external => DISPATCHER(true);
    function _.transferFrom(address s, address a, uint256 v) external => DISPATCHER(true);
    function _.balanceOf(address a) external => DISPATCHER(true);
}
