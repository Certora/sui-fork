using WETH9 as WETH;

methods {
    function BridgeVault.owner() external returns address envfree;
    function WETH.decimals() external returns (uint8) envfree;
    function WETH.balanceOf(address a) external returns (uint256) envfree;


    // Be careful that this doesn't summarize any other calls...
    function _.decimals() external => CVL_decimals(calledContract) expect uint8;
    function _.balanceOf(address a) external => CVL_balanceOf(calledContract, a) expect uint256;
    function _.transfer(address a, uint256 v) external with(env e) => CVL_transferFrom(e, calledContract, e.msg.sender, a, v) expect bool;
    function _.transferFrom(address src, address a, uint256 v) external with(env e) => CVL_transferFrom(e, calledContract, src, a, v) expect bool;
}

ghost mapping(address => mapping(address => uint256)) tokenBalances;
ghost address lastTransferredToken;

/* This hook ensures that the WETH balance is not unreasonably large to cause
 * overflows in the WETH contract itself.  As long as there are no more than a
 * few quintillion eth in existence, this will always be true.
 *
 * Since WETH9 is compiled with solidity 0.4, we need to encode the offset
 * manually.  slot 3 is the balanceOf mapping:
 * 0=name, 1=symbol, 2=decimals, 3=balanceOf, 4=allowance.
 */
hook Sload uint256 v WETH.(slot 3)[KEY address a] {
    require(v < 2^128, "It's impossible to own this much WETH");
}

ghost CVL_decimals(address) returns uint8 {
    axiom CVL_decimals(WETH) == 18;
}

function CVL_balanceOf(address token, address a) returns uint256 {
    if (token == WETH) {
        uint256 amount = WETH.balanceOf(a);
        //require(amount < 2^128, "It's impossible to own this much WETH");
        return amount;
    } else {
        return tokenBalances[token][a];
    }
}

function CVL_transferFrom(env e, address token, address src, address dest, uint256 value) returns bool {
    lastTransferredToken = token;
    if (token == WETH) {
        return WETH.transferFrom(e, src, dest, value);
    } else {
        if (tokenBalances[token][src] < value || tokenBalances[token][dest] + value >= 2^256) {
            revert();
        }
        tokenBalances[token][src] = assert_uint256(tokenBalances[token][src] - value);
        tokenBalances[token][dest] = assert_uint256(tokenBalances[token][dest] + value);
        return true;
    }
}
