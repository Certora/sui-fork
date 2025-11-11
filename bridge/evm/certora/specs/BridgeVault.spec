using WETH9 as WETH;

methods {
    function BridgeVault.owner() external returns address envfree;

    // Be careful that this doesn't summarize any other calls...
    function _.balanceOf(address a) external with(env e) => CVL_balanceOf(e, calledContract, a) expect uint256;
    function _.transfer(address a, uint256 v) external with(env e) => CVL_transferFrom(e, calledContract, e.msg.sender, a, v) expect bool;
    function _.transferFrom(address src, address a, uint256 v) external with(env e) => CVL_transferFrom(e, calledContract, src, a, v) expect bool;
}

definition ReentrancyGuard_NOT_ENTERED() returns uint256 = 1;
definition ReentrancyGuard_ENTERED() returns uint256 = 2;

ghost mapping(address => mapping(address => uint256)) tokenBalances;
ghost bool unprotectedReentrancy;
ghost bool vaultApprovedWeth {
    init_state axiom !vaultApprovedWeth;
}

hook CALL(uint g, address addr, uint value, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    if (currentContract._status != ReentrancyGuard_ENTERED()) {
        unprotectedReentrancy = true;
    }
}

hook DELEGATECALL(uint g, address addr, uint argsOffset, uint argsLength, uint retOffset, uint retLength) uint rc {
    assert false, "Unexpected DelegateCall in Vault";
}

invariant reentrancyguard_not_entered() 
    currentContract._status == ReentrancyGuard_NOT_ENTERED();

strong invariant reentrancyguard_valid() 
    currentContract._status == ReentrancyGuard_ENTERED()
    || currentContract._status == ReentrancyGuard_NOT_ENTERED();

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

/* Assert that Vault never sets any allowance (on writing to WETH storage.
 * slot 4 is allowance.
 */
hook Sstore WETH.(slot 4)[KEY address owner][KEY address spender] uint256 allowance {
    if (owner == currentContract && allowance != 0) {
        vaultApprovedWeth = true;
    }
}

/* Require that Vault has never set any allowance on reading storage.  This is
 * ensured by the above store hook.
 * slot 4 is allowance.
 */
hook Sload uint256 allowance WETH.(slot 4)[KEY address owner][KEY address spender] {
    if (owner == currentContract) {
        require(allowance != 0 => vaultApprovedWeth, "Vault approved WETH");
    }
}

strong invariant vault_approval() !vaultApprovedWeth
{
    preserved with (env e) {
        require e.msg.sender != currentContract;
    }
}

function CVL_balanceOf(env e, address token, address a) returns uint256 {
    if (token == WETH) {
        uint256 amount = WETH.balanceOf(e, a);
        //require(amount < 2^128, "It's impossible to own this much WETH");
        return amount;
    } else {
        return tokenBalances[token][a];
    }
}

function CVL_transferFrom(env e, address token, address src, address dest, uint256 value) returns bool {
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

rule only_owner_can_change_ownership(method f) {
    env e;
    calldataarg args;

    address ownerBefore = currentContract.owner();
    f(e, args);
    address ownerAfter = currentContract.owner();
    assert ownerBefore != ownerAfter => e.msg.sender == ownerBefore;
}

rule only_owner_can_transfer_out(method f, address token) {
    env e;
    calldataarg args;

    requireInvariant vault_approval();
    address ownerBefore = currentContract.owner();
    mathint balanceBefore = CVL_balanceOf(e, token, currentContract);
    f(e, args);
    mathint balanceAfter = CVL_balanceOf(e, token, currentContract);
    assert balanceAfter < balanceBefore => e.msg.sender == ownerBefore || e.msg.sender == currentContract;
}

rule nonReentrant_status_preserved(method f)
{
    env e;
    calldataarg args;

    requireInvariant reentrancyguard_valid();

    uint256 statusBefore = currentContract._status;
    f(e,args);
    uint256 statusAfter = currentContract._status;
    assert statusBefore == statusAfter;
}

rule nonReentrant_functions(method f)
filtered {
    f -> f.selector == sig:transferERC20(address, address, uint256).selector
        || f.selector == sig:transferETH(address, uint256).selector
}
{
    env e;
    calldataarg args;

    requireInvariant reentrancyguard_valid();

    unprotectedReentrancy = false;
    uint256 statusBefore = currentContract._status;
    f(e,args);
    uint256 statusAfter = currentContract._status;
    assert statusBefore == ReentrancyGuard_NOT_ENTERED() && statusAfter == statusBefore;
    assert !unprotectedReentrancy;
}

rule transferERC20_integrity {
    env e;
    address token;
    address recipient;
    uint256 value;
    address balanceToken;
    address balanceAddress;


    require recipient != currentContract, "No self transfer";
    uint256 balanceBefore = CVL_balanceOf(e,  balanceToken, balanceAddress);
    uint256 nativeBalanceBefore = nativeBalances[balanceAddress];
    currentContract.transferERC20(e, token, recipient, value);
    uint256 balanceAfter = CVL_balanceOf(e,  balanceToken, balanceAddress);
    uint256 nativeBalanceAfter = nativeBalances[balanceAddress];

    mathint balanceDiff = balanceAfter - balanceBefore;
    mathint nativeBalanceDiff = nativeBalanceAfter - nativeBalanceBefore;

    assert nativeBalanceDiff == 0, "No native balance change expected";
    assert balanceToken != token =>  balanceDiff == 0, "Balance of uninvolved tokens should not change";
    assert balanceAddress != currentContract && balanceAddress != recipient => balanceDiff == 0, "Balance of uninvolved addresses should not change";
    assert balanceToken == token && balanceAddress == currentContract => balanceDiff == -value, "Balance of vault should decrease by amount";
    assert balanceToken == token && balanceAddress == recipient => balanceDiff == value, "Balance of recipient should increase by amount";
}

rule transferERC20_self {
    env e;
    address token;
    address recipient;
    uint256 value;
    address balanceToken;
    address balanceAddress;

    require recipient == currentContract, "self transfer";

    uint256 balanceBefore = CVL_balanceOf(e,  balanceToken, balanceAddress);
    uint256 nativeBalanceBefore = nativeBalances[balanceAddress];
    currentContract.transferERC20(e, token, recipient, value);
    uint256 balanceAfter = CVL_balanceOf(e,  balanceToken, balanceAddress);
    uint256 nativeBalanceAfter = nativeBalances[balanceAddress];

    mathint balanceDiff = balanceAfter - balanceBefore;
    mathint nativeBalanceDiff = nativeBalanceAfter - nativeBalanceBefore;

    assert balanceDiff == 0 && nativeBalanceDiff == 0, "No balance change expected";
}

rule transferETH_integrity {
    env e;
    address recipient;
    uint256 value;
    address balanceToken;
    address balanceAddress;

    require recipient != currentContract && recipient != WETH, "No self transfer";

    uint256 balanceBefore = CVL_balanceOf(e,  balanceToken, balanceAddress);
    uint256 nativeBalanceBefore = nativeBalances[balanceAddress];
    currentContract.transferETH(e, recipient, value);
    uint256 balanceAfter = CVL_balanceOf(e,  balanceToken, balanceAddress);
    uint256 nativeBalanceAfter = nativeBalances[balanceAddress];

    mathint balanceDiff = balanceAfter - balanceBefore;
    mathint nativeBalanceDiff = nativeBalanceAfter - nativeBalanceBefore;

    assert balanceToken != WETH => balanceDiff == 0, "Balance of uninvolved tokens should not change";
    assert balanceAddress != currentContract && balanceAddress != recipient && balanceAddress != WETH => balanceDiff == 0 && nativeBalanceDiff == 0, "Balance of uninvolved addresses should not change";
    assert balanceToken == WETH && balanceAddress == currentContract => balanceDiff == -value && nativeBalanceDiff == 0, "Balance of vault in WETH should decrease by amount";
    assert balanceAddress == recipient => balanceDiff == 0 && nativeBalanceDiff == value, "Native balance of recipient should increase by amount";
    assert balanceAddress == WETH => balanceDiff == 0 && nativeBalanceDiff == -value, "Native balance of WETH should decrease by amount";
}

rule transferETH_self {
    env e;
    address recipient;
    uint256 value;
    address balanceToken;
    address balanceAddress;

    require recipient == currentContract || recipient == WETH, "self transfer";

    uint256 balanceBefore = CVL_balanceOf(e,  balanceToken, balanceAddress);
    uint256 nativeBalanceBefore = nativeBalances[balanceAddress];
    currentContract.transferETH(e, recipient, value);
    uint256 balanceAfter = CVL_balanceOf(e,  balanceToken, balanceAddress);
    uint256 nativeBalanceAfter = nativeBalances[balanceAddress];

    mathint balanceDiff = balanceAfter - balanceBefore;
    mathint nativeBalanceDiff = nativeBalanceAfter - nativeBalanceBefore;

    assert balanceDiff == 0 && nativeBalanceDiff == 0, "No balance change expected";
}

// The invariant nativeVaultBalance checks that the native balance of the vault is always zero.
// This is because the vault should never hold native ETH, it should always wrap any incoming
// ETH into WETH.  However, there are a few exceptions: the contract address can have already
// received ETH before the vault was deployed, or self-destructs or withdraws from the
// beaconchain can send ETH to the vault, which we cannot prevent.  Therefore, we removed this
// check.
/*
invariant nativeVaultBalance()
    nativeBalances[currentContract] == 0
{
    preserved with (env e) {
        // There are two reasons why this is necessary:
        // 1. WETH sending to currentContract will change the native balance.
        // 2. The vault itself withdrawing from WETH will change the native balance.
        // Both cases can only be done by going through transferETH.  We check that transferETH preserves the invariant.
        require e.msg.sender != currentContract && e.msg.sender != WETH, "prevent unexpected calls from WETH or Vault itself";
    }
}
*/
