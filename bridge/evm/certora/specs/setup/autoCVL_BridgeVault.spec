import "dispatching_BridgeVault.spec";

/*
 * amount == 0 => revert
 *
 * What it means: The function must revert when the amount parameter is zero
 *
 * Why it should hold: Zero-amount transfers are meaningless operations that waste gas and could indicate bugs or malicious behavior. The contract should prevent no-op operations to maintain efficiency and security
 *
 * Possible consequences: Gas waste, potential for spam attacks, masking of logical errors in calling contracts, and violation of expected transfer semantics
 */
rule transferERC20_zero_amount_reverts_1(env e) {
    // Declare variables
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((amount == 0) => transferERC20_reverted);
}

/*
 * tokenAddress == address(0) || recipientAddress == address(0) => revert
 *
 * What it means: The function must revert if either tokenAddress or recipientAddress is the zero address
 *
 * Why it should hold: Zero addresses are invalid for ERC20 operations and recipient transfers. Allowing them would cause undefined behavior or failed transfers
 *
 * Possible consequences: Loss of funds, failed transfers that appear successful, and potential contract state corruption
 */
rule transferERC20_invalid_addresses_revert_2(env e) {
    // Declare variables
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((tokenAddress == 0) || (recipientAddress == 0)) => transferERC20_reverted);
}

/*
 * recipientAddress == address(this) => revert
 *
 * What it means: The function must revert if the recipient address is the contract itself
 *
 * Why it should hold: Transferring tokens to the contract itself is a meaningless operation that doesn't achieve the intended purpose of moving tokens to external recipients
 *
 * Possible consequences: Tokens remain in the vault while bridge logic thinks they were transferred, leading to accounting mismatches and potential double-spending
 */
rule transferERC20_self_transfer_reverts_3(env e) {
    // Declare variables
    address tokenAddress;
    address recipientAddress;
    uint256 amount;
    address currentContract_before;

    // assign all the 'before' variables
    currentContract_before = currentContract;

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress == currentContract_before) => transferERC20_reverted);
}

/*
 * msg.sender != _owner => revert
 *
 * What it means: Only the contract owner can call this function, all other callers must be reverted
 *
 * Why it should hold: This is a critical access control mechanism since the function transfers tokens from the vault. Only the authorized bridge contract should be able to initiate transfers
 *
 * Possible consequences: Complete loss of all tokens in the vault if unauthorized access is allowed
 */
rule transferERC20_only_owner_executes_4(env e) {
    // Declare variables
    address tokenAddress;
    address recipientAddress;
    uint256 amount;
    address _owner_before;

    // assign all the 'before' variables
    _owner_before = currentContract._owner;

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((e.msg.sender != _owner_before) => transferERC20_reverted);
}

/*
 * _status == 2 => revert
 *
 * What it means: The function must revert if called while another nonReentrant function is executing (status == 2)
 *
 * Why it should hold: Prevents reentrancy attacks where malicious contracts could call back into the function during execution, potentially causing double-spending or state corruption
 *
 * Possible consequences: Double-spending attacks, state corruption, and potential complete vault drainage
 */
rule transferERC20_reentrancy_guard_active_5(env e) {
    // Declare variables
    address tokenAddress;
    address recipientAddress;
    uint256 amount;
    uint256 _status_before;

    // assign all the 'before' variables
    _status_before = assert_uint256(currentContract._status);

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_status_before == 2) => transferERC20_reverted);
}

/*
 * _status@before == 1 => _status@after == 1
 *
 * What it means: The reentrancy status should remain consistent (value 1) before and after the function call for valid executions
 *
 * Why it should hold: Ensures the reentrancy guard properly manages its state and doesn't get corrupted during function execution
 *
 * Possible consequences: Reentrancy guard malfunction, potential for future reentrancy attacks, and state corruption
 */
rule transferERC20_status_updated_during_call_6(env e) {
    // Declare variables
    address tokenAddress;
    address recipientAddress;
    uint256 amount;
    uint256 _status_before;
    uint256 _status_after;

    // assign all the 'before' variables
    _status_before = assert_uint256(currentContract._status);

    // call function under test
    transferERC20(e, tokenAddress, recipientAddress, amount);

    // assign all the 'after' variables
    _status_after = assert_uint256(currentContract._status);

    // verify integrity
    assert ((_status_before == 1) => (_status_after == 1));
}

/*
 * _owner@after == _owner@before
 *
 * What it means: The contract owner should not change during the execution of transferERC20
 *
 * Why it should hold: The function should only transfer tokens, not modify ownership. Ownership changes should only happen through dedicated ownership transfer functions
 *
 * Possible consequences: Unauthorized ownership changes, loss of access control, and potential vault takeover
 */
rule transferERC20_owner_unchanged_7(env e) {
    // Declare variables
    address tokenAddress;
    address recipientAddress;
    uint256 amount;
    address _owner_after;
    address _owner_before;

    // assign all the 'before' variables
    _owner_before = currentContract._owner;

    // call function under test
    transferERC20(e, tokenAddress, recipientAddress, amount);

    // assign all the 'after' variables
    _owner_after = currentContract._owner;

    // verify integrity
    assert (_owner_after == _owner_before);
}

/*
 * amount > 0 && tokenAddress != address(0) && recipientAddress != address(0) && recipientAddress != address(this) && msg.sender == _owner && _status@before == 1 => IERC20(tokenAddress).balanceOf(recipientAddress)@after == IERC20(tokenAddress).balanceOf(recipientAddress)@before + amount
 *
 * What it means: When all conditions are valid, the recipient's token balance should increase by the transfer amount
 *
 * Why it should hold: This is the core functionality - successful transfers must actually move tokens to the intended recipient
 *
 * Possible consequences: Failed transfers that appear successful, loss of user funds, and bridge accounting mismatches
 */
rule transferERC20_valid_transfer_changes_balance_8(env e) {
    // Declare variables
    address tokenAddress;
    address recipientAddress;
    uint256 amount;
    address currentContract_before;
    address _owner_before;
    uint256 _status_before;
    uint256 tokenAddress_balanceOf_recipientAddress_after;
    uint256 tokenAddress_balanceOf_recipientAddress_before;

    // assign all the 'before' variables
    currentContract_before = currentContract;
    _owner_before = currentContract._owner;
    _status_before = assert_uint256(currentContract._status);
    tokenAddress_balanceOf_recipientAddress_before = assert_uint256(tokenAddress.balanceOf(e, recipientAddress));

    // call function under test
    transferERC20(e, tokenAddress, recipientAddress, amount);

    // assign all the 'after' variables
    tokenAddress_balanceOf_recipientAddress_after = assert_uint256(tokenAddress.balanceOf(e, recipientAddress));

    // verify integrity
    assert (((((((amount > 0) && (tokenAddress != 0)) && (recipientAddress != 0)) && (recipientAddress != currentContract_before)) && (e.msg.sender == _owner_before)) && (_status_before == 1)) => (tokenAddress_balanceOf_recipientAddress_after == tokenAddress_balanceOf_recipientAddress_before + amount));
}

/*
 * amount == 0 => revert
 *
 * What it means: The function must revert when the amount parameter is zero
 *
 * Why it should hold: Zero-amount transfers are meaningless operations that waste gas and could indicate programming errors or be used in spam attacks
 *
 * Possible consequences: DoS attacks through gas waste, contract state pollution, and masking of legitimate transaction failures
 */
rule transferETH_zero_amount_reverts_9(env e) {
    // Declare variables
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((amount == 0) => transferETH_reverted);
}

/*
 * recipientAddress == address(0) => revert
 *
 * What it means: The function must revert when recipientAddress is the zero address (0x0)
 *
 * Why it should hold: Sending ETH to the zero address effectively burns it permanently, which is almost never the intended behavior
 *
 * Possible consequences: Permanent loss of funds as ETH sent to zero address cannot be recovered
 */
rule transferETH_zero_address_reverts_10(env e) {
    // Declare variables
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress == 0) => transferETH_reverted);
}

/*
 * msg.sender != _owner => revert
 *
 * What it means: The function must revert when called by any address other than the contract owner
 *
 * Why it should hold: The function has onlyOwner modifier and is intended only for the SuiBridge contract to control fund transfers
 *
 * Possible consequences: Unauthorized fund transfers, complete drainage of contract funds, and bypass of bridge security mechanisms
 */
rule transferETH_non_owner_reverts_11(env e) {
    // Declare variables
    address recipientAddress;
    uint256 amount;
    address _owner_before;

    // assign all the 'before' variables
    _owner_before = currentContract._owner;

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((e.msg.sender != _owner_before) => transferETH_reverted);
}

/*
 * _status != 1 => revert
 *
 * What it means: The function must revert if called while another nonReentrant function is already executing (when _status != 1)
 *
 * Why it should hold: The nonReentrant modifier protects against reentrancy attacks during the WETH unwrapping and ETH transfer process
 *
 * Possible consequences: Reentrancy attacks leading to double-spending, fund drainage, and state corruption
 */
rule transferETH_reentrancy_reverts_12(env e) {
    // Declare variables
    address recipientAddress;
    uint256 amount;
    uint256 _status_before;

    // assign all the 'before' variables
    _status_before = assert_uint256(currentContract._status);

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_status_before != 1) => transferETH_reverted);
}