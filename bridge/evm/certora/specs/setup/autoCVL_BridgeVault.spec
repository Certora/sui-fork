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



/*
 * msg.sender != _owner@before => revert
 *
 * What it means: The function must revert if called by anyone other than the contract owner
 *
 * Why it should hold: The function has the onlyOwner modifier, which is a critical access control mechanism. Only the owner (intended to be the SuiBridge contract) should be able to transfer tokens from the vault
 *
 * Possible consequences: Unauthorized token drainage, complete loss of all ERC20 tokens stored in the vault, bypass of bridge security mechanisms
 */
rule transferERC20_9db5dbe4_non_owner_reverts(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    address currentContract__owner_before = currentContract._owner;

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((e.msg.sender != currentContract__owner_before) => transferERC20_reverted), "msg.sender != _owner@before => revert";
}

/*
 * _status@before == 2 => revert
 *
 * What it means: The function must revert if called while already executing (reentrancy status is 2)
 *
 * Why it should hold: The function has the nonReentrant modifier which sets _status to 2 during execution to prevent reentrancy attacks
 *
 * Possible consequences: Reentrancy attacks leading to double-spending, token balance manipulation, or unexpected state changes
 */
rule transferERC20_9db5dbe4_reentrancy_reverts(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    uint256 currentContract__status_before = currentContract._status;

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract__status_before == 2) => transferERC20_reverted), "_status@before == 2 => revert";
}

/*
 * amount == 0 => revert
 *
 * What it means: The function must revert when attempting to transfer zero tokens
 *
 * Why it should hold: Zero-amount transfers are meaningless operations that waste gas and could indicate bugs in the calling contract. Following the NO-OP MUST REVERT principle
 *
 * Possible consequences: Gas waste, potential masking of logic errors in the bridge contract, unnecessary transaction costs
 */
rule transferERC20_9db5dbe4_zero_amount_reverts(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((amount == 0) => transferERC20_reverted), "amount == 0 => revert";
}

/*
 * tokenAddress == address(0) => revert
 *
 * What it means: The function must revert when the token address is the zero address
 *
 * Why it should hold: The zero address is not a valid ERC20 token contract and attempting to interact with it would cause undefined behavior
 *
 * Possible consequences: Transaction failures, unexpected behavior, potential for exploiting undefined contract interactions
 */
rule transferERC20_9db5dbe4_invalid_token_reverts(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((tokenAddress == 0) => transferERC20_reverted), "tokenAddress == address(0) => revert";
}

/*
 * recipientAddress == address(0) => revert
 *
 * What it means: The function must revert when the recipient address is the zero address
 *
 * Why it should hold: Sending tokens to the zero address effectively burns them permanently, which is likely unintended and represents a loss of user funds
 *
 * Possible consequences: Permanent loss of tokens, user funds being burned instead of transferred to intended recipients
 */
rule transferERC20_9db5dbe4_invalid_recipient_reverts(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress == 0) => transferERC20_reverted), "recipientAddress == address(0) => revert";
}

/*
 * recipientAddress == address(this) => revert
 *
 * What it means: The function must revert when attempting to transfer tokens to the vault contract itself
 *
 * Why it should hold: Transferring tokens from the vault to itself is a meaningless operation that accomplishes nothing and could indicate a bug in the bridge logic
 *
 * Possible consequences: Wasted gas, potential masking of bridge logic errors, unnecessary complexity in accounting
 */
rule transferERC20_9db5dbe4_self_transfer_reverts(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress == currentContract) => transferERC20_reverted), "recipientAddress == address(this) => revert";
}

/*
 * IERC20(tokenAddress).balanceOf(address(this))@before < amount => revert
 *
 * What it means: The function must revert when the vault doesn't have enough tokens to complete the transfer
 *
 * Why it should hold: ERC20 transfers will fail if there are insufficient tokens, so the function should check this condition and revert gracefully
 *
 * Possible consequences: Failed transactions, bridge becoming stuck, user withdrawals failing unexpectedly
 */
rule transferERC20_9db5dbe4_insufficient_balance_reverts(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    uint256 tokenAddress_balanceOf_e__currentContract__before = tokenAddress.balanceOf(e, currentContract);

    // call function under test
    transferERC20@withrevert(e, tokenAddress, recipientAddress, amount);
    bool transferERC20_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((tokenAddress_balanceOf_e__currentContract__before < amount) => transferERC20_reverted), "IERC20(tokenAddress).balanceOf(address(this))@before < amount => revert";
}

/*
 * msg.sender == _owner@before && _status@before != 2 && amount > 0 && tokenAddress != address(0) && recipientAddress != address(0) && recipientAddress != address(this) && IERC20(tokenAddress).balanceOf(address(this))@before >= amount => IERC20(tokenAddress).balanceOf(address(this))@after == IERC20(tokenAddress).balanceOf(address(this))@before - amount
 *
 * What it means: When all conditions are met for a valid transfer, the vault's token balance must decrease by exactly the transfer amount
 *
 * Why it should hold: This ensures proper accounting - when tokens are transferred out of the vault, the vault's balance must reflect this change accurately
 *
 * Possible consequences: Accounting errors, potential for infinite token generation, bridge insolvency
 */
rule transferERC20_9db5dbe4_valid_transfer_balance_decreases(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    address currentContract__owner_before = currentContract._owner;
    uint256 currentContract__status_before = currentContract._status;
    uint256 tokenAddress_balanceOf_e__currentContract__before = tokenAddress.balanceOf(e, currentContract);

    // call function under test
    transferERC20(e, tokenAddress, recipientAddress, amount);

    // assign all the 'after' variables
    uint256 tokenAddress_balanceOf_e__currentContract__after = tokenAddress.balanceOf(e, currentContract);

    // verify integrity
    assert ((((((((e.msg.sender == currentContract__owner_before) && (currentContract__status_before != 2)) && (amount > 0)) && (tokenAddress != 0)) && (recipientAddress != 0)) && (recipientAddress != currentContract)) && (tokenAddress_balanceOf_e__currentContract__before >= amount)) => (tokenAddress_balanceOf_e__currentContract__after == tokenAddress_balanceOf_e__currentContract__before - amount)), "msg.sender == _owner@before && _status@before != 2 && amount > 0 && tokenAddress != address(0) && recipientAddress != address(0) && recipientAddress != address(this) && IERC20(tokenAddress).balanceOf(address(this))@before >= amount => IERC20(tokenAddress).balanceOf(address(this))@after == IERC20(tokenAddress).balanceOf(address(this))@before - amount";
}

/*
 * msg.sender == _owner@before && _status@before != 2 && amount > 0 && tokenAddress != address(0) && recipientAddress != address(0) && recipientAddress != address(this) && IERC20(tokenAddress).balanceOf(address(this))@before >= amount => IERC20(tokenAddress).balanceOf(recipientAddress)@after == IERC20(tokenAddress).balanceOf(recipientAddress)@before + amount
 *
 * What it means: When all conditions are met for a valid transfer, the recipient's token balance must increase by exactly the transfer amount
 *
 * Why it should hold: This ensures the tokens actually reach the intended recipient and the transfer is completed successfully
 *
 * Possible consequences: Failed transfers, user funds not reaching intended recipients, bridge appearing to work while funds are lost
 */
rule transferERC20_9db5dbe4_valid_transfer_recipient_increases(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    address currentContract__owner_before = currentContract._owner;
    uint256 currentContract__status_before = currentContract._status;
    uint256 tokenAddress_balanceOf_e__currentContract__before = tokenAddress.balanceOf(e, currentContract);
    uint256 tokenAddress_balanceOf_e__recipientAddress__before = tokenAddress.balanceOf(e, recipientAddress);

    // call function under test
    transferERC20(e, tokenAddress, recipientAddress, amount);

    // assign all the 'after' variables
    uint256 tokenAddress_balanceOf_e__recipientAddress__after = tokenAddress.balanceOf(e, recipientAddress);

    // verify integrity
    assert ((((((((e.msg.sender == currentContract__owner_before) && (currentContract__status_before != 2)) && (amount > 0)) && (tokenAddress != 0)) && (recipientAddress != 0)) && (recipientAddress != currentContract)) && (tokenAddress_balanceOf_e__currentContract__before >= amount)) => (tokenAddress_balanceOf_e__recipientAddress__after == tokenAddress_balanceOf_e__recipientAddress__before + amount)), "msg.sender == _owner@before && _status@before != 2 && amount > 0 && tokenAddress != address(0) && recipientAddress != address(0) && recipientAddress != address(this) && IERC20(tokenAddress).balanceOf(address(this))@before >= amount => IERC20(tokenAddress).balanceOf(recipientAddress)@after == IERC20(tokenAddress).balanceOf(recipientAddress)@before + amount";
}

/*
 * msg.sender == _owner@before && _status@before != 2 => _status@after == 2
 *
 * What it means: When a valid call begins execution, the reentrancy status must be set to 2 to prevent reentrant calls
 *
 * Why it should hold: This is the core mechanism of the nonReentrant modifier - setting _status to 2 during execution prevents reentrancy
 *
 * Possible consequences: Reentrancy vulnerabilities, potential for double-spending attacks, state manipulation
 */
rule transferERC20_9db5dbe4_reentrancy_status_set(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    address currentContract__owner_before = currentContract._owner;
    uint256 currentContract__status_before = currentContract._status;

    // call function under test
    transferERC20(e, tokenAddress, recipientAddress, amount);

    // assign all the 'after' variables
    uint256 currentContract__status_after = currentContract._status;

    // verify integrity
    assert (((e.msg.sender == currentContract__owner_before) && (currentContract__status_before != 2)) => (currentContract__status_after == 2)), "msg.sender == _owner@before && _status@before != 2 => _status@after == 2";
}

/*
 * msg.sender == _owner@before && _status@before != 2 && amount > 0 && tokenAddress != address(0) && recipientAddress != address(0) && recipientAddress != address(this) && IERC20(tokenAddress).balanceOf(address(this))@before >= amount => _status@after == 1
 *
 * What it means: After a successful transfer completes, the reentrancy status must be reset to 1 to allow future calls
 *
 * Why it should hold: The nonReentrant modifier must reset the status after execution to allow subsequent legitimate calls to the function
 *
 * Possible consequences: Function becomes permanently locked, DoS of the entire bridge system, users unable to withdraw funds
 */
rule transferERC20_9db5dbe4_reentrancy_status_reset(env e) {
    address tokenAddress;
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    address currentContract__owner_before = currentContract._owner;
    uint256 currentContract__status_before = currentContract._status;
    uint256 tokenAddress_balanceOf_e__currentContract__before = tokenAddress.balanceOf(e, currentContract);

    // call function under test
    transferERC20(e, tokenAddress, recipientAddress, amount);

    // assign all the 'after' variables
    uint256 currentContract__status_after = currentContract._status;

    // verify integrity
    assert ((((((((e.msg.sender == currentContract__owner_before) && (currentContract__status_before != 2)) && (amount > 0)) && (tokenAddress != 0)) && (recipientAddress != 0)) && (recipientAddress != currentContract)) && (tokenAddress_balanceOf_e__currentContract__before >= amount)) => (currentContract__status_after == 1)), "msg.sender == _owner@before && _status@before != 2 && amount > 0 && tokenAddress != address(0) && recipientAddress != address(0) && recipientAddress != address(this) && IERC20(tokenAddress).balanceOf(address(this))@before >= amount => _status@after == 1";
}

/*
 * msg.sender != _owner@before => revert
 *
 * What it means: Only the contract owner (stored in _owner) can execute the transferETH function - any other caller must cause the transaction to revert
 *
 * Why it should hold: The function has the onlyOwner modifier and is intended only for the SuiBridge contract. This enforces access control to prevent unauthorized ETH transfers from the vault
 *
 * Possible consequences: Unauthorized fund drainage, complete loss of all ETH stored in the vault, bypass of bridge security mechanisms
 */
rule transferETH_7b1a4909_only_owner_can_call(env e) {
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    address currentContract__owner_before = currentContract._owner;

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((e.msg.sender != currentContract__owner_before) => transferETH_reverted), "msg.sender != _owner@before => revert";
}

/*
 * amount == 0 => revert
 *
 * What it means: Attempting to transfer 0 ETH must cause the transaction to revert rather than executing a meaningless operation
 *
 * Why it should hold: Zero-amount transfers are no-ops that waste gas and provide no value. Following the NO-OPS MUST REVERT rule, meaningless operations should fail
 *
 * Possible consequences: Gas waste, potential state inconsistencies, misleading transaction logs, DoS through spam transactions
 */
rule transferETH_7b1a4909_zero_amount_reverts(env e) {
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((amount == 0) => transferETH_reverted), "amount == 0 => revert";
}

/*
 * recipientAddress == address(0) => revert
 *
 * What it means: Attempting to transfer ETH to the zero address (0x0) must cause the transaction to revert
 *
 * Why it should hold: Transfers to zero address effectively burn ETH permanently, which is never the intended behavior for a bridge vault
 *
 * Possible consequences: Permanent fund loss, ETH burned and unrecoverable, bridge accounting errors
 */
rule transferETH_7b1a4909_zero_address_reverts(env e) {
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress == 0) => transferETH_reverted), "recipientAddress == address(0) => revert";
}

/*
 * amount > address(this).balance@before => revert
 *
 * What it means: Attempting to transfer more ETH than the contract currently holds must cause the transaction to revert
 *
 * Why it should hold: The contract cannot transfer ETH it doesn't possess - this prevents failed transfers and maintains accounting integrity
 *
 * Possible consequences: Transaction failures, accounting mismatches, potential for double-spending attempts
 */
rule transferETH_7b1a4909_insufficient_balance_reverts(env e) {
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    uint256 nativeBalances_currentContract__before = nativeBalances[currentContract];

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((amount > nativeBalances_currentContract__before) => transferETH_reverted), "amount > address(this).balance@before => revert";
}

/*
 * _status@before == 2 => revert
 *
 * What it means: If the reentrancy guard is already active (_status == 2), the function must revert to prevent reentrant calls
 *
 * Why it should hold: The nonReentrant modifier uses _status to prevent reentrancy attacks. Status 2 indicates a function is currently executing
 *
 * Possible consequences: Reentrancy attacks, double-spending, fund drainage, state corruption
 */
rule transferETH_7b1a4909_reentrancy_guard_active(env e) {
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    uint256 currentContract__status_before = currentContract._status;

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract__status_before == 2) => transferETH_reverted), "_status@before == 2 => revert";
}

/*
 * msg.sender == _owner@before && amount > 0 && recipientAddress != address(0) && amount <= address(this).balance@before && _status@before != 2 => address(this).balance@after == address(this).balance@before - amount
 *
 * What it means: When all conditions are met for a valid transfer, the contract's ETH balance must decrease by exactly the transferred amount
 *
 * Why it should hold: This ensures proper accounting - the vault's balance must accurately reflect ETH transfers out
 *
 * Possible consequences: Accounting errors, fund tracking failures, potential for creating ETH out of thin air
 */
rule transferETH_7b1a4909_valid_transfer_reduces_balance(env e) {
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    address currentContract__owner_before = currentContract._owner;
    uint256 nativeBalances_currentContract__before = nativeBalances[currentContract];
    uint256 currentContract__status_before = currentContract._status;

    // call function under test
    transferETH(e, recipientAddress, amount);

    // assign all the 'after' variables
    uint256 nativeBalances_currentContract__after = nativeBalances[currentContract];

    // verify integrity
    assert ((((((e.msg.sender == currentContract__owner_before) && (amount > 0)) && (recipientAddress != 0)) && (amount <= nativeBalances_currentContract__before)) && (currentContract__status_before != 2)) => (nativeBalances_currentContract__after == nativeBalances_currentContract__before - amount)), "msg.sender == _owner@before && amount > 0 && recipientAddress != address(0) && amount <= address(this).balance@before && _status@before != 2 => address(this).balance@after == address(this).balance@before - amount";
}

/*
 * msg.sender == _owner@before && amount > 0 && recipientAddress != address(0) && amount <= address(this).balance@before && _status@before != 2 => recipientAddress.balance@after == recipientAddress.balance@before + amount
 *
 * What it means: When all conditions are met for a valid transfer, the recipient's ETH balance must increase by exactly the transferred amount
 *
 * Why it should hold: This ensures the recipient actually receives the intended ETH amount, completing the transfer operation correctly
 *
 * Possible consequences: Recipients don't receive expected funds, bridge operations fail, user fund loss
 */
rule transferETH_7b1a4909_valid_transfer_increases_recipient(env e) {
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    address currentContract__owner_before = currentContract._owner;
    uint256 nativeBalances_currentContract__before = nativeBalances[currentContract];
    uint256 currentContract__status_before = currentContract._status;
    uint256 nativeBalances_recipientAddress__before = nativeBalances[recipientAddress];

    // call function under test
    transferETH(e, recipientAddress, amount);

    // assign all the 'after' variables
    uint256 nativeBalances_recipientAddress__after = nativeBalances[recipientAddress];

    // verify integrity
    assert ((((((e.msg.sender == currentContract__owner_before) && (amount > 0)) && (recipientAddress != 0)) && (amount <= nativeBalances_currentContract__before)) && (currentContract__status_before != 2)) => (nativeBalances_recipientAddress__after == nativeBalances_recipientAddress__before + amount)), "msg.sender == _owner@before && amount > 0 && recipientAddress != address(0) && amount <= address(this).balance@before && _status@before != 2 => recipientAddress.balance@after == recipientAddress.balance@before + amount";
}

/*
 * msg.sender == _owner@before && amount > 0 && recipientAddress != address(0) && amount <= address(this).balance@before && _status@before != 2 => _status@after == 1
 *
 * What it means: After a valid transfer completes, the reentrancy guard status must be reset to 1 (unlocked state)
 *
 * Why it should hold: The nonReentrant modifier must properly reset the guard after function execution to allow future calls
 *
 * Possible consequences: Permanent function lockout, DoS of all protected functions, bridge becomes unusable
 */
rule transferETH_7b1a4909_reentrancy_status_changes(env e) {
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables
    address currentContract__owner_before = currentContract._owner;
    uint256 nativeBalances_currentContract__before = nativeBalances[currentContract];
    uint256 currentContract__status_before = currentContract._status;

    // call function under test
    transferETH(e, recipientAddress, amount);

    // assign all the 'after' variables
    uint256 currentContract__status_after = currentContract._status;

    // verify integrity
    assert ((((((e.msg.sender == currentContract__owner_before) && (amount > 0)) && (recipientAddress != 0)) && (amount <= nativeBalances_currentContract__before)) && (currentContract__status_before != 2)) => (currentContract__status_after == 1)), "msg.sender == _owner@before && amount > 0 && recipientAddress != address(0) && amount <= address(this).balance@before && _status@before != 2 => _status@after == 1";
}

/*
 * recipientAddress == address(this) => revert
 *
 * What it means: Attempting to transfer ETH to the contract itself must cause the transaction to revert
 *
 * Why it should hold: Self-transfers are meaningless operations that don't change the contract's total balance and serve no purpose
 *
 * Possible consequences: Gas waste, misleading transaction logs, potential for infinite loops with receive() function
 */
rule transferETH_7b1a4909_self_transfer_reverts(env e) {
    address recipientAddress;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    transferETH@withrevert(e, recipientAddress, amount);
    bool transferETH_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((recipientAddress == currentContract) => transferETH_reverted), "recipientAddress == address(this) => revert";
}