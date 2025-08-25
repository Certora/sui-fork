import "dispatching_BridgeCommittee.spec";

/*
 * config@before != address(0) => config@after == config@before
 *
 * What it means: If config is already set to a non-zero address, it should remain unchanged after the function call
 *
 * Why it should hold: This ensures that once a config is properly set, it cannot be overwritten, maintaining the stability and security of the bridge configuration
 *
 * Possible consequences: If config can be changed after being set, attackers could replace legitimate config with malicious ones, compromising the entire bridge security model
 */
rule initializeConfig_config_remains_unique_9(env e) {
    // Declare variables
    address _config;
    address config_before;
    address config_after;

    // assign all the 'before' variables
    config_before = currentContract.config;

    // call function under test
    initializeConfig(e, _config);

    // assign all the 'after' variables
    config_after = currentContract.config;

    // verify integrity
    assert ((config_before != 0) => (config_after == config_before));
}

/*
 * config@before != address(0) => revert
 *
 * What it means: The function must revert if the config address has already been set to a non-zero value
 *
 * Why it should hold: Based on the function name 'initializeConfig' and the docstring stating it should be called 'directly after config deployment', this appears to be a one-time initialization function that should prevent re-initialization
 *
 * Possible consequences: State corruption, unauthorized config changes, breaking of initialization invariants
 */
rule initializeConfig_c8f55287_config_already_set(env e) {
    address _config;

    // assign all the 'before' variables
    address currentContract_config_before = currentContract.config;

    // call function under test
    initializeConfig@withrevert(e, _config);
    bool initializeConfig_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract_config_before != 0) => initializeConfig_reverted), "config@before != address(0) => revert";
}

/*
 * _config == address(0) => revert
 *
 * What it means: The function must revert if the provided config address parameter is the zero address
 *
 * Why it should hold: Setting config to zero address would make the contract non-functional since config is likely used for critical bridge operations, and zero address is typically invalid for contract references
 *
 * Possible consequences: DoS of bridge functionality, inability to perform config-dependent operations
 */
// gereon: might make sense?
rule __initializeConfig_c8f55287_invalid_config_address(env e) {
    address _config;

    // assign all the 'before' variables

    // call function under test
    initializeConfig@withrevert(e, _config);
    bool initializeConfig_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_config == 0) => initializeConfig_reverted), "_config == address(0) => revert";
}

/*
 * _config != address(0) && config@before == address(0) => config@after == _config
 *
 * What it means: When a valid non-zero config address is provided and config was previously unset, the config storage variable should be updated to the provided address
 *
 * Why it should hold: This is the core functionality of the initialization - it should actually set the config when called with valid parameters for the first time
 *
 * Possible consequences: Bridge malfunction, inability to access configuration parameters
 */
rule initializeConfig_c8f55287_valid_config_sets_storage(env e) {
    address _config;

    // assign all the 'before' variables
    address currentContract_config_before = currentContract.config;

    // call function under test
    initializeConfig(e, _config);

    // assign all the 'after' variables
    address currentContract_config_after = currentContract.config;

    // verify integrity
    assert (((_config != 0) && (currentContract_config_before == 0)) => (currentContract_config_after == _config)), "_config != address(0) && config@before == address(0) => config@after == _config";
}

/*
 * msg.sender != committee@before => revert
 *
 * What it means: Only the committee address can call this initialization function
 *
 * Why it should hold: Configuration initialization is a privileged operation that should be restricted to authorized parties, and the committee appears to be the governance entity in this bridge system
 *
 * Possible consequences: Unauthorized configuration changes, governance bypass, potential fund loss
 */
// gereon: not sure how the initialization process is supposed to work, but it's indeed weird that this function is entirely unprotected...
rule __initializeConfig_c8f55287_only_committee_can_initialize(env e) {
    address _config;

    // assign all the 'before' variables
    address currentContract_committee_before = currentContract.committee;

    // call function under test
    initializeConfig@withrevert(e, _config);
    bool initializeConfig_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((e.msg.sender != currentContract_committee_before) => initializeConfig_reverted), "msg.sender != committee@before => revert";
}

/*
 * config@before != address(0) => config@after == config@before
 *
 * What it means: If config is already set to a non-zero value, it should remain unchanged after the function call
 *
 * Why it should hold: This ensures that even if the function doesn't revert when config is already set, it won't corrupt the existing configuration
 *
 * Possible consequences: Configuration corruption, unexpected behavior in bridge operations
 */
rule initializeConfig_c8f55287_config_unchanged_if_set(env e) {
    address _config;

    // assign all the 'before' variables
    address currentContract_config_before = currentContract.config;

    // call function under test
    initializeConfig(e, _config);

    // assign all the 'after' variables
    address currentContract_config_after = currentContract.config;

    // verify integrity
    assert ((currentContract_config_before != 0) => (currentContract_config_after == currentContract_config_before)), "config@before != address(0) => config@after == config@before";
}
