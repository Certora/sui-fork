

/*
 * minStakeRequired == 0 => revert
 *
 * What it means: The initialize function must revert if the minimum stake required parameter is zero
 *
 * Why it should hold: Zero minimum stake would allow bridge operations without any stake requirements, completely undermining the security model
 *
 * Possible consequences: Complete security bypass, any signature becomes valid regardless of stake, bridge security model collapse
 */
rule initialize_zero_minimum_stake_reverts_1(env e) {
    // Declare variables
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, committee, stake, minStakeRequired);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((minStakeRequired == 0) => initialize_reverted);
}

/*
 * committee.length == 0 || stake.length == 0 => revert
 *
 * What it means: The initialize function must revert if either the committee array or stake array is empty
 *
 * Why it should hold: An empty committee would create a bridge with no validators, making it impossible to verify signatures or perform any bridge operations. This would render the entire bridge system non-functional
 *
 * Possible consequences: Complete bridge system failure, inability to process any cross-chain transactions, permanent DoS of bridge functionality
 */
rule initialize_empty_arrays_revert_1(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables
    uint256 committee_length_before = committee.length;
    uint256 stake_length_before = stake.length;

    // call function under test
    initialize@withrevert(e, committee, stake, minStakeRequired);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((committee_length_before == 0) || (stake_length_before == 0)) => initialize_reverted);
}

/*
 * committee[i] == address(0) => revert
 *
 * What it means: The initialize function must revert if any committee member address is the zero address (0x0)
 *
 * Why it should hold: Zero address cannot sign messages or participate in committee operations. Including it would create invalid committee members that reduce effective committee size
 *
 * Possible consequences: Reduced effective committee size, potential signature verification failures, weakened bridge security
 */
rule initialize_zero_address_reverts_3(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;
    uint256 i;

    // assign all the 'before' variables
    address committee_i__before = committee[i];

    // call function under test
    initialize@withrevert(e, committee, stake, minStakeRequired);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((committee_i__before == 0) => initialize_reverted);
}

/*
 * committee@after == committee
 *
 * What it means: After initialization, the committee storage variable must contain the same addresses as the input committee array
 *
 * Why it should hold: The committee array is the authoritative list of valid committee members and must be stored correctly for future reference
 *
 * Possible consequences: Incorrect committee membership records, inability to properly manage committee state
 */
/*rule initialize_committee_array_stored_2(env e) {
    // Declare variables
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables

    // verify integrity
    assert (committee == committee);
}*/

/*
 * blocklist[addr]@after == blocklist[addr]@before
 *
 * What it means: The initialize function must not modify the blocklist mapping for any address
 *
 * Why it should hold: Initialize should only set up committee structure, not modify blocklist state which is managed by separate functions
 *
 * Possible consequences: Unintended blocklist modifications, committee members incorrectly blocked or unblocked
 */
rule initialize_blocklist_remains_unchanged_3(env e) {
    // Declare variables
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;
    address addr;
    bool blocklist_addr__after;
    bool blocklist_addr__before;

    // assign all the 'before' variables
    blocklist_addr__before = currentContract.blocklist[addr];

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    blocklist_addr__after = currentContract.blocklist[addr];

    // verify integrity
    assert (blocklist_addr__after == blocklist_addr__before);
}

/*
 * config@after == config@before
 *
 * What it means: The initialize function must not modify the config storage variable
 *
 * Why it should hold: Config is set by a separate initializeConfig function and should not be modified during committee initialization
 *
 * Possible consequences: Config corruption, incorrect bridge configuration, separation of concerns violation
 */
rule initialize_config_remains_unchanged_4(env e) {
    // Declare variables
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;
    address config_after;
    address config_before;

    // assign all the 'before' variables
    config_before = currentContract.config;

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    config_after = currentContract.config;

    // verify integrity
    assert (config_after == config_before);
}

/*
 * config != address(0) => revert
 *
 * What it means: If the config address is already set to a non-zero value, any attempt to call initializeConfig should revert
 *
 * Why it should hold: This prevents re-initialization of the config after it has been set once, maintaining the integrity of the bridge configuration and preventing unauthorized changes
 *
 * Possible consequences: Without this check, an attacker could repeatedly change the config address, potentially pointing to a malicious contract that could manipulate bridge operations, steal funds, or corrupt the bridge state
 */
rule initializeConfig_config_already_set_reverts_5(env e) {
    // Declare variables
    address _config;
    address config_before;

    // assign all the 'before' variables
    config_before = currentContract.config;

    // call function under test
    initializeConfig@withrevert(e, _config);
    bool initializeConfig_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((config_before != 0) => initializeConfig_reverted);
}

/*
 * _config == address(0) => revert
 *
 * What it means: If the _config parameter passed to initializeConfig is the zero address (0x0), the function should revert
 *
 * Why it should hold: Setting config to zero address would break the bridge functionality since config is used for critical operations, and zero address cannot hold valid contract code
 *
 * Possible consequences: Setting config to zero address would cause all bridge operations that depend on config to fail, effectively breaking the entire bridge system and potentially locking funds
 */
rule initializeConfig_zero_address_config_reverts_6(env e) {
    // Declare variables
    address _config;

    // assign all the 'before' variables

    // call function under test
    initializeConfig@withrevert(e, _config);
    bool initializeConfig_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_config == 0) => initializeConfig_reverted);
}

/*
 * _config != address(0) && config == address(0) => config@after == _config
 *
 * What it means: When a valid non-zero config address is provided and the current config is unset (zero), the config state variable should be updated to the new address
 *
 * Why it should hold: This ensures that valid initialization actually sets the config address, enabling the bridge to function properly with the correct configuration contract
 *
 * Possible consequences: If valid config initialization fails to update the state, the bridge would remain non-functional even after proper initialization attempts, causing operational failures
 */
rule initializeConfig_valid_config_updates_state_7(env e) {
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
    assert (((_config != 0) && (config_before == 0)) => (config_after == _config));
}

/*
 * msg.sender != committee => revert
 *
 * What it means: Only the committee address should be able to call the initializeConfig function
 *
 * Why it should hold: Config initialization is a critical administrative function that should only be performed by authorized entities (the committee) to prevent unauthorized configuration changes
 *
 * Possible consequences: Without access control, any user could initialize or change the config, potentially pointing to malicious contracts that could manipulate bridge operations or steal funds
 */
rule initializeConfig_only_committee_can_initialize_8(env e) {
    // Declare variables
    address _config;
    address committee_before;

    // assign all the 'before' variables
    committee_before = currentContract.committee;

    // call function under test
    initializeConfig@withrevert(e, _config);
    bool initializeConfig_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((e.msg.sender != committee_before) => initializeConfig_reverted);
}

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
 * signatures.length == 0 || signatures.length > 255 => revert
 *
 * What it means: The function must revert if no signatures are provided or if more than 255 signatures are provided
 *
 * Why it should hold: Empty signatures array makes verification meaningless, and the contract uses uint8 for indexing which has a maximum value of 255, so more signatures would cause overflow
 *
 * Possible consequences: DoS attacks by providing invalid signature arrays, potential integer overflow leading to incorrect signature verification
 */
rule updateBlocklistWithSignatures_invalid_signatures_revert_10(env e) {
    // Declare variables
    bytes[] signatures;
    BridgeUtils.Message message;
    uint256 signatures_length_before;

    // assign all the 'before' variables
    signatures_length_before = assert_uint256(signatures.length);

    // call function under test
    updateBlocklistWithSignatures@withrevert(e, signatures, message);
    bool updateBlocklistWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((signatures_length_before == 0) || (signatures_length_before > 255)) => updateBlocklistWithSignatures_reverted);
}

/*
 * message.messageType != BridgeUtils.BLOCKLIST => revert
 *
 * What it means: The message type in the provided message must be BridgeUtils.BLOCKLIST for this function to process it
 *
 * Why it should hold: This function is specifically designed to handle blocklist updates, and the verifyMessageAndSignatures modifier checks for the correct message type
 *
 * Possible consequences: Unauthorized operations if wrong message types are processed, potential bypass of intended function restrictions
 */
rule updateBlocklistWithSignatures_message_type_must_match_11(env e) {
    // Declare variables
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 message_messageType_before;

    // assign all the 'before' variables
    message_messageType_before = assert_uint8(message.messageType);

    // call function under test
    updateBlocklistWithSignatures@withrevert(e, signatures, message);
    bool updateBlocklistWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message_messageType_before != 1) => updateBlocklistWithSignatures_reverted);
}

/*
 * blocklist[signer] == true => revert
 *
 * What it means: The function must revert if any signature comes from an address that is currently blocklisted
 *
 * Why it should hold: Blocklisted committee members should not be able to participate in any governance decisions, including blocklist updates
 *
 * Possible consequences: Compromised governance if blocklisted members can still influence decisions, potential for malicious actors to maintain control
 */
rule updateBlocklistWithSignatures_blocklisted_signer_reverts_12(env e) {
    // Declare variables
    bytes[] signatures;
    BridgeUtils.Message message;
    address signer;
    bool blocklist_signer__before;

    // assign all the 'before' variables
    blocklist_signer__before = currentContract.blocklist[signer];

    // call function under test
    updateBlocklistWithSignatures@withrevert(e, signatures, message);
    bool updateBlocklistWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((blocklist_signer__before == true) => updateBlocklistWithSignatures_reverted);
}

/*
 * addr != committee[i] => committeeStake[addr]@after == 0
 *
 * What it means: After initialization, any address not in the committee array must have zero stake in the committeeStake mapping
 *
 * Why it should hold: Only official committee members should have stake; random addresses with stake could participate in signature verification illegitimately
 *
 * Possible consequences: Unauthorized addresses can participate in bridge operations, signature verification accepts invalid signers
 */
rule initialize_non_committee_has_zero_stake_8(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;
    uint256 i;
    address addr;

    // assign all the 'before' variables
    address committee_i__before = committee[i];

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    uint16 committeeStake_addr__after = currentContract.committeeStake[addr];

    // verify integrity
    assert ((addr != committee_i__before) => (committeeStake_addr__after == 0));
}

/*
 * committeeStake[committee[i]]@after == stake[i]
 *
 * What it means: After initialization, each committee member's stake in the committeeStake mapping must equal their corresponding value from the stake array
 *
 * Why it should hold: Correct stake assignment is critical for signature verification and ensuring proper weight distribution in committee decisions
 *
 * Possible consequences: Incorrect voting power, signature verification failures, committee members with wrong influence levels
 */
rule initialize_committee_stake_set_correctly_6(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;
    uint256 i;

    // assign all the 'before' variables
    address committee_i__before = committee[i];
    uint16 stake_i__before = stake[i];

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    uint16 committeeStake_committee_i__before__after = currentContract.committeeStake[committee_i__before];

    // verify integrity
    assert (committeeStake_committee_i__before__after == stake_i__before);
}

/*
 * committeeStake[signer] == 0 => revert
 *
 * What it means: The function must revert if any signature comes from an address that has zero stake in the committee
 *
 * Why it should hold: Only committee members with stake should be able to sign messages, as stake represents voting power and legitimacy
 *
 * Possible consequences: Unauthorized governance participation by non-committee members, dilution of legitimate committee voting power
 */
rule updateBlocklistWithSignatures_no_stake_signer_reverts_13(env e) {
    // Declare variables
    bytes[] signatures;
    BridgeUtils.Message message;
    address signer;
    uint16 committeeStake_signer__before;

    // assign all the 'before' variables
    committeeStake_signer__before = assert_uint16(currentContract.committeeStake[signer]);

    // call function under test
    updateBlocklistWithSignatures@withrevert(e, signatures, message);
    bool updateBlocklistWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((committeeStake_signer__before == 0) => updateBlocklistWithSignatures_reverted);
}

/*
 * signatures[i].length != 65 => revert
 *
 * What it means: The function must revert if any signature in the array is not exactly 65 bytes long
 *
 * Why it should hold: ECDSA signatures must be exactly 65 bytes (32 bytes r + 32 bytes s + 1 byte v) for proper cryptographic verification
 *
 * Possible consequences: Signature verification bypass or unexpected behavior in signature parsing, potential for malformed data to cause state corruption
 */
rule updateBlocklistWithSignatures_invalid_signature_length_reverts_14(env e) {
    // Declare variables
    bytes[] signatures;
    BridgeUtils.Message message;
    uint256 i;
    uint256 signatures_i__length_before;

    // assign all the 'before' variables
    signatures_i__length_before = assert_uint256(signatures[i].length);

    // call function under test
    updateBlocklistWithSignatures@withrevert(e, signatures, message);
    bool updateBlocklistWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((signatures_i__length_before != 65) => updateBlocklistWithSignatures_reverted);
}

/*
 * committeeStake[address]@after == committeeStake[address]@before
 *
 * What it means: The stake amounts of all committee members should remain the same after blocklist updates
 *
 * Why it should hold: Blocklist operations should only affect blocklist status, not stake amounts which are managed separately
 *
 * Possible consequences: Unintended modification of committee voting power during blocklist operations, disrupting governance balance
 */
rule updateBlocklistWithSignatures_committee_stake_unchanged_15(env e) {
    // Declare variables
    bytes[] signatures;
    BridgeUtils.Message message;
    uint16 committeeStake_address__after;
    uint16 committeeStake_address__before;
    address a;

    // assign all the 'before' variables
    committeeStake_address__before = assert_uint16(currentContract.committeeStake[a]);

    // call function under test
    updateBlocklistWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    committeeStake_address__after = assert_uint16(currentContract.committeeStake[a]);

    // verify integrity
    assert (committeeStake_address__after == committeeStake_address__before);
}

/*
 * committeeIndex[address]@after == committeeIndex[address]@before
 *
 * What it means: The index positions of all committee members should remain the same after blocklist updates
 *
 * Why it should hold: Blocklist operations should not affect the committee structure or member indexing
 *
 * Possible consequences: Corruption of committee member indexing leading to signature verification failures or incorrect stake calculations
 */
rule updateBlocklistWithSignatures_committee_index_unchanged_16(env e) {
    // Declare variables
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 committeeIndex_address__after;
    uint8 committeeIndex_address__before;
    address a;

    // assign all the 'before' variables
    committeeIndex_address__before = assert_uint8(currentContract.committeeIndex[a]);

    // call function under test
    updateBlocklistWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    committeeIndex_address__after = assert_uint8(currentContract.committeeIndex[a]);

    // verify integrity
    assert (committeeIndex_address__after == committeeIndex_address__before);
}

/*
 * config@after == config@before
 *
 * What it means: The config contract address should remain the same after blocklist updates
 *
 * Why it should hold: Blocklist operations should not modify the bridge configuration, which is managed through separate mechanisms
 *
 * Possible consequences: Unintended modification of bridge configuration during blocklist operations, potentially disrupting bridge functionality
 */
rule updateBlocklistWithSignatures_config_unchanged_17(env e) {
    // Declare variables
    bytes[] signatures;
    BridgeUtils.Message message;
    address config_after;
    address config_before;

    // assign all the 'before' variables
    config_before = currentContract.config;

    // call function under test
    updateBlocklistWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    config_after = currentContract.config;

    // verify integrity
    assert (config_after == config_before);
}