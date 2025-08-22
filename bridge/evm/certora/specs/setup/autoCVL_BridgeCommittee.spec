import "dispatching_BridgeCommittee.spec";
import "snippet_BridgeUtils.spec";
import "snippet_uups.spec";

using BridgeUtilsHarness as BridgeUtils;

/*
 * committee.length == 0 || stake.length == 0 => revert
 *
 * What it means: The initialize function must revert if either the committee array or stake array is empty
 *
 * Why it should hold: An empty committee would create a bridge with no validators, making it impossible to verify signatures or perform any bridge operations. This would render the entire bridge system non-functional
 *
 * Possible consequences: Complete bridge system failure, inability to process any cross-chain transactions, permanent DoS of bridge functionality
 */
// gereon: there is no such check. Empty arrays don't make much sense...
rule __initialize_empty_arrays_revert_1(env e) {
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
 // gereon: there is no such check. maybe it should exist...
rule __initialize_zero_address_reverts_3(env e) {
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
// gereon: nice idea, but it's not easy to extract the signer from the message (and the AI didn't even attempt to do it...)
rule __updateBlocklistWithSignatures_blocklisted_signer_reverts_12(env e) {
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
// gereon: nice idea, but the AI had no idea how to implement this
rule initialize_non_committee_has_zero_stake_8(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;
    address addr;

    // assign all the 'before' variables
    require(forall uint256 j. (j < committee.length) => (addr != committee[j]));
    require(currentContract.committeeStake[addr] == 0);

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    uint16 committeeStake_addr__after = currentContract.committeeStake[addr];

    // verify integrity
    assert (committeeStake_addr__after == 0);
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
// gereon: good idea, but the AI had no idea how to do it
rule initialize_committee_stake_set_correctly_6(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables
    require(
        forall uint256 i. forall uint256 j. (i < j && j < committee.length) => (committee[i] != committee[j])
    );

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables

    // verify integrity
    assert(
        forall uint256 i. (i < committee.length) => (currentContract.committeeStake[committee[i]] == stake[i])
    );
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
// gereon: nice idea, but it's not easy to extract the signer from the message (and the AI didn't even attempt to do it...)
rule __updateBlocklistWithSignatures_no_stake_signer_reverts_13(env e) {
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

/*
 * committee.length != stake.length => revert
 *
 * What it means: The function must revert if the committee array and stake array have different lengths
 *
 * Why it should hold: The function needs to pair each committee member with their corresponding stake amount. Mismatched array lengths would cause out-of-bounds access or incorrect stake assignments
 *
 * Possible consequences: State corruption where committee members get assigned wrong stakes, or array access violations leading to unpredictable behavior
 */
rule initialize_409ac647_arrays_length_mismatch_reverts(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, committee, stake, minStakeRequired);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((committee.length != stake.length) => initialize_reverted), "committee.length != stake.length => revert";
}

/*
 * minStakeRequired == 0 => revert
 *
 * What it means: The function must revert if the minimum stake requirement is set to zero
 *
 * Why it should hold: A zero minimum stake requirement would allow any message to be approved without any committee member signatures, completely bypassing security
 *
 * Possible consequences: Complete security bypass where any bridge operation can be executed without proper authorization
 */
// gereon: no such check exists, but it would make sense
rule __initialize_409ac647_zero_min_stake_reverts(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, committee, stake, minStakeRequired);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((minStakeRequired == 0) => initialize_reverted), "minStakeRequired == 0 => revert";
}

/*
 * blocklist[addr]@after == blocklist[addr]@before
 *
 * What it means: The initialize function should not modify the blocklist mapping for any address
 *
 * Why it should hold: Initialize is meant to set up the committee structure, not manage blocklists. Blocklist changes should only happen through dedicated blocklist management functions
 *
 * Possible consequences: Unauthorized blocklist modifications that could either unblock malicious actors or block legitimate committee members
 */
rule initialize_409ac647_blocklist_remains_unchanged(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;
    address addr;

    // assign all the 'before' variables
    bool currentContract_blocklist_addr__before = currentContract.blocklist[addr];

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    bool currentContract_blocklist_addr__after = currentContract.blocklist[addr];

    // verify integrity
    assert (currentContract_blocklist_addr__after == currentContract_blocklist_addr__before), "blocklist[addr]@after == blocklist[addr]@before";
}

/*
 * config@after == config@before
 *
 * What it means: The initialize function should not modify the config contract address
 *
 * Why it should hold: The config is set separately via initializeConfig and should not be modified during committee initialization to maintain separation of concerns
 *
 * Possible consequences: Unauthorized config changes that could redirect bridge operations to malicious contracts
 */
rule initialize_409ac647_config_remains_unchanged(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables
    address currentContract_config_before = currentContract.config;

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    address currentContract_config_after = currentContract.config;

    // verify integrity
    assert (currentContract_config_after == currentContract_config_before), "config@after == config@before";
}

/*
 * committee.length > 255 => revert
 *
 * What it means: The function must revert if more than 255 committee members are provided
 *
 * Why it should hold: The committeeIndex mapping uses uint8 which can only store values 0-255, so having more members would cause index overflow
 *
 * Possible consequences: Index overflow causing multiple committee members to have the same index, breaking signature verification logic
 */
rule initialize_409ac647_committee_too_large_reverts(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, committee, stake, minStakeRequired);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((committee.length > 255) => initialize_reverted), "committee.length > 255 => revert";
}

/*
 * stake[0] > 65535 => revert
 *
 * What it means: The function must revert if any stake amount exceeds the uint16 maximum value (65535)
 *
 * Why it should hold: The committeeStake mapping uses uint16 to store stake amounts, so values above 65535 would overflow and be stored incorrectly
 *
 * Possible consequences: Stake amount truncation where high-stake members appear to have very low stakes, undermining security thresholds
 */
rule initialize_409ac647_stake_overflow_reverts(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, committee, stake, minStakeRequired);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((stake[0] > 65535) => initialize_reverted), "stake[0] > 65535 => revert";
}

/*
 * committee.length > 0 && committee.length == stake.length && minStakeRequired > 0 => committeeStake[committee[0]]@after == stake[0]
 *
 * What it means: When initialization parameters are valid, the first committee member's stake should be correctly stored
 *
 * Why it should hold: This verifies that the core functionality of storing committee member stakes works correctly for valid inputs
 *
 * Possible consequences: Committee members having incorrect stakes, leading to wrong signature validation thresholds
 */
// gereon: and once again, the AI misses that the committee addresses may not be distinct.
rule initialize_409ac647_valid_setup_updates_stake(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables
    require(forall uint256 i. (0 < i && i < committee.length) => (committee[0] != committee[i]));

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    uint16 committeeStake_after = currentContract.committeeStake[committee[0]];

    // verify integrity
    assert ((((committee.length > 0) && (committee.length == stake.length)) && (minStakeRequired > 0)) => (committeeStake_after == stake[0])), "committee.length > 0 && committee.length == stake.length && minStakeRequired > 0 => committeeStake[committee[0]]@after == stake[0]";
}

/*
 * committee.length > 0 && committee.length == stake.length && minStakeRequired > 0 => committeeIndex[committee[0]]@after == 0
 *
 * What it means: When initialization parameters are valid, the first committee member should be assigned index 0
 *
 * Why it should hold: The index system is used in signature verification to prevent duplicate signatures via bitmap checking
 *
 * Possible consequences: Broken duplicate signature detection allowing signature replay attacks
 */
// gereon: and once again, the AI misses that the committee addresses may not be distinct.
rule initialize_409ac647_valid_setup_updates_index(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables
    require(forall uint256 i. (0 < i && i < committee.length) => (committee[0] != committee[i]));

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    uint8 currentContract_committeeIndex_committee_0___after = currentContract.committeeIndex[committee[0]];

    // verify integrity
    assert ((((committee.length > 0) && (committee.length == stake.length)) && (minStakeRequired > 0)) => (currentContract_committeeIndex_committee_0___after == 0)), "committee.length > 0 && committee.length == stake.length && minStakeRequired > 0 => committeeIndex[committee[0]]@after == 0";
}

/*
 * committee.length > 1 && committee.length == stake.length && minStakeRequired > 0 => committeeStake[committee[1]]@after == stake[1]
 *
 * What it means: When there are multiple committee members, the second member's stake should be correctly stored
 *
 * Why it should hold: This ensures the stake assignment logic works correctly for all committee members, not just the first one
 *
 * Possible consequences: Incorrect stake assignments for committee members beyond the first, undermining signature validation
 */
// gereon: AI ignored that further entries could overwrite the second member's stake
rule initialize_409ac647_second_member_stake_set(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;
    uint256 i = require_uint256(committee.length - 1);

    // assign all the 'before' variables

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    uint16 committeeStake_after = currentContract.committeeStake[committee[i]];

    // verify integrity
    assert ((((committee.length > 1) && (committee.length == stake.length)) && (minStakeRequired > 0)) => (committeeStake_after == stake[i])), "committee.length > 1 && committee.length == stake.length && minStakeRequired > 0 => committeeStake[committee[1]]@after == stake[1]";
}

/*
 * committee.length > 1 && committee.length == stake.length && minStakeRequired > 0 => committeeIndex[committee[1]]@after == 1
 *
 * What it means: When there are multiple committee members, the second member should be assigned index 1
 *
 * Why it should hold: This ensures the index assignment logic works correctly for all committee members in sequence
 *
 * Possible consequences: Incorrect index assignments leading to broken duplicate signature detection
 */
// gereon: AI ignored that further entries could overwrite the second member's index
rule initialize_409ac647_second_member_index_set(env e) {
    address[] committee;
    uint16[] stake;
    uint16 minStakeRequired;

    // assign all the 'before' variables
    require(
        forall uint256 j. (1 < j && j < committee.length) => (committee[j] != committee[1])
    );

    // call function under test
    initialize(e, committee, stake, minStakeRequired);

    // assign all the 'after' variables
    uint8 currentContract_committeeIndex_committee_1___after = currentContract.committeeIndex[committee[1]];

    // verify integrity
    assert ((((committee.length > 1) && (committee.length == stake.length)) && (minStakeRequired > 0)) => (currentContract_committeeIndex_committee_1___after == 1)), "committee.length > 1 && committee.length == stake.length && minStakeRequired > 0 => committeeIndex[committee[1]]@after == 1";
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
rule initializeConfig_c8f55287_invalid_config_address(env e) {
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
rule initializeConfig_c8f55287_only_committee_can_initialize(env e) {
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

/*
 * signatures.length == 0 => revert
 *
 * What it means: The function must revert if no signatures are provided in the signatures array
 *
 * Why it should hold: An empty signatures array means no committee members have approved the blocklist update, which violates the multi-signature requirement for critical operations
 *
 * Possible consequences: Unauthorized blocklist updates without any committee approval, allowing malicious actors to manipulate the blocklist state
 */
rule updateBlocklistWithSignatures_f6f66e98_empty_signatures_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    updateBlocklistWithSignatures@withrevert(e, signatures, message);
    bool updateBlocklistWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((signatures.length == 0) => updateBlocklistWithSignatures_reverted), "signatures.length == 0 => revert";
}

/*
 * message.messageType != BridgeUtils.BLOCKLIST => revert
 *
 * What it means: The function must revert if the message type is not BridgeUtils.BLOCKLIST
 *
 * Why it should hold: This function is specifically designed to handle blocklist updates only, and processing other message types would be a logical error
 *
 * Possible consequences: Processing inappropriate message types could lead to incorrect state changes or bypass intended access controls for other operations
 */
rule updateBlocklistWithSignatures_f6f66e98_invalid_message_type_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    updateBlocklistWithSignatures@withrevert(e, signatures, message);
    bool updateBlocklistWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.messageType != BridgeUtils.BLOCKLIST(e)) => updateBlocklistWithSignatures_reverted), "message.messageType != BridgeUtils.BLOCKLIST => revert";
}

/*
 * signatures[i].length != 65 => revert
 *
 * What it means: The function must revert if any signature in the array is not exactly 65 bytes long
 *
 * Why it should hold: ECDSA signatures must be exactly 65 bytes (32 bytes r + 32 bytes s + 1 byte v), and invalid lengths indicate malformed signatures
 *
 * Possible consequences: Processing malformed signatures could lead to signature verification bypass or unexpected behavior in cryptographic operations
 */
rule updateBlocklistWithSignatures_f6f66e98_invalid_signature_length_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint256 i;
    require(i < signatures.length);

    // assign all the 'before' variables

    // call function under test
    updateBlocklistWithSignatures@withrevert(e, signatures, message);
    bool updateBlocklistWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((signatures[i].length != 65) => updateBlocklistWithSignatures_reverted), "signatures[i].length != 65 => revert";
}

/*
 * message.nonce != nonces[message.chainID]@before => revert
 *
 * What it means: The function must revert if the message nonce does not match the expected nonce for the given chain ID
 *
 * Why it should hold: Nonces prevent replay attacks by ensuring each message can only be processed once in the correct order
 *
 * Possible consequences: Replay attacks where old blocklist update messages are reused, or out-of-order message processing leading to inconsistent state
 */
// gereon: and again, nonces are indexed by message type, not chain id
rule updateBlocklistWithSignatures_f6f66e98_invalid_nonce_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 currentContract_nonces_message_chainID__before = currentContract.nonces[message.messageType];

    // call function under test
    updateBlocklistWithSignatures@withrevert(e, signatures, message);
    bool updateBlocklistWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.nonce != currentContract_nonces_message_chainID__before) => updateBlocklistWithSignatures_reverted), "message.nonce != nonces[message.chainID]@before => revert";
}

/*
 * nonces[message.chainID]@after == nonces[message.chainID]@before + 1
 *
 * What it means: After successful execution, the nonce for the message's chain ID must be incremented by exactly 1
 *
 * Why it should hold: Proper nonce management ensures message ordering and prevents replay attacks by advancing the expected nonce
 *
 * Possible consequences: Nonce desynchronization could allow replay attacks or prevent legitimate future messages from being processed
 */
// gereon: and again, nonces are indexed by message type, not chain id
rule updateBlocklistWithSignatures_f6f66e98_nonce_incremented(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 currentContract_nonces_message_chainID__before = currentContract.nonces[message.messageType];

    // call function under test
    updateBlocklistWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 currentContract_nonces_message_chainID__after = currentContract.nonces[message.messageType];

    // verify integrity
    assert (currentContract_nonces_message_chainID__after == currentContract_nonces_message_chainID__before + 1), "nonces[message.chainID]@after == nonces[message.chainID]@before + 1";
}

/*
 * committeeStake[addr]@after == committeeStake[addr]@before
 *
 * What it means: The committee stake mapping must remain unchanged after blocklist updates
 *
 * Why it should hold: Blocklist updates should only modify the blocklist mapping, not affect committee members' stake amounts
 *
 * Possible consequences: Unintended modification of stake amounts could disrupt the voting power balance and compromise the security model
 */
rule updateBlocklistWithSignatures_f6f66e98_committee_stake_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    address addr;

    // assign all the 'before' variables
    uint16 currentContract_committeeStake_addr__before = currentContract.committeeStake[addr];

    // call function under test
    updateBlocklistWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint16 currentContract_committeeStake_addr__after = currentContract.committeeStake[addr];

    // verify integrity
    assert (currentContract_committeeStake_addr__after == currentContract_committeeStake_addr__before), "committeeStake[addr]@after == committeeStake[addr]@before";
}

/*
 * committeeIndex[addr]@after == committeeIndex[addr]@before
 *
 * What it means: The committee index mapping must remain unchanged after blocklist updates
 *
 * Why it should hold: Blocklist updates should only modify the blocklist status, not affect the positional indices of committee members
 *
 * Possible consequences: Changing committee indices could break signature verification logic that relies on these indices for duplicate detection
 */
rule updateBlocklistWithSignatures_f6f66e98_committee_index_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    address addr;

    // assign all the 'before' variables
    uint8 currentContract_committeeIndex_addr__before = currentContract.committeeIndex[addr];

    // call function under test
    updateBlocklistWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint8 currentContract_committeeIndex_addr__after = currentContract.committeeIndex[addr];

    // verify integrity
    assert (currentContract_committeeIndex_addr__after == currentContract_committeeIndex_addr__before), "committeeIndex[addr]@after == committeeIndex[addr]@before";
}

/*
 * config@after == config@before
 *
 * What it means: The config contract address must remain unchanged after blocklist updates
 *
 * Why it should hold: Blocklist updates should not modify the bridge configuration, which is a separate concern managed through different mechanisms
 *
 * Possible consequences: Unauthorized config changes could redirect the bridge to use malicious configuration parameters
 */
rule updateBlocklistWithSignatures_f6f66e98_config_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address currentContract_config_before = currentContract.config;

    // call function under test
    updateBlocklistWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address currentContract_config_after = currentContract.config;

    // verify integrity
    assert (currentContract_config_after == currentContract_config_before), "config@after == config@before";
}

/*
 * blocklist[addr]@after != blocklist[addr]@before => true
 *
 * What it means: The blocklist mapping is allowed to change for any address during execution
 *
 * Why it should hold: This property acknowledges that the primary purpose of this function is to update the blocklist status of addresses
 *
 * Possible consequences: If blocklist changes are prevented, the function cannot fulfill its intended purpose
 */
rule updateBlocklistWithSignatures_f6f66e98_blocklist_changes(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    address addr;

    // assign all the 'before' variables
    bool currentContract_blocklist_addr__before = currentContract.blocklist[addr];

    // call function under test
    updateBlocklistWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool currentContract_blocklist_addr__after = currentContract.blocklist[addr];

    // verify integrity
    assert ((currentContract_blocklist_addr__after != currentContract_blocklist_addr__before) => true), "blocklist[addr]@after != blocklist[addr]@before => true";
}

/*
 * chainID != message.chainID => nonces[chainID]@after == nonces[chainID]@before
 *
 * What it means: Nonces for chain IDs other than the message's chain ID must remain unchanged
 *
 * Why it should hold: Each chain should have independent nonce tracking, and processing a message for one chain should not affect nonces for other chains
 *
 * Possible consequences: Cross-chain nonce interference could disrupt message processing for other chains or create synchronization issues
 */
// gereon: and again, nonces are indexed by message type, not chain id
rule updateBlocklistWithSignatures_f6f66e98_other_nonces_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 messageType;

    // assign all the 'before' variables
    uint64 currentContract_nonces_chainID__before = currentContract.nonces[messageType];

    // call function under test
    updateBlocklistWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 currentContract_nonces_chainID__after = currentContract.nonces[messageType];

    // verify integrity
    assert ((messageType != message.messageType) => (currentContract_nonces_chainID__after == currentContract_nonces_chainID__before)), "chainID != message.chainID => nonces[chainID]@after == nonces[chainID]@before";
}