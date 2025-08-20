import "dispatching_BridgeLimiter.spec";
import "setup_BridgeConfig.spec";
import "snippet_loopSummaries.spec";
import "snippet_uups.spec";

using BridgeUtilsHarness as BridgeUtils;

/*
 * chainIDs.length != _totalLimits.length => revert
 *
 * What it means: The initialize function must revert if the chainIDs and _totalLimits arrays have different lengths
 *
 * Why it should hold: The function pairs each chainID with its corresponding limit, so mismatched array lengths would cause out-of-bounds access or incomplete initialization
 *
 * Possible consequences: Array index out-of-bounds errors, incomplete initialization where some chains lack limits, or silent failures in limit setting
 */
rule initialize_mismatched_arrays_revert_2(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;

    // assign all the 'before' variables
    uint256 chainIDs_length_before = chainIDs.length;
    uint256 _totalLimits_length_before = _totalLimits.length;

    // call function under test
    initialize@withrevert(e, _committee, chainIDs, _totalLimits);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((chainIDs_length_before != _totalLimits_length_before) => initialize_reverted);
}

/*
 * _committee != address(0) => committee@after == _committee
 *
 * What it means: When a valid committee address is provided, the committee storage variable must be set to that address after initialization
 *
 * Why it should hold: The committee is critical for bridge operations and signature verification, so it must be properly set during initialization
 *
 * Possible consequences: Bridge operations fail due to invalid committee reference, signature verification breaks, contract becomes non-functional
 */
rule initialize_committee_set_correctly_4(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, chainIDs, _totalLimits);

    // assign all the 'after' variables
    address committee_after = currentContract.committee;

    // verify integrity
    assert ((_committee != 0) => (committee_after == _committee));
}

/*
 * i < chainIDs.length && j < chainIDs.length && i != j && chainIDs[i] == chainIDs[j] => chainLimits[chainIDs[i]]@after == _totalLimits[j]
 *
 * What it means: If the same chainID appears multiple times in the array, the last corresponding limit value should be preserved
 *
 * Why it should hold: This ensures predictable behavior when duplicate chainIDs are provided, following standard array processing semantics
 *
 * Possible consequences: Unpredictable limit values for chains, potential for setting unintended limits, configuration confusion
 */
rule initialize_duplicate_chainIDs_preserved_7(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;
    uint256 i;
    uint256 j;

    // assign all the 'before' variables
    uint256 chainIDs_length_before = chainIDs.length;
    uint8 chainIDs_i__before = chainIDs[i];
    uint8 chainIDs_j__before = chainIDs[j];
    uint64 _totalLimits_j__before = _totalLimits[j];

    require(i < chainIDs.length);
    require(j < chainIDs.length);
    require(i != j);
    require(chainIDs_i__before == chainIDs_j__before);
    require(
        forall uint256 k. (i < k && j < k && k < chainIDs.length) => (chainIDs[i] != chainIDs[k])
    );

    // call function under test
    initialize(e, _committee, chainIDs, _totalLimits);

    // assign all the 'after' variables
    uint64 chainLimits_chainIDs_i__before__after = currentContract.chainLimits[chainIDs_i__before];

    // verify integrity
    assert (((i < chainIDs_length_before) && (j < chainIDs_length_before)) => (chainLimits_chainIDs_i__before__after == _totalLimits_j__before));
}

/*
 * oldestChainTimestamp[chainID]@after == 0
 *
 * What it means: The oldestChainTimestamp mapping should remain at default zero values after initialization
 *
 * Why it should hold: Initialization should not modify timestamp tracking data, which is managed separately during bridge operations
 *
 * Possible consequences: Incorrect timestamp tracking, broken rolling window calculations, bypass of time-based limits
 */
// gereon: initialize explicitly modifies this. I guess the AI misunderstood what this mapping does.
//rule initialize_timestamps_remain_zero_8(env e) {
//    address _committee;
//    uint8[] chainIDs;
//    uint64[] _totalLimits;
//    uint8 chainID;
//
//    // assign all the 'before' variables
//
//    // call function under test
//    initialize(e, _committee, chainIDs, _totalLimits);
//
//    // assign all the 'after' variables
//    uint32 oldestChainTimestamp_chainID__after = currentContract.oldestChainTimestamp[chainID];
//
//    // verify integrity
//    assert (oldestChainTimestamp_chainID__after == 0);
//}

/*
 * chainHourlyTransferAmount[key]@after == chainHourlyTransferAmount[key]@before
 *
 * What it means: The chainHourlyTransferAmount mapping should remain unchanged during initialization
 *
 * Why it should hold: Initialization should not affect historical transfer data, which tracks actual bridge usage
 *
 * Possible consequences: Historical data corruption, incorrect rate limit calculations, bypass of existing usage tracking
 */
rule initialize_transfer_amounts_unchanged_9(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;
    uint256 key;

    // assign all the 'before' variables
    uint256 chainHourlyTransferAmount_key__before = currentContract.chainHourlyTransferAmount[key];

    // call function under test
    initialize(e, _committee, chainIDs, _totalLimits);

    // assign all the 'after' variables
    uint256 chainHourlyTransferAmount_key__after = currentContract.chainHourlyTransferAmount[key];

    // verify integrity
    assert (chainHourlyTransferAmount_key__after == chainHourlyTransferAmount_key__before);
}

/*
 * nonces[chainID]@after == nonces[chainID]@before
 *
 * What it means: The nonces mapping should remain unchanged during initialization
 *
 * Why it should hold: Nonces are used for replay protection in signature verification and should not be reset during initialization
 *
 * Possible consequences: Replay attack vulnerabilities, broken signature verification, security bypass
 */
rule initialize_nonces_unchanged_10(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;
    uint8 chainID;

    // assign all the 'before' variables
    uint64 nonces_chainID__before = currentContract.nonces[chainID];

    // call function under test
    initialize(e, _committee, chainIDs, _totalLimits);

    // assign all the 'after' variables
    uint64 nonces_chainID__after = currentContract.nonces[chainID];

    // verify integrity
    assert (nonces_chainID__after == nonces_chainID__before);
}

/*
 * amount == 0 => revert
 *
 * What it means: The function must revert when the amount parameter is zero, preventing meaningless bridge transfer records
 *
 * Why it should hold: Recording zero-amount transfers serves no legitimate purpose and wastes gas while potentially allowing manipulation of bridge statistics or bypassing intended restrictions
 *
 * Possible consequences: DoS attacks through spam transactions, manipulation of bridge usage metrics, potential bypass of rate limiting mechanisms, and unnecessary blockchain bloat
 */
rule recordBridgeTransfers_zero_amount_reverts_11(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    recordBridgeTransfers@withrevert(e, chainID, tokenID, amount);
    bool recordBridgeTransfers_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((amount == 0) => recordBridgeTransfers_reverted);
}

/*
 * !committee.config().isTokenSupported(tokenID) => revert
 *
 * What it means: The function must revert when attempting to record transfers for a tokenID that is not supported by the bridge configuration
 *
 * Why it should hold: Only officially supported tokens should have their transfers recorded to maintain system integrity and prevent manipulation through fake or unauthorized tokens
 *
 * Possible consequences: State corruption, potential fund loss through fake token manipulation, bypass of legitimate token restrictions, and inconsistent bridge accounting
 */
rule recordBridgeTransfers_unsupported_token_reverts_13(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    bool committee_config_e__isTokenSupported_e__tokenID__before = currentContract.committee.config(e).isTokenSupported(e, tokenID);

    // call function under test
    recordBridgeTransfers@withrevert(e, chainID, tokenID, amount);
    bool recordBridgeTransfers_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(committee_config_e__isTokenSupported_e__tokenID__before) => recordBridgeTransfers_reverted);
}

/*
 * amount > 0 && committee.config().isChainSupported(chainID) && committee.config().isTokenSupported(tokenID) && calculateWindowAmount(chainID) + calculateAmountInUSD(tokenID, amount) <= chainLimits[chainID] => chainHourlyTransferAmount[getChainHourTimestampKey(chainID, currentHour())]@after == chainHourlyTransferAmount[getChainHourTimestampKey(chainID, currentHour())]@before + calculateAmountInUSD(tokenID, amount)
 *
 * What it means: When all validations pass, the function must correctly update the chainHourlyTransferAmount mapping by adding the USD equivalent of the transferred amount to the current hour's total
 *
 * Why it should hold: Accurate tracking of hourly transfer amounts is essential for the rolling 24-hour window limit calculation - incorrect updates would break the entire limiting mechanism
 *
 * Possible consequences: Complete failure of the bridge limiting system, potential fund loss through untracked transfers, and incorrect limit calculations that could either block legitimate transfers or allow excessive transfers
 */
rule recordBridgeTransfers_updates_hourly_transfer_amount_15(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    bool committee_config_e__isChainSupported_e__chainID__before = currentContract.committee.config(e).isChainSupported(e, chainID);
    bool committee_config_e__isTokenSupported_e__tokenID__before = currentContract.committee.config(e).isTokenSupported(e, tokenID);
    uint256 calculateWindowAmount_e__chainID__before = calculateWindowAmount(e, chainID);
    uint256 calculateAmountInUSD_e__tokenID__amount__before = calculateAmountInUSD(e, tokenID, amount);
    uint64 chainLimits_chainID__before = currentContract.chainLimits[chainID];
    uint32 currentHour_e__before = currentHour(e);
    uint256 getChainHourTimestampKey_e__chainID__currentHour_e__before__before = getChainHourTimestampKey(e, chainID, currentHour_e__before);
    uint256 chainHourlyTransferAmount_getChainHourTimestampKey_e__chainID__currentHour_e__before__before__before = currentContract.chainHourlyTransferAmount[getChainHourTimestampKey_e__chainID__currentHour_e__before__before];

    // call function under test
    recordBridgeTransfers(e, chainID, tokenID, amount);

    // assign all the 'after' variables
    uint256 chainHourlyTransferAmount_getChainHourTimestampKey_e__chainID__currentHour_e__before__before__after = currentContract.chainHourlyTransferAmount[getChainHourTimestampKey_e__chainID__currentHour_e__before__before];

    // verify integrity
    assert (((((amount > 0) && committee_config_e__isChainSupported_e__chainID__before) && committee_config_e__isTokenSupported_e__tokenID__before) && (calculateWindowAmount_e__chainID__before + calculateAmountInUSD_e__tokenID__amount__before <= chainLimits_chainID__before)) => (chainHourlyTransferAmount_getChainHourTimestampKey_e__chainID__currentHour_e__before__before__after == chainHourlyTransferAmount_getChainHourTimestampKey_e__chainID__currentHour_e__before__before__before + calculateAmountInUSD_e__tokenID__amount__before));
}

/*
 * message.messageType != BridgeUtils.UPDATE_BRIDGE_LIMIT => revert
 *
 * What it means: The function must revert if the message type is not specifically BridgeUtils.UPDATE_BRIDGE_LIMIT
 *
 * Why it should hold: The verifyMessageAndSignatures modifier checks that the message type matches the expected UPDATE_BRIDGE_LIMIT type. Using wrong message types should be rejected to prevent message replay attacks
 *
 * Possible consequences: Accepting wrong message types could allow attackers to replay messages intended for other functions, potentially bypassing security checks or causing unintended state changes
 */
rule updateLimitWithSignatures_wrong_message_type_reverts_16(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_messageType_before = message.messageType;

    // call function under test
    updateLimitWithSignatures@withrevert(e, signatures, message);
    bool updateLimitWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message_messageType_before != 3) => updateLimitWithSignatures_reverted);
}

/*
 * signatures[i] == signatures[j] && i != j => revert
 *
 * What it means: The function must revert if the same signature appears multiple times in the signatures array
 *
 * Why it should hold: Each committee member should only sign once per message. Duplicate signatures could allow an attacker to meet the signature threshold with fewer actual committee members
 *
 * Possible consequences: Accepting duplicate signatures reduces the effective security threshold, allowing attackers to authorize limit changes with compromised keys from fewer committee members than intended
 */
rule updateLimitWithSignatures_duplicate_signatures_revert_17(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint256 i;
    uint256 j;

    require(i < signatures.length);
    require(j < signatures.length);

    // assign all the 'before' variables
    bytes signatures_i__before = signatures[i];
    bytes signatures_j__before = signatures[j];

    // call function under test
    updateLimitWithSignatures@withrevert(e, signatures, message);
    bool updateLimitWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((signatures_i__before == signatures_j__before) && (i != j)) => updateLimitWithSignatures_reverted);
}

/*
 * !committee.config().isChainSupported(message.chainID) => revert
 *
 * What it means: The function must revert if the chain ID in the message is not supported by the bridge configuration
 *
 * Why it should hold: The bridge should only manage limits for chains that are officially supported. Unsupported chains should not have configurable limits
 *
 * Possible consequences: Allowing updates for unsupported chains could lead to state corruption, unexpected behavior, or enable attackers to manipulate limits for chains that shouldn't exist in the system
 */
// gereon: checks are about different chain ids, from message.chainID and from message.payload
rule __updateLimitWithSignatures_invalid_chain_id_reverts_18(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_chainID_before = message.chainID;
    bool isChainSupported_before = currentContract.committee.config(e).isChainSupported(e, message_chainID_before);

    // call function under test
    updateLimitWithSignatures@withrevert(e, signatures, message);
    bool updateLimitWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!isChainSupported_before => updateLimitWithSignatures_reverted);
}

/*
 * nonces[message.chainID]@after == nonces[message.chainID]@before + 1
 *
 * What it means: Each successful limit update must increment the nonce for that chain ID to prevent replay attacks
 *
 * Why it should hold: Nonces ensure that each signed message can only be used once. Without proper nonce incrementation, old signatures could be replayed to revert limit changes
 *
 * Possible consequences: Failure to increment nonces enables replay attacks where old signed messages can be reused to repeatedly change limits or undo recent limit updates
 */
// gereon: the nonces are per messageType, not per chainID
rule updateLimitWithSignatures_increments_nonce_19(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 nonces_before = currentContract.nonces[message.messageType];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 nonces_after = currentContract.nonces[message.messageType];

    // verify integrity
    assert (nonces_after == nonces_before + 1);
}

/*
 * otherChainID != message.chainID => chainLimits[otherChainID]@after == chainLimits[otherChainID]@before
 *
 * What it means: Updating the limit for one chain must not affect the limits of other chains
 *
 * Why it should hold: Each chain should have independent limit management. Cross-chain interference could cause unintended security changes
 *
 * Possible consequences: If updating one chain's limit affects others, it could accidentally weaken security for unrelated chains or cause cascading limit changes
 */
// gereon: not quite sure. message.chainID is the source chain, but decodeUpdateLimitPayload retrieves the sender chain id from the payload.
rule __updateLimitWithSignatures_preserves_other_limits_20(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 otherChainID;

    // assign all the 'before' variables
    uint8 message_chainID_before = message.chainID;
    uint64 chainLimits_otherChainID__before = currentContract.chainLimits[otherChainID];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 chainLimits_otherChainID__after = currentContract.chainLimits[otherChainID];

    // verify integrity
    assert ((otherChainID != message_chainID_before) => (chainLimits_otherChainID__after == chainLimits_otherChainID__before));
}

/*
 * chainHourlyTransferAmount[key]@after == chainHourlyTransferAmount[key]@before
 *
 * What it means: Updating limits must not modify the recorded hourly transfer amounts used for rolling window calculations
 *
 * Why it should hold: Transfer history should remain immutable to maintain accurate rolling window limit enforcement. Modifying past transfer data would compromise the security model
 *
 * Possible consequences: If transfer amounts are modified, attackers could reset their usage history to bypass rolling window limits and transfer unlimited amounts
 */
rule updateLimitWithSignatures_preserves_transfer_amounts_21(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint256 key;

    // assign all the 'before' variables
    uint256 chainHourlyTransferAmount_key__before = currentContract.chainHourlyTransferAmount[key];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint256 chainHourlyTransferAmount_key__after = currentContract.chainHourlyTransferAmount[key];

    // verify integrity
    assert (chainHourlyTransferAmount_key__after == chainHourlyTransferAmount_key__before);
}

/*
 * oldestChainTimestamp[chainID]@after == oldestChainTimestamp[chainID]@before
 *
 * What it means: Updating limits must not modify the oldest timestamp tracking for each chain
 *
 * Why it should hold: Timestamp tracking is used for garbage collection and window calculations. Modifying these values could disrupt the rolling window mechanism
 *
 * Possible consequences: Corrupted timestamp tracking could break garbage collection, cause incorrect window calculations, or enable manipulation of the rolling limit system
 */
rule updateLimitWithSignatures_preserves_oldest_timestamps_22(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 chainID;

    // assign all the 'before' variables
    uint32 oldestChainTimestamp_chainID__before = currentContract.oldestChainTimestamp[chainID];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint32 oldestChainTimestamp_chainID__after = currentContract.oldestChainTimestamp[chainID];

    // verify integrity
    assert (oldestChainTimestamp_chainID__after == oldestChainTimestamp_chainID__before);
}

/*
 * chainIDs.length == 0 => revert
 *
 * What it means: The initialize function must revert if the chainIDs array is empty
 *
 * Why it should hold: An empty chainIDs array would result in no chains being configured for the bridge limiter, making the contract non-functional. The contract's purpose is to limit bridge transfers for specific chains, so it must have at least one chain configured.
 *
 * Possible consequences: Contract deployment with no functional purpose, wasted gas, and potential confusion about contract state. The contract would be deployed but unable to perform its core function of limiting bridge transfers.
 */
// gereon: no such check present
//rule initialize_43a5f2bc_empty_chainIDs_reverts(env e) {
//    address _committee;
//    uint8[] chainIDs;
//    uint64[] _totalLimits;
//
//    // assign all the 'before' variables
//
//    // call function under test
//    initialize@withrevert(e, _committee, chainIDs, _totalLimits);
//    bool initialize_reverted = lastReverted;
//
//    // assign all the 'after' variables
//
//    // verify integrity
//    assert ((chainIDs.length == 0) => initialize_reverted), "chainIDs.length == 0 => revert";
//}

/*
 * chainIDs.length != _totalLimits.length => revert
 *
 * What it means: The initialize function must revert if the chainIDs and _totalLimits arrays have different lengths
 *
 * Why it should hold: Each chain ID must have a corresponding limit value. Mismatched array lengths would cause either out-of-bounds access or incomplete initialization where some chains lack limits or some limits lack associated chains.
 *
 * Possible consequences: Array index out-of-bounds errors, incomplete initialization leaving some chains without limits, or undefined behavior when accessing mismatched indices. This could lead to contract failure or incorrect limit enforcement.
 */
rule initialize_43a5f2bc_mismatched_arrays_revert(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, chainIDs, _totalLimits);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((chainIDs.length != _totalLimits.length) => initialize_reverted), "chainIDs.length != _totalLimits.length => revert";
}

/*
 * _committee == address(0) => revert
 *
 * What it means: The initialize function must revert if the _committee address is the zero address
 *
 * Why it should hold: The committee address is essential for the contract's operation as it's used to access configuration data and validate signatures. A zero address would make these operations fail and render the contract non-functional.
 *
 * Possible consequences: Contract becomes non-functional as committee-dependent operations will fail. Functions like calculateAmountInUSD and updateLimitWithSignatures would revert when trying to access committee.config().
 */
// gereon: no such check present. Could make sense, but any other unused address would break it as well.
rule __initialize_43a5f2bc_zero_committee_reverts(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, chainIDs, _totalLimits);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_committee == 0) => initialize_reverted), "_committee == address(0) => revert";
}

/*
 * chainIDs.length > 0 && chainIDs.length == _totalLimits.length && _committee != address(0) => committee@after == _committee
 *
 * What it means: When initialization parameters are valid, the committee storage variable must be set to the provided _committee address
 *
 * Why it should hold: This is the core state change that must occur during successful initialization. The committee address is required for all subsequent operations that need to access bridge configuration and validate signatures.
 *
 * Possible consequences: If the committee is not properly set, the contract cannot function as intended. All operations requiring committee access would fail, making the bridge limiter unusable.
 */
rule initialize_43a5f2bc_sets_committee(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, chainIDs, _totalLimits);

    // assign all the 'after' variables
    address currentContract_committee_after = currentContract.committee;

    // verify integrity
    assert ((((chainIDs.length > 0) && (chainIDs.length == _totalLimits.length)) && (_committee != 0)) => (currentContract_committee_after == _committee)), "chainIDs.length > 0 && chainIDs.length == _totalLimits.length && _committee != address(0) => committee@after == _committee";
}

/*
 * chainIDs.length > 0 && chainIDs.length == _totalLimits.length && _committee != address(0) => chainLimits[chainIDs[i]]@after == _totalLimits[i]
 *
 * What it means: When initialization parameters are valid, each chain ID in the array must have its limit set to the corresponding value from _totalLimits array
 *
 * Why it should hold: This establishes the core functionality of the bridge limiter by setting the USD limits for each supported chain. Without proper limit setting, the contract cannot enforce transfer restrictions.
 *
 * Possible consequences: Chains would have default limits of 0, causing all bridge transfers to be rejected, or limits might not be set correctly, leading to improper limit enforcement.
 */
rule initialize_43a5f2bc_sets_chain_limits(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;
    uint256 i;

    // assign all the 'before' variables
    require(
        forall uint256 j. (i < j && j < chainIDs.length) => (chainIDs[j] != chainIDs[i])
    );
    require(i < chainIDs.length);

    // call function under test
    initialize(e, _committee, chainIDs, _totalLimits);

    // assign all the 'after' variables
    uint64 currentContract_chainLimits_chainIDs_i___after = currentContract.chainLimits[chainIDs[i]];

    // verify integrity
    assert ((((chainIDs.length > 0) && (chainIDs.length == _totalLimits.length)) && (_committee != 0)) => (currentContract_chainLimits_chainIDs_i___after == _totalLimits[i])), "chainIDs.length > 0 && chainIDs.length == _totalLimits.length && _committee != address(0) => chainLimits[chainIDs[i]]@after == _totalLimits[i]";
}

/*
 * i != j && chainIDs[i] == chainIDs[j] => revert
 *
 * What it means: The initialize function must revert if the chainIDs array contains duplicate chain IDs
 *
 * Why it should hold: Duplicate chain IDs would cause confusion about which limit applies and could lead to overwriting previously set limits. Each chain should have exactly one limit configuration.
 *
 * Possible consequences: Later chain IDs in the array would overwrite earlier ones, leading to unexpected limit values. This could result in either overly restrictive or overly permissive limits depending on which duplicate value is processed last.
 */
// gereon: no such check present
//rule initialize_43a5f2bc_duplicate_chainIDs_revert(env e) {
//    address _committee;
//    uint8[] chainIDs;
//    uint64[] _totalLimits;
//    uint256 i;
//    uint256 j;
//
//    // assign all the 'before' variables
//
//    // call function under test
//    initialize@withrevert(e, _committee, chainIDs, _totalLimits);
//    bool initialize_reverted = lastReverted;
//
//    // assign all the 'after' variables
//
//    // verify integrity
//    assert (((i != j) && (chainIDs[i] == chainIDs[j])) => initialize_reverted), "i != j && chainIDs[i] == chainIDs[j] => revert";
//}

/*
 * _totalLimits[i] == 0 => revert
 *
 * What it means: The initialize function must revert if any value in the _totalLimits array is zero
 *
 * Why it should hold: A zero limit would effectively disable bridging for that chain since any positive transfer amount would exceed the limit. This is likely unintentional and could cause service disruption.
 *
 * Possible consequences: Chains with zero limits would reject all bridge transfers, making bridging impossible for those chains and causing user frustration and service unavailability.
 */
// gereon: no such check present.
//rule initialize_43a5f2bc_zero_limit_reverts(env e) {
//    address _committee;
//    uint8[] chainIDs;
//    uint64[] _totalLimits;
//    uint256 i;
//
//    // assign all the 'before' variables
//
//    // call function under test
//    initialize@withrevert(e, _committee, chainIDs, _totalLimits);
//    bool initialize_reverted = lastReverted;
//
//    // assign all the 'after' variables
//
//    // verify integrity
//    assert ((_totalLimits[i] == 0) => initialize_reverted), "_totalLimits[i] == 0 => revert";
//}

/*
 * committee@before != address(0) => revert
 *
 * What it means: The initialize function must revert if the contract has already been initialized (committee is not the zero address)
 *
 * Why it should hold: This prevents double initialization which could overwrite existing configuration and potentially be exploited to change critical parameters after deployment. Initialization should only happen once.
 *
 * Possible consequences: Without this protection, an attacker could re-initialize the contract to change committee address or chain limits, potentially gaining unauthorized control or disrupting service.
 */
// gereon: initialize only checks for its own initialized flag, nothing else.
//rule initialize_43a5f2bc_already_initialized_reverts(env e) {
//    address _committee;
//    uint8[] chainIDs;
//    uint64[] _totalLimits;
//
//    // assign all the 'before' variables
//    address currentContract_committee_before = currentContract.committee;
//
//    // call function under test
//    initialize@withrevert(e, _committee, chainIDs, _totalLimits);
//    bool initialize_reverted = lastReverted;
//
//    // assign all the 'after' variables
//
//    // verify integrity
//    assert ((currentContract_committee_before != 0) => initialize_reverted), "committee@before != address(0) => revert";
//}

/*
 * msg.sender != owner()@before => revert
 *
 * What it means: Only the contract owner (intended to be the SuiBridge contract) can call the recordBridgeTransfers function
 *
 * Why it should hold: The function is marked with onlyOwner modifier and is intended to be called exclusively by the SuiBridge contract to maintain proper access control over bridge transfer recording
 *
 * Possible consequences: Unauthorized manipulation of bridge transfer records, bypassing bridge limits, state corruption of transfer tracking
 */
rule recordBridgeTransfers_9373d391_only_owner_can_call(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    address owner_e__before = owner(e);

    // call function under test
    recordBridgeTransfers@withrevert(e, chainID, tokenID, amount);
    bool recordBridgeTransfers_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((e.msg.sender != owner_e__before) => recordBridgeTransfers_reverted), "msg.sender != owner()@before => revert";
}

/*
 * amount == 0 => revert
 *
 * What it means: The function must revert when called with an amount of 0 tokens
 *
 * Why it should hold: The devdoc explicitly states 'The amount must be greater than 0' and recording zero-amount transfers serves no meaningful purpose
 *
 * Possible consequences: Waste of gas, potential manipulation of transfer counts, pollution of transfer records
 */
rule recordBridgeTransfers_9373d391_zero_amount_reverts(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables

    // call function under test
    recordBridgeTransfers@withrevert(e, chainID, tokenID, amount);
    bool recordBridgeTransfers_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((amount == 0) => recordBridgeTransfers_reverted), "amount == 0 => revert";
}

/*
 * !committee@before.config().isChainSupported(chainID) => revert
 *
 * What it means: The function must revert if the chainID is not supported by the bridge configuration
 *
 * Why it should hold: Only supported chains should have their transfers recorded, as unsupported chains are not part of the bridge ecosystem
 *
 * Possible consequences: Recording transfers for invalid chains, corrupting bridge state, bypassing proper chain validation
 */
// gereon: there is no explicit check for that, but maybe it should be added
rule __recordBridgeTransfers_9373d391_unsupported_chain_reverts(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    bool currentContract_committee_config_e__isChainSupported_e__chainID__before = currentContract.committee.config(e).isChainSupported(e, chainID);

    // call function under test
    recordBridgeTransfers@withrevert(e, chainID, tokenID, amount);
    bool recordBridgeTransfers_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(currentContract_committee_config_e__isChainSupported_e__chainID__before) => recordBridgeTransfers_reverted), "!committee@before.config().isChainSupported(chainID) => revert";
}

/*
 * !committee@before.config().isTokenSupported(tokenID) => revert
 *
 * What it means: The function must revert if the tokenID is not supported by the bridge configuration
 *
 * Why it should hold: Only supported tokens should have their transfers recorded, as the bridge only handles specific whitelisted tokens
 *
 * Possible consequences: Recording transfers for invalid tokens, incorrect USD calculations, bypassing token validation
 */
rule recordBridgeTransfers_9373d391_unsupported_token_reverts(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    bool currentContract_committee_config_e__isTokenSupported_e__tokenID__before = currentContract.committee.config(e).isTokenSupported(e, tokenID);

    // call function under test
    recordBridgeTransfers@withrevert(e, chainID, tokenID, amount);
    bool recordBridgeTransfers_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(currentContract_committee_config_e__isTokenSupported_e__tokenID__before) => recordBridgeTransfers_reverted), "!committee@before.config().isTokenSupported(tokenID) => revert";
}

/*
 * willAmountExceedLimit(chainID, tokenID, amount)@before => revert
 *
 * What it means: The function must revert if recording this transfer would cause the total amount to exceed the chain's rolling 24-hour limit
 *
 * Why it should hold: The core purpose of BridgeLimiter is to enforce rolling 24-hour limits, so transfers that would exceed these limits must be rejected
 *
 * Possible consequences: Bypassing bridge limits, allowing excessive token transfers, breaking the fundamental security mechanism
 */
// gereon: $%& AI confused amount and usdAmount
rule recordBridgeTransfers_9373d391_exceeds_limit_reverts(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    uint256 usdAmount = calculateAmountInUSD(e, tokenID, amount);
    bool willUSDAmountExceedLimit_before = willUSDAmountExceedLimit(e, chainID, usdAmount);

    // call function under test
    recordBridgeTransfers@withrevert(e, chainID, tokenID, amount);
    bool recordBridgeTransfers_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (willUSDAmountExceedLimit_before => recordBridgeTransfers_reverted), "willAmountExceedLimit(chainID, tokenID, amount)@before => revert";
}

/*
 * amount > 0 && !willAmountExceedLimit(chainID, tokenID, amount)@before && committee@before.config().isChainSupported(chainID) && committee@before.config().isTokenSupported(tokenID) => chainHourlyTransferAmount[getChainHourTimestampKey(chainID, currentHour()@before)@before]@after == chainHourlyTransferAmount[getChainHourTimestampKey(chainID, currentHour()@before)@before]@before + calculateAmountInUSD(tokenID, amount)@before
 *
 * What it means: For valid transfers (amount > 0, within limits, supported chain/token), the function updates the current hour's transfer amount by adding the USD equivalent of the transfer
 *
 * Why it should hold: This is the core functionality - tracking transfer amounts in USD within hourly buckets for the rolling 24-hour window calculation
 *
 * Possible consequences: Incorrect limit tracking, broken rolling window calculations, potential bypass of limits
 */
rule recordBridgeTransfers_9373d391_updates_hourly_transfer_amount(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    bool willAmountExceedLimit_e__chainID__tokenID__amount__before = willAmountExceedLimit(e, chainID, tokenID, amount);
    bool currentContract_committee_config_e__isChainSupported_e__chainID__before = currentContract.committee.config(e).isChainSupported(e, chainID);
    bool currentContract_committee_config_e__isTokenSupported_e__tokenID__before = currentContract.committee.config(e).isTokenSupported(e, tokenID);
    uint32 currentHour_e__before = currentHour(e);
    uint256 getChainHourTimestampKey_e__chainID__currentHour_e__before__before = getChainHourTimestampKey(e, chainID, currentHour_e__before);
    uint256 currentContract_chainHourlyTransferAmount_getChainHourTimestampKey_e__chainID__currentHour_e__before__before__before = currentContract.chainHourlyTransferAmount[getChainHourTimestampKey_e__chainID__currentHour_e__before__before];
    uint256 calculateAmountInUSD_e__tokenID__amount__before = calculateAmountInUSD(e, tokenID, amount);

    // call function under test
    recordBridgeTransfers(e, chainID, tokenID, amount);

    // assign all the 'after' variables
    uint256 currentContract_chainHourlyTransferAmount_getChainHourTimestampKey_e__chainID__currentHour_e__before__before__after = currentContract.chainHourlyTransferAmount[getChainHourTimestampKey_e__chainID__currentHour_e__before__before];

    // verify integrity
    assert (((((amount > 0) && !(willAmountExceedLimit_e__chainID__tokenID__amount__before)) && currentContract_committee_config_e__isChainSupported_e__chainID__before) && currentContract_committee_config_e__isTokenSupported_e__tokenID__before) => (currentContract_chainHourlyTransferAmount_getChainHourTimestampKey_e__chainID__currentHour_e__before__before__after == currentContract_chainHourlyTransferAmount_getChainHourTimestampKey_e__chainID__currentHour_e__before__before__before + calculateAmountInUSD_e__tokenID__amount__before)), "amount > 0 && !willAmountExceedLimit(chainID, tokenID, amount)@before && committee@before.config().isChainSupported(chainID) && committee@before.config().isTokenSupported(tokenID) => chainHourlyTransferAmount[getChainHourTimestampKey(chainID, currentHour()@before)@before]@after == chainHourlyTransferAmount[getChainHourTimestampKey(chainID, currentHour()@before)@before]@before + calculateAmountInUSD(tokenID, amount)@before";
}

/*
 * hourTimestamp != currentHour()@before => chainHourlyTransferAmount[getChainHourTimestampKey(chainID, hourTimestamp)@before]@after == chainHourlyTransferAmount[getChainHourTimestampKey(chainID, hourTimestamp)@before]@before
 *
 * What it means: Transfer amounts for hours other than the current hour should remain unchanged when recording a new transfer
 *
 * Why it should hold: Only the current hour's bucket should be updated when recording a new transfer, preserving historical data integrity
 *
 * Possible consequences: Corruption of historical transfer data, incorrect rolling window calculations, potential manipulation of past records
 */
// gereon: the function garbage collects expired hours... rule can be adapted, I guess
rule __recordBridgeTransfers_9373d391_other_hours_unchanged(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;
    uint32 hourTimestamp;

    // assign all the 'before' variables
    uint32 currentHour_e__before = currentHour(e);
    uint256 getChainHourTimestampKey_before = getChainHourTimestampKey(e, chainID, hourTimestamp);
    uint256 chainHourlyTransferAmount_before = currentContract.chainHourlyTransferAmount[getChainHourTimestampKey_before];

    // call function under test
    recordBridgeTransfers(e, chainID, tokenID, amount);

    // assign all the 'after' variables
    uint256 chainHourlyTransferAmount_after = currentContract.chainHourlyTransferAmount[getChainHourTimestampKey_before];

    // verify integrity
    assert ((hourTimestamp != currentHour_e__before) => (chainHourlyTransferAmount_after == chainHourlyTransferAmount_before)), "hourTimestamp != currentHour()@before => chainHourlyTransferAmount[getChainHourTimestampKey(chainID, hourTimestamp)@before]@after == chainHourlyTransferAmount[getChainHourTimestampKey(chainID, hourTimestamp)@before]@before";
}

/*
 * otherChainID != chainID => chainHourlyTransferAmount[getChainHourTimestampKey(otherChainID, currentHour()@before)@before]@after == chainHourlyTransferAmount[getChainHourTimestampKey(otherChainID, currentHour()@before)@before]@before
 *
 * What it means: Transfer amounts for chains other than the specified chainID should remain unchanged
 *
 * Why it should hold: Each chain's transfer tracking should be independent, and recording a transfer for one chain shouldn't affect other chains' records
 *
 * Possible consequences: Cross-chain data corruption, incorrect limit calculations for unrelated chains, potential manipulation of other chains' limits
 */
rule recordBridgeTransfers_9373d391_other_chains_unchanged(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;
    uint8 otherChainID;

    // assign all the 'before' variables
    uint32 currentHour_e__before = currentHour(e);
    uint256 getChainHourTimestampKey_e__otherChainID__currentHour_e__before__before = getChainHourTimestampKey(e, otherChainID, currentHour_e__before);
    uint256 currentContract_chainHourlyTransferAmount_getChainHourTimestampKey_e__otherChainID__currentHour_e__before__before__before = currentContract.chainHourlyTransferAmount[getChainHourTimestampKey_e__otherChainID__currentHour_e__before__before];

    // call function under test
    recordBridgeTransfers(e, chainID, tokenID, amount);

    // assign all the 'after' variables
    uint256 currentContract_chainHourlyTransferAmount_getChainHourTimestampKey_e__otherChainID__currentHour_e__before__before__after = currentContract.chainHourlyTransferAmount[getChainHourTimestampKey_e__otherChainID__currentHour_e__before__before];

    // verify integrity
    assert ((otherChainID != chainID) => (currentContract_chainHourlyTransferAmount_getChainHourTimestampKey_e__otherChainID__currentHour_e__before__before__after == currentContract_chainHourlyTransferAmount_getChainHourTimestampKey_e__otherChainID__currentHour_e__before__before__before)), "otherChainID != chainID => chainHourlyTransferAmount[getChainHourTimestampKey(otherChainID, currentHour()@before)@before]@after == chainHourlyTransferAmount[getChainHourTimestampKey(otherChainID, currentHour()@before)@before]@before";
}

/*
 * chainLimits[chainID]@after == chainLimits[chainID]@before
 *
 * What it means: The chain's configured limit should not change when recording a transfer
 *
 * Why it should hold: Recording transfers should only update usage tracking, not the configured limits themselves, which are set through separate governance mechanisms
 *
 * Possible consequences: Unauthorized modification of chain limits, bypassing governance controls, potential manipulation of bridge security parameters
 */
rule recordBridgeTransfers_9373d391_chain_limits_unchanged(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    uint64 currentContract_chainLimits_chainID__before = currentContract.chainLimits[chainID];

    // call function under test
    recordBridgeTransfers(e, chainID, tokenID, amount);

    // assign all the 'after' variables
    uint64 currentContract_chainLimits_chainID__after = currentContract.chainLimits[chainID];

    // verify integrity
    assert (currentContract_chainLimits_chainID__after == currentContract_chainLimits_chainID__before), "chainLimits[chainID]@after == chainLimits[chainID]@before";
}

/*
 * oldestChainTimestamp[chainID]@after == oldestChainTimestamp[chainID]@before
 *
 * What it means: The oldest hour timestamp tracking for the chain should not change when recording a transfer
 *
 * Why it should hold: The oldest timestamp is used for cleanup/optimization purposes and should only be updated through specific maintenance operations, not during normal transfer recording
 *
 * Possible consequences: Corruption of cleanup mechanisms, potential memory/storage issues, incorrect historical data management
 */
rule recordBridgeTransfers_9373d391_oldest_timestamp_unchanged(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    uint32 currentContract_oldestChainTimestamp_chainID__before = currentContract.oldestChainTimestamp[chainID];

    // call function under test
    recordBridgeTransfers(e, chainID, tokenID, amount);

    // assign all the 'after' variables
    uint32 currentContract_oldestChainTimestamp_chainID__after = currentContract.oldestChainTimestamp[chainID];

    // verify integrity
    assert (currentContract_oldestChainTimestamp_chainID__after == currentContract_oldestChainTimestamp_chainID__before), "oldestChainTimestamp[chainID]@after == oldestChainTimestamp[chainID]@before";
}

/*
 * signatures.length == 0 => revert
 *
 * What it means: The function must revert when called with an empty signatures array
 *
 * Why it should hold: The function requires valid signatures to authenticate the limit update request. An empty signatures array means no authentication is provided, which should be rejected
 *
 * Possible consequences: Unauthorized limit updates, bypassing multi-signature security controls, potential for unlimited bridge transfers
 */
rule updateLimitWithSignatures_97c39b13_invalid_signatures_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    updateLimitWithSignatures@withrevert(e, signatures, message);
    bool updateLimitWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((signatures.length == 0) => updateLimitWithSignatures_reverted), "signatures.length == 0 => revert";
}

/*
 * message.messageType != BridgeUtils.UPDATE_BRIDGE_LIMIT => revert
 *
 * What it means: The function must revert when the message type is not UPDATE_BRIDGE_LIMIT
 *
 * Why it should hold: This function is specifically designed to handle UPDATE_BRIDGE_LIMIT messages only. Other message types should be handled by different functions
 *
 * Possible consequences: Function confusion, processing wrong message types, potential state corruption or unintended operations
 */
rule updateLimitWithSignatures_97c39b13_invalid_message_type_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    updateLimitWithSignatures@withrevert(e, signatures, message);
    bool updateLimitWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.messageType != BridgeUtils.UPDATE_BRIDGE_LIMIT(e)) => updateLimitWithSignatures_reverted), "message.messageType != BridgeUtils.UPDATE_BRIDGE_LIMIT => revert";
}

/*
 * !committee@before.config().isChainSupported(message.chainID) => revert
 *
 * What it means: The function must revert when trying to update limits for a chain that is not supported by the bridge configuration
 *
 * Why it should hold: Only supported chains should have configurable limits. Unsupported chains should not have limit configurations to prevent confusion and maintain system integrity
 *
 * Possible consequences: Configuration corruption, wasted gas, potential for setting limits on non-existent chains
 */
// gereon: the check is for message.payload, not message.chainID
rule __updateLimitWithSignatures_97c39b13_unsupported_chain_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_committee_config_e__isChainSupported_e__message_chainID__before = currentContract.committee.config(e).isChainSupported(e, message.chainID);

    // call function under test
    updateLimitWithSignatures@withrevert(e, signatures, message);
    bool updateLimitWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(currentContract_committee_config_e__isChainSupported_e__message_chainID__before) => updateLimitWithSignatures_reverted), "!committee@before.config().isChainSupported(message.chainID) => revert";
}

/*
 * message.nonce != nonces[message.chainID]@before => revert
 *
 * What it means: The function must revert when the message nonce does not match the expected nonce for the chain
 *
 * Why it should hold: Nonces prevent replay attacks by ensuring each message can only be processed once and in the correct order
 *
 * Possible consequences: Replay attacks, out-of-order message processing, potential for replaying old limit updates
 */
// gereon: again the AI misunderstood the nonces. They are per messageType, not chainID
rule updateLimitWithSignatures_97c39b13_invalid_nonce_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 nonces_before = currentContract.nonces[message.messageType];

    // call function under test
    updateLimitWithSignatures@withrevert(e, signatures, message);
    bool updateLimitWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.nonce != nonces_before) => updateLimitWithSignatures_reverted), "message.nonce != nonces[message.chainID]@before => revert";
}

/*
 * signatures.length > 0 && message.messageType == BridgeUtils.UPDATE_BRIDGE_LIMIT && committee@before.config().isChainSupported(message.chainID) && message.nonce == nonces[message.chainID]@before => chainLimits[message.chainID]@after != chainLimits[message.chainID]@before
 *
 * What it means: When all validation passes (valid signatures, correct message type, supported chain, correct nonce), the chain limit must actually change
 *
 * Why it should hold: This ensures the function performs its intended operation when all preconditions are met, preventing no-op scenarios that waste gas
 *
 * Possible consequences: Function not working as intended, wasted gas costs, limits not being updated when they should be
 */
// gereon: there is nothing in the code that prevents updating to the old limit
rule __updateLimitWithSignatures_97c39b13_valid_signatures_update_limit(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_committee_config_e__isChainSupported_e__message_chainID__before = currentContract.committee.config(e).isChainSupported(e, message.chainID);
    uint64 currentContract_nonces_message_chainID__before = currentContract.nonces[message.chainID];
    uint64 currentContract_chainLimits_message_chainID__before = currentContract.chainLimits[message.chainID];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 currentContract_chainLimits_message_chainID__after = currentContract.chainLimits[message.chainID];

    // verify integrity
    assert (((((signatures.length > 0) && (message.messageType == BridgeUtils.UPDATE_BRIDGE_LIMIT(e))) && currentContract_committee_config_e__isChainSupported_e__message_chainID__before) && (message.nonce == currentContract_nonces_message_chainID__before)) => (currentContract_chainLimits_message_chainID__after != currentContract_chainLimits_message_chainID__before)), "signatures.length > 0 && message.messageType == BridgeUtils.UPDATE_BRIDGE_LIMIT && committee@before.config().isChainSupported(message.chainID) && message.nonce == nonces[message.chainID]@before => chainLimits[message.chainID]@after != chainLimits[message.chainID]@before";
}

/*
 * signatures.length > 0 && message.messageType == BridgeUtils.UPDATE_BRIDGE_LIMIT && committee@before.config().isChainSupported(message.chainID) && message.nonce == nonces[message.chainID]@before => nonces[message.chainID]@after == nonces[message.chainID]@before + 1
 *
 * What it means: When a valid limit update is processed, the nonce for that chain must increment by exactly 1
 *
 * Why it should hold: Nonce incrementation is essential for replay attack prevention and ensuring message ordering
 *
 * Possible consequences: Replay attacks, message reordering, potential for processing the same limit update multiple times
 */
// gereon: again the AI misunderstood the nonces. They are per messageType, not chainID
rule updateLimitWithSignatures_97c39b13_nonce_increments(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    bool currentContract_committee_config_e__isChainSupported_e__message_chainID__before = currentContract.committee.config(e).isChainSupported(e, message.chainID);
    uint64 currentContract_nonces_message_chainID__before = currentContract.nonces[message.messageType];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 currentContract_nonces_message_chainID__after = currentContract.nonces[message.messageType];

    // verify integrity
    assert (((((signatures.length > 0) && (message.messageType == BridgeUtils.UPDATE_BRIDGE_LIMIT(e))) && currentContract_committee_config_e__isChainSupported_e__message_chainID__before) && (message.nonce == currentContract_nonces_message_chainID__before)) => (currentContract_nonces_message_chainID__after == currentContract_nonces_message_chainID__before + 1)), "signatures.length > 0 && message.messageType == BridgeUtils.UPDATE_BRIDGE_LIMIT && committee@before.config().isChainSupported(message.chainID) && message.nonce == nonces[message.chainID]@before => nonces[message.chainID]@after == nonces[message.chainID]@before + 1";
}

/*
 * chainID != message.chainID => chainLimits[chainID]@after == chainLimits[chainID]@before
 *
 * What it means: When updating limits for one chain, the limits for all other chains must remain unchanged
 *
 * Why it should hold: Limit updates should be isolated to the specific chain mentioned in the message to prevent unintended side effects
 *
 * Possible consequences: Unintended limit changes on other chains, system-wide security degradation, unexpected bridge behavior
 */
rule updateLimitWithSignatures_97c39b13_other_chain_limits_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 chainID;

    require(chainID < currentContract.chainLimits.length);

    // assign all the 'before' variables
    uint64 chainLimits_before = currentContract.chainLimits[chainID];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 chainLimits_after = currentContract.chainLimits[chainID];

    // verify integrity
    assert ((chainID != message.chainID) => (chainLimits_after == chainLimits_before)), "chainID != message.chainID => chainLimits[chainID]@after == chainLimits[chainID]@before";
}

/*
 * chainID != message.chainID => nonces[chainID]@after == nonces[chainID]@before
 *
 * What it means: When updating limits for one chain, the nonces for all other chains must remain unchanged
 *
 * Why it should hold: Nonce updates should be isolated to the specific chain being updated to maintain proper message ordering per chain
 *
 * Possible consequences: Nonce desynchronization, replay attack vulnerabilities on other chains, message ordering issues
 */
// gereon: again the AI misunderstood the nonces. They are per messageType, not chainID
rule updateLimitWithSignatures_97c39b13_other_chain_nonces_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 chainID;

    require(chainID < currentContract.chainLimits.length);

    // assign all the 'before' variables
    uint64 currentContract_nonces_chainID__before = currentContract.nonces[message.messageType];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 currentContract_nonces_chainID__after = currentContract.nonces[message.messageType];

    // verify integrity
    assert ((chainID != message.chainID) => (currentContract_nonces_chainID__after == currentContract_nonces_chainID__before)), "chainID != message.chainID => nonces[chainID]@after == nonces[chainID]@before";
}

/*
 * chainHourlyTransferAmount[key]@after == chainHourlyTransferAmount[key]@before
 *
 * What it means: The hourly transfer amount tracking data must not be modified when updating limits
 *
 * Why it should hold: Limit updates should only change the limit values, not the historical transfer data used for rolling window calculations
 *
 * Possible consequences: Historical data corruption, incorrect rolling window calculations, potential for bypassing transfer limits
 */
rule updateLimitWithSignatures_97c39b13_transfer_amounts_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint256 key;

    // assign all the 'before' variables
    uint256 currentContract_chainHourlyTransferAmount_key__before = currentContract.chainHourlyTransferAmount[key];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint256 currentContract_chainHourlyTransferAmount_key__after = currentContract.chainHourlyTransferAmount[key];

    // verify integrity
    assert (currentContract_chainHourlyTransferAmount_key__after == currentContract_chainHourlyTransferAmount_key__before), "chainHourlyTransferAmount[key]@after == chainHourlyTransferAmount[key]@before";
}

/*
 * oldestChainTimestamp[chainID]@after == oldestChainTimestamp[chainID]@before
 *
 * What it means: The oldest timestamp tracking for chains must not be modified when updating limits
 *
 * Why it should hold: Timestamp tracking is used for garbage collection and should not be affected by limit updates
 *
 * Possible consequences: Garbage collection mechanism corruption, potential memory leaks, incorrect timestamp tracking
 */
rule updateLimitWithSignatures_97c39b13_oldest_timestamp_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 chainID;

    // assign all the 'before' variables
    uint32 currentContract_oldestChainTimestamp_chainID__before = currentContract.oldestChainTimestamp[chainID];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint32 currentContract_oldestChainTimestamp_chainID__after = currentContract.oldestChainTimestamp[chainID];

    // verify integrity
    assert (currentContract_oldestChainTimestamp_chainID__after == currentContract_oldestChainTimestamp_chainID__before), "oldestChainTimestamp[chainID]@after == oldestChainTimestamp[chainID]@before";
}

/*
 * committee@after == committee@before
 *
 * What it means: The committee address must not be modified when updating bridge limits
 *
 * Why it should hold: Limit updates should not affect the committee configuration, which is a separate governance concern
 *
 * Possible consequences: Governance system corruption, loss of signature verification capability, unauthorized committee changes
 */
rule updateLimitWithSignatures_97c39b13_committee_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address currentContract_committee_before = currentContract.committee;

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address currentContract_committee_after = currentContract.committee;

    // verify integrity
    assert (currentContract_committee_after == currentContract_committee_before), "committee@after == committee@before";
}
