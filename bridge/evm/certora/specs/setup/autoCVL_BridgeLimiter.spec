import "dispatching_BridgeLimiter.spec";
import "setup_BridgeConfig.spec";
import "snippet_loopSummaries.spec";
import "snippet_uups.spec";

/*
 * chainIDs.length == 0 || _totalLimits.length == 0 => revert
 *
 * What it means: The initialize function must revert if either the chainIDs array or _totalLimits array is empty
 *
 * Why it should hold: An empty array would result in no chain limits being set, leaving the contract in an uninitialized state where no chains have configured limits, making the bridge limiter non-functional
 *
 * Possible consequences: Contract becomes non-functional as a bridge limiter, allowing unlimited bridging which defeats the purpose of rate limiting and could lead to economic attacks
 */
rule initialize_empty_arrays_revert_1(env e) {
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
    assert (((chainIDs_length_before == 0) || (_totalLimits_length_before == 0)) => initialize_reverted);
}

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
 * committee != address(0) => revert
 *
 * What it means: The initialize function must revert if the contract has already been initialized (committee is not zero address)
 *
 * Why it should hold: This prevents re-initialization attacks where an attacker could reset the contract state and potentially bypass existing security configurations
 *
 * Possible consequences: Re-initialization attacks, state corruption, bypass of existing security settings, potential takeover of contract control
 */
rule initialize_already_initialized_reverts_3(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;

    // assign all the 'before' variables
    address committee_before = currentContract.committee;

    // call function under test
    initialize@withrevert(e, _committee, chainIDs, _totalLimits);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((committee_before != 0) => initialize_reverted);
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
 * _committee == address(0) => revert
 *
 * What it means: The initialize function must revert if the provided committee address is the zero address
 *
 * Why it should hold: A zero address committee would make signature verification impossible and break the bridge's security model
 *
 * Possible consequences: Complete breakdown of signature verification, unauthorized operations, bridge security compromised
 */
rule initialize_zero_committee_reverts_5(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, chainIDs, _totalLimits);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_committee == 0) => initialize_reverted);
}

/*
 * chainIDs.length > 0 && i < chainIDs.length => chainLimits[chainIDs[i]]@after == _totalLimits[i]
 *
 * What it means: For each valid index in the arrays, the chain limit for chainIDs[i] must be set to _totalLimits[i]
 *
 * Why it should hold: This is the core functionality of initialization - setting up the rate limits for each supported chain
 *
 * Possible consequences: Incorrect or missing rate limits, chains with wrong limits allowing over/under bridging, economic attacks
 */
rule initialize_chain_limits_set_6(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;
    uint256 i;

    // assign all the 'before' variables
    uint256 chainIDs_length_before = chainIDs.length;
    uint8 chainIDs_i__before = chainIDs[i];
    uint64 _totalLimits_i__before = _totalLimits[i];

    // call function under test
    initialize(e, _committee, chainIDs, _totalLimits);

    // assign all the 'after' variables
    uint64 chainLimits_chainIDs_i__before__after = currentContract.chainLimits[chainIDs_i__before];

    // verify integrity
    assert (((chainIDs_length_before > 0) && (i < chainIDs_length_before)) => (chainLimits_chainIDs_i__before__after == _totalLimits_i__before));
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

    // call function under test
    initialize(e, _committee, chainIDs, _totalLimits);

    // assign all the 'after' variables
    uint64 chainLimits_chainIDs_i__before__after = currentContract.chainLimits[chainIDs_i__before];

    // verify integrity
    assert (((((i < chainIDs_length_before) && (j < chainIDs_length_before)) && (i != j)) && (chainIDs_i__before == chainIDs_j__before)) => (chainLimits_chainIDs_i__before__after == _totalLimits_j__before));
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
rule initialize_timestamps_remain_zero_8(env e) {
    address _committee;
    uint8[] chainIDs;
    uint64[] _totalLimits;
    uint8 chainID;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, chainIDs, _totalLimits);

    // assign all the 'after' variables
    uint32 oldestChainTimestamp_chainID__after = currentContract.oldestChainTimestamp[chainID];

    // verify integrity
    assert (oldestChainTimestamp_chainID__after == 0);
}

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
 * !committee.config().isChainSupported(chainID) => revert
 *
 * What it means: The function must revert when attempting to record transfers for a chainID that is not supported by the bridge configuration
 *
 * Why it should hold: The bridge limiter should only track transfers for chains that are officially supported by the bridge system to maintain data integrity and prevent unauthorized chain additions
 *
 * Possible consequences: State corruption through invalid chain data, potential bypass of security restrictions, and inconsistent bridge state that could lead to fund loss or system malfunction
 */
rule recordBridgeTransfers_unsupported_chain_reverts_12(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    bool committee_config_e__isChainSupported_e__chainID__before = currentContract.committee.config(e).isChainSupported(e, chainID);

    // call function under test
    recordBridgeTransfers@withrevert(e, chainID, tokenID, amount);
    bool recordBridgeTransfers_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(committee_config_e__isChainSupported_e__chainID__before) => recordBridgeTransfers_reverted);
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
 * calculateWindowAmount(chainID) + calculateAmountInUSD(tokenID, amount) > chainLimits[chainID] => revert
 *
 * What it means: The function must revert when recording a transfer would cause the total bridged amount within the 24-hour window to exceed the configured limit for that chain
 *
 * Why it should hold: This is the core security mechanism of the bridge limiter - preventing excessive transfers that could drain bridge funds or enable large-scale attacks
 *
 * Possible consequences: Complete bypass of bridge security limits leading to potential fund drainage, large-scale attacks, and violation of the bridge's risk management policies
 */
rule recordBridgeTransfers_exceeds_limit_reverts_14(env e) {
    uint8 chainID;
    uint8 tokenID;
    uint256 amount;

    // assign all the 'before' variables
    uint256 calculateWindowAmount_e__chainID__before = calculateWindowAmount(e, chainID);
    uint256 calculateAmountInUSD_e__tokenID__amount__before = calculateAmountInUSD(e, tokenID, amount);
    uint64 chainLimits_chainID__before = currentContract.chainLimits[chainID];

    // call function under test
    recordBridgeTransfers@withrevert(e, chainID, tokenID, amount);
    bool recordBridgeTransfers_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((calculateWindowAmount_e__chainID__before + calculateAmountInUSD_e__tokenID__amount__before > chainLimits_chainID__before) => recordBridgeTransfers_reverted);
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
rule updateLimitWithSignatures_invalid_chain_id_reverts_18(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_chainID_before = message.chainID;
    bool committee_config_e__isChainSupported_e__message_chainID_before__before = currentContract.committee.config(e).isChainSupported(e, message_chainID_before);

    // call function under test
    updateLimitWithSignatures@withrevert(e, signatures, message);
    bool updateLimitWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (!(committee_config_e__isChainSupported_e__message_chainID_before__before) => updateLimitWithSignatures_reverted);
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
rule updateLimitWithSignatures_increments_nonce_19(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_chainID_before = message.chainID;
    uint64 nonces_message_chainID_before__before = currentContract.nonces[message_chainID_before];

    // call function under test
    updateLimitWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 nonces_message_chainID_before__after = currentContract.nonces[message_chainID_before];

    // verify integrity
    assert (nonces_message_chainID_before__after == nonces_message_chainID_before__before + 1);
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
rule updateLimitWithSignatures_preserves_other_limits_20(env e) {
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