import "dispatching_BridgeConfig.spec";
import "setup_BridgeConfig.spec";
import "snippet_uups.spec";

using BridgeUtilsHarness as BridgeUtils;

/*
 * _supportedTokens.length == 0 || _tokenPrices.length == 0 || _tokenIds.length == 0 || _suiDecimals.length == 0 || _supportedChains.length == 0 => revert
 *
 * What it means: The initialize function must revert if any of the required arrays (_supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains) are empty
 *
 * Why it should hold: An empty array would result in a bridge configuration with no supported tokens or chains, making the bridge completely non-functional. The initialize function should prevent such invalid configurations
 *
 * Possible consequences: Bridge becomes completely unusable, DoS of bridge functionality, users cannot perform any bridge operations
 */
rule initialize_empty_arrays_revert_1(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables
    uint256 _supportedTokens_length_before = _supportedTokens.length;
    uint256 _tokenPrices_length_before = _tokenPrices.length;
    uint256 _tokenIds_length_before = _tokenIds.length;
    uint256 _suiDecimals_length_before = _suiDecimals.length;
    uint256 _supportedChains_length_before = _supportedChains.length;

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((((((_supportedTokens_length_before == 0) || (_tokenPrices_length_before == 0)) || (_tokenIds_length_before == 0)) || (_suiDecimals_length_before == 0)) || (_supportedChains_length_before == 0)) => initialize_reverted);
}

/*
 * _supportedTokens.length != _tokenPrices.length || _supportedTokens.length != _tokenIds.length || _supportedTokens.length != _suiDecimals.length => revert
 *
 * What it means: The initialize function must revert if the arrays _supportedTokens, _tokenPrices, _tokenIds, and _suiDecimals have different lengths
 *
 * Why it should hold: These arrays are processed together in a loop where each index corresponds to the same token. Mismatched lengths would cause array out-of-bounds access or incomplete token configuration
 *
 * Possible consequences: Array out-of-bounds errors, incomplete token configurations, state corruption, potential contract crash
 */
rule initialize_array_length_mismatch_reverts_2(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables
    uint256 _supportedTokens_length_before = _supportedTokens.length;
    uint256 _tokenPrices_length_before = _tokenPrices.length;
    uint256 _tokenIds_length_before = _tokenIds.length;
    uint256 _suiDecimals_length_before = _suiDecimals.length;

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((((_supportedTokens_length_before != _tokenPrices_length_before) || (_supportedTokens_length_before != _tokenIds_length_before)) || (_supportedTokens_length_before != _suiDecimals_length_before)) => initialize_reverted);
}

/*
 * _committee == address(0) => revert
 *
 * What it means: The initialize function must revert if the _committee parameter is the zero address
 *
 * Why it should hold: The committee address is critical for signature verification and authorization. A zero address would break all committee-based operations
 *
 * Possible consequences: Complete loss of access control, inability to update token prices or add tokens, bridge becomes unmanageable
 */
rule initialize_invalid_committee_reverts_3(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_committee == 0) => initialize_reverted);
}

/*
 * _chainID == 0 => revert
 *
 * What it means: The initialize function must revert if the _chainID parameter is zero
 *
 * Why it should hold: Chain ID zero is typically invalid and could cause confusion with default/uninitialized values. Valid chain IDs should be positive integers
 *
 * Possible consequences: Chain identification issues, potential conflicts with default values, bridge routing problems
 */
rule initialize_invalid_chainID_reverts_4(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_chainID == 0) => initialize_reverted);
}

/*
 * _committee != address(0) => committee@after == _committee
 *
 * What it means: When _committee is not the zero address, the committee storage variable should be set to _committee after initialization
 *
 * Why it should hold: The committee address must be properly stored to enable signature verification and authorization for bridge operations
 *
 * Possible consequences: Authorization failures, inability to verify signatures, loss of administrative control
 */
rule initialize_sets_committee_5(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    address committee_after = currentContract.committee;

    // verify integrity
    assert ((_committee != 0) => (committee_after == _committee));
}

/*
 * _chainID > 0 => chainID@after == _chainID
 *
 * What it means: When _chainID is greater than zero, the chainID storage variable should be set to _chainID after initialization
 *
 * Why it should hold: The chain ID must be properly stored for the bridge to identify which chain it's operating on
 *
 * Possible consequences: Chain identification failures, cross-chain routing issues, transaction processing errors
 */
rule initialize_sets_chainID_6(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint8 chainID_after = currentContract.chainID;

    // verify integrity
    assert ((_chainID > 0) => (chainID_after == _chainID));
}

/*
 * _supportedChains.length > 0 => supportedChains[_supportedChains[i]]@after == true
 *
 * What it means: For each chain ID in the _supportedChains array, the supportedChains mapping should be set to true after initialization
 *
 * Why it should hold: Supported chains must be properly registered for the bridge to accept transactions from/to those chains
 *
 * Possible consequences: Cross-chain operations fail, users cannot bridge to/from intended chains, DoS of bridge functionality
 */
rule initialize_sets_supported_chains_7(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;
    uint256 i;

    // assign all the 'before' variables
    uint256 _supportedChains_length_before = _supportedChains.length;
    uint8 _supportedChains_i__before = _supportedChains[i];

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    bool supportedChains__supportedChains_i__before__after = currentContract.supportedChains[_supportedChains_i__before];

    // verify integrity
    assert ((_supportedChains_length_before > 0) => (supportedChains__supportedChains_i__before__after == true));
}

/*
 * _supportedTokens.length > 0 => supportedTokens[_tokenIds[i]].tokenAddress@after == _supportedTokens[i]
 *
 * What it means: For each token, the token address from _supportedTokens array should be stored in the supportedTokens mapping at the corresponding _tokenIds index
 *
 * Why it should hold: Token addresses must be properly mapped to their IDs for the bridge to identify and interact with the correct token contracts
 *
 * Possible consequences: Wrong token interactions, fund loss, bridge operations with incorrect tokens
 */
rule initialize_sets_token_addresses_8(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;
    uint256 i;

    // assign all the 'before' variables
    uint256 _supportedTokens_length_before = _supportedTokens.length;
    uint8 _tokenIds_i__before = _tokenIds[i];
    address _supportedTokens_i__before = _supportedTokens[i];

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    address supportedTokens__tokenIds_i__before__tokenAddress_after = currentContract.supportedTokens[_tokenIds_i__before].tokenAddress;

    // verify integrity
    assert ((_supportedTokens_length_before > 0) => (supportedTokens__tokenIds_i__before__tokenAddress_after == _supportedTokens_i__before));
}

/*
 * _suiDecimals.length > 0 => supportedTokens[_tokenIds[i]].suiDecimal@after == _suiDecimals[i]
 *
 * What it means: For each token, the sui decimal value from _suiDecimals array should be stored in the supportedTokens mapping at the corresponding _tokenIds index
 *
 * Why it should hold: Decimal precision is critical for accurate amount calculations when converting between different chain representations
 *
 * Possible consequences: Incorrect amount calculations, fund loss due to precision errors, bridge operations with wrong amounts
 */
rule initialize_sets_token_decimals_9(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;
    uint256 i;

    // assign all the 'before' variables
    uint256 _suiDecimals_length_before = _suiDecimals.length;
    uint8 _tokenIds_i__before = _tokenIds[i];
    uint8 _suiDecimals_i__before = _suiDecimals[i];

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint8 supportedTokens__tokenIds_i__before__suiDecimal_after = currentContract.supportedTokens[_tokenIds_i__before].suiDecimal;

    // verify integrity
    assert ((_suiDecimals_length_before > 0) => (supportedTokens__tokenIds_i__before__suiDecimal_after == _suiDecimals_i__before));
}

/*
 * _tokenPrices.length > 0 => tokenPrices[_tokenIds[i]]@after == _tokenPrices[i]
 *
 * What it means: For each token, the price from _tokenPrices array should be stored in the tokenPrices mapping at the corresponding _tokenIds index
 *
 * Why it should hold: Token prices are essential for bridge operations that depend on token valuations and fee calculations
 *
 * Possible consequences: Incorrect fee calculations, wrong token valuations, economic attacks on bridge
 */
rule initialize_sets_token_prices_10(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;
    uint256 i;

    // assign all the 'before' variables
    uint256 _tokenPrices_length_before = _tokenPrices.length;
    uint8 _tokenIds_i__before = _tokenIds[i];
    uint64 _tokenPrices_i__before = _tokenPrices[i];

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint64 tokenPrices__tokenIds_i__before__after = currentContract.tokenPrices[_tokenIds_i__before];

    // verify integrity
    assert ((_tokenPrices_length_before > 0) => (tokenPrices__tokenIds_i__before__after == _tokenPrices_i__before));
}

/*
 * i != j && i < _tokenIds.length && j < _tokenIds.length => _tokenIds[i] != _tokenIds[j]
 *
 * What it means: All token IDs in the _tokenIds array must be unique - no two different array positions should contain the same token ID
 *
 * Why it should hold: Duplicate token IDs would cause later entries to overwrite earlier ones, leading to lost token configurations and inconsistent state
 *
 * Possible consequences: Token configuration overwrites, lost token data, inconsistent bridge state, some tokens become inaccessible
 */
rule initialize_duplicate_token_IDs_unique_11(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;
    uint256 i;
    uint256 j;

    // assign all the 'before' variables
    uint256 _tokenIds_length_before = _tokenIds.length;
    uint8 _tokenIds_i__before = _tokenIds[i];
    uint8 _tokenIds_j__before = _tokenIds[j];

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables

    // verify integrity
    assert ((((i != j) && (i < _tokenIds_length_before)) && (j < _tokenIds_length_before)) => (_tokenIds_i__before != _tokenIds_j__before));
}

/*
 * i != j && i < _supportedChains.length && j < _supportedChains.length => _supportedChains[i] != _supportedChains[j]
 *
 * What it means: All chain IDs in the _supportedChains array must be unique - no two different array positions should contain the same chain ID
 *
 * Why it should hold: Duplicate chain IDs are redundant and waste gas, and could indicate configuration errors or manipulation attempts
 *
 * Possible consequences: Gas waste, potential configuration errors, unclear bridge state
 */
rule initialize_duplicate_chain_IDs_unique_12(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;
    uint256 i;
    uint256 j;

    // assign all the 'before' variables
    uint256 _supportedChains_length_before = _supportedChains.length;
    uint8 _supportedChains_i__before = _supportedChains[i];
    uint8 _supportedChains_j__before = _supportedChains[j];

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables

    // verify integrity
    assert ((((i != j) && (i < _supportedChains_length_before)) && (j < _supportedChains_length_before)) => (_supportedChains_i__before != _supportedChains_j__before));
}

/*
 * message.messageType != BridgeUtils.UPDATE_TOKEN_PRICE => revert
 *
 * What it means: The function must revert if the message type is not UPDATE_TOKEN_PRICE, ensuring only price update messages are processed
 *
 * Why it should hold: The verifyMessageAndSignatures modifier checks that the message type matches UPDATE_TOKEN_PRICE. Processing wrong message types could lead to unintended state changes or bypass security checks
 *
 * Possible consequences: Processing of unintended message types could corrupt contract state, bypass authorization checks, or execute unintended operations leading to fund loss or system compromise
 */
rule updateTokenPriceWithSignatures_wrong_message_type_reverts_13(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_messageType_before = message.messageType;

    // call function under test
    updateTokenPriceWithSignatures@withrevert(e, signatures, message);
    bool updateTokenPriceWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message_messageType_before != 4) => updateTokenPriceWithSignatures_reverted);
}

/*
 * tokenID1 != tokenID2 && supportedTokens[tokenID1].tokenAddress != address(0) && supportedTokens[tokenID2].tokenAddress != address(0) => supportedTokens[tokenID1].tokenAddress != supportedTokens[tokenID2].tokenAddress
 *
 * What it means: Different token IDs must map to different token addresses, ensuring no two token IDs can reference the same underlying token contract
 *
 * Why it should hold: Token ID uniqueness is critical for bridge accounting and prevents confusion between different bridge representations of the same underlying asset
 *
 * Possible consequences: Double-spending attacks, accounting errors, fund loss, bridge state corruption, user confusion
 */
rule addTokensWithSignatures_token_uniqueness_preserved_18(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 tokenID1;
    uint8 tokenID2;

    // assign all the 'before' variables
    address supportedTokens_tokenID1__tokenAddress_before = currentContract.supportedTokens[tokenID1].tokenAddress;
    address supportedTokens_tokenID2__tokenAddress_before = currentContract.supportedTokens[tokenID2].tokenAddress;

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables

    // verify integrity
    assert ((((tokenID1 != tokenID2) && (supportedTokens_tokenID1__tokenAddress_before != 0)) && (supportedTokens_tokenID2__tokenAddress_before != 0)) => (supportedTokens_tokenID1__tokenAddress_before != supportedTokens_tokenID2__tokenAddress_before));
}

/*
 * supportedTokens[tokenID].tokenAddress != address(0) => supportedTokens[tokenID].tokenAddress@after == supportedTokens[tokenID].tokenAddress@before
 *
 * What it means: Token IDs that already have registered tokens should not have their token addresses modified during the add operation
 *
 * Why it should hold: Modifying existing token mappings could break existing bridge operations and user balances. The function should only add new tokens, not modify existing ones
 *
 * Possible consequences: Loss of user funds, broken bridge operations, state corruption, user confusion about token mappings
 */
rule addTokensWithSignatures_existing_tokens_unchanged_19(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 tokenID;

    // assign all the 'before' variables
    address supportedTokens_tokenID__tokenAddress_before = currentContract.supportedTokens[tokenID].tokenAddress;

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address supportedTokens_tokenID__tokenAddress_after = currentContract.supportedTokens[tokenID].tokenAddress;

    // verify integrity
    assert ((supportedTokens_tokenID__tokenAddress_before != 0) => (supportedTokens_tokenID__tokenAddress_after == supportedTokens_tokenID__tokenAddress_before));
}

/*
 * _committee == address(0) => revert
 *
 * What it means: The initialize function must revert if the committee address parameter is the zero address
 *
 * Why it should hold: The committee is critical for signature verification in bridge operations. A zero address committee would make all signature validations fail or behave unpredictably
 *
 * Possible consequences: Complete bridge dysfunction, inability to process any cross-chain transactions, potential for unauthorized operations if signature verification is bypassed
 */
rule initialize_e590e3e8_zero_committee_reverts(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_committee == 0) => initialize_reverted), "_committee == address(0) => revert";
}

/*
 * _chainID == 0 => revert
 *
 * What it means: The initialize function must revert if the chain ID parameter is zero
 *
 * Why it should hold: Chain ID zero is invalid and would cause confusion in cross-chain operations where chain identification is critical
 *
 * Possible consequences: Cross-chain message routing failures, inability to distinguish between different blockchain networks, potential message replay attacks
 */
rule initialize_e590e3e8_invalid_chainID_reverts(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((_chainID == 0) => initialize_reverted), "_chainID == 0 => revert";
}

/*
 * _supportedTokens.length != _tokenPrices.length || _supportedTokens.length != _tokenIds.length || _supportedTokens.length != _suiDecimals.length => revert
 *
 * What it means: The initialize function must revert if the input arrays (_supportedTokens, _tokenPrices, _tokenIds, _suiDecimals) have different lengths
 *
 * Why it should hold: These arrays represent corresponding data for each token - address, price, ID, and decimals must match up correctly for proper token configuration
 *
 * Possible consequences: Incorrect token configuration, array out-of-bounds access, tokens with wrong prices or decimal settings
 */
rule initialize_e590e3e8_array_length_mismatch_reverts(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((((_supportedTokens.length != _tokenPrices.length) || (_supportedTokens.length != _tokenIds.length)) || (_supportedTokens.length != _suiDecimals.length)) => initialize_reverted), "_supportedTokens.length != _tokenPrices.length || _supportedTokens.length != _tokenIds.length || _supportedTokens.length != _suiDecimals.length => revert";
}

/*
 * _supportedTokens.length == 0 || _supportedChains.length == 0 => revert
 *
 * What it means: The initialize function must revert if either the supported tokens array or supported chains array is empty
 *
 * Why it should hold: A bridge with no supported tokens or chains is non-functional and serves no purpose
 *
 * Possible consequences: Deployment of a useless bridge contract, wasted gas, potential confusion for users trying to use the bridge
 */
rule initialize_e590e3e8_empty_arrays_revert(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((_supportedTokens.length == 0) || (_supportedChains.length == 0)) => initialize_reverted), "_supportedTokens.length == 0 || _supportedChains.length == 0 => revert";
}

/*
 * committee@after == _committee
 *
 * What it means: After successful initialization, the committee storage variable must equal the provided _committee parameter
 *
 * Why it should hold: The committee address is essential for signature verification in bridge operations and must be correctly stored
 *
 * Possible consequences: Signature verification failures, inability to process authorized bridge operations, potential security bypass
 */
rule initialize_e590e3e8_committee_set(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    address currentContract_committee_after = currentContract.committee;

    // verify integrity
    assert (currentContract_committee_after == _committee), "committee@after == _committee";
}

/*
 * chainID@after == _chainID
 *
 * What it means: After successful initialization, the chainID storage variable must equal the provided _chainID parameter
 *
 * Why it should hold: Chain ID is used for cross-chain message routing and network identification, must be correctly stored
 *
 * Possible consequences: Cross-chain routing failures, network misidentification, message replay vulnerabilities
 */
rule initialize_e590e3e8_chainID_set(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint8 currentContract_chainID_after = currentContract.chainID;

    // verify integrity
    assert (currentContract_chainID_after == _chainID), "chainID@after == _chainID";
}

/*
 * _tokenIds.length > 0 => supportedTokens[_tokenIds[0]].tokenAddress@after == _supportedTokens[0]
 *
 * What it means: If tokens are provided, the first token's address must be correctly stored in the supportedTokens mapping using its corresponding token ID
 *
 * Why it should hold: Token addresses are critical for identifying which ERC20 contracts are supported for bridging
 *
 * Possible consequences: Wrong token contract used for bridge operations, users bridging unsupported tokens, fund loss
 */
rule initialize_e590e3e8_token_0_address_stored(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    address currentContract_supportedTokens__tokenIds_0___tokenAddress_after = currentContract.supportedTokens[_tokenIds[0]].tokenAddress;

    // verify integrity
    assert ((_tokenIds.length > 0) => (currentContract_supportedTokens__tokenIds_0___tokenAddress_after == _supportedTokens[0])), "_tokenIds.length > 0 => supportedTokens[_tokenIds[0]].tokenAddress@after == _supportedTokens[0]";
}

/*
 * _tokenIds.length > 0 => supportedTokens[_tokenIds[0]].suiDecimal@after == _suiDecimals[0]
 *
 * What it means: If tokens are provided, the first token's Sui decimal configuration must be correctly stored
 *
 * Why it should hold: Decimal precision is critical for accurate amount conversions between different blockchain networks
 *
 * Possible consequences: Incorrect amount calculations, users receiving wrong token amounts, precision loss or overflow
 */
rule initialize_e590e3e8_token_0_decimal_stored(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint8 currentContract_supportedTokens__tokenIds_0___suiDecimal_after = currentContract.supportedTokens[_tokenIds[0]].suiDecimal;

    // verify integrity
    assert ((_tokenIds.length > 0) => (currentContract_supportedTokens__tokenIds_0___suiDecimal_after == _suiDecimals[0])), "_tokenIds.length > 0 => supportedTokens[_tokenIds[0]].suiDecimal@after == _suiDecimals[0]";
}

/*
 * _tokenIds.length > 0 => tokenPrices[_tokenIds[0]]@after == _tokenPrices[0]
 *
 * What it means: If tokens are provided, the first token's price must be correctly stored in the tokenPrices mapping
 *
 * Why it should hold: Token prices are used for fee calculations and value assessments in bridge operations
 *
 * Possible consequences: Incorrect fee calculations, wrong token valuations, economic attacks on the bridge
 */
rule initialize_e590e3e8_token_0_price_stored(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint64 currentContract_tokenPrices__tokenIds_0___after = currentContract.tokenPrices[_tokenIds[0]];

    // verify integrity
    assert ((_tokenIds.length > 0) => (currentContract_tokenPrices__tokenIds_0___after == _tokenPrices[0])), "_tokenIds.length > 0 => tokenPrices[_tokenIds[0]]@after == _tokenPrices[0]";
}

/*
 * _supportedChains.length > 0 => supportedChains[_supportedChains[0]]@after == true
 *
 * What it means: If supported chains are provided, the first chain must be marked as supported in the supportedChains mapping
 *
 * Why it should hold: Only supported chains should be allowed for cross-chain bridge operations
 *
 * Possible consequences: Unsupported chains appearing as supported, routing to invalid networks, failed cross-chain operations
 */
rule initialize_e590e3e8_chain_0_supported(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    bool currentContract_supportedChains__supportedChains_0___after = currentContract.supportedChains[_supportedChains[0]];

    // verify integrity
    assert ((_supportedChains.length > 0) => (currentContract_supportedChains__supportedChains_0___after == true)), "_supportedChains.length > 0 => supportedChains[_supportedChains[0]]@after == true";
}

/*
 * _supportedTokens.length > 0 && _supportedTokens[0] == address(0) => revert
 *
 * What it means: The initialize function must revert if any token address in the array is the zero address
 *
 * Why it should hold: Zero address is not a valid ERC20 contract and would cause bridge operations to fail
 *
 * Possible consequences: Bridge operations failing when interacting with invalid token contracts, potential for exploitation
 */
rule initialize_e590e3e8_zero_token_address_reverts(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((_supportedTokens.length > 0) && (_supportedTokens[0] == 0)) => initialize_reverted), "_supportedTokens.length > 0 && _supportedTokens[0] == address(0) => revert";
}

/*
 * _tokenPrices.length > 0 && _tokenPrices[0] == 0 => revert
 *
 * What it means: The initialize function must revert if any token price in the array is zero
 *
 * Why it should hold: Zero price tokens would break fee calculations and economic models of the bridge
 *
 * Possible consequences: Division by zero errors, free bridge operations, economic attacks, broken fee mechanisms
 */
rule initialize_e590e3e8_zero_token_price_reverts(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((_tokenPrices.length > 0) && (_tokenPrices[0] == 0)) => initialize_reverted), "_tokenPrices.length > 0 && _tokenPrices[0] == 0 => revert";
}

/*
 * _suiDecimals.length > 0 && _suiDecimals[0] == 0 => revert
 *
 * What it means: The initialize function must revert if any Sui decimal value in the array is zero
 *
 * Why it should hold: Zero decimals would cause precision issues and incorrect amount calculations in cross-chain transfers
 *
 * Possible consequences: Amount calculation errors, precision loss, incorrect token amounts on destination chains
 */
rule initialize_e590e3e8_zero_sui_decimal_reverts(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((_suiDecimals.length > 0) && (_suiDecimals[0] == 0)) => initialize_reverted), "_suiDecimals.length > 0 && _suiDecimals[0] == 0 => revert";
}

/*
 * _tokenIds.length > 1 && _tokenIds[0] == _tokenIds[1] => revert
 *
 * What it means: The initialize function must revert if the first two token IDs in the array are identical
 *
 * Why it should hold: Each token must have a unique identifier to prevent configuration conflicts and mapping overwrites
 *
 * Possible consequences: Token configuration overwrites, inconsistent token data, users unable to distinguish between different tokens
 */
rule initialize_e590e3e8_duplicate_tokenId_0_1_reverts(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((_tokenIds.length > 1) && (_tokenIds[0] == _tokenIds[1])) => initialize_reverted), "_tokenIds.length > 1 && _tokenIds[0] == _tokenIds[1] => revert";
}

/*
 * _supportedChains.length > 1 && _supportedChains[0] == _supportedChains[1] => revert
 *
 * What it means: The initialize function must revert if the first two chain IDs in the supported chains array are identical
 *
 * Why it should hold: Each chain should only be listed once to prevent configuration inconsistencies
 *
 * Possible consequences: Redundant chain configurations, potential for inconsistent chain settings, confusion in routing logic
 */
rule initialize_e590e3e8_duplicate_chain_0_1_reverts(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize@withrevert(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);
    bool initialize_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert (((_supportedChains.length > 1) && (_supportedChains[0] == _supportedChains[1])) => initialize_reverted), "_supportedChains.length > 1 && _supportedChains[0] == _supportedChains[1] => revert";
}

/*
 * _tokenIds.length > 1 => supportedTokens[_tokenIds[1]].tokenAddress@after == _supportedTokens[1]
 *
 * What it means: If a second token is provided, its address must be correctly stored in the supportedTokens mapping
 *
 * Why it should hold: All provided tokens must be properly configured for the bridge to function correctly
 *
 * Possible consequences: Second token unusable for bridging, partial bridge functionality, user confusion
 */
rule initialize_e590e3e8_token_1_address_stored(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    address currentContract_supportedTokens__tokenIds_1___tokenAddress_after = currentContract.supportedTokens[_tokenIds[1]].tokenAddress;

    // verify integrity
    assert ((_tokenIds.length > 1) => (currentContract_supportedTokens__tokenIds_1___tokenAddress_after == _supportedTokens[1])), "_tokenIds.length > 1 => supportedTokens[_tokenIds[1]].tokenAddress@after == _supportedTokens[1]";
}

/*
 * _tokenIds.length > 1 => supportedTokens[_tokenIds[1]].suiDecimal@after == _suiDecimals[1]
 *
 * What it means: If a second token is provided, its Sui decimal configuration must be correctly stored
 *
 * Why it should hold: Decimal precision must be correct for all supported tokens to ensure accurate conversions
 *
 * Possible consequences: Incorrect amount calculations for second token, precision errors, wrong token amounts
 */
rule initialize_e590e3e8_token_1_decimal_stored(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint8 currentContract_supportedTokens__tokenIds_1___suiDecimal_after = currentContract.supportedTokens[_tokenIds[1]].suiDecimal;

    // verify integrity
    assert ((_tokenIds.length > 1) => (currentContract_supportedTokens__tokenIds_1___suiDecimal_after == _suiDecimals[1])), "_tokenIds.length > 1 => supportedTokens[_tokenIds[1]].suiDecimal@after == _suiDecimals[1]";
}

/*
 * _tokenIds.length > 1 => tokenPrices[_tokenIds[1]]@after == _tokenPrices[1]
 *
 * What it means: If a second token is provided, its price must be correctly stored in the tokenPrices mapping
 *
 * Why it should hold: Accurate pricing is essential for fee calculations and economic security of all supported tokens
 *
 * Possible consequences: Wrong fee calculations for second token, economic vulnerabilities, incorrect valuations
 */
rule initialize_e590e3e8_token_1_price_stored(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint64 currentContract_tokenPrices__tokenIds_1___after = currentContract.tokenPrices[_tokenIds[1]];

    // verify integrity
    assert ((_tokenIds.length > 1) => (currentContract_tokenPrices__tokenIds_1___after == _tokenPrices[1])), "_tokenIds.length > 1 => tokenPrices[_tokenIds[1]]@after == _tokenPrices[1]";
}

/*
 * _supportedChains.length > 1 => supportedChains[_supportedChains[1]]@after == true
 *
 * What it means: If a second chain is provided, it must be marked as supported in the supportedChains mapping
 *
 * Why it should hold: All listed chains should be properly configured as supported for cross-chain operations
 *
 * Possible consequences: Second chain unusable despite being in configuration, partial bridge functionality
 */
rule initialize_e590e3e8_chain_1_supported(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    // assign all the 'before' variables

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    bool currentContract_supportedChains__supportedChains_1___after = currentContract.supportedChains[_supportedChains[1]];

    // verify integrity
    assert ((_supportedChains.length > 1) => (currentContract_supportedChains__supportedChains_1___after == true)), "_supportedChains.length > 1 => supportedChains[_supportedChains[1]]@after == true";
}

/*
 * supportedTokens[255].tokenAddress@before == supportedTokens[255].tokenAddress@after
 *
 * What it means: Token addresses not specified in the initialization should remain unchanged from their previous state
 *
 * Why it should hold: Initialize should only modify explicitly provided configurations, not affect other token slots
 *
 * Possible consequences: Unintended token configuration changes, existing token settings corrupted, unpredictable bridge behavior
 */
// gereon: AI missed the _tokenIds array
rule initialize_e590e3e8_unspecified_token_address_unchanged(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    uint8 i;
    require(forall uint256 j. (j < _tokenIds.length) => (i != _tokenIds[j]));

    // assign all the 'before' variables
    address currentContract_supportedTokens_255__tokenAddress_before = currentContract.supportedTokens[i].tokenAddress;

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    address currentContract_supportedTokens_255__tokenAddress_after = currentContract.supportedTokens[i].tokenAddress;

    // verify integrity
    assert (currentContract_supportedTokens_255__tokenAddress_before == currentContract_supportedTokens_255__tokenAddress_after), "supportedTokens[255].tokenAddress@before == supportedTokens[255].tokenAddress@after";
}

/*
 * supportedTokens[255].suiDecimal@before == supportedTokens[255].suiDecimal@after
 *
 * What it means: Token decimal configurations not specified in initialization should remain unchanged
 *
 * Why it should hold: Initialize should preserve existing token decimal settings for tokens not being reconfigured
 *
 * Possible consequences: Existing token decimal settings corrupted, amount calculation errors for previously configured tokens
 */
// gereon: AI missed the _tokenIds array
rule initialize_e590e3e8_unspecified_token_decimal_unchanged(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    uint8 i;
    require(forall uint256 j. (j < _tokenIds.length) => (i != _tokenIds[j]));

    // assign all the 'before' variables
    uint8 currentContract_supportedTokens_255__suiDecimal_before = currentContract.supportedTokens[i].suiDecimal;

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint8 currentContract_supportedTokens_255__suiDecimal_after = currentContract.supportedTokens[i].suiDecimal;

    // verify integrity
    assert (currentContract_supportedTokens_255__suiDecimal_before == currentContract_supportedTokens_255__suiDecimal_after), "supportedTokens[255].suiDecimal@before == supportedTokens[255].suiDecimal@after";
}

/*
 * tokenPrices[255]@before == tokenPrices[255]@after
 *
 * What it means: Token prices not specified in initialization should remain unchanged from their previous values
 *
 * Why it should hold: Initialize should only update prices for tokens being configured, not affect existing price data
 *
 * Possible consequences: Existing token prices corrupted, wrong fee calculations for previously configured tokens
 */
// gereon: AI missed the _tokenIds array
rule initialize_e590e3e8_unspecified_price_unchanged(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    uint8 i;
    require(forall uint256 j. (j < _tokenIds.length) => (i != _tokenIds[j]));

    // assign all the 'before' variables
    uint64 currentContract_tokenPrices_255__before = currentContract.tokenPrices[i];

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    uint64 currentContract_tokenPrices_255__after = currentContract.tokenPrices[i];

    // verify integrity
    assert (currentContract_tokenPrices_255__before == currentContract_tokenPrices_255__after), "tokenPrices[255]@before == tokenPrices[255]@after";
}

/*
 * supportedChains[255]@before == supportedChains[255]@after
 *
 * What it means: Chain support status not specified in initialization should remain unchanged
 *
 * Why it should hold: Initialize should only modify chain support for explicitly provided chains, not affect other chain configurations
 *
 * Possible consequences: Existing chain configurations corrupted, previously supported chains becoming unsupported
 */
// gereon: AI missed the _supportedChains array
rule initialize_e590e3e8_unspecified_chain_unchanged(env e) {
    address _committee;
    uint8 _chainID;
    address[] _supportedTokens;
    uint64[] _tokenPrices;
    uint8[] _tokenIds;
    uint8[] _suiDecimals;
    uint8[] _supportedChains;

    uint8 i;
    require(forall uint256 j. (j < _supportedChains.length) => (i != _supportedChains[j]));

    // assign all the 'before' variables
    bool currentContract_supportedChains_255__before = currentContract.supportedChains[i];

    // call function under test
    initialize(e, _committee, _chainID, _supportedTokens, _tokenPrices, _tokenIds, _suiDecimals, _supportedChains);

    // assign all the 'after' variables
    bool currentContract_supportedChains_255__after = currentContract.supportedChains[i];

    // verify integrity
    assert (currentContract_supportedChains_255__before == currentContract_supportedChains_255__after), "supportedChains[255]@before == supportedChains[255]@after";
}

/*
 * message.messageType != BridgeUtils.UPDATE_TOKEN_PRICE => revert
 *
 * What it means: The function must revert if the message type is not UPDATE_TOKEN_PRICE
 *
 * Why it should hold: The function has a verifyMessageAndSignatures modifier that specifically checks for BridgeUtils.UPDATE_TOKEN_PRICE message type. This ensures the function only processes token price update messages and not other message types like ADD_EVM_TOKENS or upgrade messages.
 *
 * Possible consequences: State corruption, unauthorized operations, bypass of access controls
 */
rule updateTokenPriceWithSignatures_bfb5d846_invalid_message_type_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    updateTokenPriceWithSignatures@withrevert(e, signatures, message);
    bool updateTokenPriceWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.messageType != BridgeUtils.UPDATE_TOKEN_PRICE(e)) => updateTokenPriceWithSignatures_reverted), "message.messageType != BridgeUtils.UPDATE_TOKEN_PRICE => revert";
}

/*
 * signatures.length == 0 => revert
 *
 * What it means: The function must revert if no signatures are provided in the signatures array
 *
 * Why it should hold: The verifyMessageAndSignatures modifier requires valid committee signatures to authorize token price updates. An empty signatures array means no authorization was provided, which should cause the verification to fail.
 *
 * Possible consequences: Unauthorized token price manipulation, bypass of committee governance
 */
rule updateTokenPriceWithSignatures_bfb5d846_empty_signatures_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    updateTokenPriceWithSignatures@withrevert(e, signatures, message);
    bool updateTokenPriceWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((signatures.length == 0) => updateTokenPriceWithSignatures_reverted), "signatures.length == 0 => revert";
}

/*
 * message.nonce <= nonces[message.messageType]@before => revert
 *
 * What it means: The function must revert if the message nonce is less than or equal to the current nonce for the UPDATE_TOKEN_PRICE message type
 *
 * Why it should hold: Nonces prevent replay attacks by ensuring each message can only be processed once. The nonce must be strictly greater than the previously processed nonce to maintain chronological order and prevent reuse of old signatures.
 *
 * Possible consequences: Replay attacks, stale price updates, economic manipulation
 */
// gereon: not sure why the AI chose <= instead of !=
rule updateTokenPriceWithSignatures_bfb5d846_invalid_nonce_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 currentContract_nonces_message_messageType__before = currentContract.nonces[message.messageType];

    // call function under test
    updateTokenPriceWithSignatures@withrevert(e, signatures, message);
    bool updateTokenPriceWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.nonce != currentContract_nonces_message_messageType__before) => updateTokenPriceWithSignatures_reverted), "message.nonce <= nonces[message.messageType]@before => revert";
}

/*
 * message.nonce > nonces[message.messageType]@before => nonces[message.messageType]@after == message.nonce
 *
 * What it means: When a valid message is processed (nonce greater than current), the stored nonce for UPDATE_TOKEN_PRICE message type should be updated to the message nonce
 *
 * Why it should hold: This ensures proper nonce progression and prevents replay attacks. Each successfully processed message should advance the nonce counter to mark that message as consumed.
 *
 * Possible consequences: Replay attack vulnerability, nonce desynchronization
 */
rule updateTokenPriceWithSignatures_bfb5d846_nonce_increments(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 currentContract_nonces_message_messageType__before = currentContract.nonces[message.messageType];

    // call function under test
    updateTokenPriceWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 currentContract_nonces_message_messageType__after = currentContract.nonces[message.messageType];

    // verify integrity
    assert ((message.nonce > currentContract_nonces_message_messageType__before) => (currentContract_nonces_message_messageType__after == message.nonce)), "message.nonce > nonces[message.messageType]@before => nonces[message.messageType]@after == message.nonce";
}

/*
 * supportedChains[chainId]@after == supportedChains[chainId]@before
 *
 * What it means: The supportedChains mapping should not be modified by this function for any chain ID
 *
 * Why it should hold: This function is specifically for updating token prices, not for managing supported chains. The supportedChains mapping should only be modified by dedicated chain management functions.
 *
 * Possible consequences: Unauthorized chain support changes, protocol scope manipulation
 */
rule updateTokenPriceWithSignatures_bfb5d846_chains_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 chainId;

    // assign all the 'before' variables
    bool currentContract_supportedChains_chainId__before = currentContract.supportedChains[chainId];

    // call function under test
    updateTokenPriceWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool currentContract_supportedChains_chainId__after = currentContract.supportedChains[chainId];

    // verify integrity
    assert (currentContract_supportedChains_chainId__after == currentContract_supportedChains_chainId__before), "supportedChains[chainId]@after == supportedChains[chainId]@before";
}

/*
 * supportedTokens[tokenID].tokenAddress@after == supportedTokens[tokenID].tokenAddress@before
 *
 * What it means: The token addresses in the supportedTokens mapping should not be modified by this function
 *
 * Why it should hold: This function should only update token prices, not token configurations. Token addresses are fundamental to token identity and should only be changed through dedicated token management functions like addTokensWithSignatures.
 *
 * Possible consequences: Token identity corruption, fund misdirection, protocol confusion
 */
rule updateTokenPriceWithSignatures_bfb5d846_token_addresses_unchanged(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 tokenID;

    // assign all the 'before' variables
    address currentContract_supportedTokens_tokenID__tokenAddress_before = currentContract.supportedTokens[tokenID].tokenAddress;

    // call function under test
    updateTokenPriceWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address currentContract_supportedTokens_tokenID__tokenAddress_after = currentContract.supportedTokens[tokenID].tokenAddress;

    // verify integrity
    assert (currentContract_supportedTokens_tokenID__tokenAddress_after == currentContract_supportedTokens_tokenID__tokenAddress_before), "supportedTokens[tokenID].tokenAddress@after == supportedTokens[tokenID].tokenAddress@before";
}

/*
 * signatures.length == 0 => revert
 *
 * What it means: The function must revert if no signatures are provided in the signatures array
 *
 * Why it should hold: The verifyMessageAndSignatures modifier requires valid signatures to authenticate the message. Empty signatures array means no authentication, which should be rejected
 *
 * Possible consequences: Unauthorized token additions without proper committee approval, leading to bridge compromise and potential fund loss
 */
rule addTokensWithSignatures_43025664_invalid_signatures_revert(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    addTokensWithSignatures@withrevert(e, signatures, message);
    bool addTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((signatures.length == 0) => addTokensWithSignatures_reverted), "signatures.length == 0 => revert";
}

/*
 * message.messageType != BridgeUtils.ADD_EVM_TOKENS => revert
 *
 * What it means: The function must revert if the message type is not BridgeUtils.ADD_EVM_TOKENS
 *
 * Why it should hold: The verifyMessageAndSignatures modifier expects ADD_EVM_TOKENS message type. Wrong message types indicate message reuse or incorrect function call
 *
 * Possible consequences: Message replay attacks or cross-function message abuse, leading to unauthorized operations and state corruption
 */
rule addTokensWithSignatures_43025664_message_type_must_match(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    addTokensWithSignatures@withrevert(e, signatures, message);
    bool addTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.messageType != BridgeUtils.ADD_EVM_TOKENS(e)) => addTokensWithSignatures_reverted), "message.messageType != BridgeUtils.ADD_EVM_TOKENS => revert";
}

/*
 * message.payload.length == 0 => revert
 *
 * What it means: The function must revert if the message payload is empty
 *
 * Why it should hold: The payload should contain token data to be added. Empty payload means no meaningful operation can be performed, which should be rejected as a no-op
 *
 * Possible consequences: DoS attacks through meaningless transactions that consume gas without performing useful work
 */
rule addTokensWithSignatures_43025664_empty_payload_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables

    // call function under test
    addTokensWithSignatures@withrevert(e, signatures, message);
    bool addTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.payload.length == 0) => addTokensWithSignatures_reverted), "message.payload.length == 0 => revert";
}

/*
 * supportedTokens[tokenID].tokenAddress@before != address(0) => revert
 *
 * What it means: The function must revert if trying to add a token that already exists (has a non-zero address)
 *
 * Why it should hold: Adding duplicate tokens would overwrite existing token configurations, potentially corrupting the bridge state and breaking existing functionality
 *
 * Possible consequences: State corruption, loss of existing token configurations, and potential bridge malfunction leading to fund loss
 */
rule addTokensWithSignatures_43025664_already_supported_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 tokenID;

    // assign all the 'before' variables
    address currentContract_supportedTokens_tokenID__tokenAddress_before = currentContract.supportedTokens[tokenID].tokenAddress;

    // call function under test
    addTokensWithSignatures@withrevert(e, signatures, message);
    bool addTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((currentContract_supportedTokens_tokenID__tokenAddress_before != 0) => addTokensWithSignatures_reverted), "supportedTokens[tokenID].tokenAddress@before != address(0) => revert";
}

/*
 * chainID@after == chainID@before
 *
 * What it means: The function must not modify the chainID storage variable
 *
 * Why it should hold: chainID is set during initialization and should remain constant. It identifies which blockchain the contract is deployed on
 *
 * Possible consequences: Bridge identity confusion, cross-chain message routing failures, and potential fund loss due to incorrect chain identification
 */
rule addTokensWithSignatures_43025664_preserves_chain_id(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 currentContract_chainID_before = currentContract.chainID;

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint8 currentContract_chainID_after = currentContract.chainID;

    // verify integrity
    assert (currentContract_chainID_after == currentContract_chainID_before), "chainID@after == chainID@before";
}

/*
 * committee@after == committee@before
 *
 * What it means: The function must not modify the committee address
 *
 * Why it should hold: The committee address controls signature verification and should only be changed through proper governance mechanisms, not through token addition functions
 *
 * Possible consequences: Complete bridge takeover, unauthorized control over all bridge operations, and total fund loss
 */
rule addTokensWithSignatures_43025664_preserves_committee(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address currentContract_committee_before = currentContract.committee;

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address currentContract_committee_after = currentContract.committee;

    // verify integrity
    assert (currentContract_committee_after == currentContract_committee_before), "committee@after == committee@before";
}

/*
 * supportedChains[anyChainId]@after == supportedChains[anyChainId]@before
 *
 * What it means: The function must not modify the supportedChains mapping for any chain ID
 *
 * Why it should hold: Chain support configuration should only be modified through dedicated chain management functions, not token addition functions
 *
 * Possible consequences: Unauthorized chain additions or removals, breaking cross-chain functionality and potentially enabling attacks from unsupported chains
 */
rule addTokensWithSignatures_43025664_preserves_supported_chains(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 anyChainId;

    // assign all the 'before' variables
    bool currentContract_supportedChains_anyChainId__before = currentContract.supportedChains[anyChainId];

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool currentContract_supportedChains_anyChainId__after = currentContract.supportedChains[anyChainId];

    // verify integrity
    assert (currentContract_supportedChains_anyChainId__after == currentContract_supportedChains_anyChainId__before), "supportedChains[anyChainId]@after == supportedChains[anyChainId]@before";
}

/*
 * message.nonce <= nonces[message.messageType]@before => revert
 *
 * What it means: The function must revert if the message nonce is not greater than the current nonce for the message type
 *
 * Why it should hold: Nonces prevent replay attacks by ensuring each message can only be processed once and in order
 *
 * Possible consequences: Replay attacks allowing duplicate token additions and potential state corruption
 */
rule addTokensWithSignatures_43025664_invalid_nonce_reverts(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 currentContract_nonces_message_messageType__before = currentContract.nonces[message.messageType];

    // call function under test
    addTokensWithSignatures@withrevert(e, signatures, message);
    bool addTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message.nonce <= currentContract_nonces_message_messageType__before) => addTokensWithSignatures_reverted), "message.nonce <= nonces[message.messageType]@before => revert";
}

/*
 * message.nonce > nonces[message.messageType]@before => nonces[message.messageType]@after == message.nonce
 *
 * What it means: The function must update the nonce for the message type to the message's nonce value when processing a valid message
 *
 * Why it should hold: Nonce updates are essential for replay protection - they mark messages as processed and prevent future replay
 *
 * Possible consequences: Replay attack vulnerability allowing the same message to be processed multiple times
 */
rule addTokensWithSignatures_43025664_updates_nonce(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint64 currentContract_nonces_message_messageType__before = currentContract.nonces[message.messageType];

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 currentContract_nonces_message_messageType__after = currentContract.nonces[message.messageType];

    // verify integrity
    assert ((message.nonce > currentContract_nonces_message_messageType__before) => (currentContract_nonces_message_messageType__after == message.nonce)), "message.nonce > nonces[message.messageType]@before => nonces[message.messageType]@after == message.nonce";
}

/*
 * otherType != message.messageType => nonces[otherType]@after == nonces[otherType]@before
 *
 * What it means: The function must not modify nonces for other message types, only for ADD_EVM_TOKENS
 *
 * Why it should hold: Each message type has its own nonce sequence. Modifying other nonces would break the replay protection for other functions
 *
 * Possible consequences: Cross-function replay attack vulnerabilities and broken message ordering for other bridge operations
 */
rule addTokensWithSignatures_43025664_preserves_other_nonces(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 otherType;

    // assign all the 'before' variables
    uint64 currentContract_nonces_otherType__before = currentContract.nonces[otherType];

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 currentContract_nonces_otherType__after = currentContract.nonces[otherType];

    // verify integrity
    assert ((otherType != message.messageType) => (currentContract_nonces_otherType__after == currentContract_nonces_otherType__before)), "otherType != message.messageType => nonces[otherType]@after == nonces[otherType]@before";
}

/*
 * tokenID1 != tokenID2 && supportedTokens[tokenID1].tokenAddress@after != address(0) && supportedTokens[tokenID2].tokenAddress@after != address(0) => supportedTokens[tokenID1].tokenAddress@after != supportedTokens[tokenID2].tokenAddress@after
 *
 * What it means: Different token IDs must map to different token addresses - no two token IDs can have the same address
 *
 * Why it should hold: Token ID to address mapping must be unique to prevent confusion and ensure proper token identification across the bridge
 *
 * Possible consequences: Token identification confusion, incorrect routing of bridge operations, and potential fund loss due to misidentified tokens
 */
rule addTokensWithSignatures_43025664_token_uniqueness(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 tokenID1;
    uint8 tokenID2;

    // assign all the 'before' variables

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address currentContract_supportedTokens_tokenID1__tokenAddress_after = currentContract.supportedTokens[tokenID1].tokenAddress;
    address currentContract_supportedTokens_tokenID2__tokenAddress_after = currentContract.supportedTokens[tokenID2].tokenAddress;

    // verify integrity
    assert ((((tokenID1 != tokenID2) && (currentContract_supportedTokens_tokenID1__tokenAddress_after != 0)) && (currentContract_supportedTokens_tokenID2__tokenAddress_after != 0)) => (currentContract_supportedTokens_tokenID1__tokenAddress_after != currentContract_supportedTokens_tokenID2__tokenAddress_after)), "tokenID1 != tokenID2 && supportedTokens[tokenID1].tokenAddress@after != address(0) && supportedTokens[tokenID2].tokenAddress@after != address(0) => supportedTokens[tokenID1].tokenAddress@after != supportedTokens[tokenID2].tokenAddress@after";
}