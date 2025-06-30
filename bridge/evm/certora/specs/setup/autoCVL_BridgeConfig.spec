import "dispatching_BridgeConfig.spec";
import "setup_BridgeConfig.spec";
import "snippet_uups.spec";

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
 * nonces[message.chainID]@after == nonces[message.chainID]@before + 1
 *
 * What it means: Each successful price update must increment the nonce for the message's source chain to prevent replay attacks
 *
 * Why it should hold: The verifyMessageAndSignatures modifier should increment nonces to ensure each message can only be processed once. This prevents replay attacks using the same signed message multiple times
 *
 * Possible consequences: Without proper nonce incrementation, attackers could replay the same price update message multiple times, potentially causing state inconsistencies or bypassing rate limiting
 */
rule updateTokenPriceWithSignatures_nonce_increments_14(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_chainID_before = message.chainID;
    uint64 nonces_message_chainID_before__before = currentContract.nonces[message_chainID_before];

    // call function under test
    updateTokenPriceWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint64 nonces_message_chainID_before__after = currentContract.nonces[message_chainID_before];

    // verify integrity
    assert (nonces_message_chainID_before__after == nonces_message_chainID_before__before + 1);
}

/*
 * supportedChains[chainId]@after == supportedChains[chainId]@before && chainID@after == chainID@before
 *
 * What it means: Price updates must not modify the supportedChains mapping or the chainID, which define which chains the bridge supports
 *
 * Why it should hold: updateTokenPriceWithSignatures should only update token prices, not chain configuration. Modifying chain settings would be a serious scope violation that could break bridge routing
 *
 * Possible consequences: Unintended changes to chain configuration could break cross-chain operations, enable routing to unsupported chains, or disable legitimate bridge routes
 */
rule updateTokenPriceWithSignatures_chain_config_unchanged_15(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 chainId;

    // assign all the 'before' variables
    bool supportedChains_chainId__before = currentContract.supportedChains[chainId];
    uint8 chainID_before = currentContract.chainID;

    // call function under test
    updateTokenPriceWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool supportedChains_chainId__after = currentContract.supportedChains[chainId];
    uint8 chainID_after = currentContract.chainID;

    // verify integrity
    assert ((supportedChains_chainId__after == supportedChains_chainId__before) && (chainID_after == chainID_before));
}

/*
 * message.messageType != BridgeUtils.ADD_EVM_TOKENS => revert
 *
 * What it means: The function must revert if the message type is not specifically ADD_EVM_TOKENS, preventing misuse of other message types
 *
 * Why it should hold: The verifyMessageAndSignatures modifier checks that the message type matches ADD_EVM_TOKENS. Using wrong message types could bypass intended validation logic or execute unintended operations
 *
 * Possible consequences: Function misuse, bypassing of validation checks, potential execution of unintended operations, protocol confusion
 */
rule addTokensWithSignatures_wrong_message_type_reverts_16(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 message_messageType_before = message.messageType;

    // call function under test
    addTokensWithSignatures@withrevert(e, signatures, message);
    bool addTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message_messageType_before != 7) => addTokensWithSignatures_reverted);
}

/*
 * message.payload.length == 0 => revert
 *
 * What it means: The function must revert if the message payload is empty, as there would be no token data to process
 *
 * Why it should hold: The function needs to decode token information from the payload using BridgeUtils.decodeAddTokensPayload. An empty payload would cause decoding to fail or result in invalid token data
 *
 * Possible consequences: Function execution with no meaningful operation, potential state corruption, waste of gas, protocol confusion
 */
rule addTokensWithSignatures_empty_payload_reverts_17(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint256 message_payload_length_before = message.payload.length;

    // call function under test
    addTokensWithSignatures@withrevert(e, signatures, message);
    bool addTokensWithSignatures_reverted = lastReverted;

    // assign all the 'after' variables

    // verify integrity
    assert ((message_payload_length_before == 0) => addTokensWithSignatures_reverted);
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
 * supportedChains[chainId]@after == supportedChains[chainId]@before
 *
 * What it means: The function should not modify which chains are supported by the bridge, as it only handles token addition
 *
 * Why it should hold: addTokensWithSignatures is specifically for adding tokens, not modifying chain support. Chain support changes should go through separate governance processes
 *
 * Possible consequences: Unauthorized chain modifications, bypass of chain governance, potential security vulnerabilities from unsupported chains
 */
rule addTokensWithSignatures_chain_support_unchanged_20(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;
    uint8 chainId;

    // assign all the 'before' variables
    bool supportedChains_chainId__before = currentContract.supportedChains[chainId];

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    bool supportedChains_chainId__after = currentContract.supportedChains[chainId];

    // verify integrity
    assert (supportedChains_chainId__after == supportedChains_chainId__before);
}

/*
 * committee@after == committee@before
 *
 * What it means: The committee address should remain unchanged during token addition operations
 *
 * Why it should hold: The committee is the core governance mechanism for the bridge. Token addition should not modify governance structure, which requires separate authorization
 *
 * Possible consequences: Governance takeover, unauthorized control of bridge operations, complete bridge compromise
 */
rule addTokensWithSignatures_committee_unchanged_21(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    address committee_before = currentContract.committee;

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    address committee_after = currentContract.committee;

    // verify integrity
    assert (committee_after == committee_before);
}

/*
 * chainID@after == chainID@before
 *
 * What it means: The chain ID of the current deployment should not be modified during token addition
 *
 * Why it should hold: Chain ID is a fundamental identifier for the bridge deployment and should never change after initialization. Modifying it could break cross-chain communication
 *
 * Possible consequences: Cross-chain communication failure, message routing errors, bridge isolation, fund loss
 */
rule addTokensWithSignatures_chainID_unchanged_22(env e) {
    bytes[] signatures;
    BridgeUtils.Message message;

    // assign all the 'before' variables
    uint8 chainID_before = currentContract.chainID;

    // call function under test
    addTokensWithSignatures(e, signatures, message);

    // assign all the 'after' variables
    uint8 chainID_after = currentContract.chainID;

    // verify integrity
    assert (chainID_after == chainID_before);
}