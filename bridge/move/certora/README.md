# Certora Verification of the SUI part of the SUI Bridge

## Installation and Running

The installation instructions for the Certora Prover are described in: 
(Installation of Certora Prover)[https://docs.certora.com/en/latest/docs/user-guide/install.html]. Note you will need an appropriate Java version for the local type-checking to work.

After installing the Certora Prover, you can start the verification as follows.

```
cd certora/spec
certoraSuiProver.py --server production --prover_version master
```

## Bridge Properties

### send_token burns coins
The token sent to the `send_token` function is deleted.

### Only claiming mints tokens
Of the public functions of the vault, only `claim_token` and `claim_and_transfer_token` may mint any token, i.e., increase the total supply of any token.

### Only owner can claim
Only the owner of a transfer may call the `claim_token` function.  The owner is determined by retrieving the token transfer message using `source_chain` and `seq_num`, parsing the message and taking the target_address from the parsed payload.

### transfer records are valid
If a transfer record is added to the global list of transfer records by any function, then the transfer record is either signed or it originated on the current chain, i.e., the record's `source_chain` equals the Bridge's `chain_id()`.

### seq_nums monotonically increase
The `seq_num` (used to check that messages are executed in the right order) can only increase, i.e., for any public function the sequence number after the function must be greater or equal to the sequence number before the function.

### Effects of send_token
Calling `send_token` will increase the sequence number for `TOKEN` messages, it will burn the tokens, i.e., the total supply decreases by the amount, and it will add a token deposited event with the correct sequence number and the right amount.

### Effects of approve_token_transfer
A non-reverting call of `approve_token_transfer` either generates a token transfer approved message or a token transfer already approved message, the latter if the status of the transfer before the call was already approved or claimed.  The status after a call when the transfer was already approved does not change, if the call did approve the message the status changes to `approved`.

The parameters of the generated event matches the parameters of the `approve_token_transfer` call (source chain and sequence number).

### Effects of claim_token
Successfully calling `claim_token` will emit a `TokenTransferClaimed` event (and no other token related events).  The status of the transfer must be `approved` before the call and `claimed` after the call.  The event's parameter must match the parameters of the `claim_token` function.  The total supply of the token must increase by the token's amount (the token is freshly minted), and the token amount must equal the amount specified in the transfer record.  

### Effects of claim_and_transfer_token
Successfully calling `claim_and_transfer_token` will emit exactly on of the three events `TokenTransferClaimed`, `TokenTransferAlreadyClaimed` or `TokenTransferLimitExceed`.  The  parameters of the event matches the parameters of the `claim_and_transfer_token` function. 
If the claim was successful (`TokenTransferClaimed` generated) there must be a transfer of the token and the total supply of the token increases by the token amount.  The transferred token amount must equal the amount specified in the transfer record. The status must change from `approved` to `claimed.  If the token transfer was not successful, the toal supply of the token must not change, there must be no token transfer and the status must not change.

### Changes of transfer record status
The status of a transfer record can only change in the following direction: `status_not_found` -> `pending` -> `approved` -> `claimed`.  Once the status is claimed it can never change again.  It's not possible to skip the `approved` state and jump directly to `claimed`.

### Only approve_token_transfer can approve transfer
The only way the status of a transfer record can change to `approved` from a non-approved state is by calling `approve_token_transfer`.

### Invariant: Pending status only for internal transfers
The status of a transfer record can only be pending if the source chain of the transfer record equals the Bridge's `chain_id()`.
