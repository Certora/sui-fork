set -e
sui move build --test
certoraSuiProver.py Bridge.conf --prover_args "-calltraceFreeOpt true -includeMoveRules only_claiming_mints_tokens"

# -includeMoveTargetNames claim_token
