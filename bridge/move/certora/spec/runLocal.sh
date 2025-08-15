set -e
sui move build --test
certoraSuiProver.py Bridge.conf # --prover_args "-includeMoveRules transfer_records_are_valid -calltraceFreeOpt false"
