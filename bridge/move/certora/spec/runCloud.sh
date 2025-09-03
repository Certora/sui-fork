set -e
sui move build --test
certoraSuiProver.py Bridge.conf --server staging --prover_version eric/opt --prover_args "-calltraceFreeOpt true"
