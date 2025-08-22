set -e
sui move build --test
certoraSuiProver.py Bridge.conf --server staging --prover_version eric/parametric --prover_args "-calltraceFreeOpt true"
