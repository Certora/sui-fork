set -e
sui move build --test
certoraSuiProver.py Bridge.conf --server staging --prover_version feature/move
