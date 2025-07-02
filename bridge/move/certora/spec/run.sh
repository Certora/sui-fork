set -e
sui move build --test
certoraSuiProver.py --move_path build --java_args "-Dverbose.setup.helpers" --optimistic_loop --loop_iter 2 --prover_args "-treeViewReportUpdateInterval 0" #-includeMoveRules claim_and_transfer_token_effects
