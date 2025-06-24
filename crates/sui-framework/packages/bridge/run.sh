set -e
sui move build --test
java -Dlevel.move=warn -jar $CERTORA/emv.jar -treeViewReportUpdateInterval 0 -movePath build/Bridge/bytecode_modules/ -includeMoveRules claim_token_sanity -coverageInfo advanced
