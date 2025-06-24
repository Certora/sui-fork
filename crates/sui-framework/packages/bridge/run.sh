set -e
sui move build --test
java -Dlevel.setup.helpers=warn -jar $CERTORA/emv.jar -treeViewReportUpdateInterval 0 -movePath build/Bridge/bytecode_modules/ -b 2 -assumeUnwindCond
