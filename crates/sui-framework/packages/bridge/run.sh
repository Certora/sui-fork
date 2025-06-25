set -e
sui move build --test
java -Dverbose.setup.helpers -jar $CERTORA/emv.jar -treeViewReportUpdateInterval 0 -movePath build -b 2 -assumeUnwindCond
