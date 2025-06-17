set -e
sui move build --test
java -Dlevel.move=warn -jar $CERTORA/emv.jar -movePath build/Bridge/bytecode_modules/
