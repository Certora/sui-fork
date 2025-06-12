set -e
sui move build --test
java -Dlevel.move=debug -Dlevel.bmc=debug -Dreport.jimple -Dreport.heuristical.folding.rewrite -jar $CERTORA/emv.jar -movePath build/Bridge/bytecode_modules/ -moveSpec b::certora_rules
