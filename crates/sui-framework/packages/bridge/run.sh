sui move build --test
java -Dlevel.move=info -Dreport.jimple -jar $CERTORA/emv.jar -movePath build/Bridge/bytecode_modules/ -moveSpec b::certora_rules -b 32
