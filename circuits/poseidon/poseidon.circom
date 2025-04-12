pragma circom 2.2.1;
include "../../circomlib/circuits/poseidon.circom";

template PoseidonHash(){
    signal input in[2];
    signal output out;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== in[0];
    poseidon.inputs[1] <== in[1];
    log(poseidon.out);
}

component main = PoseidonHash();

/**
snarkjs wtns calculate circuits/privtopub_js/privtopub
.wasm circuits/inputs.json circuits/witness.wtns
*/
//"in":["2663650283170244039192395520307978391420596105812817038908217229013048256723","17673564977949265178054599648760830255939124075096452209243247778790949972933"]

// 10715990366512551801584862565585442947067714049662898227573318196676824969070