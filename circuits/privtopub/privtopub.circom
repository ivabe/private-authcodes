pragma circom 2.2.1;
include "../../circomlib/circuits/babyjub.circom";

template PrivToPub(){
    signal input priv;
    signal input pubk[2];
    signal output x;
    signal output y;

    component pub = BabyPbk();
    pub.in <== priv;
    pub.Ax ==> x;
    pub.Ay ==> y;
    log(x);
    log(y);
    pubk[0] === x;
    pubk[1] === y;

}

component main {public [pubk]} = PrivToPub();
/*
    snarkjs groth16 setup privtopub.r1cs powersOfTau28_hez_final_16.ptau circuit_0000.zkey
    snarkjs zkey contribute circuit_0000.zkey final
.zkey --name="kdjiehiwejhcnkm" -v

snarkjs zkey export verificationkey final.zkey 
vkey.json

snarkjs groth16 prove final.zkey witness.wtns proof.json public.json

 *  snarkjs wtns calculate circuits/privtopub_js/privtopub
.wasm circuits/inputs.json circuits/witness.wtns
 *  snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json
 *   snarkjs groth16 verify verification_key.json public.json proof.json

1:
2663650283170244039192395520307978391420596105812817038908217229013048256723
17673564977949265178054599648760830255939124075096452209243247778790949972933
2:
344411888329936703173981763477555865184279110274359594920618223881670877266
9507720718600010449081623213891719106882270457872112404639865468382049334192
*/