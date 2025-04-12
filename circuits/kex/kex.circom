pragma circom 2.2.1;
include "../../circomlib/babyjub.circom";
include "../../circomlib/poseidon.circom";
include "../../circomlib/sha256/shift.circom";

template CommitmentProof(){
    // 
    // ------ BEGIN KEX ------
    //
    // 1) User selects a random value a
    // 2) User computes public key P_a := a*G
    // 3) User computes KEX k from the target public key := a*P_b
    signal input rand_a;
    signal input pubk_b[2];
    signal input cvv;
    signal output out_pubk_a[2];
    signal output out_commitment;
    signal k; // shared computable randomness

    // 1) Convert rand_a to bits
    component bits = Num2Bits(253);
    bits.in <== rand_a;

    // 2) a*G
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
   
    component aG = EscalarMulFix(253, BASE8);
    for (var i = 0; i < 253; i ++) {
        aG.e[i] <== bits.out[i];
    }
    aG.out[0] ==> out_pubk_a[0];
    aG.out[1] ==> out_pubk_a[1];
    
    // 3) k := a*P_b
    component pubk_bA = EscalarMulAny(253);
    for (var i = 0; i < 253; i ++) {
        pubk_bA.e[i] <== bits.out[i];
    }
    pubk_bA.p[0] <== pubk_b[0];
    pubk_bA.p[1] <== pubk_b[1];
    pubk_bA.out[0] ==> k; // Take coordinate x as random value
    log("kex: ", k);
    // ------ END KEX ------
    //
    // ------ BEGIN Commitment ------
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== k;
    poseidon.inputs[1] <== cvv;
    log("Hash: ", poseidon.out);
    poseidon.out ==> out_commitment;
    // ------ END Commitment ------
}

//component main {public [pubk_b]} = CommitmentProof();