pragma circom 2.2.1;
include "../../circomlib/eddsaposeidon.circom";

template checkCardDataSig() {
    // private inputs
    signal input hash_msg;
    signal input pubSig;      // Private Signature to verify
    signal input pubSigR8[2]; // Private Signature to verify
    signal input holder_pk[2];

    signal output verified;

    component eddsa_v = EdDSAPoseidonVerifier();
    eddsa_v.enabled <== 1;
    eddsa_v.Ax      <== holder_pk[0];
    eddsa_v.Ay      <== holder_pk[1];
    eddsa_v.S       <== pubSig;
    eddsa_v.R8x     <== pubSigR8[0];
    eddsa_v.R8y     <== pubSigR8[1];
    eddsa_v.M       <== hash_msg;
    eddsa_v.out     ==> verified; // 1 true / 0 false
}

//component main {public [hash_msg,holder_pk]} = checkCardDataSig();