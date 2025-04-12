pragma circom 2.2.1;
include "../../circomlib/eddsaposeidon.circom";
include "../../circomlib/babyjub.circom";
include "../../circomlib/poseidon.circom";
include "../../circomlib/gates.circom";
include "../../circomlib/sha256/shift.circom";

include "../card-verification/card_verification.circom";
include "../card-verification/card_sig_ver.circom";
include "../luhn/luhn.circom";

include "../kex/kex.circom";

template DVS(){
    // 
    // ------ BEGIN DESIGNATED VERIFIER CHECKS ------
    // Overview of the circuit general inputs:
    
    //// Designated Verifier inputs:
    // signal input dv_pubk[2];        // (Public) Designated verifier Public Key (BabyJubJub)
    // signal input priv;              // (Private) Holder private key
    // signal input holder_pk_jub[2];  // (Public)  User public key (EdDSA)
    // signal input dv_pubSigR8[2];    // (Private) Signature to verify
    // signal input dv_pubSig;         // (Private) Signature to verify

    //// Commitment proof inputs:
    // signal input dv_pubk[2];        // (Public) Designated verifier Public Key (BabyJubJub)
    // signal input rand_a;            // (Private) random nonce
    // signal input value;             // (Private) value to be sent

    // 
    // ------ BEGIN DESIGNATED VERIFIER PROOF OF POSSESSION ------
    //
    signal input priv;                 // Designated verifier private key to fake proof
    signal input dv_pubk_jub[2];       // Designated verifier Public Key

    signal output out_dv_pubeq;
    signal output out_cvveq;
    // Informally, AM I Bob?
    component dv_privTopub = BabyPbk();
    dv_privTopub.in <== priv;
    log("Ax: ", dv_privTopub.Ax);
    log("Ay: ", dv_privTopub.Ay);
    // Check designated verifier public key is equal to the derived public key
    component dv_eqX = IsEqual();
    dv_eqX.in[0] <== dv_privTopub.Ax;
    dv_eqX.in[1] <== dv_pubk_jub[0];
    // dv_eqX.out === 1;
    component dv_eqY = IsEqual();
    dv_eqY.in[0] <== dv_privTopub.Ay;
    dv_eqY.in[1] <== dv_pubk_jub[1];
    // dv_eqY.out === 1;
    log("Am I bob?\n", dv_eqX.out*dv_eqY.out);
    // 
    // ------ BEGIN PAYMENT CARD CHECKS ------
    //
    signal input pan[16];
    signal input exp_date;      // milliseconds
    signal input cvv;
    // public inputs
    signal input current_time;  // milliseconds
    signal input holder_pk_eddsa[2];
    // Private holder inputs 
    signal input hash_msg;      // hash(r,cvv)
    signal input hSig;          // Private Signature to verify
    signal input hSigR8[2];     // Private Signature to verify
    signal input rand_a;        // Random nonce
    // Outputs
    signal output out_pubk_a[2];
    signal output out_commitment;

    //Commitmment Proof Signature
    // 1) KEX
    component kex = CommitmentProof();
    kex.rand_a      <== rand_a;
    kex.pubk_b[0]   <== dv_pubk_jub[0];
    kex.pubk_b[1]   <== dv_pubk_jub[1];
    kex.cvv         <== cvv;
    // 2) Sign - Holder authenticates credit card data
    // Verify Signature(hash(r, cvv))
    component check_card_sig = checkCardDataSig();
    check_card_sig.hash_msg     <== kex.out_commitment; //hash_msg;
    check_card_sig.pubSig       <== hSig;
    check_card_sig.pubSigR8[0]  <== hSigR8[0];
    check_card_sig.pubSigR8[1]  <== hSigR8[1];
    check_card_sig.holder_pk[0] <== holder_pk_eddsa[0];
    check_card_sig.holder_pk[1] <== holder_pk_eddsa[1];
    log(" Is commitment signature ok?: ", check_card_sig.verified);
    //check_card_sig.verified === 1; // If 1: Sig. true

    // Ouputs
    kex.out_pubk_a[0] ==> out_pubk_a[0];
    kex.out_pubk_a[1] ==> out_pubk_a[1];
    log("Ephemeral PubK A: ", out_pubk_a[0], "\n",out_pubk_a[1]);
    kex.out_commitment ==> out_commitment;
    log("Commitment Proof: ", out_commitment);
    /* Checks credit card
        1) is not expired
        2) PAN is correct -> Luhn check
    */
    component check_card = checkCardData();
    //check_card.pan          <== pan; // it is not used
    check_card.exp_date     <== exp_date;
    check_card.cvv          <== cvv;
    check_card.current_time <== current_time;
    check_card.cvv2         <== cvv; // Redundant, but for cirucit's clarity
    check_card.out_expired === 0; // If 0 then expired false

    component luhn = luhnCheck(16);
    luhn.card_type <== 5;
    for (var i = 0; i < 16; i++) {
        luhn.pan[i] <== pan[i];
    }
    // 
    // ------ END PAYMENT CARD CHECKS ------
    //
    // Check bitwise gates
    // AM I Bob? OR Signature is valid
    component or = OR();
    or.a <== dv_eqX.out*dv_eqY.out;
    or.b <== check_card_sig.verified;
    log("dvs OR (always 1): ", or.out); 
}

component main {public [dv_pubk_jub, holder_pk_eddsa, current_time, hash_msg]} = DVS();