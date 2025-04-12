pragma circom 2.2.1;
include "../../circomlib/comparators.circom";

template checkCardData() {
    // private inputs
    //signal input pan;
    signal input exp_date;      // milliseconds
    signal input cvv;

    //public inputs
    signal input current_time;  // milliseconds
    //signal input pan2;        // for verification link
    signal input cvv2;          // for verification link

    // Public outputs
    signal output out_expired;
    signal output out_cvv_eq;

    // Check the card has not expired
    component lessThan = LessThan(252);
    lessThan.in[0] <== exp_date;
    lessThan.in[1] <== current_time;
    lessThan.out ==> out_expired; // 1 if in[0] < in[1], 0 otherwise.

    // Check variables binding
    // In case that cvv2 is used as public input, we need to bind it to the circuit
    component eq = IsEqual();
    eq.in[0] <== cvv;
    eq.in[1] <== cvv2;
    eq.out   ==> out_cvv_eq;
}

//component main {public [current_time,cvv2]} = checkCardData();