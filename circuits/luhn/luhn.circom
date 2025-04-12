pragma circom 2.2.1;

template luhnCheck(n) { // visa n -> 16
    // private inputs
    signal input card_type; // Visa = 5; Mastercard = 2
    signal input pan[n];
    signal doubling[n]; 

    var flag = 1; // indicates doubling instruction
    signal tmp[n];
    signal sep1[n];
    signal sep2[n];
    for (var k = 0; k < n; k++) {
        if (flag == 1) { // double and add
            tmp[k] <== pan[k] * 2;
            sep1[k] <-- (tmp[k] % 10);
            sep2[k] <-- (tmp[k] \ 10);
            doubling[k] <== sep1[k] + sep2[k];
            flag = 0;
        }else{
            doubling[k] <== pan[k];
            flag = 1;
        }
    }
    // Add up altogether
    signal sum[n];
    for (var i = 0; i < n; i++) {
        if (i != 0){
            sum[i] <== sum[i-1] + doubling[i];
        }else{
            sum[i] <== doubling[i];
        }
    }
    // Sum shall be divisible by 10
    signal mod;
    mod <-- sum[n-1] % 10;
    0 === mod;
}

//component main = luhnCheck(16);