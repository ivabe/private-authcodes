Make sure to download powers of tau file for the trsuted setup ceremonie (e.g., [file.ptau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau)) 

### Compile circuit
```
circom dvs.circom --r1cs --wasm --inspect
```

## Key generation
```
snarkjs groth16 setup dvs.r1cs powersOfTau28_hez_final_16.ptau 0.zkey
snarkjs zkey contribute 0.zkey 1.zkey -v -e="Random entropy here:)(:"
snarkjs zkey beacon 1.zkey final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"
snarkjs zkey verify dvs.r1cs powersOfTau28_hez_final_16.ptau final.zkey
```

## Export verification key
```
snarkjs zkey export verificationkey final.zkey vkey.json
```
### Generate proof
#### Calculate witness
```
snarkjs wtns calculate dvs_js/dvs.wasm input.json witness.wtns
OR
node dvs_js/generate_witness.js dvs_js/dvs.wasm input.json witness.wtns

snarkjs wtns check dvs.r1cs witness.wtns
```
#### Generate/Verify zk proof 
```
snarkjs groth16 prove final.zkey witness.wtns proof.json public.json

snarkjs groth16 verify vkey.json public.json proof.json
```
