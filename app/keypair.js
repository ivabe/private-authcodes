import { fileURLToPath } from 'url';
import process from 'process';
import {randomBytes} from "node:crypto";

import seedrandom from 'seedrandom';

import { buildEddsa, buildBabyjub, buildPoseidon } from 'circomlibjs';
const eddsa = await buildEddsa();
export const babyjub = await buildBabyjub();
export const F = babyjub.F;
const poseidon = await buildPoseidon();

import { utils, Scalar } from "ffjavascript";
const {stringifyBigInts, unstringifyBigInts, leBuff2int, leInt2Buff} = utils


import assert from 'node:assert';
import { symlinkSync } from 'fs';

/**
 * Generates new random secret key based on Math.random()
 * @returns {string}
 */
export const new_priv_key = (seed) => {
    let rng = seedrandom(seed);
    return BigInt(Math.floor(rng() * Math.pow(10, 32)));
};

/**
 * Generates new random secret key based on Math.random()
 * @returns {string}
 */
export function new_privk() {
    const privk = randomBytes(32);
    let s = Scalar.fromRprLE(privk, 0, 32);
    s = Scalar.shr(s,3)
    return s;//leBuff2int(privk);
};

/**
 * 
 * @param {bigint} sk
 */
export const priv2pubBJJ = (sk) => {
    const buffint = leInt2Buff(sk, 32);
    //let s = Scalar.fromRprLE(buffint, 0, 32);
    //console.log("Secret Key: ", s);
    //console.log("Scalar ShR: ", Scalar.shr(s,3));
    const b = babyjub.mulPointEscalar(babyjub.Base8, sk);
    let eddsa_pubk =  eddsa.prv2pub(buffint); // pubkey (EdDSA)
    const pubk = {
        pubk: b,
        pubk_bigint: [F.toObject(b[0]), F.toObject(b[1])],
        pubk_eddsa: [F.toObject(eddsa_pubk[0]), F.toObject(eddsa_pubk[1])]
    }
    return pubk;
};

/**
 * Generates public key from secret
 * @param sk {String} secret key
 * @returns {[String]}
 */
export const priv2pub = (sk) => {
    if(typeof sk == 'bigint'){
        sk = stringifyBigInts(sk);
    }
    let b = babyjub.mulPointEscalar(babyjub.Base8, sk); // pubkey (babyjubjub)
    let eddsa_pubk =  eddsa.prv2pub(sk); // pubkey (EdDSA)
    return [b, [F.toObject(b[0]), F.toObject(b[1])], [F.toObject(eddsa_pubk[0]), F.toObject(eddsa_pubk[1])]];
};

export function sign_poseidon(sk, msg){
    const buffint = leInt2Buff(BigInt(sk), 32);
    const h_msg = poseidon(msg);
    //console.log("Poseidon: ", h_msg, F.toObject(h_msg));

    const signature = eddsa.signPoseidon(buffint, h_msg);
    //console.log("Signature: ", signature);
    //console.log(F.toObject(signature.R8[0]), F.toObject (signature.R8[1]));
    // Verify
    const pub =  eddsa.prv2pub(buffint);
    // console.log("Secret Key: ", sk, "\n", buffint, "\n");
    // console.log("Public Keys: ", pub, "\n");
    // const pub_int = [F.toObject(pub[0]), F.toObject(pub[1])]
    // console.log("Public Keys: ", pub_int, "\n");
    assert.equal(eddsa.verifyPoseidon(h_msg, signature, pub), true); // pubk EdDSA

    const Sig = {
        msg: msg,
        hash: F.toObject(h_msg),
        sig: {
            R8: [F.toObject(signature.R8[0]), F.toObject (signature.R8[1])],
            S: signature.S,
        },
        pubk: [F.toObject(pub[0]), F.toObject(pub[1])]
    }
    return Sig
};

/**
 * Generates public key from secret
 * @param pubk_b {Point} public key point
 */
export function ephemeral_kex_key(pubk_b){
    //console.log("ephemeral_kex_key - B's pubk: ", pubk_b);
    if (!babyjub.inCurve(pubk_b)){
        throw new Error('Public key must be a Point in the Curve\n\n');
    }
    // KEX must be in the curve
    let kex1 = 0;
    let a = F.e(0);
    let pubk_a = [F.e(0), F.e(0)];
    while(!babyjub.inCurve(kex1)){
        // Generate a private random value a
        while (!babyjub.inCurve(pubk_a)) {
            // Ensure 32 bytes
            let rand_bytes = new_privk();
            while(leInt2Buff(rand_bytes).length < 32){
                rand_bytes = new_privk();
            }
            // Compute Pub Key to share P := a*G
            a = Scalar.fromRprLE(leInt2Buff(rand_bytes, 32), 0, 32);
            pubk_a = babyjub.mulPointEscalar(babyjub.Base8, Scalar.shr(a,3));
            //console.log("A's pubk to share: ", pubk_a);
        }
        pubk_a = [
            F.toObject(pubk_a[0]),
            F.toObject(pubk_a[1])
        ];
        //console.log("P_a = a*G: ");
        console.log(pubk_a);
        // Compute KEX k := Pub_b*a = ab*G
        kex1 = babyjub.mulPointEscalar(pubk_b, Scalar.shr(a,3));
        //console.log("KEX 1 k: ", kex1[0], F.toObject(kex1[0]));
    }
    return {
        priv_a: Scalar.shr(a,3),
        pubk: pubk_a,
        kex: F.toObject(kex1[0]) // Take coordinate x as random value 
    }
}

/**
 * Generates public key from secret
 * @param sk {BigInt} secret key
 * @param pubk_b {Point} pub key
 */
export function kex_key_from_priv(sk, pubk_b){
    if (typeof sk === 'string'){
        sk = unstringifyBigInts(sk);
    }
    if (!babyjub.inCurve(pubk_b)){
        throw new Error('Public key must be a Point in the Curve\n\n');
    }
    //console.log("Secret K: ", sk, "A's PubK: ", pubk_b, "\n");
    const b = Scalar.fromRprLE(leInt2Buff(sk, 32), 0, 32);
    const kex = F.toObject(babyjub.mulPointEscalar(pubk_b, b)[0]);
    return {
        priv: b,
        pubk: priv2pubBJJ(sk).pubk_bigint,
        kex: kex
    }
}

function main(){
// Private keys load
let priv = new_priv_key('your-seed-value-test');
const prvKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex"); //12380176044255134084922702101484758635377949367704015662612840402997990058562n
// console.log(F.toObject(priv));
console.log(F.toObject(prvKey));
// console.log(Buffer.from(stringifyBigInts(F.toObject(prvKey))));
// Compute public keys
let pub = priv2pub(priv);
let pub2 = priv2pub(F.toObject(prvKey));
let pub_eddsa =  eddsa.prv2pub(priv);
let pub_eddsa2 = eddsa.prv2pub(prvKey);

console.log(typeof priv, priv,"\n");
console.log(typeof prvKey, prvKey, F.toObject(prvKey),"\n");

console.log("pub BabyJub 1: ", pub,"\n");
console.log("pub BabyJub 2: ", pub2,"\n");

console.log("pub EdDSA 1:",F.toObject(pub_eddsa[0]), F.toObject(pub_eddsa[1]),"\n");
console.log("pub EdDSA 2:",F.toObject(pub_eddsa2[0]), F.toObject(pub_eddsa2[1]),"\n");

// Sign with Private keys EdDSA Poseidon
//[F.e(pub[0]), F.e(pub[1])]
console.log("Poseidon In: ", pub[0], pub[1]);
const msg = poseidon(pub[0]);
const msg2 = poseidon(pub[1]);
console.log("Poseidon: ", msg, F.toObject(msg));
console.log("Poseidon2: ", msg2, F.toObject(msg2));
assert.equal(F.toObject(msg), F.toObject(msg2));

const signature = eddsa.signPoseidon(priv, msg);
console.log("Signature: ", signature);
console.log(F.toObject(signature.R8[0]), F.toObject(signature.R8[1]));
assert.equal(eddsa.verifyPoseidon(msg, signature, pub_eddsa), true);
assert.equal(eddsa.verifyPoseidon(msg, signature, pub_eddsa2), false);
// const signature2 = eddsa.signPoseidon(prvKey, msg);
// console.log(eddsa.verifyPoseidon(msg, signature2, pub_eddsa2));
// console.log(signature2);

console.log("\n\n----------> Signature 2\n\n");
const msg_pan = poseidon(["4850737630522985","1775001601000"]);
console.log("Poseidon: ", msg_pan, F.toObject(msg_pan));
const signature2 = eddsa.signPoseidon(priv, msg_pan);
console.log("Signature: ", signature2);
console.log(F.toObject(signature2.R8[0]), F.toObject(signature2.R8[1]));
assert.equal(eddsa.verifyPoseidon(msg, signature, pub_eddsa), true);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    main();
  }
  
//module.exports = {new_priv_key, priv2pub};
