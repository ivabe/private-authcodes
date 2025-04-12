import {randomBytes} from "node:crypto";
import { readFile } from 'fs/promises';

import {babyjub, priv2pubBJJ, new_priv_key, priv2pub, ephemeral_kex_key, kex_key_from_priv} from "../app/keypair.js"
import {pack_pubk} from "../app/util.js"

import {Scalar, utils} from "ffjavascript";
const {unstringifyBigInts, leInt2Buff, leBuff2int} = utils;

import assert from 'node:assert';

function test_kex(){
    //Simulate PubKey_B
    const sk_B = new_priv_key("random-seed-here-please");
    let pubk_B = priv2pub(sk_B);
    console.log("Public Key B: ", pubk_B);
    console.log("Public Key B Packed: ", babyjub.packPoint(pubk_B[0]));
    console.log("Public Key B Packed/Compressed: ", babyjub.F.toObject(babyjub.packPoint(pubk_B[0])));
    pubk_B = babyjub.F.toObject(babyjub.packPoint(pubk_B[0]));

    console.log("Public Key B Uncompressed: ", babyjub.F.e(pubk_B));
    const unpubk_b = babyjub.unpackPoint(babyjub.F.e(pubk_B));
    console.log("Public Key B Unpacked: ",unpubk_b);

    const kex1 = ephemeral_kex_key(pubk_B);
    console.log("KEX A: ", kex1, "\n");
    // ------ Check correctness ------
    // //const kex2 = F.toObject(babyjub.packPoint(babyjub.mulPointEscalar(Pubk2, r)));
    const kex1_unpacked = babyjub.unpackPoint(babyjub.F.e(kex1.pubk));
    console.log("Read Unpacked PubK KEX 1: ", kex1_unpacked, "\n");
    const kex2 = babyjub.mulPointEscalar(kex1_unpacked, sk_B)[0];
    //const kex2 = babyjub.F.toObject(babyjub.mulPointEscalar(kex1_unpacked, sk_B)[0]);
    console.log("KEX B: ", kex2, "\n");
    assert.equal(kex1.kex === babyjub.F.toObject(kex2), true);
    // ------ Check correctness ------
}

async function test_kex_bj(){
    // Read B's keypair
    const keys = await readFile("./dvs_keypair.json", 'utf8');
    const keys_json = JSON.parse(keys);
    console.log("B's keys all: ", 
        unstringifyBigInts(keys_json.priv), 
        babyjub.F.e( unstringifyBigInts(keys_json.pub[0]) ), 
        babyjub.F.e( unstringifyBigInts(keys_json.pub[1]) ),
    "\n");
    //A computes kex
    const pubk = [
        babyjub.F.e( unstringifyBigInts(keys_json.pub[0]) ), 
        babyjub.F.e( unstringifyBigInts(keys_json.pub[1]) )
    ]
    const kex1 = ephemeral_kex_key(pubk); // [pub0, pub1]
    console.log("KEX A: ", kex1, "\n");
    // ------ Check correctness ------
    const b = Scalar.fromRprLE(leInt2Buff(unstringifyBigInts(keys_json.priv), 32), 0, 32);
    //Unpack A's pub key
    const pubk_a = [
        babyjub.F.e( unstringifyBigInts(kex1.pubk[0]) ), 
        babyjub.F.e( unstringifyBigInts(kex1.pubk[1]) )
    ]
    console.log("Unpacked kex A: ", pubk_a, "\n");
    const kex2 = babyjub.mulPointEscalar(pubk_a, Scalar.shr(b,3));
    console.log("KEX B: ", kex2[0], babyjub.F.toObject(kex2[0]),"\n");
    //}
    assert.equal(kex1.kex, babyjub.F.toObject(kex2[0]));
    // ------ Check correctness ------
    // ------ Check function    ------
    const kex22 = kex_key_from_priv(keys_json.priv, pubk_a);
    assert.equal(kex1.kex, kex22.kex);
}

function test_keypair(){
    const priv = new_priv_key("your-seed-value-test");
    const pub = priv2pub(priv);
    console.log(pub[0]);
    // console.log(F.e(pub[1][0]), F.e(pub[1][1]));
    console.log(babyjub.packPoint(pub[0]));
    console.log(babyjub.F.toObject(babyjub.packPoint(pub[0])));
    console.log(babyjub.F.e(babyjub.F.toObject(babyjub.packPoint(pub[0]))));
    const keys = {
        privk: priv,
        pubkey_bjubjub: pub[1],
        pubkey_compressed: babyjub.F.toObject(babyjub.packPoint(pub[0])),
        pubkey_eddsa: pub[2]
    }
    console.log(keys);

    // Test Babyjubjub keypair
    const priv2 = unstringifyBigInts("16748787487221912255188261441936155207590681880549050623844068489962705090750");
    const pubk = priv2pubBJJ(priv2);
    console.log(pubk);
    console.log(babyjub.inCurve(
        [
        babyjub.F.e(pubk.pubk_bigint[0]), 
        babyjub.F.e(pubk.pubk_bigint[1])
        ]
    ));
}

function test_buffint(){
    let key = "171215709323692934619248631162015486325885046519483581569569088173017678906";
    key = unstringifyBigInts(key);
    const buff = leInt2Buff(key);
    console.log(buff, buff.length);
}

async function test_packpoint(){
    const keys = await readFile("./dvs_keypair.json", 'utf8');
    const keys_json = JSON.parse(keys);
    console.log(pack_pubk(keys_json));
}

// Main
//test_kex();
//test_keypair();
test_kex_bj();
//test_buffint();
// test_packpoint();