import { readFile, writeFile} from 'fs/promises';
import {babyjub, new_privk, priv2pubBJJ, sign_poseidon, ephemeral_kex_key, kex_key_from_priv, F} from './keypair.js';
import { utils } from "ffjavascript";
const {stringifyBigInts, unstringifyBigInts} = utils
import { buildPoseidon } from 'circomlibjs';
const poseidon = await buildPoseidon();
import {groth16} from "snarkjs";
import assert from 'assert';

export async function test(){
    // User key pair
    const upriv = new_privk();
    const upubk = priv2pubBJJ(upriv);
    let data = {
        priv: stringifyBigInts(upriv),
        pubk: stringifyBigInts(upubk.pubk_bigint), // babyjubjub
        pubk2: stringifyBigInts(upubk.pubk_eddsa) // eddsa
    }
    let jdata = JSON.stringify(data, null, 2);
    console.log("Generating User key pair -> ukeys.json\n");
    await writeFile('ukeys.json', jdata, (err) => {
        if (err) {
          console.error('Error writing to file:', err);
        } else {
          console.log('User data written successfully!');
        }
      });
    // Verifier key pair
    const vpriv = new_privk();
    const vpubk = priv2pubBJJ(vpriv);
    data = {
        priv: stringifyBigInts(vpriv),
        pubk: stringifyBigInts(vpubk.pubk_bigint), // babyjubjub
        pubk2: stringifyBigInts(vpubk.pubk_eddsa) // eddsa
    }
    jdata = JSON.stringify(data, null, 2);
    console.log("Generating User key pair -> dvskeys.json\n");
    await writeFile('dvskeys.json', jdata, (err) => {
        if (err) {
          console.error('Error writing to file:', err);
        } else {
          console.log('DVS data written successfully!');
        }
    });

    //// User session
    console.log("USER - Generating a ephemeral Key Exchange key...");
    const keys = await readFile("dvskeys.json", 'utf8');
    const keys_json = JSON.parse(keys); 

    // Convert pubkey to Point
    const pubk_b = [
        babyjub.F.e( unstringifyBigInts(keys_json.pubk[0]) ), 
        babyjub.F.e( unstringifyBigInts(keys_json.pubk[1]) )
    ]
    const kex = ephemeral_kex_key(pubk_b);
    console.log("USER - kex secret share:", kex.kex);
    // Generate a new KEX key
    const content = JSON.stringify(stringifyBigInts(kex), null, 2);
    await writeFile('./kex.json', content, err => {
        if (err) {
            console.error(err);
        }
    });
    // Sign message h(r, v)
    const msg = "934";
    const sig = sign_poseidon(upriv,[kex.kex,msg]);
    console.log("USER - signature:", sig);
    // ZKP
    console.log("USER - Computing designated verifier ZKP...");
    console.log("USER - In Circuit information...");
    // Build private input file
    const input = {
        priv: upriv,
        dv_pubk_jub: vpubk.pubk_bigint, //dvs_keypair.pubk,
        exp_date: "1775001601000",
        cvv: msg,
        pan: [4,8,5,0,7,3,7,6,3,0,5,2,2,9,8,5],
        current_time: "1732284024",
        holder_pk_eddsa: upubk.pubk_eddsa,
        hash_msg: sig.hash,    
        hSig: sig.sig.S,      
        hSigR8: sig.sig.R8,
        rand_a: kex.priv_a     
    }
    //console.log(input);
    // Run Groth16
    const startTime = performance.now();
    const { proof, publicSignals } = await groth16.fullProve(input, "dvs_js/dvs.wasm", "final.zkey");
    const endTime = performance.now();
    const timeTaken = endTime - startTime;
    console.log("\n");
    console.log("Generating Proof: ");
    console.log(JSON.stringify(proof, null, 1));
    //console.log(new Blob([JSON.stringify(proof)]).size);
    const a = new Blob([proof.pi_a]).size;
    const b = new Blob([proof.pi_b]).size;
    const c = new Blob([proof.pi_c]).size;
    console.log(`Proof size: ${a+b+c} bytes`)
    console.log(`Prover's time to generate proof: ${timeTaken} milliseconds`);

    let vKey = await readFile("vkey.json");
    vKey = JSON.parse(vKey);

    const res = await groth16.verify(vKey, publicSignals, proof);

    if (res === true) {
        console.log("Verification OK");
        console.log("Public signals:", publicSignals);
    } else {
        console.log("Invalid proof");
    }
    //// DVS session
    console.log("\n\nDVS - Generating a ephemeral Key Exchange key...");
    let dvs_keypair = await readFile("dvskeys.json", 'utf8');
    dvs_keypair = JSON.parse(dvs_keypair);
    // Read kex's pub key
    let kexp = await readFile("kex.json", 'utf8');
    kexp = JSON.parse(kexp);
    //console.log(kexp);
    // Compute kex
    const pubk_a = [
        babyjub.F.e( unstringifyBigInts(kexp.pubk[0]) ), 
        babyjub.F.e( unstringifyBigInts(kexp.pubk[1]) )
    ]
    const kex2 = kex_key_from_priv(dvs_keypair.priv, pubk_a);     
    console.log("DVS - kex secret share:", kex2.kex);
    console.log("DVS - verify commitment proof...");
    assert.equal(kex2.kex, kex.kex);
    const h = poseidon([kex2.kex, msg]);
    assert.equal(F.toObject(h), publicSignals[publicSignals.length-1]);
    console.log("DVS - Hash equal...");
    console.log("DVS - ZKP public signal hash:\n", publicSignals[publicSignals.length-1]);
    console.log("DVS - Computed hash:\n", F.toObject(h));
    process.exit(0);
}