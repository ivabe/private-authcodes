import { Command } from 'commander';
const program = new Command();
import { readFile, writeFile} from 'fs/promises';

import {babyjub, new_privk, priv2pubBJJ, new_priv_key, priv2pub, sign_poseidon, ephemeral_kex_key, kex_key_from_priv} from './keypair.js';

import {utils} from "ffjavascript";
const {unstringifyBigInts, stringifyBigInts} = utils;

program.version("1.0.0");
program.option("-nk, --newkey [seed]", "Generate a new key pair (test)")
    .option("-nkbj, --newkeybj", "Generate a new key pair suited for BabyJubJub")
    .option("-s --sign <path...>", "[path1] secret key file, [path2] msg file.\tGenerate a new signature with secret key over message"
    )
    .option("-kexf --kexfrom <kex_path...>", "Generate an ephemeral key (KEX) from the given [SK_PATH] and [KEX PATH]")
    .option("-kex --kex <B's pubkey_path>", "Generate an ephemeral key (KEX)")
    .option("-pp --packpub <keypair_path>", "Compress the public key")
    .option("-t --test", "Verbose testing. Run all commands.");
program.parse(process.argv);
const options = program.opts();

// program.action(async (options) => {
    if (options.newkey) {
        if(options.newkey == true){
            options.newkey = "your-seed-value-test";
        }
        console.log("Generating a new keypair...\n");
        const keys = generate_new_keypair(options.newkey);
        console.log(keys, "\n");
    }
    if (options.newkeybj) {
        console.log("Generating a new keypair for BabyJubJub...\n");
        const priv = new_privk();
        console.log(priv);
        const pubk = priv2pubBJJ(priv);
        console.log({
            privk: priv,
            pubk
        }, "\n");
    }
    if (options.sign) {
        console.log("Generating a signature...\n");
        // read file and load json
        console.log(options.sign);
        const [sk_path, msg_path] = options.sign;
        console.log(sk_path, msg_path);
        const keys = await readFile(sk_path, 'utf8');
        const keys_json = JSON.parse(keys);
        let msg = await readFile(msg_path, 'utf8');
        msg = msg.split(',');
        //const s = sign(keys_json.privk, msg);
        const s = sign_comm(keys_json.privk, msg);
        console.log(s, "\n");
      }
    if (options.kex) {
        console.log("Generating a ephemeral Key Exchange key...\n");
        const keys = await readFile(options.kex, 'utf8');
        const keys_json = JSON.parse(keys); 
        const kex = generate_kex_key(keys_json.pub);
        console.log(kex);
        // Write to file
        const content = JSON.stringify(stringifyBigInts(kex));
        writeFile('./kex.json', content, err => {
            if (err) {
                console.error(err);
            }
        });
    }
    if (options.kexfrom) {
        console.log("Generating a ephemeral Key Exchange key...\n");
        const [keypair_path, pubk_path] = options.kexfrom;
        console.log(keypair_path, pubk_path);
        // Read private key
        let keypair = await readFile(keypair_path, 'utf8');
        keypair = JSON.parse(keypair);
        // Read kex's pub key
        let kex_path = await readFile(pubk_path, 'utf8');
        kex_path = JSON.parse(kex_path);
        // Compute kex
        const kex = generate_kex_key_2(keypair.privk, kex_path.pubk);
        console.log(kex);
    }
    if (options.packpub){
        console.log("Compressing public key...\n");
        const keypair = await readFile(options.packpub, 'utf8');
        const pubk_compress = pack_key(keypair);
        console.log(pubk_compress, "\n");
    }
    import {test} from "./test.js";
    if (options.test){
        console.log("Testing application...\n");
        test();
    }
// });


////// Generic functions //////
function generate_new_keypair(seed){
    //console.log(seed);
    const priv = new_priv_key(seed);
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
    return keys
}

function sign(sk, msg){
    console.log("Message to sign: ", msg, "\n");
    const s = sign_poseidon(sk, [msg]);
    return s
}

function sign_comm(sk, arr_msg){
    console.log("Message to sign: ", arr_msg, "\n");
    const s = sign_poseidon(sk, arr_msg);
    return s
}

function generate_kex_key(pubk){
    // Convert pubkey to Point
    const pubk_b = [
        babyjub.F.e( unstringifyBigInts(pubk[0]) ), 
        babyjub.F.e( unstringifyBigInts(pubk[1]) )
    ]
    return ephemeral_kex_key(pubk_b);
}

function generate_kex_key_2(sk, pubk){
    // Convert pubkey to Point
    //// Pub key to Point
    const pubk_a = [
        babyjub.F.e( unstringifyBigInts(pubk[0]) ), 
        babyjub.F.e( unstringifyBigInts(pubk[1]) )
    ]
    return kex_key_from_priv(sk, pubk_a);
}

import {pack_pubk} from "./util.js"
function pack_key(keypair){
    return pack_pubk(JSON.parse(keypair))
}