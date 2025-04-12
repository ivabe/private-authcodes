import { utils } from "ffjavascript";
const {unstringifyBigInts, stringifyBigInts, leInt2Buff, leBuff2int} = utils
import {babyjub} from './keypair.js';

import assert from 'node:assert';
/**
 * @param {JSON} keypair
 */
export function pack_pubk(keypair){
    // load jsonand BigInt to Uint8Array(32)
    keypair = unstringifyBigInts(keypair.pub);
    console.log("keypair: ", keypair);
    const pubk = [
        babyjub.F.e(keypair[0]), 
        babyjub.F.e(keypair[1])
    ];
    console.log("F.e: ", pubk);
    console.log(babyjub.F.toObject(pubk[0]), babyjub.F.toObject(pubk[1]));
    assert.equal(keypair[0], babyjub.F.toObject(pubk[0]));
    const pack = babyjub.packPoint(pubk);
    const pack2int = leBuff2int(pack);
    const int2pack = leInt2Buff(pack2int);
    // const packint = babyjub.F.toObject(pack)
    console.log("Packed: ", pack, pack2int);
    // Check correctness
    console.log("PackedReversed: ", int2pack);
    const unpack = babyjub.unpackPoint(int2pack);
    // console.log("Unpacked: ", unpack);
    assert.equal(keypair[0] === babyjub.F.toObject(unpack[0]), true);
    assert.equal(keypair[1] === babyjub.F.toObject(unpack[1]), true);
    // Pack pub key
    return leBuff2int(pack)//babyjub.F.toObject(babyjub.packPoint(pubk))
}