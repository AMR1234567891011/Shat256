/*
SHA256 function defined in https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 
d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 
e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da 
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 
27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 
a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 
19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 
748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2 
read left to right: 
*/

/*
shat 256:
Preprocessing:
    padding:
        ensure message is a multiple of 512 bits
        for a message of m bits append the bit 1 to the end of the message,
        followed by k zero bits where k is the smallest, non-negative solution
        to m + 1 + k = 448. ex:  m = 128 => 128 + 1 + k = 448 => k = 319 zero bits.
    parsing:
        messages are parsed into N 512 bit blocks
        *password will only be 1 block*
    initial hash value:
        H0  = 6a09e667 
        H1 = bb67ae85 
        H2 = 3c6ef372 
        H3 = a54ff53a 
        H4 = 510e527f 
        H5 = 9b05688c 
        H6 = 1f83d9ab 
        H7  = 5be0cd19
Functions:

*/
const Shat256 = (input, HexIn, HexOut) => {//HexIn: true if input is a Uint8array, Hexout: true if you want a Uint8Array output
    const K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    
    function ROTR(n, x) {// right rotate
        return ((x >>> n) | (x << (32 - n))) >>> 0;
    }
    function Ch(x, y, z) {//choose bits y,z based off of x
        return ((x & y) ^ ((~x) & z)) >>> 0;
    }
    function Maj(x, y, z) {//majority of bits set value
        return ((x & y) ^ (x & z) ^ (y & z)) >>> 0;
    }
    function S0(x) {//Big sigma 0
        return (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x)) >>> 0;
    }
    function S1(x) {//Big sigma 1
        return (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x)) >>> 0;
    }
    function s0(x) {//little sigma 0
        return (ROTR(7, x) ^ ROTR(18, x) ^ (x >>> 3)) >>> 0;
    }
    function s1(x) {//little sigma 1
        return (ROTR(17, x) ^ ROTR(19, x) ^ (x >>> 10)) >>> 0;
    }

    let IN = new Uint8Array(1);
    if (HexIn) {
        IN = new Uint8Array(input.length);
        IN.set(input, 0);
    } else {
        IN = new Uint8Array(Array.from(input).map(function(char) { 
            return char.charCodeAt(0); 
        }));

    }
    const m = IN.length;
    const bitLength = m * 8 >>> 0;
    var padLength = 56 - ((m + 1) % 64);//calculates padding at the end of the block
    if (padLength < 0) {
        padLength = padLength + 64;
    }
    const totalLength = m + 1 + padLength + 8;
    //console.log(`padLength: ${padLength} messageLen: ${m} m-bits: ${bitLength} total Length: ${totalLength}`);
    const padded = new Uint8Array(totalLength);
    padded.set(IN, 0);
    padded[m] = 0x80;
    var i;
    for (i = 4; i < 8; i = i + 1) {//put 32bit int in 64 bits at end
        padded[totalLength - 8 + i] = (bitLength >>> (8 * (7 - i))) | 0x00;
        //console.log(`byte: ${8 - i} value: ${padded[totalLength - 8 + i]}`);
    }
    const H = new Uint32Array([//initial hash values
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    ]);
    let W = new Uint32Array(64);
    var j, t;
    for (j = 0; j < totalLength; j = j + 64) {//MAIN LOOP 
        var block = padded.slice(j, j + 64);//processes block by block
        for (t = 0; t < 64; t = t + 1) {
            if (t < 16) {
                W[t] = (block[4 * t] << 24) | (block[4 * t + 1] << 16) | (block[4 * t + 2] << 8) | block[4 * t + 3];//create schedule for t < 16
            } else {
                W[t] = (s0(W[t - 15]) + W[t - 7] + s1(W[t - 2]) + W[t - 16]) >>> 0;//schedule for 16 <= t < 64
            }
        }
        var a = H[0];
        var b = H[1];
        var c = H[2];
        var d = H[3];
        var e = H[4];
        var f = H[5];
        var g = H[6];
        var h = H[7];
        var T1 = 0;
        var T2 = 0;
        for (t = 0; t < 64; t = t + 1) {//schedule execution
            T1 = (h + S1(e) + Ch(e, f, g) + K[t] + W[t]) >>> 0;
            T2 = (S0(a) + Maj(a, b, c)) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + T1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (T1 + T2) >>> 0;
        }
        //console.log(`\nFINAL VALUES: t = ${t}\na:${Uint32ToInBinary(a)}\nb:${Uint32ToInBinary(b)}\nc:${Uint32ToInBinary(c)}\nd:${Uint32ToInBinary(d)}\ne:${Uint32ToInBinary(e)}\nf:${Uint32ToInBinary(f)}\ng:${Uint32ToInBinary(g)}\nh:${Uint32ToInBinary(h)}\nT1:${Uint32ToInBinary(T1)}\nT2:${Uint32ToInBinary(T2)}\n`);
        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }
    //console.log(`\n\n ***FINAL VALUES***:\na:${Uint32ToInBinary(a)}\nb:${Uint32ToInBinary(b)}\nc:${Uint32ToInBinary(c)}\nd:${Uint32ToInBinary(d)}\ne:${Uint32ToInBinary(e)}\nf:${Uint32ToInBinary(f)}\ng:${Uint32ToInBinary(g)}\nh:${Uint32ToInBinary(h)}\nT1:${Uint32ToInBinary(T1)}\nT2:${Uint32ToInBinary(T2)}\n`);
    //console.log(`\nh0:${Uint32ToInBinary(H[0])}\nh1:${Uint32ToInBinary(H[1])}\nh2:${Uint32ToInBinary(H[2])}\nh3:${Uint32ToInBinary(H[3])}\nh4:${Uint32ToInBinary(H[4])}\nh5:${Uint32ToInBinary(H[5])}\nh6:${Uint32ToInBinary(H[6])}\nh7:${Uint32ToInBinary(H[7])}\n`);
    //BigInt(((H[7] << 224) + (H[6] << 192) + (H[5] << 160) + (H[4] << 128) + (H[3] << 96) + (H[2] << 64) + (H[1] << 32) + (H[0])) >>> 0);
    if (HexOut === true){
        let hash = new Uint8Array(32);//the & 0xFF picks leasat significant byte
        for(let i = 0; i < 8; i++) {
            //this looks flipped, but js uses LE while sha uses BE
            hash[4 * i] = H[i] >>> 24 & 0xFF;
            hash[4 * i + 1] = H[i] >>> 16 & 0xFF;
            hash[4 * i + 2] = H[i] >>> 8 & 0xFF;
            hash[4 * i + 3] = H[i] & 0xFF;
        }
        return hash;

    } else {
    let hash = '';
    function uint32ToHex(value) {
        return value.toString(16).padStart(8, '0');
    }
    for (let i = 0; i < 8; i = i + 1) {
        hash += uint32ToHex(H[i]);
    }
    return hash;
    }
};
const HMAC_Shat256 = (Key, Message) => {
    // console.log(`Key: ${Key}, Message: ${Message}`);
    let KeyLen = Key.length;
    let MessageLen = Message.length;
    let M = new Uint8Array(Array.from(Message).map(function(char) { 
        return char.charCodeAt(0); 
    }));
    let K = new Uint8Array(64).fill(0x00);
    if ((KeyLen) > 64) {
        K.set(Shat256(Key, true, true).slice(0,32), 0);//garunteed 256 bits
    } else {
        let strArr = new Uint8Array(Array.from(Key).map(function(char) {
            return char.charCodeAt(0);
        }));
        K.set(strArr, 0);
    }
    // console.log(`keyLen: ${KeyLen}, msgLen: ${MessageLen}`);
    // console.log(`K: ${Buffer.from(K).toString('hex')}\n\n`);
    let IPAD = new Uint8Array(64).fill(0x36);
    let OPAD = new Uint8Array(64).fill(0x5c);
    let KI = new Uint8Array(64);
    let KO = new Uint8Array(64);
    for(let i = 0; i < 64; i++){
        KI[i] = K[i] ^ IPAD[i] >>> 0;
        KO[i] = K[i] ^ OPAD[i] >>> 0;
    }
    const Inner = new Uint8Array(64 + MessageLen);
    const Outer = new Uint8Array(64 +  32);
    Inner.set(KI, 0);
    Inner.set(M, 64);
    let InnerHash = Shat256(Inner, true, true);
    // console.log(`KI: ${Buffer.from(KI).toString('hex')}`);
    // console.log(`KO: ${Buffer.from(KO).toString('hex')}\n\n`);
    // console.log(`Inner PreHash: ${Buffer.from(Inner).toString('hex')}`);
    // console.log(`Inner Hash using Buffer out sha: ${Buffer.from(InnerHash).toString('hex')}\n\n`);
    Outer.set(KO, 0);
    Outer.set(InnerHash , 64);
    // console.log(`Outer preHash: ${Buffer.from(Outer).toString('hex')}\n\n`);
    const Final = Shat256(Outer, true, false);    
    // console.log(`Final HMAC Hash: ${Final}`);
    return Final;
};
console.log('hash: ' + Shat256('I was working in the lab late one night When my eyes beheld an eerie sight For my monster, from his slab, began to rise And suddenly, to my surprise (He did the Mash) he did the Monster Mash (The Monster Mash) it was a graveyard smash (He did the Mash) it caught on in a flash (He did the Mash) he did the Monster Mash From my laboratory in the Castle east To the master bedroom, where the vampires feast The ghouls all came from their humble abodes To get a jolt from my electrodes', false, false));
console.log('hash: '+ Shat256('str less than 32 chars', false, false));
console.log(`HMAC_TEST: ${HMAC_Shat256('123456789123456789123456789123456789123456789123456789', '123456789123456789123456789123456789123456789123456789')}`);