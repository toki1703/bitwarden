'use strict';

const { Plugin, ItemView, Modal, Notice, Setting, PluginSettingTab, requestUrl } = require('obsidian');

const VIEW_TYPE = 'bitwarden-panel';
const DEFAULT_SETTINGS = {
    region: 'us',            // 'us' | 'eu' | 'self'
    serverUrl: '',           // base URL when region === 'self'
    email: '',
    clientId: '',            // personal API key client_id (user.xxxx)
    clientSecret: '',        // personal API key client_secret
    deviceId: '',            // generated UUID
    useIcons: true,
    iconServer: 'https://icons.bitwarden.net',
    viewMode: 'type',        // 'type' | 'folder'
    showCopyButtons: true,
    // persisted session (sensitive)
    accessToken: null,
    tokenExpiresAt: 0,
    userKeyB64: null,        // decrypted user key (enc[32] || mac[32]) base64
};

// ============================================================
// Argon2id + BLAKE2b (pure JS) — RFC 7693 / RFC 9106
// Verified against Node blake2b512 and the RFC 9106 Argon2id vector.
// ============================================================

const BLAKE2B_IV = new Uint32Array([
    0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85,
    0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
    0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
    0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);

const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

function rotr64(v, i, c) {
    const lo = v[2 * i], hi = v[2 * i + 1];
    let nlo, nhi;
    if (c === 32) { nlo = hi; nhi = lo; }
    else if (c < 32) {
        nlo = ((lo >>> c) | (hi << (32 - c))) >>> 0;
        nhi = ((hi >>> c) | (lo << (32 - c))) >>> 0;
    } else {
        const d = c - 32;
        nlo = ((hi >>> d) | (lo << (32 - d))) >>> 0;
        nhi = ((lo >>> d) | (hi << (32 - d))) >>> 0;
    }
    v[2 * i] = nlo; v[2 * i + 1] = nhi;
}

function add64(v, a, lo2, hi2) {
    const al = v[2 * a], ah = v[2 * a + 1];
    const lo = (al + lo2) >>> 0;
    const carry = ((al >>> 0) + (lo2 >>> 0) > 0xffffffff) ? 1 : 0;
    v[2 * a] = lo;
    v[2 * a + 1] = (ah + hi2 + carry) >>> 0;
}

function xor64(v, a, b) {
    v[2 * a] ^= v[2 * b];
    v[2 * a + 1] ^= v[2 * b + 1];
}

function bG(v, m, r, i, a, b, c, d) {
    const x = SIGMA[r][2 * i], y = SIGMA[r][2 * i + 1];
    add64(v, a, v[2 * b], v[2 * b + 1]); add64(v, a, m[2 * x], m[2 * x + 1]);
    xor64(v, d, a); rotr64(v, d, 32);
    add64(v, c, v[2 * d], v[2 * d + 1]);
    xor64(v, b, c); rotr64(v, b, 24);
    add64(v, a, v[2 * b], v[2 * b + 1]); add64(v, a, m[2 * y], m[2 * y + 1]);
    xor64(v, d, a); rotr64(v, d, 16);
    add64(v, c, v[2 * d], v[2 * d + 1]);
    xor64(v, b, c); rotr64(v, b, 63);
}

class Blake2b {
    constructor(outlen) {
        this.outlen = outlen;
        this.h = new Uint32Array(16);
        for (let i = 0; i < 16; i++) this.h[i] = BLAKE2B_IV[i];
        this.h[0] ^= 0x01010000 ^ outlen;
        this.t0 = 0; this.t1 = 0;
        this.buf = new Uint8Array(128);
        this.buflen = 0;
    }
    _inc(n) {
        const old = this.t0;
        this.t0 = (this.t0 + n) >>> 0;
        if ((this.t0 >>> 0) < (old >>> 0)) this.t1 = (this.t1 + 1) >>> 0;
    }
    _compress(last) {
        const v = new Uint32Array(32);
        const m = new Uint32Array(32);
        const b = this.buf;
        for (let i = 0; i < 16; i++) {
            m[2 * i] = (b[i * 8] | (b[i * 8 + 1] << 8) | (b[i * 8 + 2] << 16) | (b[i * 8 + 3] << 24)) >>> 0;
            m[2 * i + 1] = (b[i * 8 + 4] | (b[i * 8 + 5] << 8) | (b[i * 8 + 6] << 16) | (b[i * 8 + 7] << 24)) >>> 0;
        }
        for (let i = 0; i < 16; i++) v[i] = this.h[i];
        for (let i = 0; i < 16; i++) v[16 + i] = BLAKE2B_IV[i];
        v[24] = (v[24] ^ this.t0) >>> 0; v[25] = (v[25] ^ this.t1) >>> 0;
        if (last) { v[28] = (v[28] ^ 0xffffffff) >>> 0; v[29] = (v[29] ^ 0xffffffff) >>> 0; }
        for (let r = 0; r < 12; r++) {
            bG(v, m, r, 0, 0, 4, 8, 12);
            bG(v, m, r, 1, 1, 5, 9, 13);
            bG(v, m, r, 2, 2, 6, 10, 14);
            bG(v, m, r, 3, 3, 7, 11, 15);
            bG(v, m, r, 4, 0, 5, 10, 15);
            bG(v, m, r, 5, 1, 6, 11, 12);
            bG(v, m, r, 6, 2, 7, 8, 13);
            bG(v, m, r, 7, 3, 4, 9, 14);
        }
        for (let i = 0; i < 16; i++) this.h[i] = (this.h[i] ^ v[i] ^ v[16 + i]) >>> 0;
    }
    update(data) {
        for (let i = 0; i < data.length; i++) {
            if (this.buflen === 128) { this._inc(128); this._compress(false); this.buflen = 0; }
            this.buf[this.buflen++] = data[i];
        }
        return this;
    }
    digest() {
        this._inc(this.buflen);
        for (let i = this.buflen; i < 128; i++) this.buf[i] = 0;
        this._compress(true);
        const out = new Uint8Array(this.outlen);
        for (let i = 0; i < this.outlen; i++) out[i] = (this.h[i >> 2] >>> (8 * (i & 3))) & 0xff;
        return out;
    }
}

function blake2b(data, outlen = 64) {
    return new Blake2b(outlen).update(data).digest();
}

function le32(n) {
    return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

function concatU8(arrays) {
    let len = 0;
    for (const a of arrays) len += a.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
}

function hPrime(outlen, input) {
    if (outlen <= 64) return blake2b(concatU8([le32(outlen), input]), outlen);
    const r = Math.ceil(outlen / 32) - 2;
    const out = new Uint8Array(outlen);
    let v = blake2b(concatU8([le32(outlen), input]), 64);
    out.set(v.subarray(0, 32), 0);
    let pos = 32;
    for (let i = 2; i <= r; i++) {
        v = blake2b(v, 64);
        out.set(v.subarray(0, 32), pos);
        pos += 32;
    }
    const lastLen = outlen - 32 * r;
    v = blake2b(v, lastLen);
    out.set(v.subarray(0, lastLen), pos);
    return out;
}

function mul32(a, b) {
    const aLo = a & 0xffff, aHi = a >>> 16;
    const bLo = b & 0xffff, bHi = b >>> 16;
    const lo = aLo * bLo;
    const mid = aHi * bLo + aLo * bHi;
    const hi = aHi * bHi;
    const midLo = (mid & 0xffff) * 0x10000;
    const low = lo + midLo;
    const carry = Math.floor(low / 0x100000000);
    return { lo: low >>> 0, hi: (hi + Math.floor(mid / 0x10000) + carry) >>> 0 };
}

function fBlaMka(v, ai, bi) {
    const al = v[2 * ai], bl = v[2 * bi];
    const p = mul32(al, bl);
    const plo = (p.lo << 1) >>> 0;
    const phi = ((p.hi << 1) | (p.lo >>> 31)) >>> 0;
    add64(v, ai, v[2 * bi], v[2 * bi + 1]);
    add64(v, ai, plo, phi);
}

function aG(v, a, b, c, d) {
    fBlaMka(v, a, b); xor64(v, d, a); rotr64(v, d, 32);
    fBlaMka(v, c, d); xor64(v, b, c); rotr64(v, b, 24);
    fBlaMka(v, a, b); xor64(v, d, a); rotr64(v, d, 16);
    fBlaMka(v, c, d); xor64(v, b, c); rotr64(v, b, 63);
}

function permP(v, s) {
    aG(v, s[0], s[4], s[8], s[12]);
    aG(v, s[1], s[5], s[9], s[13]);
    aG(v, s[2], s[6], s[10], s[14]);
    aG(v, s[3], s[7], s[11], s[15]);
    aG(v, s[0], s[5], s[10], s[15]);
    aG(v, s[1], s[6], s[11], s[12]);
    aG(v, s[2], s[7], s[8], s[13]);
    aG(v, s[3], s[4], s[9], s[14]);
}

const ROW_SETS = [];
const COL_SETS = [];
for (let i = 0; i < 8; i++) {
    const row = [];
    for (let j = 0; j < 16; j++) row.push(i * 16 + j);
    ROW_SETS.push(row);
    const col = [];
    for (let j = 0; j < 8; j++) { col.push(2 * i + 16 * j); col.push(2 * i + 16 * j + 1); }
    COL_SETS.push(col);
}

function blkXor(dst, a, b) { for (let i = 0; i < 256; i++) dst[i] = (a[i] ^ b[i]) >>> 0; }

function fillBlock(prev, ref, out, withXor) {
    const R = new Uint32Array(256);
    blkXor(R, prev, ref);
    const Z = R.slice();
    for (let i = 0; i < 8; i++) permP(Z, ROW_SETS[i]);
    for (let i = 0; i < 8; i++) permP(Z, COL_SETS[i]);
    if (withXor) for (let i = 0; i < 256; i++) out[i] = (Z[i] ^ R[i] ^ out[i]) >>> 0;
    else for (let i = 0; i < 256; i++) out[i] = (Z[i] ^ R[i]) >>> 0;
}

function blockToBytes(block) {
    const out = new Uint8Array(1024);
    for (let i = 0; i < 256; i++) {
        out[i * 4] = block[i] & 0xff;
        out[i * 4 + 1] = (block[i] >>> 8) & 0xff;
        out[i * 4 + 2] = (block[i] >>> 16) & 0xff;
        out[i * 4 + 3] = (block[i] >>> 24) & 0xff;
    }
    return out;
}
function bytesToBlock(bytes) {
    const b = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        b[i] = (bytes[i * 4] | (bytes[i * 4 + 1] << 8) | (bytes[i * 4 + 2] << 16) | (bytes[i * 4 + 3] << 24)) >>> 0;
    }
    return b;
}

// type: 0=argon2d, 1=argon2i, 2=argon2id ; memory in KiB
function argon2(password, salt, opts = {}) {
    const type = opts.type ?? 2;
    const iterations = opts.iterations ?? 3;
    const mKiB = opts.memory ?? 32;
    const lanes = opts.parallelism ?? 4;
    const tagLength = opts.tagLength ?? 32;
    const version = opts.version ?? 0x13;
    const P = password instanceof Uint8Array ? password : new Uint8Array(password);
    const S = salt instanceof Uint8Array ? salt : new Uint8Array(salt);
    const K = opts.secret ? new Uint8Array(opts.secret) : new Uint8Array(0);
    const X = opts.ad ? new Uint8Array(opts.ad) : new Uint8Array(0);

    let memoryBlocks = Math.max(mKiB, 8 * lanes);
    const segmentLength = Math.floor(memoryBlocks / (lanes * 4));
    memoryBlocks = segmentLength * 4 * lanes;
    const laneLength = segmentLength * 4;

    const H0 = blake2b(concatU8([
        le32(lanes), le32(tagLength), le32(mKiB), le32(iterations), le32(version), le32(type),
        le32(P.length), P, le32(S.length), S, le32(K.length), K, le32(X.length), X,
    ]), 64);

    const B = new Array(memoryBlocks);
    for (let lane = 0; lane < lanes; lane++) {
        B[lane * laneLength + 0] = bytesToBlock(hPrime(1024, concatU8([H0, le32(0), le32(lane)])));
        B[lane * laneLength + 1] = bytesToBlock(hPrime(1024, concatU8([H0, le32(1), le32(lane)])));
    }

    const addressBlock = new Uint32Array(256);
    const inputBlock = new Uint32Array(256);
    const zeroBlock = new Uint32Array(256);

    for (let pass = 0; pass < iterations; pass++) {
        for (let slice = 0; slice < 4; slice++) {
            for (let lane = 0; lane < lanes; lane++) {
                const dataIndependent = (type === 1) || (type === 2 && pass === 0 && slice < 2);
                let addrIndex = 0;
                if (dataIndependent) {
                    inputBlock.fill(0);
                    inputBlock[0] = pass >>> 0; inputBlock[1] = Math.floor(pass / 0x100000000);
                    inputBlock[2] = lane >>> 0;
                    inputBlock[4] = slice >>> 0;
                    inputBlock[6] = memoryBlocks >>> 0;
                    inputBlock[8] = iterations >>> 0;
                    inputBlock[10] = type >>> 0;
                }

                const startIndex = (pass === 0 && slice === 0) ? 2 : 0;
                let curOffset = lane * laneLength + slice * segmentLength + startIndex;
                let prevOffset = (curOffset % laneLength === 0) ? curOffset + laneLength - 1 : curOffset - 1;

                for (let index = startIndex; index < segmentLength; index++, curOffset++, prevOffset++) {
                    if (curOffset % laneLength === 1) prevOffset = curOffset - 1;

                    let J1, J2;
                    if (dataIndependent) {
                        if (addrIndex % 128 === 0) {
                            inputBlock[12] = (inputBlock[12] + 1) >>> 0;
                            if (inputBlock[12] === 0) inputBlock[13] = (inputBlock[13] + 1) >>> 0;
                            fillBlock(zeroBlock, inputBlock, addressBlock, false);
                            fillBlock(zeroBlock, addressBlock, addressBlock, false);
                        }
                        const w = addrIndex % 128;
                        J1 = addressBlock[2 * w] >>> 0; J2 = addressBlock[2 * w + 1] >>> 0;
                        addrIndex++;
                    } else {
                        J1 = B[prevOffset][0] >>> 0; J2 = B[prevOffset][1] >>> 0;
                    }

                    const refLane = (pass === 0 && slice === 0) ? lane : (J2 % lanes);

                    let refAreaSize;
                    if (pass === 0) {
                        if (slice === 0) refAreaSize = index - 1;
                        else if (refLane === lane) refAreaSize = slice * segmentLength + index - 1;
                        else refAreaSize = slice * segmentLength + (index === 0 ? -1 : 0);
                    } else {
                        if (refLane === lane) refAreaSize = laneLength - segmentLength + index - 1;
                        else refAreaSize = laneLength - segmentLength + (index === 0 ? -1 : 0);
                    }

                    const x = mul32(J1, J1).hi;
                    const y = mul32(refAreaSize >>> 0, x).hi;
                    const relPos = refAreaSize - 1 - y;

                    let startPos = 0;
                    if (pass !== 0 && slice !== 3) startPos = (slice + 1) * segmentLength;
                    const refIndex = (startPos + relPos) % laneLength;
                    const refOffset = refLane * laneLength + refIndex;

                    if (!B[curOffset]) B[curOffset] = new Uint32Array(256);
                    fillBlock(B[prevOffset], B[refOffset], B[curOffset], pass !== 0);
                }
            }
        }
    }

    const final = B[laneLength - 1].slice();
    for (let lane = 1; lane < lanes; lane++) {
        const blk = B[lane * laneLength + laneLength - 1];
        for (let i = 0; i < 256; i++) final[i] ^= blk[i];
    }
    return hPrime(tagLength, blockToBytes(final));
}

// ============================================================
// Bitwarden crypto helpers (WebCrypto + the Argon2 above)
// ============================================================

const TE = new TextEncoder();
const TD = new TextDecoder();

function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}
function bytesToB64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}
function ctEqual(a, b) {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
    return r === 0;
}

async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function pbkdf2(password, salt, iterations, length = 32) {
    const key = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, length * 8);
    return new Uint8Array(bits);
}

async function hmacSha256(keyBytes, data) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

// HKDF-Expand only (RFC 5869); the master key is used directly as PRK.
async function hkdfExpand(prk, info, length) {
    const infoBytes = typeof info === 'string' ? TE.encode(info) : info;
    const hashLen = 32;
    const n = Math.ceil(length / hashLen);
    const out = new Uint8Array(n * hashLen);
    let prev = new Uint8Array(0);
    for (let i = 1; i <= n; i++) {
        prev = await hmacSha256(prk, concatU8([prev, infoBytes, new Uint8Array([i])]));
        out.set(prev, (i - 1) * hashLen);
    }
    return out.slice(0, length);
}

async function aesCbcDecrypt(keyBytes, iv, data) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, data));
}

function parseCipherString(str) {
    if (!str) return null;
    let type = 0, rest = str;
    const m = /^(\d+)\.(.+)$/s.exec(str);
    if (m) { type = parseInt(m[1], 10); rest = m[2]; }
    return { type, parts: rest.split('|') };
}

// Decrypt an AES-CBC(+HMAC) CipherString with a symmetric key {enc, mac}.
async function decryptSym(str, encKey, macKey) {
    const cs = parseCipherString(str);
    if (!cs) return new Uint8Array(0);
    let ivB64, ctB64, macB64;
    if (cs.type === 0) { ivB64 = cs.parts[0]; ctB64 = cs.parts[1]; }
    else if (cs.type === 1 || cs.type === 2) { ivB64 = cs.parts[0]; ctB64 = cs.parts[1]; macB64 = cs.parts[2]; }
    else throw new Error('UNSUPPORTED_CIPHER_TYPE_' + cs.type);
    const iv = b64ToBytes(ivB64), ct = b64ToBytes(ctB64);
    if (macKey && macB64) {
        const expected = await hmacSha256(macKey, concatU8([iv, ct]));
        if (!ctEqual(expected, b64ToBytes(macB64))) throw new Error('MAC_FAILED');
    }
    return aesCbcDecrypt(encKey, iv, ct);
}

async function decryptSymToString(str, encKey, macKey) {
    if (!str) return '';
    return TD.decode(await decryptSym(str, encKey, macKey));
}

// Decrypt the protected user key with the master key.
async function decryptUserKey(protectedKeyStr, masterKey) {
    const cs = parseCipherString(protectedKeyStr);
    let enc, mac;
    if (cs.type === 0) { enc = masterKey; mac = null; }
    else { enc = await hkdfExpand(masterKey, 'enc', 32); mac = await hkdfExpand(masterKey, 'mac', 32); }
    const full = await decryptSym(protectedKeyStr, enc, mac);
    if (full.length === 64) return { enc: full.slice(0, 32), mac: full.slice(32, 64) };
    if (full.length === 32) return { enc: full, mac: null };
    throw new Error('BAD_USER_KEY_LENGTH_' + full.length);
}

// RSA-OAEP decrypt (org keys / private key payloads).
async function rsaDecrypt(str, privKeyPkcs8) {
    const cs = parseCipherString(str);
    const hash = cs.type === 4 ? 'SHA-1' : 'SHA-256';
    const key = await crypto.subtle.importKey('pkcs8', privKeyPkcs8, { name: 'RSA-OAEP', hash }, false, ['decrypt']);
    const ct = b64ToBytes(cs.parts[0]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, ct));
}

async function deriveMasterKey(password, email, kdf) {
    const pw = TE.encode(password);
    const emailNorm = TE.encode((email || '').trim().toLowerCase());
    if (kdf.type === 1) {
        const salt = await sha256(emailNorm);
        return argon2(pw, salt, {
            type: 2,
            iterations: kdf.iterations,
            memory: kdf.memory * 1024, // MiB -> KiB
            parallelism: kdf.parallelism,
            tagLength: 32,
        });
    }
    return pbkdf2(pw, emailNorm, kdf.iterations, 32);
}

function field(obj, name) {
    if (obj == null) return undefined;
    if (obj[name] !== undefined) return obj[name];
    const cap = name[0].toUpperCase() + name.slice(1);
    return obj[cap];
}

// ============================================================
// UI icons
// ============================================================

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
    'shield': '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
    'alert-triangle': '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    'alert-circle': '<circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>',
    'lock': '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    'settings': '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
    'refresh-cw': '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/>',
    'search': '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    'loader-2': '<path d="M21 12a9 9 0 1 1-6.219-8.56"/>',
    'key-round': '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
    'credit-card': '<rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/>',
    'file-text': '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/>',
    'user': '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    'file': '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/>',
    'star': '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
    'copy': '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    'eye': '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    'eye-off': '<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/>',
    'clock': '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    'folder': '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
    'list': '<line x1="8" x2="21" y1="6" y2="6"/><line x1="8" x2="21" y1="12" y2="12"/><line x1="8" x2="21" y1="18" y2="18"/><line x1="3" x2="3.01" y1="6" y2="6"/><line x1="3" x2="3.01" y1="12" y2="12"/><line x1="3" x2="3.01" y1="18" y2="18"/>',
    'arrow-left': '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
};

function setIcon(el, name) {
    while (el.firstChild) el.removeChild(el.firstChild);
    const inner = ICONS[name];
    if (!inner) return;
    const svg = new DOMParser().parseFromString(
        `<svg xmlns="${SVG_NS}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`,
        'image/svg+xml'
    ).documentElement;
    el.appendChild(svg);
}

function extractDomain(uri) {
    if (!uri) return null;
    try {
        return new URL(uri.startsWith('http') ? uri : `https://${uri}`).hostname;
    } catch {
        return null;
    }
}

// --- TOTP ---

function base32Decode(input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const s = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
    let bits = '';
    for (const ch of s) {
        const idx = alphabet.indexOf(ch);
        if (idx < 0) continue;
        bits += idx.toString(2).padStart(5, '0');
    }
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    }
    return bytes;
}

function parseTotpUri(totpValue) {
    if (!totpValue) return null;
    let secret = totpValue, digits = 6, period = 30;
    if (totpValue.startsWith('otpauth://')) {
        try {
            const url = new URL(totpValue);
            secret = url.searchParams.get('secret') || '';
            digits = parseInt(url.searchParams.get('digits') || '6', 10);
            period = parseInt(url.searchParams.get('period') || '30', 10);
        } catch { return null; }
    }
    if (!secret) return null;
    return { secret, digits, period };
}

async function generateTotp(secret, digits = 6, period = 30) {
    const key = await crypto.subtle.importKey(
        'raw',
        base32Decode(secret),
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
    );
    const counter = Math.floor(Date.now() / 1000 / period);
    const buf = new ArrayBuffer(8);
    new DataView(buf).setUint32(4, counter, false);
    const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
    const offset = hmac[19] & 0xf;
    const code = (
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)
    ) % (10 ** digits);
    return code.toString().padStart(digits, '0');
}

// ============================================================
// Plugin
// ============================================================

class BitwardenPlugin extends Plugin {
    userKey = null;   // { enc: Uint8Array, mac: Uint8Array|null }
    orgKeys = {};
    vault = null;     // { items: [], folders: [] }

    async onload() {
        await this.loadSettings();
        this.registerView(VIEW_TYPE, (leaf) => new BitwardenView(leaf, this));
        this.addRibbonIcon('shield', 'Bitwarden', () => this.activateView());
        this.addCommand({
            id: 'open-bitwarden',
            name: 'Bitwardenパネルを開く',
            callback: () => this.activateView(),
        });
        this.addSettingTab(new BitwardenSettingTab(this.app, this));
    }

    async onunload() {
        this.userKey = null;
        this.orgKeys = {};
        this.vault = null;
        this.app.workspace.detachLeavesOfType(VIEW_TYPE);
    }

    async activateView() {
        const { workspace } = this.app;
        let [leaf] = workspace.getLeavesOfType(VIEW_TYPE);
        if (!leaf) {
            leaf = workspace.getRightLeaf(false);
            if (leaf) await leaf.setViewState({ type: VIEW_TYPE, active: true });
        }
        if (leaf) workspace.revealLeaf(leaf);
    }

    // --- endpoints ---

    endpoints() {
        const r = this.settings.region;
        if (r === 'eu') {
            return { identity: 'https://identity.bitwarden.eu', api: 'https://api.bitwarden.eu' };
        }
        if (r === 'self') {
            const base = (this.settings.serverUrl || '').replace(/\/+$/, '');
            return { identity: `${base}/identity`, api: `${base}/api` };
        }
        return { identity: 'https://identity.bitwarden.com', api: 'https://api.bitwarden.com' };
    }

    isConfigured() {
        if (!this.settings.email || !this.settings.clientId || !this.settings.clientSecret) return false;
        if (this.settings.region === 'self' && !this.settings.serverUrl) return false;
        return true;
    }

    get isUnlocked() { return !!this.userKey; }

    // --- API ---

    async prelogin() {
        const body = JSON.stringify({ email: this.settings.email });
        const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
        const { identity, api } = this.endpoints();
        for (const url of [`${identity}/accounts/prelogin`, `${api}/accounts/prelogin`]) {
            const res = await requestUrl({ url, method: 'POST', headers, body, throw: false });
            if (res.status === 200) {
                const j = res.json;
                return {
                    type: field(j, 'kdf') ?? 0,
                    iterations: field(j, 'kdfIterations') ?? 600000,
                    memory: field(j, 'kdfMemory') ?? 64,
                    parallelism: field(j, 'kdfParallelism') ?? 4,
                };
            }
            if (res.status !== 404 && res.status !== 405) {
                throw new Error('PRELOGIN_FAILED_' + res.status);
            }
        }
        throw new Error('PRELOGIN_FAILED');
    }

    async login() {
        const { identity } = this.endpoints();
        const params = new URLSearchParams();
        params.set('grant_type', 'client_credentials');
        params.set('scope', 'api');
        params.set('client_id', this.settings.clientId);
        params.set('client_secret', this.settings.clientSecret);
        params.set('deviceType', '14');
        params.set('deviceIdentifier', this.settings.deviceId);
        params.set('deviceName', 'obsidian');
        const res = await requestUrl({
            url: `${identity}/connect/token`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                'Accept': 'application/json',
                'Device-Type': '14',
            },
            body: params.toString(),
            throw: false,
        });
        if (res.status !== 200) throw new Error('LOGIN_FAILED_' + res.status);
        const j = res.json;
        this.settings.accessToken = j.access_token;
        this.settings.tokenExpiresAt = Date.now() + ((j.expires_in || 3600) * 1000);
        await this.saveSettings();
        return j.access_token;
    }

    async ensureToken() {
        if (this.settings.accessToken && Date.now() < this.settings.tokenExpiresAt - 60000) {
            return this.settings.accessToken;
        }
        return this.login();
    }

    async syncRaw() {
        const { api } = this.endpoints();
        const doFetch = async (token) => requestUrl({
            url: `${api}/sync?excludeDomains=true`,
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
            throw: false,
        });
        let token = await this.ensureToken();
        let res = await doFetch(token);
        if (res.status === 401) {
            this.settings.accessToken = null;
            this.settings.tokenExpiresAt = 0;
            token = await this.login();
            res = await doFetch(token);
        }
        if (res.status !== 200) throw new Error('SYNC_FAILED_' + res.status);
        return res.json;
    }

    // --- vault ---

    async buildOrgKeys(profile) {
        const orgKeys = {};
        const orgs = field(profile, 'organizations') || [];
        const privEnc = field(profile, 'privateKey');
        if (!orgs.length || !privEnc) return orgKeys;
        const privPkcs8 = await decryptSym(privEnc, this.userKey.enc, this.userKey.mac);
        for (const org of orgs) {
            const id = field(org, 'id');
            const keyStr = field(org, 'key');
            if (!id || !keyStr) continue;
            try {
                const raw = await rsaDecrypt(keyStr, privPkcs8);
                orgKeys[id] = raw.length === 64
                    ? { enc: raw.slice(0, 32), mac: raw.slice(32, 64) }
                    : { enc: raw, mac: null };
            } catch { /* skip org we cannot decrypt */ }
        }
        return orgKeys;
    }

    keyForCipher(cipher) {
        const orgId = field(cipher, 'organizationId');
        if (orgId && this.orgKeys[orgId]) return this.orgKeys[orgId];
        return this.userKey;
    }

    async decryptCipher(c) {
        const key = this.keyForCipher(c);
        const dec = (s) => decryptSymToString(s, key.enc, key.mac);
        const type = field(c, 'type');
        const item = {
            id: field(c, 'id'),
            type,
            favorite: !!field(c, 'favorite'),
            folderId: field(c, 'folderId') || null,
            name: await dec(field(c, 'name')),
        };
        const notes = field(c, 'notes');
        if (notes) item.notes = await dec(notes);

        if (type === 1) {
            const login = field(c, 'login');
            if (login) {
                const urisRaw = field(login, 'uris') || [];
                const uris = [];
                for (const u of urisRaw) uris.push({ uri: await dec(field(u, 'uri')) });
                item.login = {
                    username: field(login, 'username') ? await dec(field(login, 'username')) : '',
                    password: field(login, 'password') ? await dec(field(login, 'password')) : '',
                    totp: field(login, 'totp') ? await dec(field(login, 'totp')) : null,
                    uris,
                };
            }
        } else if (type === 3) {
            const card = field(c, 'card');
            if (card) {
                item.card = {
                    cardholderName: field(card, 'cardholderName') ? await dec(field(card, 'cardholderName')) : '',
                    number: field(card, 'number') ? await dec(field(card, 'number')) : '',
                    expMonth: field(card, 'expMonth') ? await dec(field(card, 'expMonth')) : '',
                    expYear: field(card, 'expYear') ? await dec(field(card, 'expYear')) : '',
                    code: field(card, 'code') ? await dec(field(card, 'code')) : '',
                    brand: field(card, 'brand') ? await dec(field(card, 'brand')) : '',
                };
            }
        }
        return item;
    }

    async decryptVault(sync) {
        const ciphers = field(sync, 'ciphers') || [];
        const folders = field(sync, 'folders') || [];
        const items = [];
        for (const c of ciphers) {
            if (field(c, 'deletedDate')) continue; // skip trashed
            try { items.push(await this.decryptCipher(c)); } catch { /* skip undecryptable */ }
        }
        const decFolders = [];
        for (const f of folders) {
            const id = field(f, 'id');
            if (!id) continue; // null id = "no folder" placeholder
            decFolders.push({ id, name: await decryptSymToString(field(f, 'name'), this.userKey.enc, this.userKey.mac) });
        }
        return { items, folders: decFolders };
    }

    async sync() {
        if (!this.userKey) throw new Error('LOCKED');
        const raw = await this.syncRaw();
        const profile = field(raw, 'profile');
        this.orgKeys = await this.buildOrgKeys(profile);
        this.vault = await this.decryptVault(raw);
    }

    async unlock(password) {
        const kdf = await this.prelogin();
        const raw = await this.syncRaw();
        const profile = field(raw, 'profile');
        const masterKey = await deriveMasterKey(password, this.settings.email, kdf);
        const userKey = await decryptUserKey(field(profile, 'key'), masterKey); // throws MAC_FAILED on wrong password
        this.userKey = userKey;
        this.orgKeys = await this.buildOrgKeys(profile);
        this.vault = await this.decryptVault(raw);
        const macPart = userKey.mac || new Uint8Array(0);
        this.settings.userKeyB64 = bytesToB64(concatU8([userKey.enc, macPart]));
        await this.saveSettings();
    }

    async lock() {
        this.userKey = null;
        this.orgKeys = {};
        this.vault = null;
        this.settings.userKeyB64 = null;
        this.settings.accessToken = null;
        this.settings.tokenExpiresAt = 0;
        await this.saveSettings();
    }

    async ensureVault() {
        if (!this.vault) await this.sync();
        return this.vault;
    }

    async listItems() {
        return (await this.ensureVault()).items;
    }

    async listFolders() {
        return (await this.ensureVault()).folders;
    }

    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
        if (!this.settings.deviceId) {
            this.settings.deviceId = crypto.randomUUID();
            await this.saveSettings();
        }
        if (this.settings.userKeyB64) {
            const raw = b64ToBytes(this.settings.userKeyB64);
            this.userKey = raw.length === 64
                ? { enc: raw.slice(0, 32), mac: raw.slice(32, 64) }
                : { enc: raw.slice(0, 32), mac: null };
        } else {
            this.userKey = null;
        }
    }

    async saveSettings() {
        await this.saveData(this.settings);
    }
}

function buildFolderTree(folders) {
    const nodeMap = new Map();
    const roots = [];

    const sorted = [...folders].sort((a, b) => a.name.localeCompare(b.name, 'ja'));

    for (const folder of sorted) {
        const parts = folder.name.split('/').map(p => p.trim()).filter(Boolean);
        let siblings = roots;
        let path = '';

        for (let i = 0; i < parts.length; i++) {
            const part = parts[i];
            path = path ? `${path}/${part}` : part;
            const isLast = i === parts.length - 1;

            if (!nodeMap.has(path)) {
                const node = { name: part, path, folder: null, children: [] };
                nodeMap.set(path, node);
                siblings.push(node);
            }
            const node = nodeMap.get(path);
            if (isLast) node.folder = folder;
            siblings = node.children;
        }
    }

    return roots;
}

function pruneEmptyFolderTree(nodes, items) {
    const result = [];
    for (const node of nodes) {
        const prunedChildren = pruneEmptyFolderTree(node.children, items);
        const hasItems = node.folder && items.some(i => (i.folderId || null) === node.folder.id);
        if (hasItems || prunedChildren.length > 0) {
            result.push({ ...node, children: prunedChildren });
        }
    }
    return result;
}

class BitwardenView extends ItemView {
    constructor(leaf, plugin) {
        super(leaf);
        this.plugin = plugin;
        this.listContainer = null;
        this.searchBar = null;
        this.searchInput = null;
        this.searchTimer = null;
        this.folderNav = null;
        this.itemsCache = null;
        this.foldersCache = null;
    }

    getViewType() { return VIEW_TYPE; }
    getDisplayText() { return 'Bitwarden'; }
    getIcon() { return 'shield'; }

    async onOpen() {
        await this.render();
    }

    async render() {
        const container = this.containerEl.children[1];
        container.empty();
        container.addClass('bw-panel');

        if (this.plugin.isUnlocked) {
            await this.renderUnlocked(container);
        } else {
            this.renderLockScreen(container);
        }
    }

    renderLockScreen(container) {
        const screen = container.createDiv('bw-lock-screen');
        const configured = this.plugin.isConfigured();

        const iconEl = screen.createDiv('bw-lock-icon');
        setIcon(iconEl, configured ? 'lock' : 'settings');

        screen.createEl('h3', { text: 'Bitwarden', cls: 'bw-lock-title' });

        if (!configured) {
            screen.createEl('p', {
                text: 'APIキーが未設定です。設定でメールアドレス・client_id・client_secret（とサーバー）を入力してください。',
                cls: 'bw-hint-text',
            });
            screen.createEl('p', {
                text: 'APIキーはWeb Vaultの「アカウント設定 → セキュリティ → キー → APIキー」で取得できます。',
                cls: 'bw-hint-text',
            });
            return;
        }

        const form = screen.createDiv('bw-unlock-form');
        const passwordInput = form.createEl('input', {
            type: 'password',
            placeholder: 'マスターパスワード',
            cls: 'bw-password-input',
        });
        const submitBtn = form.createEl('button', {
            text: 'アンロック',
            cls: 'mod-cta bw-unlock-btn',
        });
        const errorEl = screen.createEl('p', { cls: 'bw-error-text' });

        const doUnlock = async () => {
            const pw = passwordInput.value;
            if (!pw) return;
            submitBtn.disabled = true;
            submitBtn.textContent = '処理中...';
            errorEl.textContent = '';
            try {
                await this.plugin.unlock(pw);
                await this.render();
            } catch (err) {
                errorEl.textContent = this.unlockErrorMessage(err);
                submitBtn.disabled = false;
                submitBtn.textContent = 'アンロック';
            }
        };

        submitBtn.addEventListener('click', doUnlock);
        passwordInput.addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });
        setTimeout(() => passwordInput.focus(), 50);
    }

    unlockErrorMessage(err) {
        const m = err && err.message ? err.message : '';
        if (m === 'MAC_FAILED' || m.startsWith('BAD_USER_KEY')) {
            return 'アンロックに失敗しました。パスワードを確認してください。';
        }
        if (m.startsWith('LOGIN_FAILED')) {
            return 'ログインに失敗しました。APIキー（client_id / client_secret）を確認してください。';
        }
        if (m.startsWith('PRELOGIN_FAILED') || m.startsWith('SYNC_FAILED')) {
            return 'サーバーに接続できませんでした。サーバーURLとネットワークを確認してください。';
        }
        return '不明なエラーが発生しました: ' + m;
    }

    async renderUnlocked(container) {
        const header = container.createDiv('bw-header');
        const titleDiv = header.createDiv('bw-title');
        const titleIcon = titleDiv.createSpan('bw-title-icon');
        setIcon(titleIcon, 'shield');
        titleDiv.createSpan({ text: 'Bitwarden', cls: 'bw-title-text' });

        const btnGroup = header.createDiv('bw-btn-group');

        const syncBtn = btnGroup.createEl('button', {
            cls: 'bw-icon-btn',
            attr: { title: '同期', 'aria-label': '同期' },
        });
        setIcon(syncBtn, 'refresh-cw');
        syncBtn.addEventListener('click', async () => {
            syncBtn.disabled = true;
            syncBtn.addClass('bw-spinning');
            try {
                await this.plugin.sync();
                this.itemsCache = null;
                this.foldersCache = null;
                new Notice('Bitwarden: 同期完了');
                await this.loadItems(this.lastQuery || '');
            } catch {
                new Notice('Bitwarden: 同期に失敗しました');
            } finally {
                syncBtn.disabled = false;
                syncBtn.removeClass('bw-spinning');
            }
        });

        const lockBtn = btnGroup.createEl('button', {
            cls: 'bw-icon-btn',
            attr: { title: 'ロック', 'aria-label': 'ロック' },
        });
        setIcon(lockBtn, 'lock');
        lockBtn.addEventListener('click', async () => {
            await this.plugin.lock();
            await this.render();
        });

        const isFolder = this.plugin.settings.viewMode === 'folder';
        const viewModeBtn = btnGroup.createEl('button', {
            cls: 'bw-icon-btn',
            attr: {
                title: isFolder ? 'タイプ別表示' : 'フォルダ別表示',
                'aria-label': 'ビュー切替',
            },
        });
        setIcon(viewModeBtn, isFolder ? 'list' : 'folder');
        viewModeBtn.addEventListener('click', async () => {
            this.plugin.settings.viewMode = this.plugin.settings.viewMode === 'type' ? 'folder' : 'type';
            await this.plugin.saveSettings();
            await this.render();
        });

        this.folderNav = null;
        this.itemsCache = null;
        this.foldersCache = null;

        this.searchBar = container.createDiv('bw-search-bar');
        const searchIconEl = this.searchBar.createSpan('bw-search-icon');
        setIcon(searchIconEl, 'search');
        this.searchInput = this.searchBar.createEl('input', {
            type: 'text',
            placeholder: 'アイテムを検索...',
            cls: 'bw-search-input',
        });
        this.searchInput.addEventListener('input', () => {
            clearTimeout(this.searchTimer);
            this.lastQuery = this.searchInput.value;
            this.searchTimer = setTimeout(() => this.loadItems(this.searchInput.value), 300);
        });

        this.listContainer = container.createDiv('bw-list-container');
        this.lastQuery = '';

        await this.loadItems();
        if (this.plugin.settings.viewMode !== 'folder') {
            setTimeout(() => this.searchInput.focus(), 50);
        }
    }

    async getItems(query = '') {
        if (!this.itemsCache) {
            this.itemsCache = await this.plugin.listItems();
        }
        if (!query) return this.itemsCache;
        const q = query.toLowerCase();
        return this.itemsCache.filter(item =>
            item.name?.toLowerCase().includes(q) ||
            item.login?.username?.toLowerCase().includes(q) ||
            item.login?.uris?.[0]?.uri?.toLowerCase().includes(q)
        );
    }

    async getFolders() {
        if (!this.foldersCache) {
            this.foldersCache = await this.plugin.listFolders();
        }
        return this.foldersCache;
    }

    async loadItems(query = '') {
        if (!this.listContainer) return;
        this.listContainer.empty();

        const loadingEl = this.listContainer.createDiv('bw-loading');
        setIcon(loadingEl, 'loader-2');

        try {
            if (this.plugin.settings.viewMode === 'folder' && !this.folderNav) {
                if (this.searchBar) this.searchBar.style.display = 'none';
                await this.loadFolderHome();
            } else {
                if (this.searchBar) this.searchBar.style.display = '';
                const items = await this.getItems(query);
                this.listContainer.empty();

                if (this.plugin.settings.viewMode === 'folder' && this.folderNav) {
                    this.renderFolderBackButton();

                    const allFolders = await this.getFolders();
                    const prefix = this.folderNav.name + '/';
                    const childFolders = allFolders
                        .filter(f => f.name.startsWith(prefix))
                        .map(f => ({ id: f.id, name: f.name.slice(prefix.length), _fullName: f.name }));
                    const allItems = this.itemsCache || [];
                    const childTree = pruneEmptyFolderTree(buildFolderTree(childFolders), allItems);
                    if (childTree.length) {
                        const groupHeader = this.listContainer.createDiv('bw-group-label');
                        setIcon(groupHeader.createSpan('bw-group-icon'), 'folder');
                        groupHeader.createSpan({ text: 'フォルダ' });
                        this.renderFolderTree(this.listContainer, childTree, 0);
                    }

                    const folderItems = items.filter(i => (i.folderId || null) === this.folderNav.id);
                    if (!folderItems.length && !childTree.length) {
                        const emptyEl = this.listContainer.createDiv('bw-empty');
                        setIcon(emptyEl.createSpan(), 'search');
                        emptyEl.createSpan({ text: query ? '見つかりません' : 'アイテムがありません' });
                    } else if (folderItems.length) {
                        this.renderItems(folderItems);
                    }
                } else {
                    if (!items.length) {
                        const emptyEl = this.listContainer.createDiv('bw-empty');
                        setIcon(emptyEl.createSpan(), 'search');
                        emptyEl.createSpan({ text: query ? '見つかりません' : 'アイテムがありません' });
                        return;
                    }
                    this.renderByType(items);
                }
            }
        } catch (err) {
            const m = err && err.message ? err.message : '';
            this.listContainer.empty();
            const errEl = this.listContainer.createDiv('bw-error-state');
            setIcon(errEl.createSpan('bw-error-icon'), 'alert-circle');
            errEl.createEl('p', { text: this.unlockErrorMessage(err) || m || '不明なエラーが発生しました' });
        }
    }

    async loadFolderHome() {
        const [folders, items] = await Promise.all([this.getFolders(), this.getItems('')]);
        this.listContainer.empty();

        const favorites = items.filter(i => i.favorite);
        if (favorites.length) {
            this.renderGroup('お気に入り', 'star', favorites);
        }

        if (!folders.length) {
            if (!favorites.length) {
                const emptyEl = this.listContainer.createDiv('bw-empty');
                setIcon(emptyEl.createSpan(), 'folder');
                emptyEl.createSpan({ text: 'フォルダがありません' });
            }
            return;
        }

        const tree = pruneEmptyFolderTree(buildFolderTree(folders), items);
        this.renderFolderTree(this.listContainer, tree, 0, 0);
    }

    renderFolderTree(container, nodes, depth, maxDepth = Infinity) {
        for (const node of nodes) {
            const row = container.createDiv('bw-item');

            if (depth > 0) {
                const indent = row.createDiv();
                indent.style.cssText = `width:${depth * 1.25}rem;flex-shrink:0`;
            }

            const iconEl = row.createDiv('bw-item-icon');
            setIcon(iconEl, 'folder');

            const info = row.createDiv('bw-item-info');
            info.createDiv({ text: node.name, cls: 'bw-item-name' });

            if (node.folder) {
                row.addEventListener('click', () => {
                    this.folderNav = { id: node.folder.id, name: node.folder._fullName || node.folder.name };
                    if (this.searchInput) { this.searchInput.value = ''; this.lastQuery = ''; }
                    this.loadItems('');
                });
            } else {
                row.style.cursor = 'default';
            }

            if (node.children.length > 0 && depth < maxDepth) {
                this.renderFolderTree(container, node.children, depth + 1, maxDepth);
            }
        }
    }

    renderFolderBackButton() {
        const row = this.listContainer.createDiv('bw-folder-back-row');
        const backBtn = row.createEl('button', {
            cls: 'bw-icon-btn',
            attr: { title: 'フォルダ一覧に戻る', 'aria-label': '戻る' },
        });
        setIcon(backBtn, 'arrow-left');
        const displayName = this.folderNav.name.split('/').pop();
        row.createSpan({ text: displayName, cls: 'bw-folder-current-name' });
        backBtn.addEventListener('click', () => {
            this.folderNav = null;
            if (this.searchInput) { this.searchInput.value = ''; this.lastQuery = ''; }
            this.loadItems('');
        });
    }

    renderItems(items) {
        const groups = [
            { type: 1, label: 'ログイン', icon: 'key-round' },
            { type: 3, label: 'カード', icon: 'credit-card' },
            { type: 2, label: 'メモ', icon: 'file-text' },
            { type: 4, label: 'ID', icon: 'user' },
        ];
        for (const { type, label, icon } of groups) {
            const filtered = items.filter(i => i.type === type);
            if (!filtered.length) continue;
            this.renderGroup(label, icon, filtered);
        }
    }

    renderByType(items) {
        const favorites = items.filter(i => i.favorite);
        if (favorites.length) this.renderGroup('お気に入り', 'star', favorites);

        const groups = [
            { type: 1, label: 'ログイン', icon: 'key-round' },
            { type: 3, label: 'カード', icon: 'credit-card' },
            { type: 2, label: 'メモ', icon: 'file-text' },
            { type: 4, label: 'ID', icon: 'user' },
        ];

        for (const { type, label, icon } of groups) {
            const filtered = items.filter(i => i.type === type && !i.favorite);
            if (!filtered.length) continue;
            this.renderGroup(label, icon, filtered);
        }
    }

    renderGroup(label, icon, items) {
        const group = this.listContainer.createDiv('bw-group');
        if (icon === 'star') group.addClass('bw-group--favorites');
        const groupHeader = group.createDiv('bw-group-label');
        setIcon(groupHeader.createSpan('bw-group-icon'), icon);
        groupHeader.createSpan({ text: `${label}  ${items.length}` });

        const sortedItems = [...items].sort((a, b) => (a.name || '').localeCompare(b.name || '', 'ja'));
        for (const item of sortedItems) {
            const el = group.createDiv('bw-item');

            const itemIcon = el.createDiv('bw-item-icon');
            const typeIcon = { 1: 'key-round', 2: 'file-text', 3: 'credit-card', 4: 'user' }[item.type] || 'file';
            const domain = item.type === 1 ? extractDomain(item.login?.uris?.[0]?.uri) : null;
            if (domain && this.plugin.settings.useIcons) {
                const server = this.plugin.settings.iconServer || 'https://icons.bitwarden.net';
                const img = itemIcon.createEl('img', {
                    cls: 'bw-site-icon',
                    attr: { src: `${server}/${domain}/icon.png`, alt: '' },
                });
                img.addEventListener('error', () => { img.remove(); setIcon(itemIcon, typeIcon); });
            } else {
                setIcon(itemIcon, typeIcon);
            }

            const info = el.createDiv('bw-item-info');
            info.createDiv({ text: item.name, cls: 'bw-item-name' });

            const sub = item.type === 1
                ? (item.login?.username || item.login?.uris?.[0]?.uri || '')
                : '';
            if (sub) info.createDiv({ text: sub, cls: 'bw-item-sub' });

            const actions = el.createDiv('bw-item-actions');

            if (this.plugin.settings.showCopyButtons) {
                if (item.type === 1 && item.login?.username) {
                    const btn = actions.createEl('button', {
                        cls: 'bw-copy-btn',
                        attr: { title: 'ユーザー名をコピー' },
                    });
                    setIcon(btn, 'user');
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(item.login.username);
                        new Notice('ユーザー名をコピーしました');
                    });
                }

                if (item.type === 1 && item.login?.password) {
                    const btn = actions.createEl('button', {
                        cls: 'bw-copy-btn',
                        attr: { title: 'パスワードをコピー' },
                    });
                    setIcon(btn, 'copy');
                    btn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(item.login.password);
                        new Notice('パスワードをコピーしました');
                    });
                }

                if (item.type === 1 && item.login?.totp) {
                    const btn = actions.createEl('button', {
                        cls: 'bw-copy-btn',
                        attr: { title: 'TOTPコードをコピー' },
                    });
                    setIcon(btn, 'clock');
                    btn.addEventListener('click', async (e) => {
                        e.stopPropagation();
                        const parsed = parseTotpUri(item.login.totp);
                        if (!parsed) return;
                        try {
                            const code = await generateTotp(parsed.secret, parsed.digits, parsed.period);
                            await navigator.clipboard.writeText(code);
                            new Notice(`TOTPコード: ${code}`);
                        } catch {
                            new Notice('TOTPコードの生成に失敗しました');
                        }
                    });
                }
            }

            el.addEventListener('click', () => new BitwardenItemModal(this.app, item).open());
        }
    }
}

class BitwardenItemModal extends Modal {
    constructor(app, item) {
        super(app);
        this.item = item;
        this._totpInterval = null;
        this._lastCounter = -1;
    }

    async onOpen() {
        const { contentEl } = this;
        contentEl.addClass('bw-modal');
        contentEl.createEl('h2', { text: this.item.name, cls: 'bw-modal-title' });

        const { type, login, card, notes } = this.item;

        if (type === 1 && login) {
            this.addField('ユーザー名', login.username, { copyable: true });
            this.addField('パスワード', login.password, { copyable: true, masked: true });
            if (login.totp) await this.addTotpField(login.totp);
            if (login.uris?.length) {
                login.uris.forEach((u, i) =>
                    this.addField(i === 0 ? 'URL' : `URL ${i + 1}`, u.uri));
            }
        }

        if (type === 3 && card) {
            this.addField('カード番号', card.number, { copyable: true, masked: false });
            this.addField('カード名義', card.cardholderName);
            if (card.expMonth && card.expYear) {
                this.addField('有効期限', `${card.expMonth}/${card.expYear}`);
            }
            if (card.code) this.addField('CVV', card.code, { copyable: true, masked: false });
        }

        if (notes) this.addField('メモ', notes);
    }

    async addTotpField(totpValue) {
        const parsed = parseTotpUri(totpValue);
        if (!parsed) {
            this.addField('TOTP', totpValue, { copyable: true });
            return;
        }
        const { secret, digits, period } = parsed;

        const row = this.contentEl.createDiv('bw-field-row');
        row.createEl('label', { text: 'TOTP', cls: 'bw-field-label' });

        const box = row.createDiv('bw-totp-box');
        const topRow = box.createDiv('bw-totp-code-row');
        const codeEl = topRow.createEl('span', { cls: 'bw-totp-code', text: '--- ---' });
        const timerEl = topRow.createEl('span', { cls: 'bw-totp-timer', text: '' });
        const copyBtn = topRow.createEl('button', {
            cls: 'bw-icon-btn',
            attr: { title: 'TOTPコードをコピー' },
        });
        setIcon(copyBtn, 'copy');

        const gaugeTrack = box.createDiv('bw-totp-gauge');
        const gaugeFill = gaugeTrack.createDiv('bw-totp-gauge-fill');

        let currentCode = '';

        const update = async () => {
            const now = Math.floor(Date.now() / 1000);
            const counter = Math.floor(now / period);
            const remaining = period - (now % period);
            const pct = (remaining / period) * 100;

            if (counter !== this._lastCounter) {
                this._lastCounter = counter;
                try {
                    currentCode = await generateTotp(secret, digits, period);
                } catch {
                    currentCode = '';
                }
                const fmt = digits === 6 && currentCode
                    ? `${currentCode.slice(0, 3)} ${currentCode.slice(3)}`
                    : (currentCode || '--- ---');
                codeEl.textContent = fmt;
            }

            timerEl.textContent = `${remaining}s`;
            gaugeFill.style.width = `${pct}%`;

            const warn = remaining <= 5;
            gaugeFill.classList.toggle('bw-totp-gauge-fill--warning', warn);
            timerEl.classList.toggle('bw-totp-timer--warning', warn);
        };

        copyBtn.addEventListener('click', () => {
            if (!currentCode) return;
            navigator.clipboard.writeText(currentCode);
            new Notice('TOTPコードをコピーしました');
        });

        await update();
        this._totpInterval = setInterval(update, 1000);
    }

    addField(label, value, opts = {}) {
        if (!value) return;
        const { copyable = false, masked = false } = opts;

        const row = this.contentEl.createDiv('bw-field-row');
        row.createEl('label', { text: label, cls: 'bw-field-label' });

        const valueArea = row.createDiv('bw-field-value-area');
        const valueEl = valueArea.createEl('span', { cls: 'bw-field-value' });

        let revealed = false;
        if (masked) {
            valueEl.textContent = "•".repeat(value.length);
            const eyeBtn = valueArea.createEl('button', { cls: 'bw-icon-btn' });
            setIcon(eyeBtn, 'eye');
            eyeBtn.addEventListener('click', () => {
                revealed = !revealed;
                valueEl.textContent = revealed ? value : "•".repeat(value.length);
                setIcon(eyeBtn, revealed ? 'eye-off' : 'eye');
            });
        } else {
            valueEl.textContent = value;
        }

        if (copyable) {
            const copyBtn = valueArea.createEl('button', { cls: 'bw-icon-btn' });
            setIcon(copyBtn, 'copy');
            copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(value);
                new Notice(`${label}をコピーしました`);
            });
        }
    }

    onClose() {
        if (this._totpInterval) {
            clearInterval(this._totpInterval);
            this._totpInterval = null;
        }
        this.contentEl.empty();
    }
}

class BitwardenSettingTab extends PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display() {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.createEl('h2', { text: 'Bitwarden 設定' });

        containerEl.createEl('h3', { text: 'アカウント' });

        new Setting(containerEl)
            .setName('サーバー')
            .setDesc('利用しているBitwardenサーバー。セルフホストの場合は「セルフホスト」を選び、URLを入力してください。')
            .addDropdown(drop => drop
                .addOption('us', '米国 (bitwarden.com)')
                .addOption('eu', 'EU (bitwarden.eu)')
                .addOption('self', 'セルフホスト')
                .setValue(this.plugin.settings.region)
                .onChange(async value => {
                    this.plugin.settings.region = value;
                    await this.plugin.saveSettings();
                    this.display();
                }));

        if (this.plugin.settings.region === 'self') {
            new Setting(containerEl)
                .setName('サーバーURL')
                .setDesc('セルフホストのベースURL（例: https://vault.example.com）。/identity と /api を自動付与します。')
                .addText(text => text
                    .setPlaceholder('https://vault.example.com')
                    .setValue(this.plugin.settings.serverUrl)
                    .onChange(async value => {
                        this.plugin.settings.serverUrl = value.trim();
                        await this.plugin.saveSettings();
                    }));
        }

        new Setting(containerEl)
            .setName('メールアドレス')
            .setDesc('Bitwardenアカウントのメールアドレス。Vault復号の鍵導出に使用します。')
            .addText(text => text
                .setPlaceholder('you@example.com')
                .setValue(this.plugin.settings.email)
                .onChange(async value => {
                    this.plugin.settings.email = value.trim();
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('client_id')
            .setDesc('個人APIキーの client_id（user.xxxx 形式）。Web Vaultの「セキュリティ → キー → APIキー」で取得。')
            .addText(text => text
                .setPlaceholder('user.xxxxxxxx-xxxx-...')
                .setValue(this.plugin.settings.clientId)
                .onChange(async value => {
                    this.plugin.settings.clientId = value.trim();
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('client_secret')
            .setDesc('個人APIキーの client_secret。')
            .addText(text => {
                text.inputEl.type = 'password';
                text
                    .setPlaceholder('client_secret')
                    .setValue(this.plugin.settings.clientSecret)
                    .onChange(async value => {
                        this.plugin.settings.clientSecret = value.trim();
                        await this.plugin.saveSettings();
                    });
            });

        new Setting(containerEl)
            .setName('認証情報をクリア')
            .setDesc('保存されたセッション（アクセストークン・Vault鍵）を消去してロックします。APIキーやメールは保持されます。')
            .addButton(btn => btn
                .setButtonText('ロック / セッション消去')
                .setWarning()
                .onClick(async () => {
                    await this.plugin.lock();
                    new Notice('Bitwarden: ロックしました');
                }));

        containerEl.createEl('h3', { text: '表示' });

        new Setting(containerEl)
            .setName('コピーボタンを表示')
            .setDesc('リスト表示でユーザー名・パスワード・TOTPのクイックコピーボタンを表示します。オフにするとアイテムをクリックして詳細モーダルからコピーできます。')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.showCopyButtons)
                .onChange(async value => {
                    this.plugin.settings.showCopyButtons = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('表示モード')
            .setDesc('アイテムをタイプ別またはフォルダ別にグループ表示します。パネルのボタンからも切り替えられます。')
            .addDropdown(drop => drop
                .addOption('type', 'タイプ別')
                .addOption('folder', 'フォルダ別')
                .setValue(this.plugin.settings.viewMode)
                .onChange(async value => {
                    this.plugin.settings.viewMode = value;
                    await this.plugin.saveSettings();
                }));

        containerEl.createEl('h3', { text: 'アイコン' });

        new Setting(containerEl)
            .setName('Webサイトアイコンを表示')
            .setDesc('Vaultのログインアイテムに登録されたURIのファビコンを取得して表示します。アイコンサーバーへのリクエストが発生します。')
            .addToggle(toggle => toggle
                .setValue(this.plugin.settings.useIcons)
                .onChange(async value => {
                    this.plugin.settings.useIcons = value;
                    await this.plugin.saveSettings();
                    iconServerSetting.settingEl.style.display = value ? '' : 'none';
                }));

        const iconServerSetting = new Setting(containerEl)
            .setName('アイコンサーバー URL')
            .setDesc('Bitwarden icon server provides the delivery endpoint for website icons. If you are using website icons on a device, Bitwarden will issue requests to icons.bitwarden.net for each login in your vault that has a URI that resembles a website (for example, google.com or https://google.com, but not google or http://localhost).')
            .addText(text => text
                .setPlaceholder('https://icons.bitwarden.net')
                .setValue(this.plugin.settings.iconServer)
                .onChange(async value => {
                    this.plugin.settings.iconServer = value.trim() || 'https://icons.bitwarden.net';
                    await this.plugin.saveSettings();
                }));

        iconServerSetting.settingEl.style.display = this.plugin.settings.useIcons ? '' : 'none';
    }
}

module.exports = BitwardenPlugin;
