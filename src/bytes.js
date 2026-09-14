// Byte helpers and a SHA-256, so the library runs wherever JavaScript does.
//
// The offline half of Lastmile belongs in a browser as much as a server: the
// phone that signs a voucher with no signal is the whole point. Node's `Buffer`
// and `node:crypto` are not there, and asking every caller to bundle a polyfill
// for two small jobs is worse than doing the two small jobs here.

/** @param {...Uint8Array} parts */
export function concat(...parts) {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export const utf8 = (s) => new TextEncoder().encode(s);

export const toHex = (u8) =>
  Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

export function fromHex(s) {
  if (typeof s !== 'string' || !/^[0-9a-fA-F]*$/.test(s) || s.length % 2) {
    throw new TypeError('expected an even-length hex string');
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

// base64url, via the one base64 codec every runtime agrees on.
export function toBase64Url(u8) {
  let s = '';
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new TypeError('expected a base64url string');
  }
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// ---- big-endian 64-bit, because the wire format is fixed-width ----

export function writeU64BE(out, at, v) {
  let x = BigInt(v);
  for (let i = 7; i >= 0; i--) {
    out[at + i] = Number(x & 0xffn);
    x >>= 8n;
  }
}

export function readU64BE(u8, at) {
  let x = 0n;
  for (let i = 0; i < 8; i++) x = (x << 8n) | BigInt(u8[at + i]);
  return x;
}

/** Two's complement, so a negative amount round-trips instead of wrapping. */
export function writeI64BE(out, at, v) {
  const x = BigInt(v);
  writeU64BE(out, at, x < 0n ? x + (1n << 64n) : x);
}

export function readI64BE(u8, at) {
  const x = readU64BE(u8, at);
  return x >= 1n << 63n ? x - (1n << 64n) : x;
}

// ---- SHA-256 ----
//
// The contract hashes the payload on chain; a signer with no network has to get
// the same 32 bytes or nothing verifies. Small, synchronous and self-contained
// beats an async import that changes this library's shape.

const K = Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

export function sha256(msg) {
  const len = msg.length;
  const withPad = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  withPad.set(msg);
  withPad[len] = 0x80;
  new DataView(withPad.buffer).setUint32(withPad.length - 4, len << 3, false);
  new DataView(withPad.buffer).setUint32(withPad.length - 8, Math.floor(len / 0x20000000), false);

  const h = Int32Array.from([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Int32Array(64);
  const view = new DataView(withPad.buffer);

  for (let off = 0; off < withPad.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getInt32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15];
      const b = w[i - 2];
      const s0 = rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3);
      const s1 = rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
  }

  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setInt32(i * 4, h[i], false);
  return out;
}
