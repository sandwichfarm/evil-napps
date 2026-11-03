// Minimal, dependency-free BIP340 (schnorr) over secp256k1 + nostr event ids.
// Used by tools/make-evil09-fixtures.mjs to produce REAL signed kind 35130
// manifest fixtures, and by tests/evil-09.spec.mjs to verify them — so the
// rung's core claim ("a relay withholding the newest version serves a valid,
// signed, older one") is machine-checked, never asserted.
//
// Affine point math on BigInt: slow, but these are one-off fixture
// generations and spec-time verifications of three events.
import { createHash } from 'node:crypto';

export const P = 2n ** 256n - 2n ** 32n - 977n;
export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

const mod = (a, m) => ((a % m) + m) % m;

function powmod(base, exp, m) {
  let r = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

const invert = (a, m) => powmod(a, m - 2n, m); // P and N are prime

// affine points, null = point at infinity
function ptAdd(p, q) {
  if (!p) return q;
  if (!q) return p;
  const [x1, y1] = p;
  const [x2, y2] = q;
  if (x1 === x2) {
    if (mod(y1 + y2, P) === 0n) return null;
    const l = mod(3n * x1 * x1 * invert(2n * y1, P), P);
    const x3 = mod(l * l - 2n * x1, P);
    return [x3, mod(l * (x1 - x3) - y1, P)];
  }
  const l = mod((y2 - y1) * invert(x2 - x1, P), P);
  const x3 = mod(l * l - x1 - x2, P);
  return [x3, mod(l * (x1 - x3) - y1, P)];
}

function ptMul(k, p) {
  let r = null;
  let a = p;
  let kk = mod(k, N);
  while (kk > 0n) {
    if (kk & 1n) r = ptAdd(r, a);
    a = ptAdd(a, a);
    kk >>= 1n;
  }
  return r;
}

export function taggedHash(tag, ...msgs) {
  const t = createHash('sha256').update(tag).digest();
  const h = createHash('sha256');
  h.update(t);
  h.update(t);
  for (const m of msgs) h.update(m);
  return h.digest();
}

// x-only pubkey (BIP340 even-y convention): negates the secret when the
// public point's y is odd, so the x coordinate IS the pubkey.
export function pubkeyFromSecret(secret) {
  let d = mod(secret, N);
  if (d === 0n) throw new Error('zero secret key');
  const pt = ptMul(d, [Gx, Gy]);
  if (pt[1] % 2n !== 0n) d = N - d;
  return { d, pubHex: pt[0].toString(16).padStart(64, '0') };
}

// Deterministic signing (zero aux randomness) so rebuilds reproduce byte-
// identical fixtures. BIP340 nonce: t = d XOR taggedHash(aux) with aux = 0^32.
export function schnorrSign(msg32, secret) {
  const { d, pubHex } = pubkeyFromSecret(secret);
  const t = BigInt('0x' + taggedHash('BIP0340/aux', Buffer.alloc(32)).toString('hex')) ^ d;
  const tBuf = Buffer.from(mod(t, 2n ** 256n).toString(16).padStart(64, '0'), 'hex');
  const px = Buffer.from(pubHex, 'hex');
  const rand = taggedHash('BIP0340/nonce', tBuf, px, msg32);
  let k = BigInt('0x' + rand.toString('hex')) % N;
  if (k === 0n) throw new Error('zero nonce (hash collision — retry with a new key)');
  const R = ptMul(k, [Gx, Gy]);
  if (R[1] % 2n !== 0n) k = N - k; // R must be even-y; rx is unchanged
  const rx = Buffer.from(R[0].toString(16).padStart(64, '0'), 'hex');
  const e = BigInt('0x' + taggedHash('BIP0340/challenge', rx, px, msg32).toString('hex')) % N;
  const s = mod(k + e * d, N);
  return rx.toString('hex').padStart(64, '0') + s.toString(16).padStart(64, '0');
}

export function schnorrVerify(msg32, pubHex, sigHex) {
  if (!/^[0-9a-f]{64}$/.test(pubHex) || !/^[0-9a-f]{128}$/.test(sigHex)) return false;
  const r = BigInt('0x' + sigHex.slice(0, 64));
  const s = BigInt('0x' + sigHex.slice(64));
  const px = BigInt('0x' + pubHex);
  if (r >= P || s >= N || px >= P) return false;
  // the even-y point for this x must exist: y² = x³ + 7 (P ≡ 3 mod 4)
  const y2 = mod(px * px * px + 7n, P);
  const y = powmod(y2, (P + 1n) / 4n, P);
  if (mod(y * y, P) !== y2) return false;
  const Py = y % 2n === 0n ? y : P - y;
  const e = BigInt('0x' + taggedHash(
    'BIP0340/challenge',
    Buffer.from(sigHex.slice(0, 64), 'hex'),
    Buffer.from(pubHex, 'hex'),
    msg32
  ).toString('hex')) % N;
  const R = ptAdd(ptMul(s, [Gx, Gy]), ptMul(mod(N - e, N), [px, Py]));
  return !!R && R[0] === r && R[1] % 2n === 0n;
}

// nostr: the event id is sha256 over [0, pubkey, created_at, kind, tags, content]
export function eventId(ev) {
  const serialized = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
  return createHash('sha256').update(serialized).digest('hex');
}

export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}
