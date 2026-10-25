import { compactVerify, importJWK, SignJWT, type CryptoKey, type JWK } from 'jose';
import { base64url } from './encoding.js';

/** JWS algorithms Plenipo signs with. Agents, platforms and status lists use ES256 unless configured otherwise. */
export type JwsAlg = 'ES256' | 'ES384' | 'ES512' | 'EdDSA' | 'PS256' | 'RS256';

/**
 * A key that never leaves its keystore: a cloud KMS, an HSM over PKCS#11, a mobile secure element.
 * `sign` receives the JWS signing input (ASCII `base64url(header).base64url(payload)`) and returns the
 * signature in JOSE form: for ECDSA the raw `r || s` concatenation, not DER. Most KMS and PKCS#11 APIs
 * return DER for ECDSA; wrap them with `externalSignerFromDer`.
 */
export interface ExternalSigner {
  readonly alg: JwsAlg;
  /** Optional key id, copied into the JWS header when the call site does not set one. */
  readonly kid?: string;
  /**
   * Public key of the signer. When present, every signature is verified locally before it is returned,
   * so a misconfigured key (wrong key id in the KMS, wrong curve) fails here instead of at the verifier.
   */
  readonly publicJwk?: JWK;
  sign(signingInput: Uint8Array): Promise<Uint8Array>;
}

/** Either a WebCrypto private key held in memory, or an external signer. Accepted wherever Plenipo signs. */
export type SigningKey = CryptoKey | ExternalSigner;

export function isExternalSigner(k: unknown): k is ExternalSigner {
  return typeof k === 'object' && k !== null && typeof (k as ExternalSigner).sign === 'function' && typeof (k as ExternalSigner).alg === 'string';
}

const ECDSA_SIZES: Partial<Record<JwsAlg, number>> = { ES256: 32, ES384: 48, ES512: 66 };

/**
 * Converts a DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) to the JOSE `r || s` form.
 * Strict parser: short-form or one-byte long-form lengths only, positive integers, no trailing bytes.
 */
export function ecdsaDerToJose(der: Uint8Array, alg: 'ES256' | 'ES384' | 'ES512'): Uint8Array {
  const n = ECDSA_SIZES[alg]!;
  let p = 0;
  const fail = (why: string): never => {
    throw new Error(`invalid DER ECDSA signature: ${why}`);
  };
  const readLen = (): number => {
    if (p >= der.length) fail('truncated');
    const b = der[p++];
    if (b < 0x80) return b;
    if (b !== 0x81) fail('unsupported length encoding');
    if (p >= der.length) fail('truncated');
    const l = der[p++];
    if (l < 0x80) fail('non-minimal length');
    return l;
  };
  if (der[p++] !== 0x30) fail('not a SEQUENCE');
  const seqLen = readLen();
  if (p + seqLen !== der.length) fail('length mismatch');
  const out = new Uint8Array(2 * n);
  for (let i = 0; i < 2; i++) {
    if (der[p++] !== 0x02) fail('not an INTEGER');
    const len = readLen();
    if (len === 0 || p + len > der.length) fail('bad INTEGER length');
    let v = der.subarray(p, p + len);
    p += len;
    if (v[0] & 0x80) fail('negative INTEGER');
    if (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) fail('non-minimal INTEGER');
    if (v[0] === 0) v = v.subarray(1);
    if (v.length > n) fail('INTEGER too large for the curve');
    out.set(v, i * n + (n - v.length));
  }
  if (p !== der.length) fail('trailing bytes');
  return out;
}

/** Wraps a signer that returns DER ECDSA signatures (AWS KMS, Google Cloud KMS, Azure Key Vault in DER mode, PKCS#11 wrappers). */
export function externalSignerFromDer(params: {
  alg: 'ES256' | 'ES384' | 'ES512';
  kid?: string;
  publicJwk?: JWK;
  signDer: (signingInput: Uint8Array) => Promise<Uint8Array>;
}): ExternalSigner {
  return {
    alg: params.alg,
    kid: params.kid,
    publicJwk: params.publicJwk,
    sign: async (input) => ecdsaDerToJose(await params.signDer(input), params.alg),
  };
}

const enc = new TextEncoder();

/**
 * Signs a compact JWS with either kind of key. The header must name the algorithm; with an external
 * signer it must equal the signer's `alg`, so a call site that expects ES256 never emits something else.
 */
export async function signCompactJwt(
  payload: Record<string, unknown>,
  header: Record<string, unknown> & { alg: string },
  key: SigningKey,
): Promise<string> {
  if (!isExternalSigner(key)) {
    return new SignJWT(payload).setProtectedHeader(header as never).sign(key);
  }
  if (header.alg !== key.alg) throw new Error(`signer algorithm ${key.alg} does not match the required ${header.alg}`);
  const h = key.kid && header.kid === undefined ? { ...header, kid: key.kid } : header;
  const signingInput = `${base64url(JSON.stringify(h))}.${base64url(JSON.stringify(payload))}`;
  const sig = await key.sign(enc.encode(signingInput));
  if (!(sig instanceof Uint8Array)) throw new Error('external signer returned no signature');
  const n = ECDSA_SIZES[key.alg];
  if (n !== undefined && sig.length !== 2 * n) {
    throw new Error(`external signer returned ${sig.length} bytes; ${key.alg} needs ${2 * n} (JOSE r||s, not DER)`);
  }
  const jws = `${signingInput}.${base64url(sig)}`;
  if (key.publicJwk) {
    try {
      await compactVerify(jws, await importJWK(key.publicJwk, key.alg), { algorithms: [key.alg] });
    } catch {
      throw new Error('external signer produced a signature that does not verify against its public key');
    }
  }
  return jws;
}
