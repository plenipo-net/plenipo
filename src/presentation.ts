/**
 * Verification of an SD-JWT VC presentation other than the PID, presented in the same wallet response:
 * the SCA attestation a TS12 e-mandate is bound to, or a representation attestation for a legal person.
 */
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest } from '@sd-jwt/crypto-nodejs';
import { decodeJwt, decodeProtectedHeader, type JWK } from 'jose';
import { fromBase64url } from './encoding.js';
import { isStatusReference, type StatusReference } from './status.js';
import { resolveSigningKey, TrustError, type TrustConfig } from './trust.js';

export class PresentationError extends Error {
  constructor(
    readonly kind: 'untrusted' | 'invalid',
    message: string,
    readonly detail?: string,
  ) {
    super(message);
  }
}

export interface VerifiedPresentation {
  /** Disclosed claims, including technical ones (iss, vct, cnf, status...). */
  payload: Record<string, unknown>;
  iss: string;
  trustedVia: 'issuer' | 'x5c';
  holderJwk: JWK;
  /** Key binding JWT claims. */
  kb: Record<string, unknown>;
  status?: StatusReference;
  /**
   * The issuer-signed JWT payload before any disclosure is applied: what the issuer put in plain text,
   * with `_sd` digests where it made claims selectively disclosable. Restrictions are read from here.
   */
  signedPayload: Record<string, unknown>;
  /**
   * The validated certificate path of the issuer (leaf first, ending with the anchor) when trusted via x5c.
   * Its revocation is checked by the caller, after the cheaper checks (`checkAttestationCertificates`).
   */
  certificateChain?: string[];
}

/**
 * Claims SD-JWT VC forbids issuers to make selectively disclosable. A credential that discloses one of them
 * comes from a non-compliant issuer, and its holder could equally have withheld it (status, exp): refuse it.
 */
export const PROTECTED_CLAIMS = new Set(['iss', 'nbf', 'exp', 'iat', 'cnf', 'vct', 'vct#integrity', 'status']);

/**
 * Names of the object-property disclosures in an SD-JWT presentation (`salt~name~value` arrays), at any
 * depth: nested disclosures are listed in the same sequence. Throws on an unreadable disclosure.
 */
export function disclosureNames(presentation: string): string[] {
  const parts = presentation.split('~');
  const names: string[] = [];
  // parts[0] is the issuer JWT, the last part the key binding JWT (or empty).
  for (const d of parts.slice(1, -1)) {
    if (d.length === 0) continue;
    const decoded = JSON.parse(fromBase64url(d));
    if (!Array.isArray(decoded)) throw new Error('a disclosure is not an array');
    if (decoded.length === 3) names.push(String(decoded[1]));
  }
  return names;
}

/** Returns the protected claim names a presentation discloses, or throws if a disclosure cannot be read. */
export function disclosedProtectedClaims(presentation: string): string[] {
  return disclosureNames(presentation).filter((n) => PROTECTED_CLAIMS.has(n));
}

/** True when an issuer-signed value contains selective disclosure digests (`_sd` or `{"...": digest}`), at any depth. */
export function hasDigests(value: unknown, depth = 0): boolean {
  if (depth > 32) return true;
  if (Array.isArray(value)) {
    return value.some((v) => (typeof v === 'object' && v !== null && !Array.isArray(v) && '...' in v) || hasDigests(v, depth + 1));
  }
  if (typeof value === 'object' && value !== null) {
    if ('_sd' in value) return true;
    return Object.values(value).some((v) => hasDigests(v, depth + 1));
  }
  return false;
}

const MAX_PRESENTATION = 64 * 1024;

/**
 * Verifies issuer signature (under `trust`, for the identity named by the credential's `iss`, as for the
 * PID), validity times, accepted `vct`, and a key binding JWT signed by the `cnf` key for exactly `nonce`
 * and `aud`: the same request as the PID presentation it accompanies.
 */
export async function verifyAttestationPresentation(
  presentation: unknown,
  opts: { label: string; trust: TrustConfig; acceptedVcts: string[]; nonce: string; aud: unknown; now: number; skewSeconds?: number },
): Promise<VerifiedPresentation> {
  const { label } = opts;
  if (typeof presentation !== 'string' || presentation.length === 0 || presentation.length > MAX_PRESENTATION) {
    throw new PresentationError('invalid', `${label} presentation is missing or too large`);
  }
  if (!opts.trust?.trustedIssuers?.length && !opts.trust?.trustAnchors?.length) {
    throw new PresentationError('untrusted', `no trust is configured for the ${label}`);
  }
  const parts = presentation.split('~');
  let header: Record<string, unknown>;
  let iss: unknown;
  let kbNonce: unknown;
  let protectedDisclosed: string[];
  try {
    header = decodeProtectedHeader(parts[0]) as Record<string, unknown>;
    iss = decodeJwt(parts[0]).iss;
    kbNonce = decodeJwt(parts[parts.length - 1]).nonce;
    protectedDisclosed = disclosedProtectedClaims(presentation);
  } catch {
    throw new PresentationError('invalid', `${label} is not an SD-JWT presentation with key binding`);
  }
  if (protectedDisclosed.length) {
    throw new PresentationError('invalid', `the ${label} makes ${protectedDisclosed.join(', ')} selectively disclosable, which SD-JWT VC forbids`);
  }
  if (typeof iss !== 'string' || iss.length === 0) throw new PresentationError('invalid', `the ${label} has no iss`);
  // Checked before the signature work: the presentation must answer this very request.
  if (kbNonce !== opts.nonce) throw new PresentationError('invalid', `the ${label} was not presented for this request`);

  let key;
  try {
    // Certificate revocation needs the network: it is checked later, on the chain returned here.
    key = resolveSigningKey(header, iss, { ...opts.trust, certificateRevocation: undefined }, opts.now);
  } catch (e) {
    if (e instanceof TrustError) throw new PresentationError('untrusted', `${label} issuer not trusted`, e.message);
    throw e;
  }

  const sdjwt = new SDJwtVcInstance({
    hasher: digest,
    hashAlg: 'sha-256',
    verifier: await ES256.getVerifier(key.jwk),
    kbVerifier: async (data: string, sig: string, payload: Record<string, any>) => {
      const jwk = payload?.cnf?.jwk;
      if (!jwk) return false;
      return (await ES256.getVerifier(jwk))(data, sig);
    },
  });
  let verified: Awaited<ReturnType<typeof sdjwt.verify>>;
  try {
    verified = await sdjwt.verify(presentation, {
      keyBindingNonce: opts.nonce,
      currentDate: opts.now,
      skewSeconds: opts.skewSeconds ?? 60,
      allowedIssuerAlgorithms: ['ES256'],
      allowedKeyBindingAlgorithms: ['ES256'],
      disableStatusVerification: true,
    });
  } catch (e) {
    throw new PresentationError('invalid', `${label} presentation does not verify`, (e as Error).message);
  }
  if (!verified.kb) throw new PresentationError('invalid', `${label} presentation has no key binding JWT`);
  const payload = verified.payload as Record<string, unknown>;
  const kb = verified.kb.payload as Record<string, unknown>;
  if (kb.aud !== opts.aud) throw new PresentationError('invalid', `the ${label} was presented to another audience`);
  if (!opts.acceptedVcts.includes(String(payload.vct))) {
    throw new PresentationError('invalid', `credential type ${String(payload.vct)} is not an accepted ${label} type`);
  }
  const cnf = payload.cnf as { jwk?: JWK } | undefined;
  if (!cnf?.jwk || typeof cnf.jwk !== 'object') throw new PresentationError('invalid', `the ${label} has no holder key`);
  // status and exp are read only from the issuer-signed plain text: a withheld digest cannot be told from an
  // absent claim, so a claim the verifier relies on must be in clear (disclosed ones are refused above).
  const signedPayload = decodeJwt(parts[0]) as Record<string, unknown>;
  if (typeof signedPayload.exp !== 'number') throw new PresentationError('invalid', `the ${label} has no exp`);
  let status: StatusReference | undefined;
  if (signedPayload.status !== undefined) {
    if (!isStatusReference(signedPayload.status)) throw new PresentationError('invalid', `${label} status reference is malformed`);
    status = signedPayload.status;
  }
  return {
    payload,
    iss,
    trustedVia: key.via,
    holderJwk: cnf.jwk,
    kb,
    status,
    signedPayload,
    ...(key.chain ? { certificateChain: key.chain } : {}),
  };
}
