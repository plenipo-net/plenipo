/**
 * Sub-delegations in the Delegate SD-JWT format (draft-gco-oauth-delegate-sd-jwt-00), in a strict
 * Plenipo profile. See docs/delegation.md for the wire format, the deviations from the draft and why
 * selective disclosure is refused inside a delegation.
 */
import { signCompactJwt, type SigningKey } from './signer.js';
import { randomBytes } from 'node:crypto';
import {
  calculateJwkThumbprint,
  compactVerify,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  type JWK,
} from 'jose';
import { base64url, canonicalize, fromBase64url, sha256 } from './encoding.js';
import type { DelegationPayload, Mandate } from './types.js';

/** `typ` of a KB-SD-JWT+KB as registered in the draft's IANA section (A.2) and used in its section 5.1.4. */
export const DELEGATE_SDJWT_TYP = 'kb+sd-jwt+kb';
/** Spelling used in the draft's section 6. Accepted on input, never emitted. */
const DELEGATE_SDJWT_TYP_ALT = 'kb-sd-jwt+kb';
/** Claim of the Delegate Payload that carries the child mandate, as a visible claim (draft section 8.2). */
export const PLENIPO_MANDATE_CLAIM = 'plenipo_mandate';
/** OpenID4VP transaction data type defined in the draft's section 7.1. */
export const DELEGATE_TX_DATA_TYPE = 'delegate';

/** Upper bound on an SD-JWT delegation, checked before any parsing. A mandate is a few hundred bytes. */
export const MAX_DELEGATION_LENGTH = 64 * 1024;
/** Upper bound on JSON nesting inside a Delegate Payload; a mandate needs four levels. */
const MAX_JSON_DEPTH = 16;

const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const OUTER_CLAIMS = new Set(['iat', '_sd_alg', 'delegate_payload']);
const DELEGATE_PAYLOAD_CLAIMS = new Set(['cnf', PLENIPO_MANDATE_CLAIM, 'parent_id', 'parent_hash', 'nbf', 'exp']);
/** Keys that make a JSON object selectively disclosable under RFC 9901. None may appear in a delegation. */
const SD_MARKERS = new Set(['_sd', '_sd_alg', '...']);

export type DelegationFormat = 'jws' | 'sd-jwt';

/**
 * Raised when an SD-JWT delegation fails. The code is the DenyCode the verifier reports; `message`
 * is safe to return to a caller, `detail` may contain library messages and is for logs only.
 */
export class DelegationError extends Error {
  constructor(
    readonly code: 'DELEGATION_SIGNATURE_INVALID' | 'MALFORMED',
    message: string,
    readonly detail?: string,
  ) {
    super(message);
  }
}

/** A delegation decoded without verification. */
export interface ParsedDelegation {
  format: DelegationFormat;
  header: Record<string, unknown>;
  /** The delegation in the common shape, whatever the wire format. Unverified. */
  payload: DelegationPayload;
  /** Present for the SD-JWT format: the key the Delegate Payload binds. */
  cnf?: unknown;
}

/** True when the token uses the Delegate SD-JWT serialization. A compact JWS never contains `~`. */
export function isSdJwtDelegation(token: unknown): token is string {
  return typeof token === 'string' && token.includes('~');
}

interface SplitToken {
  jwt: string;
  disclosure: string;
}

function split(token: string): SplitToken {
  if (token.length > MAX_DELEGATION_LENGTH) {
    throw new DelegationError('MALFORMED', `SD-JWT delegation longer than ${MAX_DELEGATION_LENGTH} characters`);
  }
  const parts = token.split('~');
  // Exactly `<KB-SD-JWT>~<Delegate Payload Disclosure>~`: one disclosure, the trailing `~`, no key binding JWT.
  if (parts.length !== 3 || parts[2] !== '' || parts[0] === '' || parts[1] === '') {
    throw new DelegationError('MALFORMED', 'SD-JWT delegation must be <KB-SD-JWT>~<Delegate Payload Disclosure>~');
  }
  return { jwt: parts[0], disclosure: parts[1] };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function normalizeTyp(typ: unknown): string | undefined {
  if (typeof typ !== 'string') return undefined;
  const t = typ.toLowerCase();
  return t.startsWith('application/') ? t.slice('application/'.length) : t;
}

interface OuterPayload {
  iat: number;
  digest: string;
}

/** Validates the signed part: only the claims this profile defines, one delegate payload digest, SHA-256. */
function checkOuter(payload: unknown): OuterPayload {
  if (!isPlainObject(payload)) throw new DelegationError('MALFORMED', 'KB-SD-JWT payload is not an object');
  for (const k of Object.keys(payload)) {
    if (!OUTER_CLAIMS.has(k)) throw new DelegationError('MALFORMED', `KB-SD-JWT claim ${k} is not allowed in a Plenipo delegation`);
  }
  if (!Number.isInteger(payload.iat)) throw new DelegationError('MALFORMED', 'KB-SD-JWT iat must be an integer');
  if (payload._sd_alg !== undefined && payload._sd_alg !== 'sha-256') {
    throw new DelegationError('MALFORMED', 'only sha-256 is supported as _sd_alg');
  }
  const dp = payload.delegate_payload;
  if (!Array.isArray(dp) || dp.length !== 1) {
    throw new DelegationError('MALFORMED', 'delegate_payload must contain exactly one element');
  }
  const el = dp[0];
  if (!isPlainObject(el) || Object.keys(el).length !== 1 || typeof el['...'] !== 'string' || !B64URL_RE.test(el['...'])) {
    throw new DelegationError('MALFORMED', 'delegate_payload element must be {"...": "<digest>"}');
  }
  return { iat: payload.iat as number, digest: el['...'] };
}

/** Decodes the Delegate Payload Disclosure, `[salt, payload]`, which must be canonical JSON (RFC 8785). */
function decodeDisclosure(disclosure: string): Record<string, unknown> {
  if (!B64URL_RE.test(disclosure)) throw new DelegationError('MALFORMED', 'Delegate Payload Disclosure is not base64url');
  let parsed: unknown;
  let json: string;
  try {
    json = fromBase64url(disclosure);
    parsed = JSON.parse(json);
  } catch {
    throw new DelegationError('MALFORMED', 'Delegate Payload Disclosure is not JSON');
  }
  // Canonical form rules out duplicate keys and other inputs that two parsers could read differently.
  let canonical: string | undefined;
  try {
    canonical = canonicalize(parsed);
  } catch {
    canonical = undefined;
  }
  if (canonical !== json) throw new DelegationError('MALFORMED', 'Delegate Payload Disclosure must be canonical JSON (RFC 8785)');
  if (!Array.isArray(parsed) || parsed.length !== 2 || typeof parsed[0] !== 'string' || parsed[0].length === 0) {
    throw new DelegationError('MALFORMED', 'Delegate Payload Disclosure must be [salt, payload]');
  }
  if (!isPlainObject(parsed[1])) throw new DelegationError('MALFORMED', 'Delegate Payload is not an object');
  return parsed[1];
}

/**
 * Finds anything selective disclosure could hide behind. A digest the verifier cannot see could stand for
 * a constraint, and a verifier that ignores it would read a wider mandate than the delegator signed.
 */
function sdMarker(value: unknown): string | undefined {
  const stack: Array<{ v: unknown; depth: number }> = [{ v: value, depth: 0 }];
  while (stack.length) {
    const { v, depth } = stack.pop()!;
    if (depth > MAX_JSON_DEPTH) return 'nesting is too deep';
    if (Array.isArray(v)) {
      for (const x of v) stack.push({ v: x, depth: depth + 1 });
    } else if (isPlainObject(v)) {
      for (const [k, x] of Object.entries(v)) {
        if (SD_MARKERS.has(k)) return `selectively disclosable claim marker ${k}`;
        stack.push({ v: x, depth: depth + 1 });
      }
    }
  }
  return undefined;
}

/** Validates the Delegate Payload and returns the delegation in the shape the verifier uses for JWS. */
async function checkDelegatePayload(dp: Record<string, unknown>, iat: number): Promise<DelegationPayload> {
  const marker = sdMarker(dp);
  if (marker) throw new DelegationError('MALFORMED', `every constraint must be plainly visible: ${marker}`);
  for (const k of Object.keys(dp)) {
    if (!DELEGATE_PAYLOAD_CLAIMS.has(k)) {
      throw new DelegationError('MALFORMED', `Delegate Payload claim ${k} has no meaning in a Plenipo delegation`);
    }
  }

  const mandate = dp[PLENIPO_MANDATE_CLAIM];
  if (!isPlainObject(mandate)) throw new DelegationError('MALFORMED', `Delegate Payload has no ${PLENIPO_MANDATE_CLAIM} object`);
  const m = mandate as Partial<Mandate>;

  // The key bound by the delegation is the key the child mandate names; anything else is ambiguous.
  const cnf = dp.cnf;
  if (!isPlainObject(cnf) || Object.keys(cnf).length !== 1 || !isPlainObject(cnf.jwk)) {
    throw new DelegationError('MALFORMED', 'Delegate Payload cnf must be { jwk }');
  }
  if ('d' in cnf.jwk) throw new DelegationError('MALFORMED', 'cnf.jwk contains a private key');
  if (!isPlainObject(m.agent) || !isPlainObject(m.agent.jwk)) {
    throw new DelegationError('MALFORMED', 'child mandate has no agent.jwk');
  }
  let same = false;
  try {
    same = (await calculateJwkThumbprint(cnf.jwk as JWK)) === (await calculateJwkThumbprint(m.agent.jwk as JWK));
  } catch {
    same = false;
  }
  if (!same) throw new DelegationError('MALFORMED', 'cnf.jwk differs from the child mandate agent.jwk');

  // nbf and exp are mirrored for verifiers that only know the draft; they must say what the mandate says.
  if (dp.nbf !== m.nbf || dp.exp !== m.exp) {
    throw new DelegationError('MALFORMED', 'Delegate Payload nbf and exp must equal the child mandate nbf and exp');
  }
  return {
    mandate: mandate as unknown as Mandate,
    parent_id: dp.parent_id as string,
    parent_hash: dp.parent_hash as string,
    iat,
  };
}

/**
 * Verifies an SD-JWT delegation against the parent agent key and returns its payload. It checks the
 * signature, the disclosure digest and the profile; parent binding, attenuation and depth are left to
 * `verifyAuthorization`, exactly as for JWS delegations. Throws DelegationError.
 */
export async function verifyDelegateSdJwt(token: string, parentAgentJwk: JWK): Promise<DelegationPayload> {
  if (typeof token !== 'string') throw new DelegationError('MALFORMED', 'delegation must be a string');
  const { jwt, disclosure } = split(token);

  let header: Record<string, unknown>;
  let outerRaw: unknown;
  try {
    const key = await importJWK(parentAgentJwk, 'ES256');
    const res = await compactVerify(jwt, key, { algorithms: ['ES256'] });
    header = res.protectedHeader as Record<string, unknown>;
    outerRaw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(res.payload));
  } catch (e) {
    throw new DelegationError('DELEGATION_SIGNATURE_INVALID', 'not signed by the parent agent', (e as Error).message);
  }
  // Unencoded payloads (RFC 7797) and other critical extensions have no place in a delegation.
  if (header.crit !== undefined || header.b64 !== undefined) {
    throw new DelegationError('DELEGATION_SIGNATURE_INVALID', 'KB-SD-JWT header must not use crit or b64');
  }
  const typ = normalizeTyp(header.typ);
  if (typ !== DELEGATE_SDJWT_TYP && typ !== DELEGATE_SDJWT_TYP_ALT) {
    throw new DelegationError('DELEGATION_SIGNATURE_INVALID', `KB-SD-JWT typ must be ${DELEGATE_SDJWT_TYP}`);
  }
  const outer = checkOuter(outerRaw);
  // The disclosure is not covered by the signature; its digest is.
  if (sha256(disclosure) !== outer.digest) {
    throw new DelegationError('DELEGATION_SIGNATURE_INVALID', 'Delegate Payload Disclosure does not match the signed digest');
  }
  return checkDelegatePayload(decodeDisclosure(disclosure), outer.iat);
}

/**
 * Detects the format of a delegation and decodes it WITHOUT verifying it, for logging and routing.
 * Never base an authorization decision on the result. Throws on input that cannot be decoded.
 */
export function parseDelegation(token: string): ParsedDelegation {
  if (typeof token !== 'string' || token.length === 0) throw new Error('delegation must be a non-empty string');
  if (!isSdJwtDelegation(token)) {
    const header = decodeProtectedHeader(token) as Record<string, unknown>;
    return { format: 'jws', header, payload: decodeJwt(token) as unknown as DelegationPayload };
  }
  const { jwt, disclosure } = split(token);
  const header = decodeProtectedHeader(jwt) as Record<string, unknown>;
  const outer = checkOuter(decodeJwt(jwt));
  if (sha256(disclosure) !== outer.digest) throw new Error('Delegate Payload Disclosure does not match the digest');
  const dp = decodeDisclosure(disclosure);
  return {
    format: 'sd-jwt',
    header,
    payload: {
      mandate: dp[PLENIPO_MANDATE_CLAIM] as Mandate,
      parent_id: dp.parent_id as string,
      parent_hash: dp.parent_hash as string,
      iat: outer.iat,
    },
    cnf: dp.cnf,
  };
}

function salt(): string {
  return randomBytes(16).toString('base64url');
}

/** `[salt, payload]` as canonical JSON in base64url, so the verifier's canonical check passes. */
function makeDisclosure(payload: Record<string, unknown>): string {
  return base64url(canonicalize([salt(), payload]));
}

/**
 * Signs a delegation payload as a Delegate SD-JWT without any authority check. Callers must have
 * validated the child against the parent; `delegateMandateSdJwt` does that and is the public entry point.
 */
export async function issueDelegateSdJwt(payload: DelegationPayload, parentAgentKey: SigningKey): Promise<string> {
  const child = payload.mandate;
  const delegatePayload: Record<string, unknown> = {
    cnf: { jwk: child.agent.jwk },
    [PLENIPO_MANDATE_CLAIM]: child,
    parent_id: payload.parent_id,
    parent_hash: payload.parent_hash,
    nbf: child.nbf,
    exp: child.exp,
  };
  const disclosure = makeDisclosure(delegatePayload);
  const jwt = await signCompactJwt(
    { iat: payload.iat, _sd_alg: 'sha-256', delegate_payload: [{ '...': sha256(disclosure) }] },
    { alg: 'ES256', typ: DELEGATE_SDJWT_TYP },
    parentAgentKey,
  );
  return `${jwt}~${disclosure}~`;
}

/** The OpenID4VP transaction data object of type `delegate` (draft section 7.1). */
export interface DelegateTransactionData {
  type: typeof DELEGATE_TX_DATA_TYPE;
  credential_ids: string[];
  format: 'dSD-JWT' | 'dSD-JWT+KB';
  /** Array Disclosure `[salt, Delegate Payload]`, base64url. */
  delegate_payload_disclosure: string;
  /** Disclosures of selectively disclosable claims inside the Delegate Payload. */
  delegate_disclosures?: string[];
}

export interface DelegateTransactionDataInput {
  /** DCQL credential query ids the delegation applies to. */
  credentialIds: string[];
  /** Claims of the Delegate Payload the wallet is asked to issue. */
  delegatePayload: Record<string, unknown>;
  /** Default `dSD-JWT+KB`: the delegate holds a key and proves possession. */
  format?: 'dSD-JWT' | 'dSD-JWT+KB';
  delegateDisclosures?: string[];
}

/**
 * Builds the `delegate` transaction data of draft section 7.1, for a verifier that asks a wallet to issue
 * a delegation inside an OpenID4VP presentation. Helper only: Plenipo roots still use `plenipo_mandate`.
 * Returns the object, its base64url encoding for the request, and the digest the wallet is expected to
 * put in the `delegate_payload` claim of its KB-SD-JWT.
 */
export function createDelegateTransactionData(input: DelegateTransactionDataInput): {
  transactionData: DelegateTransactionData;
  encoded: string;
  delegatePayloadDigest: string;
} {
  const ids = input.credentialIds;
  if (!Array.isArray(ids) || ids.length === 0 || ids.some((c) => typeof c !== 'string' || c.length === 0)) {
    throw new Error('credentialIds must be a non-empty array of strings');
  }
  if (!isPlainObject(input.delegatePayload)) throw new Error('delegatePayload must be an object');
  const format = input.format ?? 'dSD-JWT+KB';
  if (format !== 'dSD-JWT' && format !== 'dSD-JWT+KB') throw new Error('format must be dSD-JWT or dSD-JWT+KB');
  if (format === 'dSD-JWT+KB' && !isPlainObject(input.delegatePayload.cnf)) {
    throw new Error('a dSD-JWT+KB Delegate Payload needs a cnf claim');
  }
  const extra = input.delegateDisclosures;
  if (extra !== undefined && (!Array.isArray(extra) || extra.some((d) => typeof d !== 'string' || !B64URL_RE.test(d)))) {
    throw new Error('delegateDisclosures must be base64url strings');
  }
  const disclosure = makeDisclosure(input.delegatePayload);
  const transactionData: DelegateTransactionData = {
    type: DELEGATE_TX_DATA_TYPE,
    credential_ids: [...ids],
    format,
    delegate_payload_disclosure: disclosure,
    ...(extra?.length ? { delegate_disclosures: [...extra] } : {}),
  };
  return { transactionData, encoded: base64url(canonicalize(transactionData)), delegatePayloadDigest: sha256(disclosure) };
}
