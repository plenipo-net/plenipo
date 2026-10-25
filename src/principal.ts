/**
 * A stable identity for the principal of an ALLOW decision, for policy engines and audit records.
 *
 * Display names are not identities: two people can share a name, and every legal-person decision has a
 * company and a representative rather than a name. The identifier is chosen, in order, from:
 *   1. legal persons: the EUID of the company, with the representative identified separately;
 *   2. a unique PID claim, when disclosed (default `personal_administrative_number`);
 *   3. the thumbprint of the PID holder key (`pid_holder_jkt`): unique, but a wallet that uses a fresh key
 *      per PID copy gives the same person several identifiers;
 *   4. a hash of every disclosed PID claim: collides only for people whose disclosed claims are all equal.
 * Natural-person identifiers are hashed with the PID issuer, so they carry no readable personal data.
 */
import { canonicalize, sha256 } from './encoding.js';
import type { Decision, LegalPersonPrincipal } from './types.js';

type AllowDecision = Extract<Decision, { decision: 'ALLOW' }>;

export const DEFAULT_PRINCIPAL_ID_CLAIMS = ['personal_administrative_number'];

export type PrincipalIdBasis = 'euid' | `claim:${string}` | 'holder_key' | 'disclosed_claims';

export interface PersonIdentity {
  id: string;
  id_basis: PrincipalIdBasis;
}

export type PrincipalIdentity =
  | ({ type: 'natural_person'; claims: Record<string, unknown> } & PersonIdentity)
  | {
      type: 'legal_person';
      id: string;
      id_basis: 'euid';
      euid: string;
      legal_name: string | null;
      role: { code: string; name: string | null; basis: string };
      representative: PersonIdentity & { claims: Record<string, unknown> };
    };

export interface PrincipalIdentityOptions {
  /** Claims, in order of preference, that identify a person uniquely. Default `['personal_administrative_number']`. */
  idClaims?: string[];
  /**
   * Throw a PrincipalIdentityError instead of falling back to the holder key or the disclosed claims when no
   * `idClaims` claim was disclosed. Use it for per-person policies that must hold across PID copies.
   */
  requireIdClaim?: boolean;
  /** Claims exported for the person (or the representative). Default given_name and family_name; `'all'` for every one. */
  principalClaims?: string[] | 'all';
}

export class PrincipalIdentityError extends Error {}

/**
 * Whether a decision was given on behalf of a legal person. Decided by `decision.representation`, which the
 * verifier sets only after checking a representation attestation, never by the shape of `principal`: a
 * natural person's PID could disclose claims named `type` or `euid`.
 */
export function isLegalPersonDecision(decision: AllowDecision): boolean {
  return decision.representation !== undefined;
}

/** Shape check of a LegalPersonPrincipal. Use `isLegalPersonDecision` to decide whether a decision is one. */
export function isLegalPersonPrincipal(p: unknown): p is LegalPersonPrincipal {
  const x = p as Record<string, unknown> | null;
  return typeof x === 'object' && x !== null && x.type === 'legal_person' && typeof x.euid === 'string';
}

function pick(claims: Record<string, unknown>, keep: string[] | 'all' | undefined): Record<string, unknown> {
  const list = keep ?? ['given_name', 'family_name'];
  if (list === 'all') return { ...claims };
  return Object.fromEntries(list.filter((k) => claims[k] !== undefined).map((k) => [k, claims[k]]));
}

function personId(issuer: string, claims: Record<string, unknown>, holderJkt: string | undefined, idClaims: string[], requireIdClaim: boolean): PersonIdentity {
  const hash = (basis: string, value: unknown) => sha256(canonicalize({ iss: issuer, basis, value }));
  for (const c of idClaims) {
    const v = claims[c];
    if ((typeof v === 'string' && v.length > 0) || typeof v === 'number') return { id: hash(`claim:${c}`, v), id_basis: `claim:${c}` };
  }
  if (requireIdClaim) throw new PrincipalIdentityError(`none of ${idClaims.join(', ')} was disclosed`);
  if (holderJkt) return { id: hash('holder_key', holderJkt), id_basis: 'holder_key' };
  let all: string;
  try {
    all = canonicalize(claims);
  } catch {
    all = JSON.stringify(Object.keys(claims).sort());
  }
  return { id: hash('disclosed_claims', all), id_basis: 'disclosed_claims' };
}

/** Identifies the principal of an ALLOW decision. */
export function principalIdentity(decision: AllowDecision, opts: PrincipalIdentityOptions = {}): PrincipalIdentity {
  const idClaims = opts.idClaims ?? DEFAULT_PRINCIPAL_ID_CLAIMS;
  const req = opts.requireIdClaim ?? false;
  const p = decision.principal;
  if (isLegalPersonDecision(decision)) {
    if (!isLegalPersonPrincipal(p)) throw new PrincipalIdentityError('a legal-person decision without a legal-person principal');
    const rep = (p.representative ?? {}) as Record<string, unknown>;
    return {
      type: 'legal_person',
      id: p.euid,
      id_basis: 'euid',
      euid: p.euid,
      legal_name: typeof p.legal_name === 'string' ? p.legal_name : null,
      role: { code: String(p.role?.code ?? ''), name: typeof p.role?.name === 'string' ? p.role.name : null, basis: String(p.role?.basis ?? '') },
      representative: { ...personId(decision.pid_issuer, rep, decision.pid_holder_jkt, idClaims, req), claims: pick(rep, opts.principalClaims) },
    };
  }
  return { type: 'natural_person', ...personId(decision.pid_issuer, p, decision.pid_holder_jkt, idClaims, req), claims: pick(p, opts.principalClaims) };
}
