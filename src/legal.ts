/**
 * Experimental: mandates given on behalf of a legal person.
 *
 * A natural person approves the mandate in their wallet with their PID and also presents a representation
 * attestation, issued by a register the relying party trusts, stating that they hold a role for the legal
 * person with a given EUID and what that role empowers them to do. The verifier checks the attestation
 * (issuer, status, validity, holder) and that the mandate stays within the role's powers, so an agent can
 * never receive more authority than the representative holds (Council general approach on the European
 * Business Wallet, art. 6(2)(b): over-delegation and expired authorisations detected in real time).
 *
 * The attestation format `urn:plenipo:representation:1` is defined by Plenipo, not by a register; see
 * docs/root.md. The vct is configurable so that a real format can be mapped later.
 */
import { calculateJwkThumbprint, type JWK } from 'jose';
import { canonicalize } from './encoding.js';
import { createMandate, type MandateInput } from './mandate.js';
import { hasDigests, type VerifiedPresentation } from './presentation.js';
import { anyActionCovers, hostCovers, MAX_DEPTH, type PolicyOptions } from './scope.js';
import type { StatusReference } from './status.js';
import type { TrustConfig } from './trust.js';
import {
  REPRESENTATION_VCT,
  type LegalPersonPrincipal,
  type LegalPrincipal,
  type Limits,
  type Mandate,
  type RepresentationInfo,
} from './types.js';

export const REPRESENTATION_QUERY_ID = 'representation';

export type RoleBasis = 'legal_representation' | 'power_of_attorney';
const BASES: RoleBasis[] = ['legal_representation', 'power_of_attorney'];

/**
 * Claims of a `urn:plenipo:representation:1` attestation, besides iss, iat, nbf, exp, vct, cnf and status.
 * The legal person claims reuse the LPID names of EWC RFC005.
 */
export interface RepresentationClaims {
  /** EUID of the legal person. */
  legal_person_id: string;
  /** Registered name of the legal person. */
  legal_person_name?: string;
  /** Identity of the natural person, for relying parties that bind by claims instead of by holder key. */
  representative?: Record<string, unknown>;
  role: {
    code: string;
    name?: string;
    /**
     * Where the power comes from: the law or the statutes (e.g. a director), or a power of attorney the legal
     * person granted. Technical roles in a Business Wallet (EBW authorisations, art. 3(19), recital 18) are
     * not powers of representation and are not accepted.
     */
    basis: RoleBasis;
    valid_from?: number;
    valid_until?: number;
  };
  powers: {
    actions: string[];
    counterparties?: string[];
    limits?: Limits;
    /** Maximum sub-delegation depth a mandate given in this role may allow. Absent means no limit beyond Plenipo's. */
    max_delegation_depth?: number;
  };
}

export interface RepresentationVerifyOptions {
  /** Who may issue representation attestations: business registers, or legal persons' Business Wallets. */
  trust: TrustConfig;
  /** Accepted vct values. Default [`urn:plenipo:representation:1`]. */
  acceptedVcts?: string[];
  /**
   * PID claims that must equal the attestation's `representative` claims when the attestation is not bound
   * to the PID holder key. Empty or absent: the holder key must be the same. Prefer unique identifiers
   * (e.g. a national personal number) over names.
   */
  identityClaims?: string[];
  /**
   * EUIDs each issuer may attest for, by issuer: exact EUIDs or prefixes ending in `*`. Required in practice
   * when a legal person's own Business Wallet is trusted, so it cannot attest for another legal person.
   * Absent: every trusted issuer may attest for any EUID.
   */
  euidScopes?: Record<string, string[]>;
  /** Accepted bases of the role. Default both. */
  acceptedBases?: RoleBasis[];
  /** Require a status list entry, so the attestation can be revoked in real time. Default true. */
  requireStatus?: boolean;
}

export interface VerifiedRepresentation {
  principal: LegalPersonPrincipal;
  info: RepresentationInfo;
  status?: StatusReference;
}

export class RepresentationError extends Error {
  constructor(
    readonly code: 'ATTESTATION_INVALID' | 'ATTESTATION_UNTRUSTED' | 'ROLE_EXCEEDED' | 'MALFORMED',
    message: string,
  ) {
    super(message);
  }
}

/**
 * EUID syntax (Implementing Regulation (EU) 2021/1042): country code, business register code, a dot, the
 * domestic registration number, optionally `_` and a validation character. Only a sanity check: EUIDs are
 * compared exactly.
 */
const EUID_RE = /^[A-Z]{2}[A-Za-z0-9]{1,13}\.[A-Za-z0-9][A-Za-z0-9.\-/]{0,49}(_[A-Za-z0-9])?$/;
const ROLE_CODE_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const ACTION_RE = /^(\*|[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?)$/;
const HOST_RE = /^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+$/;
const CURRENCY_RE = /^[A-Z]{3}$/;

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

/** Validates the `principal` member of a mandate. */
export function legalPrincipalProblems(p: unknown): string[] {
  if (!isObject(p)) return ['principal must be an object'];
  const e: string[] = [];
  for (const k of Object.keys(p)) if (!['type', 'euid', 'role'].includes(k)) e.push(`principal has unexpected member ${k}`);
  if (p.type !== 'legal_person') e.push('principal.type must be legal_person');
  if (typeof p.euid !== 'string' || !EUID_RE.test(p.euid)) e.push('principal.euid is not a valid EUID');
  if (p.role !== undefined && (typeof p.role !== 'string' || !ROLE_CODE_RE.test(p.role))) e.push('principal.role is not a valid role code');
  return e;
}

/** Builds a mandate on behalf of a legal person. Throws on invalid input. */
export function createLegalMandate(input: MandateInput & { principal: LegalPrincipal }, policy: PolicyOptions = {}): Mandate {
  const problems = legalPrincipalProblems(input.principal);
  if (problems.length) throw new Error(`invalid principal: ${problems.join('; ')}`);
  const { principal, ...rest } = input;
  return { ...createMandate(rest, policy), principal: { ...principal } };
}

function isLimits(x: unknown): x is Limits {
  if (!isObject(x)) return false;
  if (typeof x.currency !== 'string' || !CURRENCY_RE.test(x.currency)) return false;
  for (const k of ['per_operation', 'total']) {
    const v = x[k];
    if (v !== undefined && (!Number.isSafeInteger(v) || (v as number) < 0)) return false;
  }
  return x.per_operation !== undefined || x.total !== undefined;
}

/** Validates the claims of a representation attestation; returns problems. */
export function representationClaimsProblems(c: Record<string, unknown>): string[] {
  const e: string[] = [];
  if (typeof c.legal_person_id !== 'string' || !EUID_RE.test(c.legal_person_id)) e.push('legal_person_id is missing or not an EUID');
  if (c.legal_person_name !== undefined && (typeof c.legal_person_name !== 'string' || c.legal_person_name.length > 500)) {
    e.push('legal_person_name is invalid');
  }
  const role = c.role;
  if (!isObject(role)) e.push('role is missing');
  else {
    if (typeof role.code !== 'string' || !ROLE_CODE_RE.test(role.code)) e.push('role.code is missing or invalid');
    if (role.name !== undefined && (typeof role.name !== 'string' || role.name.length > 200)) e.push('role.name is invalid');
    if (!BASES.includes(role.basis as RoleBasis)) e.push('role.basis must be legal_representation or power_of_attorney');
    for (const k of ['valid_from', 'valid_until']) if (role[k] !== undefined && !Number.isSafeInteger(role[k])) e.push(`role.${k} must be an integer`);
  }
  const p = c.powers;
  if (!isObject(p)) e.push('powers is missing');
  else {
    if (!Array.isArray(p.actions) || p.actions.length === 0 || p.actions.length > 100 || !p.actions.every((a) => typeof a === 'string' && ACTION_RE.test(a))) {
      e.push('powers.actions must be a non-empty list of action patterns');
    }
    if (p.counterparties !== undefined) {
      if (!Array.isArray(p.counterparties) || p.counterparties.length === 0 || !p.counterparties.every((h) => typeof h === 'string' && HOST_RE.test(h))) {
        e.push('powers.counterparties must be a non-empty list of host patterns');
      }
    }
    if (p.limits !== undefined && !isLimits(p.limits)) e.push('powers.limits is invalid');
    const d = p.max_delegation_depth;
    if (d !== undefined && (!Number.isInteger(d) || (d as number) < 0 || (d as number) > MAX_DEPTH)) e.push('powers.max_delegation_depth is invalid');
  }
  if (c.representative !== undefined && !isObject(c.representative)) e.push('representative must be an object');
  return e;
}

/**
 * Violations of the role's powers by a mandate: actions not covered, counterparties outside the role,
 * limits above the role's, a deeper delegation than allowed, or a validity window outside the role's.
 * The role's total is an upper bound for each mandate's total; spending is not aggregated across mandates.
 */
export function rolePowerViolations(claims: RepresentationClaims, mandate: Mandate, credentialExp?: number): string[] {
  const v: string[] = [];
  const p = claims.powers;
  for (const a of mandate.actions) if (!anyActionCovers(p.actions, a)) v.push(`action ${a} is outside the role's powers`);
  if (p.counterparties) {
    if (!mandate.counterparties) v.push('the role is restricted to some counterparties, the mandate is not');
    else for (const c of mandate.counterparties) if (!p.counterparties.some((r) => hostCovers(r, c))) v.push(`counterparty ${c} is outside the role's powers`);
  }
  if (p.limits) {
    const ml = mandate.limits;
    if (!ml) v.push('the role has spending limits, the mandate has none');
    else if (ml.currency !== p.limits.currency) v.push(`the mandate is in ${ml.currency}, the role's limits are in ${p.limits.currency}`);
    else {
      if (p.limits.per_operation !== undefined) {
        const perOp = Math.min(ml.per_operation ?? Infinity, ml.total ?? Infinity);
        if (perOp > p.limits.per_operation) v.push(`per-operation limit ${perOp} exceeds the role's ${p.limits.per_operation}`);
      }
      if (p.limits.total !== undefined && (ml.total === undefined || ml.total > p.limits.total)) {
        v.push(`total limit ${ml.total ?? 'unlimited'} exceeds the role's ${p.limits.total}`);
      }
    }
  }
  const depth = mandate.delegation?.max_depth ?? 0;
  if (p.max_delegation_depth !== undefined && depth > p.max_delegation_depth) {
    v.push(`delegation depth ${depth} exceeds the role's ${p.max_delegation_depth}`);
  }
  const r = claims.role;
  if (r.valid_from !== undefined && mandate.nbf < r.valid_from) v.push('the mandate starts before the role');
  if (r.valid_until !== undefined && mandate.exp > r.valid_until) v.push('the mandate outlives the role');
  if (credentialExp !== undefined && mandate.exp > credentialExp) v.push('the mandate outlives the representation attestation');
  return v;
}

function euidAllowed(scopes: Record<string, string[]> | undefined, iss: string, euid: string): boolean {
  if (!scopes) return true;
  const list = Object.prototype.hasOwnProperty.call(scopes, iss) ? scopes[iss] : undefined;
  if (!Array.isArray(list)) return false;
  return list.some((s) => (s.endsWith('*') ? euid.startsWith(s.slice(0, -1)) : euid === s));
}

/**
 * Checks a verified representation presentation against the mandate and the PID it accompanies, at `now`.
 * Signature, key binding to the request and vct are checked before, by `verifyAttestationPresentation`.
 */
export async function checkRepresentation(
  att: VerifiedPresentation,
  ctx: { mandate: Mandate; pidHolderJwk: JWK; pidClaims: Record<string, unknown>; now: number; skewSeconds: number },
  opts: RepresentationVerifyOptions,
): Promise<VerifiedRepresentation> {
  // Restrictions are optional members: if the issuer made any of them selectively disclosable, withholding it
  // would read as "no restriction". So role and powers count only as issuer-signed plain text, digest-free.
  for (const k of ['role', 'powers'] as const) {
    if (!Object.prototype.hasOwnProperty.call(att.signedPayload, k) || hasDigests(att.signedPayload[k])) {
      throw new RepresentationError('ATTESTATION_INVALID', `representation attestation: ${k} must be signed in plain text, not selectively disclosable`);
    }
  }
  const problems = representationClaimsProblems(att.payload);
  if (problems.length) throw new RepresentationError('ATTESTATION_INVALID', `representation attestation: ${problems.join('; ')}`);
  const claims = { ...att.payload, role: att.signedPayload.role, powers: att.signedPayload.powers } as unknown as RepresentationClaims;
  const principal = ctx.mandate.principal!;

  if (!euidAllowed(opts.euidScopes, att.iss, claims.legal_person_id)) {
    throw new RepresentationError('ATTESTATION_UNTRUSTED', 'the issuer may not attest for this legal person');
  }
  if (claims.legal_person_id !== principal.euid) {
    throw new RepresentationError('ATTESTATION_INVALID', 'the attestation is for another legal person');
  }
  if (principal.role !== undefined && claims.role.code !== principal.role) {
    throw new RepresentationError('ATTESTATION_INVALID', 'the attestation is for another role');
  }
  const bases = opts.acceptedBases ?? BASES;
  if (!bases.includes(claims.role.basis)) throw new RepresentationError('ATTESTATION_INVALID', `role basis ${claims.role.basis} is not accepted`);
  if ((opts.requireStatus ?? true) && !att.status) {
    throw new RepresentationError('ATTESTATION_INVALID', 'the attestation has no status list entry and cannot be revoked');
  }

  // The role must be valid now; skew is tolerated on the start only, never on the end.
  if (claims.role.valid_from !== undefined && ctx.now + ctx.skewSeconds < claims.role.valid_from) {
    throw new RepresentationError('ATTESTATION_INVALID', 'the role is not valid yet');
  }
  if (claims.role.valid_until !== undefined && ctx.now >= claims.role.valid_until) {
    throw new RepresentationError('ATTESTATION_INVALID', 'the role has ended');
  }
  const exp = att.payload.exp;
  if (typeof exp !== 'number') throw new RepresentationError('ATTESTATION_INVALID', 'the attestation has no exp');
  if (ctx.now >= exp) throw new RepresentationError('ATTESTATION_INVALID', 'the attestation has expired');

  let holderBinding: 'cnf' | 'claims';
  try {
    holderBinding = await bindToPidHolder(
      { holderJwk: att.holderJwk, claims: att.payload.representative },
      { holderJwk: ctx.pidHolderJwk, claims: ctx.pidClaims },
      opts.identityClaims ?? [],
    );
  } catch (e) {
    throw new RepresentationError('ATTESTATION_INVALID', `representation attestation: ${(e as Error).message}`);
  }

  const violations = rolePowerViolations(claims, ctx.mandate, exp);
  if (violations.length) throw new RepresentationError('ROLE_EXCEEDED', `the mandate exceeds the role: ${violations.join('; ')}`);

  return {
    principal: {
      type: 'legal_person',
      euid: claims.legal_person_id,
      ...(claims.legal_person_name !== undefined ? { legal_name: claims.legal_person_name } : {}),
      role: { code: claims.role.code, ...(claims.role.name !== undefined ? { name: claims.role.name } : {}), basis: claims.role.basis },
      representative: ctx.pidClaims,
    },
    info: { register: att.iss, trusted_via: att.trustedVia, holder_binding: holderBinding },
    status: att.status,
  };
}

async function thumbprint(jwk: JWK): Promise<string | undefined> {
  try {
    return await calculateJwkThumbprint(jwk, 'sha256');
  } catch {
    return undefined;
  }
}

/**
 * Ties another credential to the person who presented the PID. Both presentations are already bound to the
 * same request (nonce and audience), but whoever controls the request can collect them from two different
 * people answering it, so that alone does not show one person stands behind both. The same holder key is a
 * cryptographic binding; matching identity claims shows that the issuer of the other credential names the
 * PID holder, and is used only when the relying party lists the claims. Throws when neither holds.
 */
export async function bindToPidHolder(
  other: { holderJwk: JWK; claims: unknown },
  pid: { holderJwk: JWK; claims: Record<string, unknown> },
  identityClaims: string[],
): Promise<'cnf' | 'claims'> {
  const a = await thumbprint(other.holderJwk);
  const b = await thumbprint(pid.holderJwk);
  if (a !== undefined && a === b) return 'cnf';
  if (identityClaims.length === 0) throw new Error('it is bound to another holder key');
  if (!isObject(other.claims)) throw new Error('it does not identify the holder');
  for (const c of identityClaims) {
    const fromPid = pid.claims[c];
    const fromOther = other.claims[c];
    if (fromPid === undefined || fromOther === undefined) throw new Error(`identity claim ${c} was not disclosed in both credentials`);
    if (canonicalize(fromPid) !== canonicalize(fromOther)) throw new Error('it names another person');
  }
  return 'claims';
}

/** DCQL credential query for the representation attestation. */
export function representationQuery(opts: { vcts?: string[]; identityClaims?: string[] } = {}): Record<string, unknown> {
  return {
    id: REPRESENTATION_QUERY_ID,
    format: 'dc+sd-jwt',
    meta: { vct_values: opts.vcts ?? [REPRESENTATION_VCT] },
    claims: [
      { path: ['legal_person_id'] },
      { path: ['legal_person_name'] },
      { path: ['role'] },
      { path: ['powers'] },
      ...(opts.identityClaims ?? []).map((c) => ({ path: ['representative', c] })),
    ],
  };
}
