import type { Limits, Mandate } from './types.js';
import { MANDATE_VERSION } from './types.js';
import { isStatusReference } from './status.js';
import { IDEMPOTENCY_KEY_RE } from './idempotency.js';

const ACTION_RE = /^(\*|[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?)$/;
const CONCRETE_ACTION_RE = /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/;
const HOST_RE = /^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+$/;
/** A concrete, lowercase host name: letters, digits and hyphens in dot-separated labels, no wildcard. */
const CONCRETE_HOST_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const CURRENCY_RE = /^[A-Z]{3}$/;
/** Upper bound on delegation depth, to keep chains short and verification cheap. */
export const MAX_DEPTH = 5;
/** Maximum length of a mandate purpose, in UTF-16 code units. */
export const MAX_PURPOSE_LENGTH = 500;

/** True when `pattern` covers the concrete or wildcard action `action`. */
export function actionCovers(pattern: string, action: string): boolean {
  if (pattern === '*') return true;
  if (pattern === action) return true;
  if (pattern.endsWith('.*')) {
    const base = pattern.slice(0, -2);
    if (action === base) return true;
    return action.startsWith(base + '.');
  }
  return false;
}

/** True when `pattern` covers the host or host pattern `host`. */
export function hostCovers(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p === h) return true;
  if (p.startsWith('*.')) {
    const base = p.slice(2);
    const target = h.startsWith('*.') ? h.slice(2) : h;
    return target === base || target.endsWith('.' + base);
  }
  return false;
}

export function anyActionCovers(patterns: string[], action: string): boolean {
  return patterns.some((p) => actionCovers(p, action));
}

export function counterpartyAllowed(patterns: string[] | undefined, host: string): boolean {
  if (!patterns) return true;
  return patterns.some((p) => hostCovers(p, host));
}

export interface PolicyOptions {
  /** Maximum mandate lifetime in seconds. Default 90 days. */
  maxLifetimeSeconds?: number;
}

export const DEFAULT_MAX_LIFETIME = 90 * 24 * 3600;

/** Returns a list of problems; empty means the mandate is well formed and within policy. */
export function validateMandate(m: unknown, policy: PolicyOptions = {}): string[] {
  const errors: string[] = [];
  if (typeof m !== 'object' || m === null) return ['mandate is not an object'];
  const x = m as Partial<Mandate> & Record<string, unknown>;
  if (x.v !== MANDATE_VERSION) errors.push(`unsupported version ${String(x.v)}`);
  errors.push(...unknownMembers(x));
  if (typeof x.id !== 'string' || x.id.length < 8) errors.push('id missing or too short');
  if (!x.agent || typeof x.agent !== 'object' || typeof x.agent.jwk !== 'object' || x.agent.jwk === null) {
    errors.push('agent.jwk missing');
  } else if ('d' in x.agent.jwk) {
    errors.push('agent.jwk contains a private key');
  }
  if (!Array.isArray(x.actions) || x.actions.length === 0) {
    errors.push('actions missing');
  } else {
    for (const a of x.actions) if (typeof a !== 'string' || !ACTION_RE.test(a)) errors.push(`invalid action ${String(a)}`);
  }
  if (x.counterparties !== undefined) {
    if (!Array.isArray(x.counterparties) || x.counterparties.length === 0) errors.push('counterparties must be a non-empty array when present');
    else for (const c of x.counterparties) if (typeof c !== 'string' || !HOST_RE.test(c.toLowerCase())) errors.push(`invalid counterparty ${String(c)}`);
  }
  if (x.limits !== undefined) errors.push(...validateLimits(x.limits));
  if (!Number.isInteger(x.nbf)) errors.push('nbf missing');
  if (!Number.isInteger(x.exp)) errors.push('exp missing');
  if (Number.isInteger(x.nbf) && Number.isInteger(x.exp)) {
    if ((x.exp as number) <= (x.nbf as number)) errors.push('exp must be after nbf');
    const max = policy.maxLifetimeSeconds ?? DEFAULT_MAX_LIFETIME;
    if ((x.exp as number) - (x.nbf as number) > max) errors.push(`lifetime exceeds ${max} seconds`);
  }
  if (x.delegation !== undefined) {
    if (
      typeof x.delegation !== 'object' ||
      x.delegation === null ||
      !Number.isInteger(x.delegation.max_depth) ||
      x.delegation.max_depth < 0 ||
      x.delegation.max_depth > MAX_DEPTH
    ) {
      errors.push(`delegation.max_depth must be an integer between 0 and ${MAX_DEPTH}`);
    }
  }
  if (x.purpose !== undefined) {
    // The purpose is shown to the person (also inside a TS12 e-mandate): no control or format characters
    // (line breaks, bidi overrides, zero-width characters) that could make it read differently.
    if (typeof x.purpose !== 'string') errors.push('purpose must be a string');
    else if (x.purpose.length > MAX_PURPOSE_LENGTH) errors.push(`purpose must be at most ${MAX_PURPOSE_LENGTH} characters`);
    else if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(x.purpose)) errors.push('purpose must not contain control, format or line separator characters');
    else if (/^\s|\s$|\s\s/u.test(x.purpose)) errors.push('purpose must not start or end with spaces or contain consecutive spaces');
  }
  if (x.status !== undefined && !isStatusReference(x.status)) errors.push('status must be { status_list: { uri, idx } }');
  return errors;
}

/**
 * Validates an untrusted invocation payload. Every field the verifier compares must have
 * exactly the expected type and shape, otherwise comparisons could silently pass.
 */
export function validateInvocationPayload(p: unknown): string[] {
  const e: string[] = [];
  if (typeof p !== 'object' || p === null) return ['invocation payload is not an object'];
  const x = p as Record<string, unknown>;
  if (typeof x.mandate !== 'string' || x.mandate.length === 0) e.push('mandate must be a string');
  if (typeof x.action !== 'string' || !CONCRETE_ACTION_RE.test(x.action)) e.push('action must be a concrete action name without wildcards');
  if (x.counterparty !== undefined) {
    if (typeof x.counterparty !== 'string' || x.counterparty.length > 253 || !CONCRETE_HOST_RE.test(x.counterparty)) {
      e.push('counterparty must be a concrete lowercase host name');
    }
  }
  if (x.amount !== undefined) {
    const a = x.amount as Record<string, unknown> | null;
    if (typeof a !== 'object' || a === null) e.push('amount must be an object');
    else {
      if (typeof a.value !== 'number' || !Number.isSafeInteger(a.value) || a.value < 0) e.push('amount.value must be a non-negative integer in minor units');
      if (typeof a.currency !== 'string' || !CURRENCY_RE.test(a.currency)) e.push('amount.currency must be an ISO 4217 code');
    }
  }
  if (typeof x.aud !== 'string' || x.aud.length === 0) e.push('aud must be a string');
  if (typeof x.nonce !== 'string' || x.nonce.length === 0 || x.nonce.length > 256) e.push('nonce must be a string of 1 to 256 characters');
  if (typeof x.iat !== 'number' || !Number.isInteger(x.iat)) e.push('iat must be an integer');
  if (x.args_hash !== undefined && typeof x.args_hash !== 'string') e.push('args_hash must be a string');
  if (x.idem !== undefined) {
    if (typeof x.idem !== 'string' || !IDEMPOTENCY_KEY_RE.test(x.idem)) e.push('idem must be 16 to 128 base64url characters');
    // A key that does not cover the arguments could pair a retry with a different operation.
    if (x.args_hash === undefined) e.push('idem requires args_hash');
  }
  // As for mandates and delegations: a member this verifier does not know could be a constraint it would ignore.
  const extra = Object.keys(x).filter((k) => !INVOCATION_MEMBERS.has(k));
  if (extra.length) e.push(`unknown member ${extra.join(', ')}`);
  return e;
}

/** Members an invocation may carry. */
const INVOCATION_MEMBERS: ReadonlySet<string> = new Set(['mandate', 'action', 'counterparty', 'amount', 'aud', 'nonce', 'iat', 'args_hash', 'chain_hash', 'idem']);

function validateLimits(l: Limits): string[] {
  const e: string[] = [];
  if (typeof l !== 'object' || l === null) return ['limits is not an object'];
  if (typeof l.currency !== 'string' || !CURRENCY_RE.test(l.currency)) e.push('limits.currency must be an ISO 4217 code');
  for (const k of ['per_operation', 'total'] as const) {
    const v = l[k];
    if (v !== undefined && (!Number.isInteger(v) || v < 0)) e.push(`limits.${k} must be a non-negative integer in minor units`);
  }
  if (l.per_operation === undefined && l.total === undefined) e.push('limits needs per_operation or total');
  return e;
}

export function maxDepth(m: Mandate): number {
  return m.delegation?.max_depth ?? 0;
}

/**
 * Checks that `child` is a strict-or-equal narrowing of `parent`.
 * Returns a list of violations; empty means the delegation is attenuating.
 */
export function attenuationViolations(parent: Mandate, child: Mandate): string[] {
  const v: string[] = [];
  for (const a of child.actions) {
    if (!anyActionCovers(parent.actions, a)) v.push(`action ${a} is not covered by the parent`);
  }
  if (parent.counterparties) {
    if (!child.counterparties) v.push('parent restricts counterparties but child does not');
    else for (const c of child.counterparties) {
      if (!parent.counterparties.some((p) => hostCovers(p, c))) v.push(`counterparty ${c} is not covered by the parent`);
    }
  }
  if (parent.limits) {
    const pl = parent.limits;
    const cl = child.limits;
    if (!cl) v.push('parent has limits but child does not');
    else {
      if (cl.currency !== pl.currency) v.push(`currency ${cl.currency} differs from parent ${pl.currency}`);
      for (const k of ['per_operation', 'total'] as const) {
        const pv = pl[k];
        if (pv === undefined) continue;
        const cv = cl[k];
        if (cv === undefined) v.push(`parent sets limits.${k} but child does not`);
        else if (cv > pv) v.push(`limits.${k} ${cv} exceeds parent ${pv}`);
      }
    }
  }
  if (child.nbf < parent.nbf) v.push('child starts before parent');
  if (child.exp > parent.exp) v.push('child expires after parent');
  if (maxDepth(parent) >= 1 && maxDepth(child) > maxDepth(parent) - 1) {
    v.push(`child max_depth ${maxDepth(child)} exceeds ${maxDepth(parent) - 1}`);
  }
  return v;
}

/** True when the parent mandate allows at least one more delegation hop. */
export function allowsDelegation(parent: Mandate): boolean {
  return maxDepth(parent) >= 1;
}

/**
 * Members a version 0.1 mandate may have, per object. Anything else is refused rather than ignored: an
 * unknown member may be a constraint someone meant (a wallet showing a daily cap, a misspelt
 * `counterparty`), and a verifier that skipped it would enforce a wider mandate than the one approved.
 */
const MANDATE_MEMBERS: Record<string, readonly string[]> = {
  mandate: ['v', 'id', 'agent', 'actions', 'counterparties', 'limits', 'nbf', 'exp', 'delegation', 'purpose', 'status', 'principal'],
  agent: ['jwk'],
  limits: ['currency', 'per_operation', 'total'],
  delegation: ['max_depth'],
  status: ['status_list'],
  status_list: ['uri', 'idx'],
};

function extraKeys(o: unknown, allowed: readonly string[]): string[] {
  if (typeof o !== 'object' || o === null || Array.isArray(o)) return [];
  return Object.keys(o).filter((k) => !allowed.includes(k));
}

function unknownMembers(x: Record<string, unknown>): string[] {
  const found: string[] = [];
  const check = (o: unknown, kind: string, path: string) => {
    for (const k of extraKeys(o, MANDATE_MEMBERS[kind])) found.push(`unknown member ${path}${k}`);
  };
  check(x, 'mandate', '');
  check(x.agent, 'agent', 'agent.');
  check(x.limits, 'limits', 'limits.');
  check(x.delegation, 'delegation', 'delegation.');
  check(x.status, 'status', 'status.');
  if (typeof x.status === 'object' && x.status !== null) {
    check((x.status as Record<string, unknown>).status_list, 'status_list', 'status.status_list.');
  }
  return found;
}
