/**
 * Turns an ALLOW decision into input for an external policy engine, so a bank can add its own rules
 * (thresholds, hours, chain depth) on top of what the mandate allows. Plenipo decides whether the agent
 * holds authority; the policy engine decides whether the bank wants to act on it. Neither OPA nor Cedar
 * is a dependency: these functions only build JSON.
 */
import { calculateJwkThumbprint } from 'jose';
import { canonicalize, mandateHash, sha256 } from './encoding.js';
import type { SpendingLedger } from './registry.js';
import { principalIdentity, type PrincipalIdentity } from './principal.js';
import type { Decision, Mandate } from './types.js';

type AllowDecision = Extract<Decision, { decision: 'ALLOW' }>;

export const POLICY_INPUT_VERSION = '1';
export const DEFAULT_POLICY_PRINCIPAL_CLAIMS = ['given_name', 'family_name'];

export interface PolicyExportOptions {
  /** When given, each mandate's total limit comes with what has been spent and what is left. */
  ledger?: SpendingLedger;
  /** Evaluation time in seconds; defaults to now. */
  now?: number;
  /** IANA time zone for `local_hour` and `weekday`, e.g. `Europe/Rome`. Default `UTC`. */
  timeZone?: string;
  /** PID claims passed to the engine. Default given_name and family_name; `'all'` passes every disclosed claim. */
  principalClaims?: string[] | 'all';
  /** Claims that identify a person uniquely, in order of preference. Default `['personal_administrative_number']`. */
  principalIdClaims?: string[];
  /** Throw (PrincipalIdentityError) when none of `principalIdClaims` was disclosed, instead of falling back. */
  requireIdClaim?: boolean;
  /** The HTTP request, when the decision came from the gateway. */
  request?: { method: string; path: string };
}

export interface MandateLimitsView {
  depth: number;
  mandate_id: string;
  currency: string;
  per_operation?: number;
  total?: number;
  /** Committed plus pending spending under this mandate, including this operation's reservation. */
  spent?: number;
  /** total - spent. */
  residual?: number;
}

/** The OPA input document. Send it as `{"input": <this>}` to OPA's Data API. */
export interface OpaInput {
  plenipo: typeof POLICY_INPUT_VERSION;
  /**
   * Who gave the mandate. `id` is stable and never a display name (see src/principal.ts); for a legal person
   * it is the EUID, and the representative who approved in the wallet is identified separately.
   */
  principal: PrincipalIdentity & { issuer: string; trusted_via: 'issuer' | 'x5c' };
  /** How the chain is anchored. Always `eudi_pid` in this version. */
  root: { type: 'eudi_pid'; mandate_id: string };
  chain: {
    /** Number of delegations below the root mandate: 0 when the root agent acts itself. */
    depth: number;
    mandate_ids: string[];
    /** Earliest expiry in the chain, seconds since epoch. */
    exp: number;
  };
  agent: {
    /** RFC 7638 SHA-256 thumbprint of the leaf agent key, the one that signed the invocation. */
    jkt: string;
    /** Thumbprint of the root agent key, the one the person approved in the wallet. */
    root_jkt: string;
  };
  action: string;
  counterparty: string | null;
  amount: { value: number; currency: string } | null;
  limits: MandateLimitsView[];
  invocation: { aud: string; iat: number; nonce: string; args_hash: string | null };
  time: { epoch: number; iso: string; time_zone: string; local_hour: number; weekday: number };
  request: { method: string; path: string } | null;
}

/** Hour (0-23) and ISO weekday (1 = Monday ... 7 = Sunday) in a time zone. */
function localTime(epoch: number, timeZone: string): { hour: number; weekday: number } {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone, hour: 'numeric', hourCycle: 'h23', weekday: 'short' }).formatToParts(
    new Date(epoch * 1000),
  );
  const hour = Number(parts.find((p) => p.type === 'hour')?.value);
  const wd = parts.find((p) => p.type === 'weekday')?.value ?? '';
  const weekday = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].indexOf(wd) + 1;
  return { hour, weekday };
}

async function limitsView(mandates: Mandate[], currency: string | undefined, ledger: SpendingLedger | undefined): Promise<MandateLimitsView[]> {
  const out: MandateLimitsView[] = [];
  for (let i = 0; i < mandates.length; i++) {
    const m = mandates[i];
    if (!m.limits) continue;
    const v: MandateLimitsView = { depth: i, mandate_id: m.id, currency: m.limits.currency };
    if (m.limits.per_operation !== undefined) v.per_operation = m.limits.per_operation;
    if (m.limits.total !== undefined) {
      v.total = m.limits.total;
      if (ledger) {
        const spent = await ledger.spent(mandateHash(m), currency ?? m.limits.currency);
        v.spent = spent;
        v.residual = m.limits.total - spent;
      }
    }
    out.push(v);
  }
  return out;
}

/** Builds the OPA input document for an ALLOW decision. */
export async function toOpaInput(decision: AllowDecision, opts: PolicyExportOptions = {}): Promise<OpaInput> {
  if (decision?.decision !== 'ALLOW') throw new Error('only ALLOW decisions can be exported');
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const timeZone = opts.timeZone ?? 'UTC';
  const { hour, weekday } = localTime(now, timeZone);
  const mandates = decision.mandates;
  const leaf = mandates[mandates.length - 1];
  const inv = decision.invocation;
  return {
    plenipo: POLICY_INPUT_VERSION,
    principal: {
      ...principalIdentity(decision, { principalClaims: opts.principalClaims ?? DEFAULT_POLICY_PRINCIPAL_CLAIMS, idClaims: opts.principalIdClaims, requireIdClaim: opts.requireIdClaim }),
      issuer: decision.pid_issuer,
      trusted_via: decision.pid_trusted_via,
    },
    root: { type: 'eudi_pid', mandate_id: mandates[0].id },
    chain: { depth: mandates.length - 1, mandate_ids: mandates.map((m) => m.id), exp: Math.min(...mandates.map((m) => m.exp)) },
    agent: { jkt: await calculateJwkThumbprint(leaf.agent.jwk, 'sha256'), root_jkt: await calculateJwkThumbprint(mandates[0].agent.jwk, 'sha256') },
    action: inv.action,
    counterparty: inv.counterparty ?? null,
    amount: inv.amount ? { value: inv.amount.value, currency: inv.amount.currency } : null,
    limits: await limitsView(mandates, inv.amount?.currency, opts.ledger),
    invocation: { aud: inv.aud, iat: inv.iat, nonce: inv.nonce, args_hash: inv.args_hash ?? null },
    time: { epoch: now, iso: new Date(now * 1000).toISOString(), time_zone: timeZone, local_hour: hour, weekday },
    request: opts.request ? { method: opts.request.method, path: opts.request.path } : null,
  };
}

/** A Cedar entity reference. */
export interface CedarUid {
  type: string;
  id: string;
}

/** A Cedar entity in the JSON entity format: `uid`, `attrs`, `parents`. */
export interface CedarEntity {
  uid: CedarUid;
  attrs: Record<string, unknown>;
  parents: CedarUid[];
}

/** A Cedar authorization request with its entities, ready for `isAuthorized`. */
export interface CedarRequest {
  principal: CedarUid;
  action: CedarUid;
  resource: CedarUid;
  context: Record<string, unknown>;
  entities: CedarEntity[];
}

/** Cedar namespace of the exported types. */
export const CEDAR_NAMESPACE = 'Plenipo';

const T = {
  agent: `${CEDAR_NAMESPACE}::Agent`,
  person: `${CEDAR_NAMESPACE}::Person`,
  legalPerson: `${CEDAR_NAMESPACE}::LegalPerson`,
  mandate: `${CEDAR_NAMESPACE}::Mandate`,
  action: `${CEDAR_NAMESPACE}::Action`,
  operation: `${CEDAR_NAMESPACE}::Operation`,
  counterparty: `${CEDAR_NAMESPACE}::Counterparty`,
};

const ref = (type: string, id: string) => ({ __entity: { type, id } });

/**
 * Builds a Cedar request for an ALLOW decision.
 *
 * - principal: `Plenipo::Agent::"<jkt>"`, the leaf agent, child of its mandate and of the person.
 * - action: `Plenipo::Action::"<dotted action>"`, child of each dotted prefix, so
 *   `action in Plenipo::Action::"payments"` covers `payments.sepa.transfer`.
 * - resource: `Plenipo::Operation::"<invocation hash>"`, with amount and currency, child of its counterparty.
 * - context: chain depth, time, amount and the smallest residual total in the chain.
 *
 * The mandate giver is `Plenipo::Person::"<id>"` for a natural person, with the stable identifier of
 * src/principal.ts (never a display name), or `Plenipo::LegalPerson::"<euid>"` for a legal person, whose
 * `representative` attribute refers to the `Plenipo::Person` who approved in the wallet.
 */
export async function toCedarRequest(decision: AllowDecision, opts: PolicyExportOptions = {}): Promise<CedarRequest> {
  const input = await toOpaInput(decision, opts);
  const mandates = decision.mandates;
  const entities: CedarEntity[] = [];

  const pr = input.principal;
  const personAttrs = (p: { id_basis: string; claims: Record<string, unknown> }) => ({
    id_basis: p.id_basis,
    issuer: pr.issuer,
    trusted_via: pr.trusted_via,
    claims: { ...p.claims },
  });
  let principalUid: CedarUid;
  if (pr.type === 'legal_person') {
    const repUid = { type: T.person, id: pr.representative.id };
    entities.push({ uid: repUid, attrs: personAttrs(pr.representative), parents: [] });
    principalUid = { type: T.legalPerson, id: pr.euid };
    const attrs: Record<string, unknown> = { euid: pr.euid, role_code: pr.role.code, role_basis: pr.role.basis, representative: ref(T.person, repUid.id) };
    if (pr.legal_name !== null) attrs.legal_name = pr.legal_name;
    if (pr.role.name !== null) attrs.role_name = pr.role.name;
    entities.push({ uid: principalUid, attrs, parents: [] });
  } else {
    principalUid = { type: T.person, id: pr.id };
    entities.push({ uid: principalUid, attrs: personAttrs(pr), parents: [] });
  }

  const limitsByDepth = new Map(input.limits.map((l) => [l.depth, l]));
  for (let i = 0; i < mandates.length; i++) {
    const m = mandates[i];
    const l = limitsByDepth.get(i);
    const attrs: Record<string, unknown> = { depth: i, actions: [...m.actions], nbf: m.nbf, exp: m.exp };
    if (m.counterparties) attrs.counterparties = [...m.counterparties];
    if (l) {
      attrs.currency = l.currency;
      for (const k of ['per_operation', 'total', 'spent', 'residual'] as const) if (l[k] !== undefined) attrs[k] = l[k];
    }
    entities.push({ uid: { type: T.mandate, id: m.id }, attrs, parents: i === 0 ? [principalUid] : [{ type: T.mandate, id: mandates[i - 1].id }] });
  }

  const leafMandate = { type: T.mandate, id: mandates[mandates.length - 1].id };
  const agentUid = { type: T.agent, id: input.agent.jkt };
  entities.push({ uid: agentUid, attrs: { depth: input.chain.depth, mandate: ref(T.mandate, leafMandate.id) }, parents: [leafMandate, principalUid] });

  const segments = input.action.split('.');
  const actionIds = segments.map((_, i) => segments.slice(0, i + 1).join('.'));
  for (let i = 0; i < actionIds.length; i++) {
    entities.push({ uid: { type: T.action, id: actionIds[i] }, attrs: {}, parents: i === 0 ? [] : [{ type: T.action, id: actionIds[i - 1] }] });
  }

  const opAttrs: Record<string, unknown> = {};
  const opParents: CedarUid[] = [];
  if (input.amount) {
    opAttrs.amount = input.amount.value;
    opAttrs.currency = input.amount.currency;
  }
  if (input.counterparty) {
    opAttrs.counterparty = input.counterparty;
    const cp = { type: T.counterparty, id: input.counterparty };
    entities.push({ uid: cp, attrs: { host: input.counterparty }, parents: [] });
    opParents.push(cp);
  }
  const resource = { type: T.operation, id: sha256(canonicalize(decision.invocation)) };
  entities.push({ uid: resource, attrs: opAttrs, parents: opParents });

  const residuals = input.limits.map((l) => l.residual).filter((r): r is number => r !== undefined);
  const context: Record<string, unknown> = {
    depth: input.chain.depth,
    chain_length: mandates.length,
    root_type: input.root.type,
    principal_type: pr.type,
    pid_trusted_via: input.principal.trusted_via,
    time: input.time.epoch,
    local_hour: input.time.local_hour,
    weekday: input.time.weekday,
    chain_exp: input.chain.exp,
  };
  if (input.amount) {
    context.amount = input.amount.value;
    context.currency = input.amount.currency;
  }
  if (residuals.length) context.min_residual = Math.min(...residuals);
  if (input.request) context.request = { ...input.request };

  return { principal: agentUid, action: { type: T.action, id: input.action }, resource, context, entities };
}
