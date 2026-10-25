import { randomUUID } from 'node:crypto';
import { type JWK } from 'jose';
import { signCompactJwt, type SigningKey } from './signer.js';
import { base64url, canonicalize, mandateHash } from './encoding.js';
import { issueDelegateSdJwt } from './delegate-sdjwt.js';
import { validateMandate, attenuationViolations, allowsDelegation, type PolicyOptions } from './scope.js';
import {
  DELEGATION_TYP,
  MANDATE_VERSION,
  TX_DATA_TYPE,
  type DelegationPayload,
  type Limits,
  type Mandate,
  type MandateTransactionData,
} from './types.js';

export interface MandateInput {
  agentJwk: JWK;
  actions: string[];
  counterparties?: string[];
  limits?: Limits;
  /** Seconds since epoch; defaults to now. */
  nbf?: number;
  /** Lifetime in seconds, used when `exp` is not given. Default 7 days. */
  ttlSeconds?: number;
  exp?: number;
  maxDepth?: number;
  purpose?: string;
  id?: string;
  /** Status list entry, e.g. from `StatusListPublisher.allocate()`. */
  status?: { status_list: { uri: string; idx: number } };
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Builds and validates a mandate. Throws on invalid input. */
export function createMandate(input: MandateInput, policy: PolicyOptions = {}): Mandate {
  const nbf = input.nbf ?? nowSeconds();
  const exp = input.exp ?? nbf + (input.ttlSeconds ?? 7 * 24 * 3600);
  const mandate: Mandate = {
    v: MANDATE_VERSION,
    id: input.id ?? randomUUID(),
    agent: { jwk: input.agentJwk },
    actions: input.actions,
    ...(input.counterparties ? { counterparties: input.counterparties } : {}),
    ...(input.limits ? { limits: input.limits } : {}),
    nbf,
    exp,
    ...(input.maxDepth !== undefined ? { delegation: { max_depth: input.maxDepth } } : {}),
    ...(input.purpose ? { purpose: input.purpose } : {}),
    ...(input.status ? { status: input.status } : {}),
  };
  const errors = validateMandate(mandate, policy);
  if (errors.length) throw new Error(`invalid mandate: ${errors.join('; ')}`);
  return mandate;
}

/**
 * Wraps a mandate as OpenID4VP transaction data, base64url-encoded.
 * This exact string goes in the wallet request; its hash comes back in the key binding JWT.
 */
export function encodeMandateTransactionData(mandate: Mandate, credentialId = 'pid'): string {
  const td: MandateTransactionData = { type: TX_DATA_TYPE, credential_ids: [credentialId], mandate };
  return base64url(canonicalize(td));
}

/**
 * Signs a narrower mandate for a sub-agent with the parent agent's key.
 * Throws if the child would widen the parent's authority.
 */
export async function delegateMandate(params: {
  parent: Mandate;
  parentAgentKey: SigningKey;
  child: Mandate;
  policy?: PolicyOptions;
}): Promise<string> {
  const { parent, parentAgentKey, child, policy } = params;
  const errors = validateMandate(child, policy);
  if (errors.length) throw new Error(`invalid child mandate: ${errors.join('; ')}`);
  if (!allowsDelegation(parent)) throw new Error('parent mandate does not allow sub-delegation');
  const violations = attenuationViolations(parent, child);
  if (violations.length) throw new Error(`child widens parent authority: ${violations.join('; ')}`);
  const payload: DelegationPayload = {
    mandate: child,
    parent_id: parent.id,
    parent_hash: mandateHash(parent),
    iat: nowSeconds(),
  };
  return signCompactJwt(payload as unknown as Record<string, unknown>, { alg: 'ES256', typ: DELEGATION_TYP }, parentAgentKey);
}

/**
 * Same as `delegateMandate`, with the same checks, but issues the delegation as a Delegate SD-JWT
 * (draft-gco-oauth-delegate-sd-jwt) in the Plenipo profile: a KB-SD-JWT+KB signed by the parent agent
 * whose Delegate Payload carries the child mandate as plainly visible claims and binds the child agent
 * key in `cnf`. See docs/delegation.md.
 */
export async function delegateMandateSdJwt(params: {
  parent: Mandate;
  parentAgentKey: SigningKey;
  child: Mandate;
  policy?: PolicyOptions;
}): Promise<string> {
  const { parent, parentAgentKey, child, policy } = params;
  const errors = validateMandate(child, policy);
  if (errors.length) throw new Error(`invalid child mandate: ${errors.join('; ')}`);
  if (!allowsDelegation(parent)) throw new Error('parent mandate does not allow sub-delegation');
  const violations = attenuationViolations(parent, child);
  if (violations.length) throw new Error(`child widens parent authority: ${violations.join('; ')}`);
  return issueDelegateSdJwt(
    { mandate: child, parent_id: parent.id, parent_hash: mandateHash(parent), iat: nowSeconds() },
    parentAgentKey,
  );
}
