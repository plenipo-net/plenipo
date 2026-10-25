/**
 * HTTP mapping of Plenipo decisions: a status code, a stable machine code and an RFC 9457 problem
 * document for every DenyCode, plus the problems the HTTP gateway itself can raise.
 *
 * The problem body never carries the decision's `reason` or `detail`: reasons quote library messages,
 * hosts and amounts, and details carry network errors. Both stay in the audit log.
 */
import type { Decision, DenyCode } from '../types.js';

export const PROBLEM_TYPE_BASE = 'https://plenipo.net/problems/';
export const PROBLEM_CONTENT_TYPE = 'application/problem+json';

/**
 * Broad class of a failure. `authentication`: the presented chain or invocation is not valid credentials.
 * `authorization`: valid credentials that do not cover this request. `request`: the HTTP request itself is
 * unusable. `conflict`: replay. `infrastructure`: a dependency could not be reached, retry may succeed.
 * `configuration`: the service is misconfigured; the caller cannot fix it.
 */
export type ProblemKind = 'authentication' | 'authorization' | 'request' | 'conflict' | 'infrastructure' | 'configuration';

export interface ProblemSpec {
  status: number;
  /** Stable machine code, lowercase; also the last segment of the problem type URI. */
  code: string;
  /** Short, fixed, human-readable summary. Never specific to the occurrence. */
  title: string;
  kind: ProblemKind;
}

const spec = (status: number, code: string, title: string, kind: ProblemKind): ProblemSpec =>
  Object.freeze({ status, code, title, kind });

/**
 * One entry per DenyCode. Infrastructure failures have their own codes (`STATUS_UNAVAILABLE`, `INTERNAL`),
 * so `problemForDecision` maps by code alone.
 */
export const DENY_PROBLEMS: Readonly<Record<DenyCode, ProblemSpec>> = Object.freeze({
  CONFIGURATION: spec(500, 'configuration', 'The service is not configured to verify this authorization', 'configuration'),
  MALFORMED: spec(400, 'malformed', 'The authorization is malformed', 'request'),
  INVOCATION_MISMATCH: spec(422, 'invocation_mismatch', 'The invocation does not match the request', 'request'),
  ROOT_INVALID: spec(401, 'root_invalid', 'The wallet authorization is not valid', 'authentication'),
  PID_ISSUER_UNTRUSTED: spec(401, 'pid_issuer_untrusted', 'The PID provider is not trusted', 'authentication'),
  PID_REVOKED: spec(401, 'pid_revoked', 'The PID is revoked or suspended', 'authentication'),
  TX_DATA_MISMATCH: spec(401, 'tx_data_mismatch', 'The wallet did not approve this mandate', 'authentication'),
  LIFETIME_POLICY: spec(403, 'lifetime_policy', 'The mandate lifetime is not accepted by this service', 'authorization'),
  DELEGATION_SIGNATURE_INVALID: spec(401, 'delegation_signature_invalid', 'A delegation signature is not valid', 'authentication'),
  DELEGATION_PARENT_MISMATCH: spec(401, 'delegation_parent_mismatch', 'A delegation does not refer to its parent mandate', 'authentication'),
  DELEGATION_NOT_ALLOWED: spec(403, 'delegation_not_allowed', 'A mandate in the chain does not allow sub-delegation', 'authorization'),
  ATTENUATION_VIOLATION: spec(403, 'attenuation_violation', 'A delegation widens the authority of its parent', 'authorization'),
  NOT_YET_VALID: spec(401, 'not_yet_valid', 'A mandate in the chain is not valid yet', 'authentication'),
  EXPIRED: spec(401, 'expired', 'A mandate in the chain has expired', 'authentication'),
  REVOKED: spec(401, 'revoked', 'A mandate in the chain is revoked or suspended', 'authentication'),
  INVOCATION_SIGNATURE_INVALID: spec(401, 'invocation_signature_invalid', 'The invocation is not signed by the leaf agent', 'authentication'),
  INVOCATION_MANDATE_MISMATCH: spec(401, 'invocation_mandate_mismatch', 'The invocation refers to another mandate', 'authentication'),
  INVOCATION_STALE: spec(401, 'invocation_stale', 'The invocation is too old or from the future', 'authentication'),
  AUDIENCE_MISMATCH: spec(401, 'audience_mismatch', 'The invocation is addressed to another service', 'authentication'),
  REPLAY: spec(409, 'replay', 'The invocation nonce was already used', 'conflict'),
  ACTION_NOT_PERMITTED: spec(403, 'action_not_permitted', 'The action is outside the mandate', 'authorization'),
  COUNTERPARTY_NOT_PERMITTED: spec(403, 'counterparty_not_permitted', 'The counterparty is outside the mandate', 'authorization'),
  CURRENCY_MISMATCH: spec(403, 'currency_mismatch', 'The currency differs from the mandate limits', 'authorization'),
  LIMIT_PER_OPERATION: spec(403, 'limit_per_operation', 'The amount exceeds the per-operation limit', 'authorization'),
  LIMIT_TOTAL: spec(403, 'limit_total', 'The amount would exceed a total limit in the chain', 'authorization'),
  DISPLAY_MISMATCH: spec(401, 'display_mismatch', 'What the wallet displayed does not cover the mandate', 'authentication'),
  ROOT_POLICY: spec(403, 'root_policy', 'This form of wallet authorization is not accepted by this service', 'authorization'),
  ATTESTATION_UNTRUSTED: spec(401, 'attestation_untrusted', 'An attestation issuer is not trusted', 'authentication'),
  ATTESTATION_INVALID: spec(401, 'attestation_invalid', 'An attestation presentation is not valid', 'authentication'),
  ATTESTATION_REVOKED: spec(401, 'attestation_revoked', 'An attestation is revoked or suspended', 'authentication'),
  ROLE_EXCEEDED: spec(403, 'role_exceeded', 'The mandate exceeds the representative role', 'authorization'),
  STATUS_UNAVAILABLE: spec(503, 'status_unavailable', 'A status list could not be checked', 'infrastructure'),
  INTERNAL: spec(500, 'internal', 'The request could not be processed', 'infrastructure'),
});

/** Problems raised by the HTTP layer, before or after `verifyAuthorization`. */
export const GATEWAY_PROBLEMS = Object.freeze({
  authorization_required: spec(401, 'authorization_required', 'Plenipo authorization headers are required', 'authentication'),
  malformed_authorization: spec(400, 'malformed_authorization', 'The Plenipo authorization headers are malformed', 'request'),
  header_too_large: spec(431, 'header_too_large', 'A Plenipo authorization header is too large', 'request'),
  body_too_large: spec(413, 'body_too_large', 'The request body is too large', 'request'),
  malformed_target: spec(400, 'malformed_target', 'The request target is not in normal form', 'request'),
  body_not_allowed: spec(400, 'body_not_allowed', 'This method does not accept a request body', 'request'),
  malformed_body: spec(400, 'malformed_body', 'The request body is not valid JSON without duplicate keys', 'request'),
  unsupported_media_type: spec(415, 'unsupported_media_type', 'The request body must be sent as JSON', 'request'),
  request_unmapped: spec(400, 'request_unmapped', 'The request does not carry the fields its route requires', 'request'),
  no_route: spec(404, 'no_route', 'No protected route matches the request', 'request'),
  status_unavailable: spec(503, 'status_unavailable', 'A status list could not be checked', 'infrastructure'),
  audit_unavailable: spec(503, 'audit_unavailable', 'The decision could not be recorded', 'infrastructure'),
  processing_error: spec(500, 'processing_error', 'The request could not be processed', 'infrastructure'),
  policy_denied: spec(403, 'policy_denied', 'The request is refused by the service policy', 'authorization'),
  admin_forbidden: spec(403, 'admin_forbidden', 'The caller may not perform this administrative operation', 'authorization'),
  entry_unknown: spec(404, 'entry_unknown', 'The status list or entry does not exist', 'request'),
  entry_revoked: spec(409, 'entry_revoked', 'The entry is revoked, which cannot be undone', 'conflict'),
  method_not_allowed: spec(405, 'method_not_allowed', 'The method is not allowed on this resource', 'request'),
} satisfies Record<string, ProblemSpec>);

export type GatewayProblemCode = keyof typeof GATEWAY_PROBLEMS;

/** RFC 9457 problem document. `code` and `at` are extension members. */
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  code: string;
  /** Index in the mandate chain where verification failed (0 is the root), when it applies. */
  at?: number;
}

export function problemFromSpec(s: ProblemSpec, at?: number): ProblemDetails {
  return {
    type: PROBLEM_TYPE_BASE + s.code,
    title: s.title,
    status: s.status,
    code: s.code,
    ...(at !== undefined && Number.isSafeInteger(at) ? { at } : {}),
  };
}

export function isDenyCode(x: unknown): x is DenyCode {
  return typeof x === 'string' && Object.prototype.hasOwnProperty.call(DENY_PROBLEMS, x);
}

/**
 * Resolves the problem specification of a DENY decision. Infrastructure failures have their own codes
 * (`STATUS_UNAVAILABLE`, `INTERNAL`), so the mapping is by code alone. An unknown code (a newer library
 * version) maps to `processing_error`: fail closed, reveal nothing.
 */
export function problemSpecForDecision(d: Extract<Decision, { decision: 'DENY' }>): ProblemSpec {
  if (!isDenyCode(d.code)) return GATEWAY_PROBLEMS.processing_error;
  return DENY_PROBLEMS[d.code];
}

/** The problem document for a DENY decision. Contains neither `reason` nor `detail`. */
export function problemForDecision(d: Extract<Decision, { decision: 'DENY' }>): ProblemDetails {
  return problemFromSpec(problemSpecForDecision(d), d.at);
}

export interface ProblemResponseOptions {
  /** Seconds for `Retry-After` on 503 responses. Default 5. */
  retryAfterSeconds?: number;
  /** Realm in the `WWW-Authenticate` challenge of 401 responses. */
  realm?: string;
}

/**
 * Builds the HTTP response for a problem. 401 responses carry a `WWW-Authenticate: Plenipo` challenge, as
 * RFC 9110 requires; 503 responses carry `Retry-After`. Problems are never cached.
 */
export function problemResponse(p: ProblemDetails, opts: ProblemResponseOptions = {}): Response {
  const headers = new Headers({
    'content-type': PROBLEM_CONTENT_TYPE,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  if (p.status === 401) {
    // Only a plain printable realm is echoed, so configuration cannot inject header syntax.
    const realm = opts.realm && /^[\x20-\x7e]*$/.test(opts.realm) && !/["\\]/.test(opts.realm) ? `realm="${opts.realm}", ` : '';
    headers.set('www-authenticate', `Plenipo ${realm}error="${p.code}"`);
  }
  if (p.status === 503) headers.set('retry-after', String(opts.retryAfterSeconds ?? 5));
  return new Response(JSON.stringify(p), { status: p.status, headers });
}
