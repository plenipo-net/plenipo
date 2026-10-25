/**
 * How a mandate chain and an invocation travel in an HTTP request.
 *
 *   Plenipo-Chain: base64url(UTF-8 JSON of the MandateChain), unpadded
 *   Plenipo-Invocation: the invocation compact JWS
 *
 * Both values are hostile input: sizes are checked before decoding, the encoding is strict, and the
 * decoded chain must have exactly the MandateChain shape. Everything else is left to verifyAuthorization.
 */
import type { MandateChain } from '../types.js';
import { GATEWAY_PROBLEMS, type ProblemSpec } from './errors.js';

export const CHAIN_HEADER = 'plenipo-chain';
export const INVOCATION_HEADER = 'plenipo-invocation';

export const DEFAULT_MAX_CHAIN_HEADER_BYTES = 64 * 1024;
export const DEFAULT_MAX_INVOCATION_HEADER_BYTES = 8 * 1024;

const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const COMPACT_JWS_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
/** A delegation: a compact JWS, or a Delegate SD-JWT (`<jwt>~<disclosure>~`); the verifier checks the exact profile. */
const DELEGATION_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(~[A-Za-z0-9_-]+)*~?$/;
const MAX_DELEGATIONS = 5;
/** Further presentations a root may carry (TS12 SCA attestation, representation attestation), and their size cap. */
const ROOT_PRESENTATION_IDS = ['sca', 'representation'];
const MAX_ROOT_PRESENTATION_CHARS = 64 * 1024;

export interface HeaderLimits {
  /** Maximum length of the Plenipo-Chain header value, in bytes. Default 64 KiB. */
  maxChainHeaderBytes?: number;
  /** Maximum length of the Plenipo-Invocation header value, in bytes. Default 8 KiB. */
  maxInvocationHeaderBytes?: number;
}

export type ParsedAuthorization =
  | { ok: true; chain: MandateChain; invocation: string }
  | { ok: false; problem: ProblemSpec; /** Internal reason, for the audit log only. */ reason: string };

function fail(problem: ProblemSpec, reason: string): ParsedAuthorization {
  return { ok: false, problem, reason };
}

/** Encodes a chain for the Plenipo-Chain header. */
export function encodeChainHeader(chain: MandateChain): string {
  return Buffer.from(JSON.stringify({ root: chain.root, delegations: chain.delegations }), 'utf8').toString('base64url');
}

/** Builds the two request headers an agent sends. */
export function authorizationHeaders(chain: MandateChain, invocation: string): Record<string, string> {
  return { 'Plenipo-Chain': encodeChainHeader(chain), 'Plenipo-Invocation': invocation };
}

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function hasExactly(o: Record<string, unknown>, keys: string[]): boolean {
  const own = Object.keys(o);
  return own.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));
}

/**
 * Checks that a decoded value is exactly a MandateChain: no extra members, strings where strings belong.
 * The root may also carry `mandate` (an object, for TS12 e-mandate roots) and `presentations` (only `sca`
 * and `representation`, as strings); their content is verified by verifyAuthorization.
 */
export function asMandateChain(x: unknown): MandateChain | undefined {
  if (!isPlainObject(x) || !hasExactly(x, ['root', 'delegations'])) return undefined;
  const root = x.root;
  if (!isPlainObject(root)) return undefined;
  const keys = ['transaction_data', 'presentation', ...['mandate', 'presentations'].filter((k) => Object.prototype.hasOwnProperty.call(root, k))];
  if (!hasExactly(root, keys)) return undefined;
  if (typeof root.transaction_data !== 'string' || typeof root.presentation !== 'string') return undefined;
  const out: MandateChain['root'] = { transaction_data: root.transaction_data, presentation: root.presentation };
  if (root.mandate !== undefined) {
    if (!isPlainObject(root.mandate)) return undefined;
    out.mandate = root.mandate as unknown as NonNullable<MandateChain['root']['mandate']>;
  }
  if (root.presentations !== undefined) {
    const p = root.presentations;
    if (!isPlainObject(p) || Object.keys(p).length === 0) return undefined;
    const copy: Record<string, string> = {};
    for (const [k, v] of Object.entries(p)) {
      if (!ROOT_PRESENTATION_IDS.includes(k) || typeof v !== 'string' || v.length === 0 || v.length > MAX_ROOT_PRESENTATION_CHARS) return undefined;
      copy[k] = v;
    }
    out.presentations = copy;
  }
  const d = x.delegations;
  if (!Array.isArray(d) || d.length > MAX_DELEGATIONS || !d.every((s) => typeof s === 'string' && DELEGATION_RE.test(s))) return undefined;
  return { root: out, delegations: [...d] };
}

/**
 * Reads and decodes the authorization headers. A repeated header arrives joined with ", " and fails the
 * strict encoding check, so an intermediary cannot append a second chain.
 */
export function parseAuthorizationHeaders(headers: Headers, limits: HeaderLimits = {}): ParsedAuthorization {
  const maxChain = limits.maxChainHeaderBytes ?? DEFAULT_MAX_CHAIN_HEADER_BYTES;
  const maxInv = limits.maxInvocationHeaderBytes ?? DEFAULT_MAX_INVOCATION_HEADER_BYTES;
  const chainValue = headers.get(CHAIN_HEADER);
  const invocation = headers.get(INVOCATION_HEADER);
  if (chainValue === null || invocation === null) {
    return fail(GATEWAY_PROBLEMS.authorization_required, 'missing Plenipo-Chain or Plenipo-Invocation header');
  }
  // Header values are ISO-8859-1 at most, and the accepted alphabet is ASCII, so length is bytes.
  if (chainValue.length > maxChain) return fail(GATEWAY_PROBLEMS.header_too_large, `Plenipo-Chain is longer than ${maxChain} bytes`);
  if (invocation.length > maxInv) return fail(GATEWAY_PROBLEMS.header_too_large, `Plenipo-Invocation is longer than ${maxInv} bytes`);
  if (!B64URL_RE.test(chainValue)) return fail(GATEWAY_PROBLEMS.malformed_authorization, 'Plenipo-Chain is not unpadded base64url');
  if (!COMPACT_JWS_RE.test(invocation)) return fail(GATEWAY_PROBLEMS.malformed_authorization, 'Plenipo-Invocation is not a compact JWS');
  const bytes = Buffer.from(chainValue, 'base64url');
  // Round-trip check: Node's decoder skips characters it cannot place, which would make two encodings equal.
  if (bytes.toString('base64url') !== chainValue) return fail(GATEWAY_PROBLEMS.malformed_authorization, 'Plenipo-Chain is not canonical base64url');
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return fail(GATEWAY_PROBLEMS.malformed_authorization, 'Plenipo-Chain is not UTF-8 JSON');
  }
  const chain = asMandateChain(decoded);
  if (!chain) return fail(GATEWAY_PROBLEMS.malformed_authorization, 'Plenipo-Chain does not have the MandateChain shape');
  return { ok: true, chain, invocation };
}
