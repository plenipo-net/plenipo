/**
 * Profile it-wallet-1 (experimental): mandate requests shaped for the Italian IT-Wallet System.
 *
 * What it follows, from the IT-Wallet technical specification (version 1.4.7, September 2026):
 * - remote flow on OpenID4VP 1.0 with a signed request object, a DCQL query and response_mode
 *   direct_post.jwt, the response encrypted with ECDH-ES on P-256 and AES-GCM;
 * - client identifier prefixes `openid_federation` and `x509_hash`; this profile builds `x509_hash`,
 *   `openid_federation` needs a federation entity and is not implemented yet;
 * - transaction_data as an optional request parameter, its hashes in `transaction_data_hashes` of the
 *   SD-JWT VC key binding JWT, which is how a `plenipo_mandate` is already bound;
 * - PID as SD-JWT VC; the specification's example type is `urn:eudi:pid:it:1`, used here as default.
 *
 * What is not known: whether the IT-Wallet app shows a `plenipo_mandate` to the person and signs it, or
 * refuses the request. Nothing in this profile has run against an Italian wallet. The PID type and the
 * claims may change when the PID data model is confirmed: pass `pidVcts` and `disclose` to override.
 */
import { DEFAULT_CLAIM_PURPOSES, x509HashClientId, type MandateRequestOptions } from './openid4vp.js';
import type { SigningKey } from './signer.js';
import type { Mandate } from './types.js';

export const IT_WALLET_PROFILE = 'it-wallet-1';
/** PID type in the examples of the IT-Wallet specification. Not yet confirmed against an issued PID. */
export const IT_WALLET_PID_VCT = 'urn:eudi:pid:it:1';
/** Client identifier prefixes the IT-Wallet specification allows for relying parties. */
export const IT_WALLET_CLIENT_ID_PREFIXES: readonly string[] = Object.freeze(['openid_federation', 'x509_hash']);
/** Claims asked by default: the names for the record and a stable identifier for the principal. */
export const IT_WALLET_DEFAULT_CLAIMS: readonly string[] = Object.freeze(['given_name', 'family_name', 'personal_administrative_number']);

export interface ItWalletRequestInput {
  mandate: Mandate;
  /** Where the wallet posts its response. */
  responseUri: string;
  /** Signs the request object. The client identifier is the x509_hash of `x5c[0]`. */
  signer: { key: SigningKey; x5c: string[] };
  /** PID claims to request. Default `IT_WALLET_DEFAULT_CLAIMS`. Each needs a purpose. */
  disclose?: string[];
  /** Purposes for claims beyond those Plenipo relies on. */
  claimPurposes?: Record<string, string>;
  /** Accepted PID types. Default `[IT_WALLET_PID_VCT]`. */
  pidVcts?: string[];
  lifetimeSeconds?: number;
}

/**
 * Options for `createMandateRequest` under profile it-wallet-1: x509_hash client identifier from the
 * signing certificate, encrypted response, the Italian PID type, and a stated purpose for every claim.
 */
export function itWalletRequestOptions(input: ItWalletRequestInput): MandateRequestOptions {
  const leaf = input.signer?.x5c?.[0];
  if (!leaf) throw new Error('profile it-wallet-1 needs a signer with its certificate in x5c');
  return {
    mandate: input.mandate,
    clientId: x509HashClientId(leaf),
    responseUri: input.responseUri,
    signer: input.signer,
    encryptResponse: true,
    transactionDataType: 'plenipo_mandate',
    pidVcts: input.pidVcts ?? [IT_WALLET_PID_VCT],
    disclose: input.disclose ?? [...IT_WALLET_DEFAULT_CLAIMS],
    claimPurposes: { ...DEFAULT_CLAIM_PURPOSES, ...(input.claimPurposes ?? {}) },
    requireClaimPurposes: true,
    ...(input.lifetimeSeconds !== undefined ? { lifetimeSeconds: input.lifetimeSeconds } : {}),
  };
}

/** Verifier settings matching the profile: accept the Italian PID type. */
export function itWalletVerifyDefaults(pidVcts: string[] = [IT_WALLET_PID_VCT]): { acceptedPidVcts: string[]; acceptedVcts: string[] } {
  return { acceptedPidVcts: [...pidVcts], acceptedVcts: [...pidVcts] };
}

/**
 * Checks built request parameters against the rules of the Italian remote flow that this profile knows.
 * Returns the problems found; empty means none of these rules is broken, not that a wallet will accept it.
 */
export function itWalletRequestProblems(params: Record<string, unknown>, requestObject?: string): string[] {
  const problems: string[] = [];
  const clientId = params.client_id;
  const prefix = typeof clientId === 'string' ? clientId.slice(0, Math.max(0, clientId.indexOf(':'))) : '';
  if (!IT_WALLET_CLIENT_ID_PREFIXES.includes(prefix)) problems.push(`client_id prefix must be one of ${IT_WALLET_CLIENT_ID_PREFIXES.join(', ')}`);
  if (params.response_mode !== 'direct_post.jwt') problems.push('response_mode must be direct_post.jwt');
  if (params.response_type !== 'vp_token') problems.push('response_type must be vp_token');
  const dcql = params.dcql_query as { credentials?: unknown } | undefined;
  if (!dcql || !Array.isArray(dcql.credentials) || dcql.credentials.length === 0) problems.push('a DCQL query is required');
  else if (dcql.credentials.some((c) => (c as { format?: unknown })?.format !== 'dc+sd-jwt')) problems.push('every credential query must ask for dc+sd-jwt');
  if (typeof params.nonce !== 'string' || params.nonce.length < 16) problems.push('nonce must be a string of at least 16 characters');
  if (!Array.isArray(params.transaction_data) || params.transaction_data.length === 0) problems.push('transaction_data is missing');
  if (typeof requestObject !== 'string' || requestObject.split('.').length !== 3) problems.push('the request object must be signed');
  return problems;
}
