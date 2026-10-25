/**
 * OpenID for Verifiable Presentations 1.0: how an agent platform asks a person's wallet to approve a
 * mandate, and how it turns the wallet's answer into the root of a mandate chain.
 *
 * The request asks for the PID with a DCQL query and carries the mandate as transaction data. The wallet
 * shows the mandate, and on approval returns the PID with a key binding JWT over the transaction data.
 * Responses are encrypted to the platform by default (response_mode direct_post.jwt), as HAIP requires.
 */
import { signCompactJwt, type SigningKey } from './signer.js';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  compactDecrypt,
  exportJWK,
  generateKeyPair,
  type CryptoKey,
  type JWK,
} from 'jose';
import { REPRESENTATION_QUERY_ID, representationQuery } from './legal.js';
import { encodeMandateTransactionData } from './mandate.js';
import type { NonceStore } from './registry.js';
import { checkChainRevocation, TrustError } from './trust.js';
import { checkAttestationCertificates, checkAttestationStatus, checkPidStatus, RootError, SCA_QUERY_ID, verifyRoot, type RootOptions, type RootResult } from './root.js';
import { encodeEmandateTransactionData, mandateToEmandate, type EmandatePayee } from './ts12.js';
import { EMANDATE_TX_DATA_TYPE, PID_VCT, type Mandate, type RootAuthorization } from './types.js';

export const PID_QUERY_ID = 'pid';
export const REQUEST_OBJECT_TYP = 'oauth-authz-req+jwt';

export interface MandateRequestOptions {
  mandate: Mandate;
  /** Client identifier with its prefix, e.g. `x509_san_dns:agents.example` or `redirect_uri:https://…`. */
  clientId: string;
  /** Where the wallet posts its response. */
  responseUri: string;
  /** PID claims to request. Default given_name and family_name. */
  disclose?: string[];
  /** Encrypt the wallet response to this platform. Default true. */
  encryptResponse?: boolean;
  /** Signs the request object. Required by most wallets for x509_san_dns client identifiers. */
  signer?: { key: SigningKey; x5c?: string[] };
  /**
   * `plenipo_mandate` (default): the wallet shows and signs the whole mandate. `emandate`: the wallet shows
   * a TS12 `urn:eudi:sca:emandate:1` summary whose reference_number binds the mandate by hash.
   */
  transactionDataType?: 'plenipo_mandate' | 'emandate';
  /** E-mandate settings, used with `transactionDataType: 'emandate'`. */
  emandate?: {
    /**
     * `sca` (default, as TS12 requires): bind the e-mandate to an SCA attestation from the payer's PSP,
     * requested next to the PID. `pid`: bind it to the PID, for wallets configured to accept that.
     */
    credential?: 'sca' | 'pid';
    /** Accepted SCA attestation types; required with `credential: 'sca'`. */
    scaVcts?: string[];
    /** SCA attestation claims to request, for relying parties that tie it to the PID by `scaIdentityClaims`. */
    scaIdentityClaims?: string[];
    /** Transaction data type; default `urn:eudi:sca:emandate:1`. Use the key the SCA attestation metadata lists. */
    type?: string;
    payee?: EmandatePayee;
    describe?: (mandate: Mandate) => string;
    /** Logo URLs the payee may show; the verifier must allow the same (`emandate.allowedPayeeLogos`). */
    allowedPayeeLogos?: string[];
  };
  /** Representation attestation request, used when the mandate has a legal person `principal`. */
  representation?: { vcts?: string[]; identityClaims?: string[] };
}

/** What the platform keeps between the request and the response. Contains a private key: keep it server-side. */
export interface MandateRequestSession {
  clientId: string;
  nonce: string;
  state: string;
  transactionData: string;
  mandateId: string;
  responseMode: 'direct_post' | 'direct_post.jwt';
  decryptionKey?: CryptoKey;
  createdAt: number;
  /** The mandate, for e-mandate requests: the transaction data only carries its hash. */
  mandate?: Mandate;
  /** DCQL query ids besides `pid` whose presentations the response must contain. */
  extraQueries?: string[];
}

export interface MandateRequest {
  /** Authorization request parameters, as JSON. */
  params: Record<string, unknown>;
  /** Signed request object, when a signer was given: serve it at the request_uri. */
  requestObject?: string;
  session: MandateRequestSession;
}

/** Builds the OpenID4VP authorization request for a mandate. */
export async function createMandateRequest(opts: MandateRequestOptions): Promise<MandateRequest> {
  const nonce = randomBytes(16).toString('base64url');
  const state = randomUUID();
  const emandate = opts.transactionDataType === 'emandate';
  const em = opts.emandate ?? {};
  const bindTo = em.credential ?? SCA_QUERY_ID;
  if (emandate && bindTo === SCA_QUERY_ID && !em.scaVcts?.length) throw new Error('emandate.scaVcts is required to bind an e-mandate to an SCA attestation');
  const transactionData = emandate
    ? encodeEmandateTransactionData(mandateToEmandate(opts.mandate, { payee: em.payee, describe: em.describe, allowedPayeeLogos: em.allowedPayeeLogos }), {
        credentialId: bindTo,
        type: em.type ?? EMANDATE_TX_DATA_TYPE,
      })
    : encodeMandateTransactionData(opts.mandate, PID_QUERY_ID);
  const extraQueries: string[] = [];
  // Identity claims compared with another credential must be disclosed by the PID too.
  const pidClaims = new Set(opts.disclose ?? ['given_name', 'family_name']);
  if (emandate && bindTo === SCA_QUERY_ID) for (const c of em.scaIdentityClaims ?? []) pidClaims.add(c);
  if (opts.mandate.principal) for (const c of opts.representation?.identityClaims ?? []) pidClaims.add(c);
  const queries: Record<string, unknown>[] = [
    {
      id: PID_QUERY_ID,
      format: 'dc+sd-jwt',
      meta: { vct_values: [PID_VCT] },
      claims: [...pidClaims].map((c) => ({ path: [c] })),
    },
  ];
  if (emandate && bindTo === SCA_QUERY_ID) {
    extraQueries.push(SCA_QUERY_ID);
    queries.push({
      id: SCA_QUERY_ID,
      format: 'dc+sd-jwt',
      meta: { vct_values: em.scaVcts },
      ...(em.scaIdentityClaims?.length ? { claims: em.scaIdentityClaims.map((c) => ({ path: [c] })) } : {}),
    });
  }
  if (opts.mandate.principal) {
    extraQueries.push(REPRESENTATION_QUERY_ID);
    queries.push(representationQuery(opts.representation));
  }
  const encrypt = opts.encryptResponse ?? true;

  let decryptionKey: CryptoKey | undefined;
  let encJwk: JWK | undefined;
  if (encrypt) {
    const pair = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    decryptionKey = pair.privateKey;
    const pub = await exportJWK(pair.publicKey);
    encJwk = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y, use: 'enc', alg: 'ECDH-ES', kid: randomUUID() };
  }

  const params: Record<string, unknown> = {
    response_type: 'vp_token',
    client_id: opts.clientId,
    response_mode: encrypt ? 'direct_post.jwt' : 'direct_post',
    response_uri: opts.responseUri,
    nonce,
    state,
    dcql_query: { credentials: queries },
    transaction_data: [transactionData],
    client_metadata: {
      vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] } },
      ...(encJwk ? { jwks: { keys: [encJwk] }, encrypted_response_enc_values_supported: ['A128GCM'] } : {}),
    },
  };

  let requestObject: string | undefined;
  if (opts.signer) {
    requestObject = await signCompactJwt(
      { ...params, aud: 'https://self-issued.me/v2', iat: Math.floor(Date.now() / 1000) },
      { alg: 'ES256', typ: REQUEST_OBJECT_TYP, ...(opts.signer.x5c ? { x5c: opts.signer.x5c } : {}) },
      opts.signer.key,
    );
  }

  return {
    params,
    requestObject,
    session: {
      clientId: opts.clientId,
      nonce,
      state,
      transactionData,
      mandateId: opts.mandate.id,
      responseMode: encrypt ? 'direct_post.jwt' : 'direct_post',
      decryptionKey,
      createdAt: Math.floor(Date.now() / 1000),
      ...(emandate ? { mandate: opts.mandate } : {}),
      ...(extraQueries.length ? { extraQueries } : {}),
    },
  };
}

/** The URL to put in a QR code or a link, for a request object served at `requestUri`. */
export function authorizationRequestUrl(clientId: string, requestUri: string, scheme = 'openid4vp://'): string {
  const q = new URLSearchParams({ client_id: clientId, request_uri: requestUri });
  return `${scheme}?${q.toString()}`;
}

export interface MandateResponseResult {
  root: RootAuthorization;
  verified: RootResult;
}

export interface MandateResponseOptions extends RootOptions {
  /**
   * Marks a request session as used. Required: without it the same wallet response could be redeemed
   * twice. `consume(state)` must return true only the first time; the in-memory nonce store works
   * within one process, a shared store is needed across instances. Use a store of its own, not the
   * invocation nonce store: the state is visible to anyone who sees the request.
   */
  sessions: NonceStore;
  /** How long a request stays valid, in seconds. Default 600. */
  maxAgeSeconds?: number;
}

/** Error codes a wallet may return (OpenID4VP 1.0 and OAuth 2.0); anything else is reported as unknown. */
const WALLET_ERRORS = new Set([
  'access_denied',
  'invalid_request',
  'invalid_client',
  'invalid_scope',
  'invalid_transaction_data',
  'vp_formats_not_supported',
  'invalid_request_uri_method',
  'wallet_unavailable',
  'server_error',
  'temporarily_unavailable',
]);

/**
 * Turns the wallet's POST body into a verified root. Decrypts when required, checks state before
 * anything else, verifies the PID and the key binding, binds the key binding to this request through
 * nonce and audience, and consumes the session so the response cannot be redeemed twice.
 * An error response does not consume the session: anyone who saw the request can post one.
 */
export async function handleMandateResponse(
  body: Record<string, unknown>,
  session: MandateRequestSession,
  opts: MandateResponseOptions,
): Promise<MandateResponseResult> {
  if (!opts?.sessions) throw new RootError('CONFIGURATION', 'a session store is required to prevent replay');
  const sessionRetention = opts.sessions.retentionSeconds;
  if (typeof sessionRetention === 'number' && sessionRetention < (opts.maxAgeSeconds ?? 600)) {
    throw new RootError('CONFIGURATION', 'the session store forgets responses before requests expire');
  }
  if (opts.now - session.createdAt > (opts.maxAgeSeconds ?? 600)) throw new RootError('ROOT_INVALID', 'the request session has expired');

  let payload: Record<string, unknown> = body;
  if (session.responseMode === 'direct_post.jwt') {
    if (typeof body.response !== 'string' || !session.decryptionKey) {
      throw new RootError('MALFORMED', 'an encrypted response was expected');
    }
    try {
      const { plaintext, protectedHeader } = await compactDecrypt(body.response, session.decryptionKey, {
        keyManagementAlgorithms: ['ECDH-ES'],
        contentEncryptionAlgorithms: ['A128GCM', 'A256GCM'],
      });
      if (protectedHeader.alg !== 'ECDH-ES') throw new Error('unexpected alg');
      payload = JSON.parse(new TextDecoder().decode(plaintext));
    } catch (e) {
      throw new RootError('MALFORMED', 'response could not be decrypted', (e as Error).message);
    }
  }
  if (typeof payload !== 'object' || payload === null) throw new RootError('MALFORMED', 'response is not an object');

  if (payload.state !== session.state) throw new RootError('ROOT_INVALID', 'state does not match the request');
  if (payload.error !== undefined) {
    const code = typeof payload.error === 'string' && WALLET_ERRORS.has(payload.error) ? payload.error : 'unknown_error';
    throw new RootError('ROOT_INVALID', `the wallet returned ${code}`);
  }

  const vp = payload.vp_token as Record<string, unknown> | undefined;
  const wanted = [PID_QUERY_ID, ...(session.extraQueries ?? [])];
  const presentations: Record<string, string> = {};
  if (!vp || typeof vp !== 'object' || Array.isArray(vp)) throw new RootError('MALFORMED', 'vp_token must be an object');
  for (const k of Object.keys(vp)) if (!wanted.includes(k)) throw new RootError('MALFORMED', 'vp_token contains an unrequested presentation');
  for (const id of wanted) {
    const list = vp[id];
    if (!Array.isArray(list) || list.length !== 1 || typeof list[0] !== 'string') {
      throw new RootError('MALFORMED', `vp_token must contain exactly one presentation for ${id}`);
    }
    presentations[id] = list[0];
  }

  const root: RootAuthorization = { transaction_data: session.transactionData, presentation: presentations[PID_QUERY_ID] };
  if (session.mandate) root.mandate = session.mandate;
  const extra = Object.fromEntries(Object.entries(presentations).filter(([k]) => k !== PID_QUERY_ID));
  if (Object.keys(extra).length) root.presentations = extra;
  // Everything that needs the network (certificate revocation, status lists) is deferred until the response
  // is known to answer this request: otherwise anyone who saw the request could make this service fetch.
  const verified = await verifyRoot(root, {
    ...opts,
    certificateRevocation: undefined,
    pidStatus: opts.pidStatus === 'skip' ? 'skip' : 'defer',
    attestationStatus: 'defer',
  });
  if (verified.scaResponseMode !== undefined && verified.scaResponseMode !== session.responseMode) {
    throw new RootError('ROOT_INVALID', 'the SCA key binding names another response mode');
  }
  if (verified.mandate.id !== session.mandateId) throw new RootError('TX_DATA_MISMATCH', 'the response is for another mandate');
  if (verified.keyBinding.nonce !== session.nonce) throw new RootError('ROOT_INVALID', 'key binding nonce does not match the request');
  if (verified.keyBinding.aud !== session.clientId) throw new RootError('ROOT_INVALID', 'key binding audience is not this client');
  const revocation = opts.certificateRevocation;
  if (revocation && revocation.policy !== 'off' && verified.pidCertificateChain) {
    try {
      await checkChainRevocation(verified.pidCertificateChain, revocation, opts.now);
    } catch (e) {
      if (e instanceof TrustError) throw new RootError('PID_ISSUER_UNTRUSTED', 'PID provider not trusted', e.message);
      throw e;
    }
  }
  if (verified.pidStatus) {
    await checkPidStatus(verified.pidStatus, verified.pidIssuer, opts);
    delete verified.pidStatus;
  }
  for (const c of verified.deferredCertificates ?? []) await checkAttestationCertificates(c, opts.now);
  delete verified.deferredCertificates;
  for (const d of verified.deferredStatus ?? []) await checkAttestationStatus(d, opts);
  delete verified.deferredStatus;
  if (!(await opts.sessions.consume(`openid4vp:${session.state}`))) {
    throw new RootError('REPLAY', 'this request has already been answered');
  }
  return { root, verified };
}
