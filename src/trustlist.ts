/**
 * Lists of Trusted Entities (ETSI TS 119 602, "LoTE"), the format in which the EU publishes PID providers,
 * wallet providers and attestation providers for the EUDI Wallet.
 *
 * Only the JSON binding signed as a compact JWS (JAdES baseline B in compact serialization) is supported.
 * The list is never fetched by the loader: the caller passes the document and the certificate(s) that are
 * expected to sign it, taken from an authoritative source (the Official Journal publication, or the
 * pointer in the list of lists). XML lists (XAdES) and the EU LOTL (ETSI TS 119 612) are refused with an
 * explicit error.
 */
import 'reflect-metadata';
import { X509Certificate as NodeCert, createHash } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { compactVerify, type JWK } from 'jose';
import { z } from 'zod';
import type { TrustConfig } from './trust.js';
import type { TrustedIssuer } from './types.js';
import { readBodyLimited } from './x509-revocation.js';

/** LoTE types (ETSI TS 119 602 Annex C to I). */
export const LOTE_TYPE = {
  pidProviders: 'http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList',
  walletProviders: 'http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList',
  wrpacProviders: 'http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList',
  wrprcProviders: 'http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList',
  pubEaaProviders: 'http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList',
} as const;

/** Service type identifiers used by the EU LoTE profiles. */
export const LOTE_SERVICE_TYPE = {
  pidIssuance: 'http://uri.etsi.org/19602/SvcType/PID/Issuance',
  pidRevocation: 'http://uri.etsi.org/19602/SvcType/PID/Revocation',
  walletIssuance: 'http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance',
  walletRevocation: 'http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation',
  wrpacIssuance: 'http://uri.etsi.org/19602/SvcType/WRPAC/Issuance',
  wrpacRevocation: 'http://uri.etsi.org/19602/SvcType/WRPAC/Revocation',
  wrprcIssuance: 'http://uri.etsi.org/19602/SvcType/WRPRC/Issuance',
  wrprcRevocation: 'http://uri.etsi.org/19602/SvcType/WRPRC/Revocation',
  pubEaaIssuance: 'http://uri.etsi.org/19602/SvcType/PubEAA/Issuance',
  pubEaaRevocation: 'http://uri.etsi.org/19602/SvcType/PubEAA/Revocation',
} as const;

export class TrustListError extends Error {}

export interface LoadTrustedListOptions {
  /**
   * Certificates (PEM or base64 DER) of whoever may sign this list. The JWS must identify one of them
   * (x5c leaf or x5t#S256) and verify under its key. Required unless `unsigned` is set.
   */
  signerCertificates?: string[];
  /**
   * Accept a plain, unsigned JSON list. For tests and local fixtures only; a signed JWS is never accepted
   * without verifying it.
   */
  unsigned?: 'accept-for-testing';
  /** Current time in seconds; defaults to now. */
  now?: number;
  /** The LoTEType the list must declare, e.g. `LOTE_TYPE.pidProviders`. */
  expectedType?: string;
  /** Refuse a list whose sequence number is lower, to stop a replay of an older, still unexpired list. */
  minSequenceNumber?: number;
  /** Largest NextUpdate - ListIssueDateTime accepted, in seconds. The EU profiles allow six months. */
  maxValiditySeconds?: number;
  /** JWS algorithms accepted. Default ES256, ES384, ES512, PS256, PS384, PS512. */
  algorithms?: string[];
  /** Clock skew tolerated on ListIssueDateTime and sigT, in seconds. Default 300. Never applied to NextUpdate. */
  skewSeconds?: number;
  /** Largest document accepted, in bytes. Default 5 MB. */
  maxBytes?: number;
  /**
   * Require the signing certificate subject to carry C = SchemeTerritory and O = one of the
   * SchemeOperatorName values (ETSI TS 119 602 clause 6.8). Default false.
   */
  requireSignerMatchesOperator?: boolean;
}

export interface TrustedListService {
  names: string[];
  type?: string;
  status?: string;
  statusStartingTime?: number;
  /** Base64 DER X.509 certificates of the service. */
  certificates: string[];
  /** Public keys of the service, as published. */
  publicKeys: JWK[];
  subjectNames: string[];
  /** Subject key identifiers, base64 as published. */
  skis: string[];
  otherIds: string[];
  /** Service supply point URIs (where the service is reached). */
  supplyPoints: string[];
}

export interface TrustedListEntity {
  names: string[];
  tradeNames: string[];
  informationUris: string[];
  services: TrustedListService[];
}

export interface TrustedList {
  type?: string;
  version: number;
  sequenceNumber: number;
  /** Seconds since the epoch. */
  issued: number;
  nextUpdate: number;
  operatorNames: string[];
  territory?: string;
  distributionPoints: string[];
  entities: TrustedListEntity[];
  /** How the list was accepted. */
  verification:
    | { kind: 'jades-compact'; alg: string; signerSubject: string; signerFingerprint256: string; signingTime?: number }
    | { kind: 'unsigned-accepted-for-testing' };
}

// --- schema -----------------------------------------------------------------------------------------------

const MAX_STR = 4096;
const str = z.string().max(MAX_STR);
const localized = z.looseObject({ lang: str, value: str });
const localizedUri = z.looseObject({ lang: str, uriValue: str });
const date = z.string().max(64);
const pkiObject = z.looseObject({ val: z.string().min(1).max(65_536), encoding: str.optional(), specRef: str.optional() });
const digitalIdentity = z.looseObject({
  X509Certificates: z.array(pkiObject).max(64).optional(),
  X509SubjectNames: z.array(str).max(64).optional(),
  PublicKeyValues: z.array(z.record(z.string().max(64), z.unknown())).max(64).optional(),
  X509SKIs: z.array(str).max(64).optional(),
  OtherIds: z.array(str).max(64).optional(),
});
const serviceInformation = z.looseObject({
  ServiceName: z.array(localized).min(1).max(32),
  ServiceDigitalIdentity: digitalIdentity,
  ServiceTypeIdentifier: str.optional(),
  ServiceStatus: str.optional(),
  StatusStartingTime: date.optional(),
  ServiceSupplyPoints: z.array(z.looseObject({ uriValue: str, ServiceType: str.optional() })).max(64).optional(),
});
const entity = z.looseObject({
  TrustedEntityInformation: z.looseObject({
    TEName: z.array(localized).min(1).max(32),
    TETradeName: z.array(localized).max(32).optional(),
    TEInformationURI: z.array(localizedUri).max(64).optional(),
  }),
  TrustedEntityServices: z.array(z.looseObject({ ServiceInformation: serviceInformation })).min(1).max(256),
});
const loteDocument = z.looseObject({
  LoTE: z.looseObject({
    ListAndSchemeInformation: z.looseObject({
      LoTEVersionIdentifier: z.number().int().positive(),
      LoTESequenceNumber: z.number().int().nonnegative(),
      LoTEType: str.optional(),
      SchemeOperatorName: z.array(localized).min(1).max(32),
      SchemeTerritory: str.optional(),
      ListIssueDateTime: date,
      // null marks a closed list (clause 6.3.15); it is refused below.
      NextUpdate: date.nullable(),
      DistributionPoints: z.array(str).max(32).optional(),
    }),
    TrustedEntitiesList: z.array(entity).max(10_000).optional(),
  }),
});

// --- loading ----------------------------------------------------------------------------------------------

const DEFAULT_ALGS = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];
/** JWS header parameters this loader understands in `crit` (JAdES clause 5.2). */
const UNDERSTOOD_CRIT = new Set(['sigT']);

function parseCertificate(c: string): NodeCert {
  const s = c.trim();
  return new NodeCert(s.startsWith('-----BEGIN') ? s : Buffer.from(s, 'base64'));
}

function toSeconds(iso: string, what: string): number {
  // RFC 3339 / xsd:dateTime in UTC, as both bindings use.
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.test(iso)) throw new TrustListError(`${what} is not a date-time`);
  const t = Date.parse(iso);
  if (Number.isNaN(t)) throw new TrustListError(`${what} is not a date-time`);
  return Math.floor(t / 1000);
}

function b64url(s: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new TrustListError('the list is not a compact JWS');
  return Buffer.from(s, 'base64url');
}

/**
 * Verifies and reads a List of Trusted Entities. Throws `TrustListError` unless the list is signed by one
 * of `signerCertificates` (or is plain JSON and `unsigned: 'accept-for-testing'` is set), is well formed
 * within the size bounds, is not closed, and is fresh: issued, and NextUpdate still in the future.
 */
export async function loadTrustedList(document: string | Uint8Array, opts: LoadTrustedListOptions = {}): Promise<TrustedList> {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = opts.skewSeconds ?? 300;
  const maxBytes = opts.maxBytes ?? 5_000_000;
  const size = typeof document === 'string' ? Buffer.byteLength(document) : document?.byteLength;
  if (typeof size !== 'number') throw new TrustListError('the list must be a string or bytes');
  if (size > maxBytes) throw new TrustListError('the list is too large');
  let text: string;
  try {
    text = (typeof document === 'string' ? document : new TextDecoder('utf-8', { fatal: true }).decode(document)).trim();
  } catch {
    throw new TrustListError('the list is not UTF-8');
  }
  if (text.startsWith('<')) {
    throw new TrustListError('XML lists (XAdES, ETSI TS 119 612 or the XML binding of TS 119 602) are not supported');
  }

  let payload: unknown;
  let verification: TrustedList['verification'];
  if (text.startsWith('{')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new TrustListError('the list is not valid JSON');
    }
    if (parsed && typeof parsed === 'object' && 'signatures' in parsed) {
      throw new TrustListError('JWS JSON serialization is not supported; use the compact serialization');
    }
    if (opts.unsigned !== 'accept-for-testing') throw new TrustListError('the list is not signed');
    payload = parsed;
    verification = { kind: 'unsigned-accepted-for-testing' };
  } else {
    const v = await verifyCompact(text, opts, now, skew);
    payload = v.payload;
    verification = v.verification;
  }

  const doc = loteDocument.safeParse(payload);
  if (!doc.success) throw new TrustListError('the list does not follow the LoTE JSON schema');
  const info = doc.data.LoTE.ListAndSchemeInformation;
  if (opts.expectedType !== undefined && info.LoTEType !== opts.expectedType) {
    throw new TrustListError(`the list is of type ${String(info.LoTEType)}, not ${opts.expectedType}`);
  }
  const issued = toSeconds(info.ListIssueDateTime, 'ListIssueDateTime');
  if (issued > now + skew) throw new TrustListError('the list is issued in the future');
  if (info.NextUpdate === null) throw new TrustListError('the list is closed');
  const nextUpdate = toSeconds(info.NextUpdate, 'NextUpdate');
  if (nextUpdate <= now) throw new TrustListError('the list has expired (NextUpdate is past)');
  if (nextUpdate <= issued) throw new TrustListError('the list NextUpdate is not after its issue time');
  if (opts.maxValiditySeconds !== undefined && nextUpdate - issued > opts.maxValiditySeconds) {
    throw new TrustListError('the list validity is longer than allowed');
  }
  if (opts.minSequenceNumber !== undefined && info.LoTESequenceNumber < opts.minSequenceNumber) {
    throw new TrustListError('the list is older than one already seen');
  }
  const operatorNames = info.SchemeOperatorName.map((n) => n.value);
  if (opts.requireSignerMatchesOperator && verification.kind === 'jades-compact') {
    checkSignerNames(verification.signerSubject, info.SchemeTerritory, operatorNames);
  }

  const entities: TrustedListEntity[] = (doc.data.LoTE.TrustedEntitiesList ?? []).map((e) => ({
    names: e.TrustedEntityInformation.TEName.map((n) => n.value),
    tradeNames: (e.TrustedEntityInformation.TETradeName ?? []).map((n) => n.value),
    informationUris: (e.TrustedEntityInformation.TEInformationURI ?? []).map((u) => u.uriValue),
    services: e.TrustedEntityServices.map(({ ServiceInformation: s }) => ({
      names: s.ServiceName.map((n) => n.value),
      type: s.ServiceTypeIdentifier,
      status: s.ServiceStatus,
      statusStartingTime: s.StatusStartingTime !== undefined ? toSeconds(s.StatusStartingTime, 'StatusStartingTime') : undefined,
      certificates: (s.ServiceDigitalIdentity.X509Certificates ?? []).map((c) => c.val),
      publicKeys: (s.ServiceDigitalIdentity.PublicKeyValues ?? []) as JWK[],
      subjectNames: s.ServiceDigitalIdentity.X509SubjectNames ?? [],
      skis: s.ServiceDigitalIdentity.X509SKIs ?? [],
      otherIds: s.ServiceDigitalIdentity.OtherIds ?? [],
      supplyPoints: (s.ServiceSupplyPoints ?? []).map((p) => p.uriValue),
    })),
  }));

  return {
    type: info.LoTEType,
    version: info.LoTEVersionIdentifier,
    sequenceNumber: info.LoTESequenceNumber,
    issued,
    nextUpdate,
    operatorNames,
    territory: info.SchemeTerritory,
    distributionPoints: info.DistributionPoints ?? [],
    entities,
    verification,
  };
}

/**
 * Verifies a compact JWS the way JAdES baseline B needs for a list signed by a pinned certificate:
 * - the protected header names an accepted `alg` and identifies the signing certificate by `x5c` (leaf
 *   first) and/or `x5t#S256`; that certificate must be byte-identical to one of `signerCertificates`;
 * - `crit`, when present, lists only parameters understood here (`sigT`), each present;
 * - `sigT`, when present, is an RFC 3339 UTC time not in the future and within the certificate validity;
 * - `b64: false`, detached payloads (`sigD`) and the `sigX5ts` / `x5t#o` references are refused;
 * - the signing certificate is valid now and, when it has key usage, allows digital signatures;
 * - the signature verifies under the certificate key.
 * Not done: path validation or revocation of the signing certificate (it is pinned instead), timestamps
 * and the higher JAdES levels (T, LT, LTA), signature policies, counter-signatures.
 */
async function verifyCompact(
  jws: string,
  opts: LoadTrustedListOptions,
  now: number,
  skew: number,
): Promise<{ payload: unknown; verification: TrustedList['verification'] }> {
  const signers = opts.signerCertificates ?? [];
  if (signers.length === 0) throw new TrustListError('no signer certificates configured for the list');
  let pinned: NodeCert[];
  try {
    pinned = signers.map(parseCertificate);
  } catch {
    throw new TrustListError('a configured list signer certificate is not valid');
  }
  const parts = jws.split('.');
  if (parts.length !== 3 || parts[1].length === 0) throw new TrustListError('the list is not a compact JWS with an attached payload');
  let header: Record<string, unknown>;
  try {
    header = JSON.parse(b64url(parts[0]).toString('utf8'));
  } catch (e) {
    if (e instanceof TrustListError) throw e;
    throw new TrustListError('the list JWS header is not JSON');
  }
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw new TrustListError('the list JWS header is not an object');

  const algorithms = opts.algorithms ?? DEFAULT_ALGS;
  const alg = header.alg;
  if (typeof alg !== 'string' || !algorithms.includes(alg)) throw new TrustListError('the list signature algorithm is not accepted');
  if (header.b64 !== undefined || header.sigD !== undefined) throw new TrustListError('detached or unencoded list payloads are not supported');
  if (header.sigX5ts !== undefined || header['x5t#o'] !== undefined) {
    throw new TrustListError('sigX5ts and x5t#o certificate references are not supported');
  }
  if (header.crit !== undefined) {
    const crit = header.crit;
    if (!Array.isArray(crit) || crit.length === 0 || !crit.every((c) => typeof c === 'string' && UNDERSTOOD_CRIT.has(c) && header[c] !== undefined)) {
      throw new TrustListError('the list JWS has critical header parameters that are not understood');
    }
  }

  // The signing certificate: named by the header, but accepted only if it is one of the pinned ones.
  let signer: NodeCert | undefined;
  if (header.x5c !== undefined) {
    const x5c = header.x5c;
    if (!Array.isArray(x5c) || x5c.length === 0 || x5c.length > 10 || !x5c.every((c) => typeof c === 'string' && c.length < 65_536)) {
      throw new TrustListError('the list x5c header is malformed');
    }
    let leaf: NodeCert;
    try {
      leaf = new NodeCert(Buffer.from(x5c[0], 'base64'));
    } catch {
      throw new TrustListError('the list x5c header is malformed');
    }
    signer = pinned.find((p) => p.raw.equals(leaf.raw));
    if (!signer) throw new TrustListError('the list is signed by a certificate that is not an expected list signer');
  }
  if (header['x5t#S256'] !== undefined) {
    const t = header['x5t#S256'];
    if (typeof t !== 'string') throw new TrustListError('the list x5t#S256 header is malformed');
    const byThumb = pinned.find((p) => createHash('sha256').update(p.raw).digest('base64url') === t);
    if (!byThumb || (signer && !signer.raw.equals(byThumb.raw))) {
      throw new TrustListError('the list is signed by a certificate that is not an expected list signer');
    }
    signer = byThumb;
  }
  if (!signer) throw new TrustListError('the list does not identify its signing certificate (x5c or x5t#S256)');

  const from = signer.validFromDate.getTime() / 1000;
  const to = signer.validToDate.getTime() / 1000;
  if (now < from || now > to) throw new TrustListError('the list signer certificate is not valid now');
  const ku = new x509.X509Certificate(signer.raw).getExtension(x509.KeyUsagesExtension)?.usages;
  if (ku !== undefined && !(ku & (x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation))) {
    throw new TrustListError('the list signer certificate may not sign');
  }

  let signingTime: number | undefined;
  if (header.sigT !== undefined) {
    if (typeof header.sigT !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(header.sigT)) {
      throw new TrustListError('the list sigT header is malformed');
    }
    signingTime = toSeconds(header.sigT, 'sigT');
    if (signingTime > now + skew) throw new TrustListError('the list claims to be signed in the future');
    if (signingTime < from || signingTime > to) throw new TrustListError('the list was signed outside the signer certificate validity');
  }

  let payload: unknown;
  try {
    const res = await compactVerify(jws, signer.publicKey, { algorithms, crit: { sigT: true } });
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(res.payload));
  } catch {
    throw new TrustListError('the list signature does not verify');
  }
  return {
    payload,
    verification: {
      kind: 'jades-compact',
      alg,
      signerSubject: signer.subject,
      signerFingerprint256: signer.fingerprint256,
      ...(signingTime !== undefined ? { signingTime } : {}),
    },
  };
}

function checkSignerNames(subject: string, territory: string | undefined, operatorNames: string[]): void {
  const attrs = new Map<string, string[]>();
  for (const line of subject.split('\n')) {
    const i = line.indexOf('=');
    if (i <= 0) continue;
    const k = line.slice(0, i);
    attrs.set(k, [...(attrs.get(k) ?? []), line.slice(i + 1)]);
  }
  if (!territory || !(attrs.get('C') ?? []).includes(territory)) throw new TrustListError('the list signer country does not match the scheme territory');
  if (!(attrs.get('O') ?? []).some((o) => operatorNames.includes(o))) throw new TrustListError('the list signer organisation is not the scheme operator');
}

// --- trust configuration ----------------------------------------------------------------------------------

export interface ListedServicesOptions {
  /** Service type identifiers to take, e.g. `[LOTE_SERVICE_TYPE.pidIssuance]`. */
  serviceTypes: string[];
  /**
   * ServiceStatus URIs that count as active. The EU LoTE profiles carry no status (a listed service is
   * trusted), so services without a status are always taken; a service with a status is taken only when
   * its status is listed here. Default none.
   */
  acceptedStatuses?: string[];
  /** Current time in seconds, to skip statuses that start in the future. */
  now?: number;
}

export interface ListedService extends TrustedListService {
  entityNames: string[];
  entityInformationUris: string[];
}

/** The services of the given types that are currently active in the lists. */
export function listedServices(lists: TrustedList | TrustedList[], opts: ListedServicesOptions): ListedService[] {
  if (!Array.isArray(opts?.serviceTypes) || opts.serviceTypes.length === 0) throw new TrustListError('serviceTypes is required');
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const out: ListedService[] = [];
  for (const list of Array.isArray(lists) ? lists : [lists]) {
    for (const e of list.entities) {
      for (const s of e.services) {
        if (!s.type || !opts.serviceTypes.includes(s.type)) continue;
        if (s.status !== undefined && !(opts.acceptedStatuses ?? []).includes(s.status)) continue;
        if (s.statusStartingTime !== undefined && s.statusStartingTime > now) continue;
        out.push({ ...s, entityNames: e.names, entityInformationUris: e.informationUris });
      }
    }
  }
  return out;
}

export interface TrustConfigFromListsOptions extends ListedServicesOptions {
  /** Settings to keep (policies, EKUs, status origins, revocation); the anchors and issuers are added. */
  base?: TrustConfig;
  /**
   * Also trust the published public keys (PublicKeyValues) as `trustedIssuers`, each for the service supply
   * point URIs of its service, which must then equal the `iss` of what it signs. Default false: a supply
   * point is where a service is reached, which is not always the credential issuer identifier.
   */
  publicKeysAsIssuersOfSupplyPoints?: boolean;
}

/**
 * Builds a `TrustConfig` from verified lists: every certificate of a matching service becomes a trust
 * anchor (a CA vouches for what it issues, a non-CA certificate only for itself). The signer must still
 * present an x5c chain whose leaf names the expected identity, as with hand-configured anchors.
 */
export function trustConfigFromLists(lists: TrustedList | TrustedList[], opts: TrustConfigFromListsOptions): TrustConfig {
  const services = listedServices(lists, opts);
  const anchors = new Map<string, string>();
  const issuers: TrustedIssuer[] = [...(opts.base?.trustedIssuers ?? [])];
  for (const s of services) {
    for (const c of s.certificates) {
      let cert: NodeCert;
      try {
        cert = new NodeCert(Buffer.from(c, 'base64'));
      } catch {
        continue; // An unreadable entry grants nothing.
      }
      anchors.set(cert.fingerprint256, cert.toString());
    }
    if (opts.publicKeysAsIssuersOfSupplyPoints) {
      for (const jwk of s.publicKeys) {
        const pub = publicEcKey(jwk);
        if (!pub) continue;
        for (const iss of s.supplyPoints) if (iss.startsWith('https://')) issuers.push({ iss, jwk: pub });
      }
    }
  }
  const out: TrustConfig = { ...(opts.base ?? {}), trustAnchors: [...(opts.base?.trustAnchors ?? []), ...anchors.values()] };
  if (issuers.length) out.trustedIssuers = issuers;
  return out;
}

/** Only P-256 public keys are usable for PIDs; anything carrying private material is ignored. */
function publicEcKey(jwk: JWK): JWK | undefined {
  if (!jwk || typeof jwk !== 'object' || 'd' in jwk) return undefined;
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return undefined;
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

// --- optional fetch ---------------------------------------------------------------------------------------

export interface FetchTrustedListOptions {
  /** Default 10 000 ms. */
  timeoutMs?: number;
  /** Default 5 MB. */
  maxBytes?: number;
}

/**
 * Downloads a list document: HTTPS only, no redirects, bounded time and size. The result still has to go
 * through `loadTrustedList`; fetching proves nothing about the list.
 */
export async function fetchTrustedList(url: string, opts: FetchTrustedListOptions = {}): Promise<Uint8Array> {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new TrustListError('the list URL is not valid');
  }
  if (u.protocol !== 'https:' || u.username || u.password) throw new TrustListError('lists are fetched over https only');
  const res = await fetch(u, {
    headers: { accept: 'application/jwt, application/json;q=0.5' },
    redirect: 'error',
    signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
  });
  if (!res.ok) throw new TrustListError(`the list server returned HTTP ${res.status}`);
  return readBodyLimited(res, opts.maxBytes ?? 5_000_000, 'trusted list');
}
