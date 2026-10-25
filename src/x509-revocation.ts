/**
 * Certificate revocation checking for x5c chains: CRLs (RFC 5280) and OCSP (RFC 6960).
 *
 * It runs only on a chain that has already been validated to a trust anchor by `verifyX5c`, so every URL it
 * may contact was put in a certificate by a trusted CA, not by whoever presented the chain. The anchor
 * itself is never checked here: its status is the trusted list's business.
 */
import 'reflect-metadata';
import { createHash, randomBytes, verify as cryptoVerify, X509Certificate as NodeCert, type KeyObject } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { AlgorithmIdentifier, CertificateList, Extension, IssuingDistributionPoint } from '@peculiar/asn1-x509';
import {
  BasicOCSPResponse,
  CertID,
  OCSPRequest,
  OCSPResponse,
  OCSPResponseStatus,
  Request,
  TBSRequest,
  id_kp_OCSPSigning,
  id_pkix_ocsp_basic,
  id_pkix_ocsp_nonce,
} from '@peculiar/asn1-ocsp';

/**
 * - `off`: no check (the default, as in earlier versions).
 * - `soft-fail`: a revoked certificate is rejected; a certificate whose status cannot be obtained (no URL,
 *   no fetcher, network or HTTP error, responder busy) is accepted.
 * - `hard-fail`: every certificate below the anchor must be proven good by a valid CRL or OCSP response.
 *   Recommended for production.
 *
 * In both checking modes, a response that was obtained but does not verify (bad signature, wrong
 * responder, stale, OCSP `unknown`, nonce mismatch) is a rejection, not an unavailability.
 */
export type RevocationPolicy = 'off' | 'soft-fail' | 'hard-fail';

/**
 * Fetches revocation data. A custom fetcher must bound time and size and must not follow redirects,
 * like `httpRevocationFetcher`.
 */
export interface RevocationFetcher {
  /** GETs a CRL from a CRL distribution point URL. */
  crl(url: string): Promise<Uint8Array>;
  /** POSTs a DER OCSP request to a responder URL and returns the DER response. */
  ocsp(url: string, request: Uint8Array): Promise<Uint8Array>;
}

export interface CertificateRevocationOptions {
  policy: RevocationPolicy;
  /** How CRLs and OCSP responses are obtained. Without it nothing is fetched: only `crls` and the cache count. */
  fetcher?: RevocationFetcher;
  /** CRLs (DER bytes, or PEM) obtained out of band. They are verified like fetched ones. */
  crls?: Array<string | Uint8Array>;
  /** Shared cache of verified statuses and CRLs, kept until their nextUpdate. */
  cache?: RevocationCache;
  /** Methods in the order they are tried. Default `['ocsp', 'crl']`. */
  methods?: Array<'ocsp' | 'crl'>;
  /** Send a nonce in OCSP requests and require it back. Default false: many responders serve pre-signed responses. */
  ocspNonce?: boolean;
  /** Clock skew tolerated on thisUpdate and producedAt, in seconds. Default 300. Never applied to nextUpdate. */
  skewSeconds?: number;
  /** Maximum age of an OCSP response without nextUpdate, in seconds. Default 3600. */
  maxAgeWithoutNextUpdate?: number;
  /** Largest CRL accepted, in bytes. Default 10 MB. */
  maxCrlBytes?: number;
}

export class RevocationError extends Error {
  constructor(
    message: string,
    /** `revoked`: a valid CRL or OCSP response says so. `invalid`: revocation data failed verification. `unavailable`: no status could be obtained (hard-fail only). */
    readonly reason: 'revoked' | 'invalid' | 'unavailable' | 'configuration',
  ) {
    super(message);
  }
}

export interface RevocationReport {
  certificates: Array<{
    subject: string;
    /** `undetermined` only under soft-fail. */
    status: 'good' | 'undetermined';
    via?: 'ocsp' | 'crl' | 'cache';
    /** Why the status is undetermined. */
    detail?: string;
  }>;
}

/**
 * Remembers verified statuses (per issuer and serial) and verified CRLs (per issuer and URL) until their
 * nextUpdate. Bounded: the oldest entries are dropped first.
 */
/**
 * How a cached status was obtained. A status is served only to a check whose options it satisfies: an OCSP
 * answer without a nonce is not served to a check that requires one, an answer without nextUpdate is
 * re-aged with the requesting `maxAgeWithoutNextUpdate`, and a status is not served to a check that does
 * not allow the method it came from.
 */
export interface CachedStatusInfo {
  via: 'ocsp' | 'crl';
  /** True when the OCSP request carried a nonce and the response echoed it. */
  ocspNonce: boolean;
  /** thisUpdate of an OCSP response without nextUpdate, in seconds. */
  thisUpdate?: number;
}

export class RevocationCache {
  private readonly statuses = new Map<string, { status: 'good' | 'revoked'; until: number; info?: CachedStatusInfo }>();
  private readonly crls = new Map<string, { crl: VerifiedCrl; until: number }>();
  constructor(
    private readonly maxStatuses = 10_000,
    private readonly maxCrls = 64,
  ) {}

  /**
   * Returns a cached status. With `accept`, a cached `good` is returned only when `accept` approves how it
   * was obtained (an entry stored without that information never is); `revoked` is always returned.
   */
  getStatus(key: string, now: number, accept?: (info: CachedStatusInfo | undefined) => boolean): 'good' | 'revoked' | undefined {
    const e = this.statuses.get(key);
    if (!e) return undefined;
    if (e.until <= now) {
      this.statuses.delete(key);
      return undefined;
    }
    if (e.status === 'good' && accept && !accept(e.info)) return undefined;
    return e.status;
  }

  setStatus(key: string, status: 'good' | 'revoked', until: number, info?: CachedStatusInfo): void {
    bounded(this.statuses, this.maxStatuses);
    this.statuses.set(key, { status, until, ...(info ? { info } : {}) });
  }

  /** @internal */
  getCrl(key: string, now: number): VerifiedCrl | undefined {
    const e = this.crls.get(key);
    if (!e) return undefined;
    if (e.until <= now) {
      this.crls.delete(key);
      return undefined;
    }
    return e.crl;
  }

  /** @internal */
  setCrl(key: string, crl: VerifiedCrl, until: number): void {
    bounded(this.crls, this.maxCrls);
    this.crls.set(key, { crl, until });
  }
}

/** Whether a cached `good` status satisfies the options of the check asking for it. */
function cachedStatusAcceptable(
  info: CachedStatusInfo | undefined,
  opts: CertificateRevocationOptions,
  methods: Array<'ocsp' | 'crl'>,
  now: number,
): boolean {
  if (!info || !methods.includes(info.via)) return false;
  if (info.via === 'ocsp') {
    if (opts.ocspNonce && !info.ocspNonce) return false;
    if (info.thisUpdate !== undefined && now - info.thisUpdate > (opts.maxAgeWithoutNextUpdate ?? 3600)) return false;
  }
  return true;
}

function bounded(map: Map<string, unknown>, max: number): void {
  while (map.size >= max) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) return;
    map.delete(oldest);
  }
}

// ---------------------------------------------------------------------------------------------------------
// HTTP fetcher

/** Reads a response body, refusing more than `max` bytes. */
export async function readBodyLimited(res: Response, max: number, what: string): Promise<Uint8Array> {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > max) throw new Error(`${what} is too large`);
  const reader = res.body?.getReader();
  if (!reader) throw new Error(`${what} has no body`);
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      throw new Error(`${what} is too large`);
    }
    chunks.push(value);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

export interface HttpRevocationFetcherOptions {
  /** Per request. Default 5000 ms. */
  timeoutMs?: number;
  /** Default 10 MB. */
  maxCrlBytes?: number;
  /** Default 64 KB. */
  maxOcspBytes?: number;
  /**
   * Allow plain `http:`. Default true: CRLs and OCSP responses are signed, and RFC 5280 recommends http
   * distribution points. Set false to require https.
   */
  allowHttp?: boolean;
  /** When set, only these host names may be contacted. */
  allowedHosts?: string[];
}

/**
 * A fetcher for CRL distribution points and OCSP responders: http(s) only, no redirects, bounded time and
 * size. Network access happens only when a verifier is configured with it.
 */
export function httpRevocationFetcher(o: HttpRevocationFetcherOptions = {}): RevocationFetcher {
  const timeout = o.timeoutMs ?? 5_000;
  const check = (raw: string): URL => {
    const u = new URL(raw);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (o.allowHttp ?? true))) {
      throw new Error('revocation data is fetched over http(s) only');
    }
    if (u.username || u.password) throw new Error('revocation URLs with credentials are refused');
    if (o.allowedHosts && !o.allowedHosts.includes(u.hostname)) throw new Error('revocation host is not allowed');
    return u;
  };
  return {
    async crl(url) {
      const res = await fetch(check(url), { redirect: 'error', signal: AbortSignal.timeout(timeout) });
      if (!res.ok) throw new Error(`CRL distribution point returned HTTP ${res.status}`);
      return readBodyLimited(res, o.maxCrlBytes ?? 10_000_000, 'CRL');
    },
    async ocsp(url, request) {
      const res = await fetch(check(url), {
        method: 'POST',
        headers: { 'content-type': 'application/ocsp-request', accept: 'application/ocsp-response' },
        body: Buffer.from(request),
        redirect: 'error',
        signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok) throw new Error(`OCSP responder returned HTTP ${res.status}`);
      return readBodyLimited(res, o.maxOcspBytes ?? 65_536, 'OCSP response');
    },
  };
}

// ---------------------------------------------------------------------------------------------------------
// Certificates

interface Cert {
  der: Buffer;
  node: NodeCert;
  px: x509.X509Certificate;
  /** INTEGER content of the serial number, without leading zero bytes, as hex. */
  serial: string;
  serialRaw: Buffer;
  issuerName: Buffer;
  subjectName: Buffer;
  /** Contents of the subjectPublicKey BIT STRING. */
  keyBits: Buffer;
  /** SHA-256 of the DER, hex. */
  id: string;
}

interface Tlv {
  tag: number;
  start: number;
  body: number;
  end: number;
}

/** A minimal DER reader, used to take exact bytes (names, key, serial) out of certificates. */
function tlv(buf: Uint8Array, pos: number, limit: number): Tlv {
  if (pos + 2 > limit) throw new Error('truncated DER');
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) throw new Error('unsupported DER tag');
  let len = buf[pos + 1];
  let p = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > limit) throw new Error('bad DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
  }
  if (p + len > limit) throw new Error('truncated DER');
  return { tag, start: pos, body: p, end: p + len };
}

function children(buf: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let p = t.body; p < t.end; ) {
    const c = tlv(buf, p, t.end);
    out.push(c);
    p = c.end;
    if (out.length > 32) throw new Error('too many DER elements');
  }
  return out;
}

function normSerial(b: Uint8Array): string {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return Buffer.from(b.subarray(i)).toString('hex');
}

function parseCert(der: Buffer): Cert {
  const node = new NodeCert(der);
  const px = new x509.X509Certificate(node.raw);
  const outer = tlv(der, 0, der.length);
  const tbs = children(der, outer)[0];
  let f = children(der, tbs);
  if (f[0].tag === 0xa0) f = f.slice(1);
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  const [serial, , issuer, , subject, spki] = f;
  const bits = children(der, spki)[1];
  if (bits.tag !== 0x03 || der[bits.body] !== 0) throw new Error('bad subjectPublicKey');
  const serialRaw = Buffer.from(der.subarray(serial.body, serial.end));
  return {
    der,
    node,
    px,
    serial: normSerial(serialRaw),
    serialRaw,
    issuerName: Buffer.from(der.subarray(issuer.start, issuer.end)),
    subjectName: Buffer.from(der.subarray(subject.start, subject.end)),
    keyBits: Buffer.from(der.subarray(bits.body + 1, bits.end)),
    id: createHash('sha256').update(der).digest('hex'),
  };
}

function validAt(c: Cert, now: number): boolean {
  const t = now * 1000;
  return c.node.validFromDate.getTime() <= t && t <= c.node.validToDate.getTime();
}

function isCa(c: Cert): boolean {
  return c.px.getExtension(x509.BasicConstraintsExtension)?.ca === true;
}

function uris(names: Array<{ uniformResourceIdentifier?: string }> | undefined): string[] {
  return (names ?? []).map((n) => n.uniformResourceIdentifier).filter((u): u is string => typeof u === 'string');
}

function fetchable(u: string): boolean {
  return /^https?:\/\//i.test(u) && u.length <= 2048;
}

function ocspUrls(c: Cert): string[] {
  const aia = c.px.getExtension(x509.AuthorityInfoAccessExtension);
  return (aia?.ocsp ?? []).filter((g) => g.type === 'url').map((g) => g.value).filter(fetchable);
}

/** Distribution point URIs this CA itself issues CRLs for (points with a separate cRLIssuer are indirect). */
function crlUrls(c: Cert): string[] {
  const ext = c.px.getExtension(x509.CRLDistributionPointsExtension);
  const out: string[] = [];
  for (const dp of ext?.distributionPoints ?? []) {
    if (dp.cRLIssuer || dp.reasons) continue;
    out.push(...uris(dp.distributionPoint?.fullName));
  }
  return out.filter(fetchable);
}

const sha = (alg: string, data: Uint8Array): Buffer => createHash(alg).update(data).digest();

/** Signature algorithms accepted on CRLs and OCSP responses, and the key type each needs. */
const SIG_ALGS: Record<string, { hash: string | null; key: string }> = {
  '1.2.840.10045.4.3.2': { hash: 'sha256', key: 'ec' },
  '1.2.840.10045.4.3.3': { hash: 'sha384', key: 'ec' },
  '1.2.840.10045.4.3.4': { hash: 'sha512', key: 'ec' },
  '1.2.840.113549.1.1.11': { hash: 'sha256', key: 'rsa' },
  '1.2.840.113549.1.1.12': { hash: 'sha384', key: 'rsa' },
  '1.2.840.113549.1.1.13': { hash: 'sha512', key: 'rsa' },
  '1.3.101.112': { hash: null, key: 'ed25519' },
};

function verifySig(alg: AlgorithmIdentifier, data: ArrayBuffer, sig: ArrayBuffer, key: KeyObject): boolean {
  const a = SIG_ALGS[alg.algorithm];
  if (!a || key.asymmetricKeyType !== a.key) return false;
  try {
    return cryptoVerify(a.hash, Buffer.from(data), key, Buffer.from(sig));
  } catch {
    return false;
  }
}

function parseDer<T>(bytes: Uint8Array, type: new () => T, maxBytes: number): T {
  if (bytes.byteLength > maxBytes) throw new Error('too large');
  // A DER node takes at least two bytes, so this bound never rejects a well-formed input.
  const maxNodes = Math.ceil(bytes.byteLength / 2) + 16;
  return AsnConvert.parse(bytes, type, { berOptions: { maxDepth: 32, maxNodes, maxContentLength: maxBytes } } as never);
}

const same = (a: ArrayBuffer | Uint8Array, b: ArrayBuffer | Uint8Array): boolean => Buffer.from(a as ArrayBuffer).equals(Buffer.from(b as ArrayBuffer));

// ---------------------------------------------------------------------------------------------------------
// Checking

type Outcome =
  | {
      kind: 'good' | 'revoked';
      via: 'ocsp' | 'crl' | 'cache';
      until?: number;
      /** OCSP only: the response echoed the request nonce. */
      nonce?: boolean;
      /** OCSP only, when the response has no nextUpdate. */
      thisUpdate?: number;
    }
  | { kind: 'unavailable' | 'invalid'; reason: string }
  | { kind: 'not-applicable' };

interface Ctx {
  opts: CertificateRevocationOptions;
  now: number;
  skew: number;
  supplied: Uint8Array[];
}

/**
 * Checks the revocation status of every certificate of a validated chain (leaf first, base64 DER, ending
 * with the anchor that validated it). Each certificate is checked against the next one as its issuer.
 * Throws `RevocationError` when a certificate is revoked, when revocation data fails verification, or
 * (under hard-fail) when a status cannot be obtained.
 */
export async function checkCertificateRevocation(
  chain: string[],
  opts: CertificateRevocationOptions,
  now: number,
): Promise<RevocationReport> {
  if (!opts || !['off', 'soft-fail', 'hard-fail'].includes(opts.policy)) {
    throw new RevocationError('certificate revocation policy must be off, soft-fail or hard-fail', 'configuration');
  }
  const report: RevocationReport = { certificates: [] };
  if (opts.policy === 'off') return report;
  if (!Array.isArray(chain) || chain.length === 0 || chain.length > 6) throw new RevocationError('the chain to check is malformed', 'configuration');
  const methods = opts.methods ?? ['ocsp', 'crl'];
  if (methods.length === 0 || methods.some((m) => m !== 'ocsp' && m !== 'crl')) {
    throw new RevocationError('revocation methods must be ocsp and/or crl', 'configuration');
  }
  let certs: Cert[];
  try {
    certs = chain.map((c) => parseCert(Buffer.from(c, 'base64')));
  } catch {
    throw new RevocationError('the chain to check contains an invalid certificate', 'configuration');
  }
  const ctx: Ctx = {
    opts,
    now,
    skew: opts.skewSeconds ?? 300,
    supplied: (opts.crls ?? []).map(toDer),
  };

  for (let i = 0; i < certs.length - 1; i++) {
    const cert = certs[i];
    const issuer = certs[i + 1];
    const subject = cert.node.subject.replace(/\n/g, ', ');
    const key = `${issuer.id}:${cert.serial}`;
    const cached = opts.cache?.getStatus(key, now, (info) => cachedStatusAcceptable(info, opts, methods, now));
    if (cached === 'revoked') throw new RevocationError(`certificate ${subject} is revoked`, 'revoked');
    if (cached === 'good') {
      report.certificates.push({ subject, status: 'good', via: 'cache' });
      continue;
    }
    const problems: Outcome[] = [];
    let decided: Outcome | undefined;
    for (const m of methods) {
      const o = m === 'ocsp' ? await viaOcsp(cert, issuer, ctx) : await viaCrl(cert, issuer, ctx);
      if (o.kind === 'good' || o.kind === 'revoked') {
        decided = o;
        break;
      }
      problems.push(o);
    }
    if (decided && (decided.kind === 'good' || decided.kind === 'revoked')) {
      if (opts.cache && decided.until !== undefined && decided.via !== 'cache') {
        opts.cache.setStatus(key, decided.kind, decided.until, {
          via: decided.via,
          ocspNonce: decided.nonce === true,
          ...(decided.thisUpdate !== undefined ? { thisUpdate: decided.thisUpdate } : {}),
        });
      }
      if (decided.kind === 'revoked') throw new RevocationError(`certificate ${subject} is revoked`, 'revoked');
      report.certificates.push({ subject, status: 'good', via: decided.via });
      continue;
    }
    const invalid = problems.find((p) => p.kind === 'invalid') as { reason: string } | undefined;
    if (invalid) throw new RevocationError(`revocation data for ${subject} is not valid: ${invalid.reason}`, 'invalid');
    const reasons = problems.map((p) => ('reason' in p ? p.reason : 'not applicable')).join('; ');
    if (opts.policy === 'hard-fail') throw new RevocationError(`the revocation status of ${subject} could not be determined: ${reasons}`, 'unavailable');
    report.certificates.push({ subject, status: 'undetermined', detail: reasons });
  }
  return report;
}

function toDer(c: string | Uint8Array): Uint8Array {
  if (typeof c !== 'string') return c;
  const m = /-----BEGIN X509 CRL-----([\s\S]+?)-----END X509 CRL-----/.exec(c);
  return new Uint8Array(Buffer.from(m ? m[1] : c, 'base64'));
}

// --- OCSP -------------------------------------------------------------------------------------------------

const SHA1 = '1.3.14.3.2.26';
const CERT_ID_HASHES: Record<string, string> = {
  [SHA1]: 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};
const MAX_OCSP_BYTES = 65_536;

/** Builds a DER OCSP request for `cert` issued by `issuer`. Exported for tests and custom fetchers. */
export function buildOcspRequest(certB64: string, issuerB64: string, nonce?: Uint8Array): Uint8Array {
  return ocspRequest(parseCert(Buffer.from(certB64, 'base64')), parseCert(Buffer.from(issuerB64, 'base64')), nonce);
}

function ocspRequest(cert: Cert, issuer: Cert, nonce?: Uint8Array): Uint8Array {
  const reqCert = new CertID({
    // SHA-1 here only identifies the certificate (RFC 5019); it carries no security.
    hashAlgorithm: new AlgorithmIdentifier({ algorithm: SHA1, parameters: null }),
    issuerNameHash: new OctetString(sha('sha1', cert.issuerName)),
    issuerKeyHash: new OctetString(sha('sha1', issuer.keyBits)),
    serialNumber: new Uint8Array(cert.serialRaw).buffer,
  });
  const tbsRequest = new TBSRequest({ requestList: [new Request({ reqCert })] });
  if (nonce) {
    tbsRequest.requestExtensions = [
      new Extension({ extnID: id_pkix_ocsp_nonce, critical: false, extnValue: new OctetString(AsnConvert.serialize(new OctetString(nonce))) }),
    ];
  }
  return new Uint8Array(AsnConvert.serialize(new OCSPRequest({ tbsRequest })));
}

async function viaOcsp(cert: Cert, issuer: Cert, ctx: Ctx): Promise<Outcome> {
  const urls = ocspUrls(cert).slice(0, 2);
  if (urls.length === 0) return { kind: 'unavailable', reason: 'no OCSP responder' };
  if (!ctx.opts.fetcher) return { kind: 'unavailable', reason: 'no fetcher configured for OCSP' };
  let last: Outcome = { kind: 'unavailable', reason: 'OCSP responder unreachable' };
  for (const url of urls) {
    const nonce = ctx.opts.ocspNonce ? randomBytes(32) : undefined;
    let bytes: Uint8Array;
    try {
      bytes = await ctx.opts.fetcher.ocsp(url, ocspRequest(cert, issuer, nonce));
    } catch (e) {
      last = { kind: 'unavailable', reason: `OCSP responder unreachable (${(e as Error).message})` };
      continue;
    }
    return evaluateOcsp(bytes, cert, issuer, nonce, ctx);
  }
  return last;
}

function evaluateOcsp(bytes: Uint8Array, cert: Cert, issuer: Cert, nonce: Uint8Array | undefined, ctx: Ctx): Outcome {
  const invalid = (reason: string): Outcome => ({ kind: 'invalid', reason });
  let resp: OCSPResponse;
  let basic: BasicOCSPResponse;
  try {
    resp = parseDer(bytes, OCSPResponse, MAX_OCSP_BYTES);
    if (resp.responseStatus !== OCSPResponseStatus.successful) {
      // Unsigned error statuses: the responder gave no answer, which is an unavailability.
      return { kind: 'unavailable', reason: `OCSP responder answered ${OCSPResponseStatus[resp.responseStatus] ?? 'an error'}` };
    }
    if (!resp.responseBytes || resp.responseBytes.responseType !== id_pkix_ocsp_basic) return invalid('OCSP response is not a basic response');
    basic = parseDer(new Uint8Array(resp.responseBytes.response.buffer), BasicOCSPResponse, MAX_OCSP_BYTES);
  } catch {
    return invalid('OCSP response is malformed');
  }
  if (!basic.tbsResponseDataRaw) return invalid('OCSP response is malformed');
  const data = basic.tbsResponseData;
  const extra = basic.certs ?? [];
  if (extra.length > 4 || data.responses.length > 32) return invalid('OCSP response is too large');

  // Who signed: the issuing CA itself, or a responder it certified for OCSP signing.
  let signerKey: KeyObject;
  if (responderIs(issuer, data.responderID)) {
    signerKey = issuer.node.publicKey;
  } else {
    let responder: Cert | undefined;
    try {
      responder = extra.map((c) => parseCert(Buffer.from(AsnConvert.serialize(c)))).find((c) => responderIs(c, data.responderID));
    } catch {
      return invalid('OCSP response carries an invalid certificate');
    }
    if (!responder) return invalid('OCSP response is not signed by the issuer or by a responder it designated');
    const problem = delegatedResponderProblem(responder, issuer, ctx.now);
    if (problem) return invalid(problem);
    signerKey = responder.node.publicKey;
  }
  if (!verifySig(basic.signatureAlgorithm, basic.tbsResponseDataRaw, basic.signature, signerKey)) {
    return invalid('OCSP response signature does not verify');
  }

  const now = ctx.now;
  if (data.producedAt.getTime() / 1000 > now + ctx.skew) return invalid('OCSP response is from the future');
  for (const ext of data.responseExtensions ?? []) {
    if (ext.critical && ext.extnID !== id_pkix_ocsp_nonce) return invalid(`OCSP response has an unsupported critical extension ${ext.extnID}`);
  }
  if (nonce) {
    const ext = (data.responseExtensions ?? []).find((e) => e.extnID === id_pkix_ocsp_nonce);
    if (!ext || !nonceMatches(new Uint8Array(ext.extnValue.buffer), nonce)) return invalid('OCSP response nonce does not match the request');
  }
  const single = data.responses.find((r) => certIdMatches(r.certID, cert, issuer));
  if (!single) return invalid('OCSP response does not cover this certificate');
  if ((single.singleExtensions ?? []).some((e) => e.critical)) return invalid('OCSP single response has an unsupported critical extension');
  const thisUpdate = single.thisUpdate.getTime() / 1000;
  if (thisUpdate > now + ctx.skew) return invalid('OCSP response is from the future');
  let until: number;
  let unbounded: number | undefined;
  if (single.nextUpdate) {
    until = single.nextUpdate.getTime() / 1000;
    if (until <= now) return invalid('OCSP response is stale');
  } else {
    const maxAge = ctx.opts.maxAgeWithoutNextUpdate ?? 3600;
    if (now - thisUpdate > maxAge) return invalid('OCSP response is stale');
    until = thisUpdate + maxAge;
    unbounded = thisUpdate;
  }
  const meta = { nonce: nonce !== undefined, ...(unbounded !== undefined ? { thisUpdate: unbounded } : {}) };
  const st = single.certStatus;
  if (st.revoked) return { kind: 'revoked', via: 'ocsp', until, ...meta };
  // CertStatus is a CHOICE: the chosen alternative is null, the others undefined.
  if (st.good === null && st.unknown === undefined) return { kind: 'good', via: 'ocsp', until, ...meta };
  return invalid('OCSP responder does not know this certificate');
}

function nonceMatches(extnValue: Uint8Array, nonce: Uint8Array): boolean {
  if (same(extnValue, nonce)) return true;
  try {
    return same(AsnConvert.parse(extnValue, OctetString).buffer, nonce);
  } catch {
    return false;
  }
}

function responderIs(c: Cert, rid: BasicOCSPResponse['tbsResponseData']['responderID']): boolean {
  if (rid.byKey) return same(rid.byKey.buffer, sha('sha1', c.keyBits));
  if (rid.byName) return same(AsnConvert.serialize(rid.byName), c.subjectName);
  return false;
}

const RESPONDER_EXTENSIONS = new Set([
  '2.5.29.19', // basic constraints
  '2.5.29.15', // key usage
  '2.5.29.37', // extended key usage
  '2.5.29.17', // subject alternative name
  '2.5.29.14', // subject key identifier
  '2.5.29.35', // authority key identifier
  '2.5.29.32', // certificate policies
  '1.3.6.1.5.5.7.48.1.5', // id-pkix-ocsp-nocheck
]);

function delegatedResponderProblem(r: Cert, issuer: Cert, now: number): string | undefined {
  if (!r.node.checkIssued(issuer.node) || !r.node.verify(issuer.node.publicKey)) return 'OCSP responder certificate is not issued by the certificate issuer';
  if (!validAt(r, now)) return 'OCSP responder certificate is not valid now';
  const eku = r.px.getExtension(x509.ExtendedKeyUsageExtension);
  if (!eku || !eku.usages.map(String).includes(id_kp_OCSPSigning)) return 'OCSP responder certificate lacks the OCSPSigning extended key usage';
  const ku = r.px.getExtension(x509.KeyUsagesExtension)?.usages;
  if (ku !== undefined && !(ku & x509.KeyUsageFlags.digitalSignature)) return 'OCSP responder certificate lacks the digitalSignature key usage';
  for (const ext of r.px.extensions) {
    if (ext.critical && !RESPONDER_EXTENSIONS.has(ext.type)) return `OCSP responder certificate has an unsupported critical extension ${ext.type}`;
  }
  return undefined;
}

function certIdMatches(id: CertID, cert: Cert, issuer: Cert): boolean {
  const alg = CERT_ID_HASHES[id.hashAlgorithm.algorithm];
  if (!alg) return false;
  return (
    normSerial(new Uint8Array(id.serialNumber)) === cert.serial &&
    same(id.issuerNameHash.buffer, sha(alg, cert.issuerName)) &&
    same(id.issuerKeyHash.buffer, sha(alg, issuer.keyBits))
  );
}

// --- CRL --------------------------------------------------------------------------------------------------

/** @internal What is kept of a CRL once its signature, issuer and freshness have been checked. */
export interface VerifiedCrl {
  revoked: Set<string>;
  onlyUser: boolean;
  onlyCa: boolean;
  /** Distribution point URIs from the issuing distribution point extension; empty means the whole CA. */
  scope: string[];
  nextUpdate: number;
}

const CRL_DELTA_INDICATOR = '2.5.29.27';
const CRL_ISSUING_DP = '2.5.29.28';
const CRL_ENTRY_CERT_ISSUER = '2.5.29.29';

async function viaCrl(cert: Cert, issuer: Cert, ctx: Ctx): Promise<Outcome> {
  const problems: Outcome[] = [];
  const consider = (o: Outcome): Outcome | undefined => {
    if (o.kind === 'good' || o.kind === 'revoked') return o;
    if (o.kind !== 'not-applicable') problems.push(o);
    return undefined;
  };
  for (const der of ctx.supplied) {
    const v = verifyCrl(der, issuer, ctx, undefined);
    if ('kind' in v) {
      // A supplied CRL from another CA is simply not about this certificate.
      if (v.kind === 'not-applicable') continue;
      problems.push(v);
      continue;
    }
    const d = consider(decide(v, cert, undefined));
    if (d) return d;
  }
  const maxBytes = ctx.opts.maxCrlBytes ?? 10_000_000;
  for (const url of crlUrls(cert).slice(0, 3)) {
    const key = `${issuer.id}:${url}`;
    let v: VerifiedCrl | Outcome | undefined = ctx.opts.cache?.getCrl(key, ctx.now);
    if (!v) {
      if (!ctx.opts.fetcher) {
        problems.push({ kind: 'unavailable', reason: 'no fetcher configured for CRLs' });
        continue;
      }
      let bytes: Uint8Array;
      try {
        bytes = await ctx.opts.fetcher.crl(url);
        if (bytes.byteLength > maxBytes) throw new Error('CRL is too large');
      } catch (e) {
        problems.push({ kind: 'unavailable', reason: `CRL distribution point unreachable (${(e as Error).message})` });
        continue;
      }
      v = verifyCrl(bytes, issuer, ctx, url);
      if ('kind' in v) {
        problems.push(v.kind === 'not-applicable' ? { kind: 'invalid', reason: 'the CRL at the distribution point is issued by another CA' } : v);
        continue;
      }
      ctx.opts.cache?.setCrl(key, v, v.nextUpdate);
    }
    const d = decide(v as VerifiedCrl, cert, url);
    if (d.kind === 'not-applicable') {
      problems.push({ kind: 'invalid', reason: 'the CRL at the distribution point does not cover this certificate' });
      continue;
    }
    const r = consider(d);
    if (r) return r;
  }
  if (problems.length === 0) return { kind: 'unavailable', reason: 'no CRL distribution point' };
  return problems.find((p) => p.kind === 'invalid') ?? problems[0];
}

function decide(crl: VerifiedCrl, cert: Cert, url: string | undefined): Outcome {
  const ca = isCa(cert);
  if ((crl.onlyCa && !ca) || (crl.onlyUser && ca)) return { kind: 'not-applicable' };
  if (crl.scope.length) {
    const points = url ? [url] : crlUrls(cert);
    if (!points.some((p) => crl.scope.includes(p))) return { kind: 'not-applicable' };
  }
  return { kind: crl.revoked.has(cert.serial) ? 'revoked' : 'good', via: 'crl', until: crl.nextUpdate };
}

function verifyCrl(bytes: Uint8Array, issuer: Cert, ctx: Ctx, url: string | undefined): VerifiedCrl | Outcome {
  const invalid = (reason: string): Outcome => ({ kind: 'invalid', reason });
  const maxBytes = ctx.opts.maxCrlBytes ?? 10_000_000;
  let list: CertificateList;
  try {
    list = parseDer(bytes, CertificateList, maxBytes);
  } catch {
    return invalid('CRL is malformed or too large');
  }
  const tbs = list.tbsCertList;
  if (!same(AsnConvert.serialize(tbs.issuer), issuer.subjectName)) return { kind: 'not-applicable' };
  if (!list.tbsCertListRaw || !same(AsnConvert.serialize(tbs.signature), AsnConvert.serialize(list.signatureAlgorithm))) {
    return invalid('CRL signature algorithms disagree');
  }
  const ku = issuer.px.getExtension(x509.KeyUsagesExtension)?.usages;
  if (ku !== undefined && !(ku & x509.KeyUsageFlags.cRLSign)) return invalid('the CRL issuer may not sign CRLs');
  if (!verifySig(list.signatureAlgorithm, list.tbsCertListRaw, list.signature, issuer.node.publicKey)) {
    return invalid('CRL signature does not verify');
  }
  const thisUpdate = tbs.thisUpdate.getTime().getTime() / 1000;
  if (thisUpdate > ctx.now + ctx.skew) return invalid('CRL is from the future');
  if (!tbs.nextUpdate) return invalid('CRL has no nextUpdate');
  const nextUpdate = tbs.nextUpdate.getTime().getTime() / 1000;
  if (nextUpdate <= ctx.now) return invalid('CRL is stale');

  const out: VerifiedCrl = { revoked: new Set(), onlyUser: false, onlyCa: false, scope: [], nextUpdate };
  for (const ext of tbs.crlExtensions ?? []) {
    if (ext.extnID === CRL_DELTA_INDICATOR) return invalid('delta CRLs are not supported');
    if (ext.extnID === CRL_ISSUING_DP) {
      let idp: IssuingDistributionPoint;
      try {
        idp = AsnConvert.parse(ext.extnValue.buffer, IssuingDistributionPoint);
      } catch {
        return invalid('CRL issuing distribution point is malformed');
      }
      if (idp.indirectCRL || idp.onlyContainsAttributeCerts || idp.onlySomeReasons) return invalid('CRL scope is not supported');
      out.onlyUser = idp.onlyContainsUserCerts;
      out.onlyCa = idp.onlyContainsCACerts;
      if (idp.distributionPoint) {
        out.scope = uris(idp.distributionPoint.fullName);
        if (out.scope.length === 0) return invalid('CRL scope is not supported');
      }
      continue;
    }
    if (ext.critical) return invalid(`CRL has an unsupported critical extension ${ext.extnID}`);
  }
  if (url && out.scope.length && !out.scope.includes(url)) return invalid('CRL does not belong to the distribution point it was fetched from');
  for (const entry of tbs.revokedCertificates ?? []) {
    for (const ext of entry.crlEntryExtensions ?? []) {
      if (ext.extnID === CRL_ENTRY_CERT_ISSUER) return invalid('indirect CRLs are not supported');
      if (ext.critical) return invalid(`CRL entry has an unsupported critical extension ${ext.extnID}`);
    }
    // Every listed serial counts as revoked, whatever the reason (a hold is not trusted either).
    out.revoked.add(normSerial(new Uint8Array(entry.userCertificate)));
  }
  return out;
}
