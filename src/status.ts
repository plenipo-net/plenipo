/**
 * IETF Token Status List support, for the PID and for mandates.
 * A status list token is a JWT (typ statuslist+jwt) that carries a compressed bit array;
 * a credential or mandate points to one entry with `status.status_list = { uri, idx }`.
 */
import { signCompactJwt, type SigningKey } from './signer.js';
import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { StatusList, createHeaderAndPayload, verifyStatusListJwtClaims, verifyStatusListJwtHeader } from '@owf/token-status-list';
import { randomInt } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { resolveSigningKeyAsync, type TrustConfig } from './trust.js';
import { canonicalize, sha256 } from './encoding.js';

export interface StatusReference {
  status_list: { uri: string; idx: number };
}

/**
 * Fetches a status list token. The default fetcher uses HTTPS only, refuses redirects, stops after
 * 5 seconds and reads at most 1 MB. A custom fetcher must keep the same guarantees.
 *
 * `maxAgeSeconds` is set when the caller needs a list no older than that (see `VerifyOptions.maxStatusAgeSeconds`):
 * the default fetcher sends it as `Cache-Control: max-age`, so HTTP caches on the way revalidate older copies.
 */
export type StatusFetcher = (uri: string, opts?: { maxAgeSeconds?: number }) => Promise<string>;

const MAX_TOKEN_BYTES = 1_000_000;

export const defaultStatusFetcher: StatusFetcher = async (uri, opts) => {
  if (new URL(uri).protocol !== 'https:') throw new Error('status lists are fetched over https only');
  const maxAge = opts?.maxAgeSeconds;
  const res = await fetch(uri, {
    headers: {
      accept: 'application/statuslist+jwt',
      // A request directive (RFC 9111): caches between here and the origin must not answer with an older copy.
      ...(typeof maxAge === 'number' && Number.isFinite(maxAge) && maxAge >= 0 ? { 'cache-control': `max-age=${Math.floor(maxAge)}` } : {}),
    },
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
  });
  if (!res.ok) throw new Error(`status list returned HTTP ${res.status}`);
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_TOKEN_BYTES) throw new Error('status list is too large');
  const reader = res.body?.getReader();
  if (!reader) throw new Error('status list has no body');
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_TOKEN_BYTES) {
      await reader.cancel();
      throw new Error('status list is too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8').trim();
};

/**
 * Default `ttl` of the status lists this library publishes, in seconds. Verifiers and HTTP caches may keep a
 * list that long, so it is how long a revocation can go unnoticed; it matches the default `StatusListCache`.
 */
export const DEFAULT_STATUS_TTL_SECONDS = 60;

export const STATUS_VALID = 0;
export const STATUS_INVALID = 1;
export const STATUS_SUSPENDED = 2;

export interface StatusCheckOptions {
  /** Who may sign the status list token. */
  trust: TrustConfig;
  /**
   * The identity the signer must have, taken from the verifier's context, never from the token: the PID
   * `iss` for PID status, the status list origin for mandates. With `trustedIssuers` it selects the key;
   * with x5c the leaf certificate must name it.
   */
  signer: string;
  /** Origins the list may be fetched from. A URI outside them is refused before any network access. */
  allowedOrigins: string[];
  fetcher?: StatusFetcher;
  /** Current time in seconds. */
  now: number;
  /** Optional cache shared across verifications. */
  cache?: StatusListCache;
  /**
   * When set, a cached list obtained more than this many seconds ago is not used, and the fetcher is asked
   * for a copy no older than that. `0` always fetches.
   */
  maxAgeSeconds?: number;
  /**
   * Largest status list accepted once inflated, in bytes. Default `DEFAULT_MAX_STATUS_LIST_BYTES` (1 MiB:
   * 4 194 304 entries at 2 bits, 8 388 608 at 1 bit). A token is at most 1 MB, but DEFLATE compresses a
   * list of zeros about a thousand times, so the inflated size needs its own bound.
   */
  maxListBytes?: number;
}

/** Default bound on an inflated status list: 1 MiB. */
export const DEFAULT_MAX_STATUS_LIST_BYTES = 1024 * 1024;

/** A status list as the verifier keeps it: the inflated bytes, never an array of entries. */
export interface DecodedStatusList {
  bits: 1 | 2 | 4 | 8;
  bytes: Uint8Array;
}

/**
 * Decodes `status_list` of a verified token: strict base64url, ZLIB inflate bounded by `maxBytes`, and a
 * `bits` value the draft allows. Inflation stops as soon as the bound is reached.
 */
export function decodeStatusList(statusList: unknown, maxBytes = DEFAULT_MAX_STATUS_LIST_BYTES): DecodedStatusList {
  if (typeof statusList !== 'object' || statusList === null) throw new Error('status list token has no status_list');
  const sl = statusList as Record<string, unknown>;
  const bits = sl.bits;
  if (bits !== 1 && bits !== 2 && bits !== 4 && bits !== 8) throw new Error('status_list.bits must be 1, 2, 4 or 8');
  const lst = sl.lst;
  if (typeof lst !== 'string' || lst.length === 0 || lst.length > MAX_TOKEN_BYTES || !/^[A-Za-z0-9_-]+$/.test(lst)) {
    throw new Error('status_list.lst must be base64url');
  }
  let bytes: Buffer;
  try {
    bytes = inflateSync(Buffer.from(lst, 'base64url'), { maxOutputLength: maxBytes });
  } catch {
    throw new Error(`status list cannot be inflated within ${maxBytes} bytes`);
  }
  if (bytes.length === 0) throw new Error('status list is empty');
  return { bits, bytes: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.length) };
}

/**
 * Reads entry `idx`. Per the IETF Token Status List draft, entry i occupies `bits` bits starting at bit
 * (i * bits) mod 8 of byte floor(i * bits / 8), counting from the least significant bit.
 */
export function readStatus(list: DecodedStatusList, idx: number): number {
  const total = (list.bytes.length * 8) / list.bits;
  if (!Number.isSafeInteger(idx) || idx < 0 || idx >= total) throw new Error(`status index ${idx} is outside the list`);
  const bit = idx * list.bits;
  return (list.bytes[Math.floor(bit / 8)] >> (bit % 8)) & ((1 << list.bits) - 1);
}

/**
 * Caches verified status lists for a short time, to avoid a fetch on every invocation.
 * Entries are keyed by URI and by the signer identity and trust they were verified under, so a list
 * accepted under one trust configuration is never served to a check that requires another.
 */
export class StatusListCache {
  private readonly entries = new Map<string, { list: DecodedStatusList; until: number; fetchedAt?: number }>();
  constructor(private readonly maxAgeSeconds = 60) {}
  /**
   * The cached list, unless it expired or, with `maxAgeSeconds`, was obtained more than that many seconds
   * before `now`. This is what bounds how long a revocation can go unnoticed.
   */
  get(key: string, now: number, maxAgeSeconds?: number): DecodedStatusList | undefined {
    const e = this.entries.get(key);
    if (!e || e.until <= now) return undefined;
    // `0` means "obtained for this check": never served from the cache, whatever the clock resolution.
    if (maxAgeSeconds !== undefined && (maxAgeSeconds === 0 || e.fetchedAt === undefined || now - e.fetchedAt > maxAgeSeconds)) return undefined;
    return e.list;
  }
  set(key: string, list: DecodedStatusList, until: number, fetchedAt?: number): void {
    this.entries.set(key, { list, until, ...(fetchedAt !== undefined ? { fetchedAt } : {}) });
  }
  get maxAge(): number {
    return this.maxAgeSeconds;
  }
}

/** Content fingerprint of a trust configuration, so equal configurations share cache entries. */
function trustId(t: TrustConfig): string {
  return sha256(
    canonicalize({
      i: (t.trustedIssuers ?? []).map((x) => ({ iss: x.iss, jwk: x.jwk })),
      a: t.trustAnchors ?? [],
      p: t.requiredPolicyOids ?? [],
      e: t.requiredEkus ?? [],
      // A list accepted without a revocation check must not be served to a check that requires one.
      ...(t.certificateRevocation && t.certificateRevocation.policy !== 'off' ? { r: t.certificateRevocation.policy } : {}),
    }),
  );
}

/** The origin of an https URL, or undefined. */
export function httpsOrigin(uri: string): string | undefined {
  try {
    const u = new URL(uri);
    return u.protocol === 'https:' ? u.origin : undefined;
  } catch {
    return undefined;
  }
}

export function isStatusReference(x: unknown): x is StatusReference {
  if (typeof x !== 'object' || x === null) return false;
  const sl = (x as Record<string, unknown>).status_list as Record<string, unknown> | undefined;
  if (typeof sl !== 'object' || sl === null) return false;
  if (typeof sl.uri !== 'string' || sl.uri.length > 2048 || !Number.isSafeInteger(sl.idx) || (sl.idx as number) < 0) return false;
  return httpsOrigin(sl.uri) !== undefined;
}

/**
 * Fetches, verifies and reads one status. Throws when the URI is not allowed or the token cannot be
 * trusted or read; callers must treat a throw as "not valid".
 */
/**
 * The status list could not be obtained (network error, HTTP error, size limit). Distinct from a list that
 * was obtained and failed verification, which is treated as an attack, not an outage.
 */
export class StatusUnavailableError extends Error {}

export async function checkStatus(ref: StatusReference, opts: StatusCheckOptions): Promise<number> {
  const { uri, idx } = ref.status_list;
  const origin = httpsOrigin(uri);
  if (!origin || !opts.allowedOrigins.includes(origin)) throw new Error('status list origin is not allowed');
  const maxBytes = opts.maxListBytes ?? DEFAULT_MAX_STATUS_LIST_BYTES;
  // The bound is part of the key: a list accepted under a larger bound is not served to a stricter check.
  const key = JSON.stringify([trustId(opts.trust), opts.signer, uri, maxBytes]);
  const maxAge = opts.maxAgeSeconds;
  if (maxAge !== undefined && (typeof maxAge !== 'number' || !Number.isFinite(maxAge) || maxAge < 0)) {
    throw new Error('maxAgeSeconds must be a non-negative number');
  }
  let list = opts.cache?.get(key, opts.now, maxAge);
  if (!list) {
    let token: string;
    try {
      const fetcher = opts.fetcher ?? defaultStatusFetcher;
      token = await (maxAge !== undefined ? fetcher(uri, { maxAgeSeconds: maxAge }) : fetcher(uri));
    } catch (e) {
      throw new StatusUnavailableError((e as Error)?.message ?? String(e));
    }
    const header = decodeProtectedHeader(token) as Record<string, unknown>;
    verifyStatusListJwtHeader(header);
    if (header.alg !== 'ES256') throw new Error('status list token must use ES256');
    const signingKey = await resolveSigningKeyAsync(header, opts.signer, opts.trust, opts.now);
    const { payload } = await jwtVerify(token, await importJWK(signingKey.jwk, 'ES256'), {
      algorithms: ['ES256'],
      currentDate: new Date(opts.now * 1000),
    });
    verifyStatusListJwtClaims(payload as any, { uri, now: new Date(opts.now * 1000), requireExpirationTime: true });
    list = decodeStatusList((payload as Record<string, unknown>).status_list, maxBytes);
    if (opts.cache) {
      const ttl = typeof payload.ttl === 'number' && payload.ttl >= 0 ? payload.ttl : opts.cache.maxAge;
      const until = Math.min(opts.now + opts.cache.maxAge, opts.now + ttl, Number(payload.exp));
      opts.cache.set(key, list, until, opts.now);
    }
  }
  return readStatus(list, idx);
}

/**
 * Publishes a status list for mandates. The agent platform that creates mandates allocates an index for
 * each one, flips it to revoke, and serves `token()` at `uri`.
 * Indexes are allocated at random, so the position of an entry says nothing about when it was created.
 */
export class StatusListPublisher {
  private readonly list: StatusList;
  private readonly used = new Set<number>();
  constructor(
    private readonly opts: {
      uri: string;
      signingKey: SigningKey;
      /** Number of entries. Default 16384: a larger list hides individual entries in the crowd. */
      size?: number;
      /** Issuer claim, matched against `trustedIssuers` when verifiers do not use x5c. */
      iss?: string;
      /** Certificate chain, leaf first, base64 DER. */
      x5c?: string[];
      /** Token lifetime in seconds. Default 1 hour. */
      lifetimeSeconds?: number;
      /** Hint for verifier and HTTP caches, in seconds: how long a revocation may go unnoticed. Default 60. */
      ttlSeconds?: number;
    },
  ) {
    // Two bits per entry: valid, invalid and suspended all need to be representable.
    this.list = new StatusList(new Array(opts.size ?? 16384).fill(0), 2);
  }

  get uri(): string {
    return this.opts.uri;
  }

  /** Reserves a free index and returns the status reference to put in a mandate. */
  allocate(): StatusReference {
    const size = this.list.totalStatuses;
    if (this.used.size >= size) throw new Error('status list is full');
    let idx: number;
    do idx = randomInt(size);
    while (this.used.has(idx));
    this.used.add(idx);
    return { status_list: { uri: this.opts.uri, idx } };
  }

  revoke(ref: StatusReference): void {
    this.list.setStatus(ref.status_list.idx, STATUS_INVALID);
  }

  suspend(ref: StatusReference): void {
    this.list.setStatus(ref.status_list.idx, STATUS_SUSPENDED);
  }

  reinstate(ref: StatusReference): void {
    this.list.setStatus(ref.status_list.idx, STATUS_VALID);
  }

  /** Current status of an entry. Throws for an index outside the list. */
  getStatus(idx: number): number {
    return this.list.getStatus(idx);
  }

  /** Whether `allocate` handed out this index. */
  isAllocated(idx: number): boolean {
    return this.used.has(idx);
  }

  /** Signs the current list as a status list token. */
  async token(now = Math.floor(Date.now() / 1000)): Promise<string> {
    const { header, payload } = createHeaderAndPayload(
      this.list,
      {
        sub: this.opts.uri,
        iat: now,
        exp: now + (this.opts.lifetimeSeconds ?? 3600),
        ttl: this.opts.ttlSeconds ?? DEFAULT_STATUS_TTL_SECONDS,
        ...(this.opts.iss ? { iss: this.opts.iss } : {}),
      },
      { alg: 'ES256', typ: 'statuslist+jwt', ...(this.opts.x5c ? { x5c: this.opts.x5c } : {}) } as any,
    );
    return signCompactJwt(payload as Record<string, unknown>, header as { alg: string }, this.opts.signingKey);
  }
}
