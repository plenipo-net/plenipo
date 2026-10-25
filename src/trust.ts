import 'reflect-metadata';
import { X509Certificate as NodeCert } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import type { JWK } from 'jose';
import type { TrustedIssuer } from './types.js';
import { checkCertificateRevocation, RevocationError, type CertificateRevocationOptions, type RevocationReport } from './x509-revocation.js';

/**
 * How a verifier decides which keys it trusts.
 *
 * - `trustedIssuers`: explicit issuer identifiers and public keys.
 * - `trustAnchors`: PEM certificates from the applicable trusted lists. A signer that carries an `x5c` chain
 *   is trusted when the chain leads to one of them and the leaf names the expected identity. An anchor that
 *   is a CA vouches for the certificates it issues; an anchor that is not a CA (a provider's signing
 *   certificate published on the list) vouches only for itself, matched byte for byte as the x5c leaf.
 *   This is how EUDI Wallet PID providers are recognised in production.
 */
export interface TrustConfig {
  trustedIssuers?: TrustedIssuer[];
  trustAnchors?: string[];
  /**
   * Certificate policy OIDs, one of which the leaf must carry. Use it when an anchor also certifies
   * entities that must not sign for this purpose (relying parties, attestation providers).
   */
  requiredPolicyOids?: string[];
  /**
   * Extended key usage OIDs accepted on the leaf. A leaf without EKU is accepted; a leaf with an EKU must
   * list one of these. Without this option a leaf with a critical EKU is rejected, since its purpose
   * cannot be checked.
   */
  requiredEkus?: string[];
  /**
   * Origins (`https://host[:port]`) from which status lists may be fetched under this trust.
   * Defaults depend on the use: see `VerifyOptions.mandateStatusTrust` and `pidStatusTrust`.
   */
  statusOrigins?: string[];
  /**
   * CRL and OCSP checking of x5c chains. Absent or `policy: 'off'` keeps the earlier behaviour: a revoked
   * certificate stays trusted until it expires. Needs `resolveSigningKeyAsync`.
   */
  certificateRevocation?: CertificateRevocationOptions;
}

export class TrustError extends Error {}

export interface ResolvedKey {
  jwk: JWK;
  /** How the key was trusted. */
  via: 'issuer' | 'x5c';
  /** Subject of the leaf certificate, when trusted via x5c. */
  subject?: string;
  /**
   * The validated path, base64 DER, leaf first and ending with the anchor that vouched for it. A leaf
   * trusted directly as an anchor is the whole path.
   */
  chain?: string[];
  /** Outcome of the revocation check, when one ran. */
  revocation?: RevocationReport;
}

const OID = {
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  subjectAltName: '2.5.29.17',
  certificatePolicies: '2.5.29.32',
  nameConstraints: '2.5.29.30',
  subjectKeyId: '2.5.29.14',
  authorityKeyId: '2.5.29.35',
  crlDistributionPoints: '2.5.29.31',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
};
const UNDERSTOOD = new Set(Object.values(OID).filter((o) => o !== OID.nameConstraints));
const ANY_POLICY = '2.5.29.32.0';

interface Cert {
  node: NodeCert;
  px: x509.X509Certificate;
}

function parse(der: Buffer | string): Cert {
  const node = new NodeCert(der);
  return { node, px: new x509.X509Certificate(node.raw) };
}

function parseAnchors(pems: string[]): Cert[] {
  return pems.map((p) => {
    try {
      return parse(p);
    } catch {
      throw new TrustError('a configured trust anchor is not a valid PEM certificate');
    }
  });
}

function validAt(c: Cert, now: number): boolean {
  const t = now * 1000;
  return c.node.validFromDate.getTime() <= t && t <= c.node.validToDate.getTime();
}

function basicConstraints(c: Cert): x509.BasicConstraintsExtension | null {
  return c.px.getExtension(x509.BasicConstraintsExtension);
}

function keyUsages(c: Cert): x509.KeyUsageFlags | undefined {
  return c.px.getExtension(x509.KeyUsagesExtension)?.usages;
}

/** Fails closed on extensions this validator does not implement. */
function checkExtensions(c: Cert, role: string): void {
  for (const ext of c.px.extensions) {
    if (ext.type === OID.nameConstraints) throw new TrustError(`${role} has name constraints, which are not supported`);
    if (ext.critical && !UNDERSTOOD.has(ext.type)) throw new TrustError(`${role} has an unsupported critical extension ${ext.type}`);
  }
}

function checkCa(c: Cert, role: string, intermediatesBelow: number): void {
  checkExtensions(c, role);
  const bc = basicConstraints(c);
  if (!bc?.ca) throw new TrustError(`${role} is not a CA`);
  if (bc.pathLength !== undefined && intermediatesBelow > bc.pathLength) {
    throw new TrustError(`${role} allows ${bc.pathLength} intermediate CAs below it, the chain has ${intermediatesBelow}`);
  }
  const ku = keyUsages(c);
  if (ku !== undefined && !(ku & x509.KeyUsageFlags.keyCertSign)) throw new TrustError(`${role} may not sign certificates`);
}

/**
 * True when the leaf names `name`: exactly as a URI subject alternative name, or by its DNS name when
 * `name` is a bare https origin (no port, path, query or fragment). Paths never match by DNS, so one
 * tenant's certificate on a shared host cannot sign for another tenant's issuer URL.
 */
function namesIdentity(c: Cert, name: string): boolean {
  const san = c.px.getExtension(x509.SubjectAlternativeNameExtension);
  if (!san) return false;
  const items = san.names.items;
  if (items.some((n) => n.type === 'url' && n.value === name)) return true;
  let u: URL;
  try {
    u = new URL(name);
  } catch {
    return false;
  }
  const bareOrigin = u.protocol === 'https:' && !u.port && (u.pathname === '/' || u.pathname === '') && !u.search && !u.hash;
  if (!bareOrigin || name.replace(/\/$/, '') !== u.origin) return false;
  return items.some((n) => n.type === 'dns' && n.value.toLowerCase() === u.hostname);
}

/**
 * Validates an x5c chain (leaf first, base64 DER) against trust anchors at time `now` and returns the
 * leaf public key. The leaf must name `name` (see `namesIdentity`), be an end-entity certificate with
 * the digitalSignature key usage, and carry a P-256 key. Basic constraints, path length and key usage
 * are enforced on every CA; name constraints and unknown critical extensions are rejected.
 * An anchor that is not a CA is trusted only as the leaf itself (byte-identical), never as an issuer.
 * The returned `chain` is the validated path, ending with the anchor.
 */
export function verifyX5c(
  x5c: unknown,
  anchorsPem: string[],
  now: number,
  name: string,
  opts: { requiredPolicyOids?: string[]; requiredEkus?: string[] } = {},
): ResolvedKey {
  if (typeof name !== 'string' || name.length === 0) throw new TrustError('the signer identity to check is missing');
  if (!Array.isArray(x5c) || x5c.length === 0 || x5c.length > 5 || !x5c.every((c) => typeof c === 'string')) {
    throw new TrustError('x5c must be an array of 1 to 5 base64 certificates');
  }
  let chain: Cert[];
  try {
    chain = x5c.map((c: string) => parse(Buffer.from(c, 'base64')));
  } catch {
    throw new TrustError('x5c contains an invalid certificate');
  }
  const anchors = parseAnchors(anchorsPem);
  if (anchors.length === 0) throw new TrustError('no trust anchors configured');

  const leaf = chain[0];
  if (!validAt(leaf, now)) throw new TrustError(`certificate ${leaf.node.subject} is not valid now`);
  // A list may publish the provider's signing certificate itself. Such an anchor is not a CA and vouches
  // only for this exact certificate; the rest of x5c, if any, plays no part.
  const direct = anchors.find((a) => !basicConstraints(a)?.ca && a.node.raw.equals(leaf.node.raw));
  let path: Cert[];
  if (direct) {
    path = [leaf];
  } else {
    for (const c of chain) if (!validAt(c, now)) throw new TrustError(`certificate ${c.node.subject} is not valid now`);
    for (let i = 0; i < chain.length - 1; i++) {
      if (!chain[i].node.checkIssued(chain[i + 1].node) || !chain[i].node.verify(chain[i + 1].node.publicKey)) {
        throw new TrustError('x5c chain is broken');
      }
      // chain[i + 1] is a CA with i intermediate CAs below it (the leaf is not counted).
      checkCa(chain[i + 1], `certificate ${i + 1} in x5c`, i);
    }

    const top = chain[chain.length - 1];
    const anchorIsTop = anchors.find((a) => a.node.fingerprint256 === top.node.fingerprint256);
    if (anchorIsTop) {
      if (chain.length === 1) throw new TrustError('a trust anchor cannot sign directly');
      if (!validAt(anchorIsTop, now)) throw new TrustError('the trust anchor is not valid now');
      path = chain;
    } else {
      const issuer = anchors.find((a) => validAt(a, now) && top.node.checkIssued(a.node) && top.node.verify(a.node.publicKey));
      if (!issuer) throw new TrustError('x5c chain does not lead to a trusted anchor');
      checkCa(issuer, 'the trust anchor', chain.length - 1);
      path = [...chain, issuer];
    }
  }

  checkExtensions(leaf, 'the signing certificate');
  if (basicConstraints(leaf)?.ca) throw new TrustError('the signing certificate is a CA');
  const ku = keyUsages(leaf);
  if (ku === undefined || !(ku & x509.KeyUsageFlags.digitalSignature)) {
    throw new TrustError('the signing certificate lacks the digitalSignature key usage');
  }
  if (opts.requiredPolicyOids?.length) {
    const policies = leaf.px.getExtension(x509.CertificatePolicyExtension)?.policies ?? [];
    if (!opts.requiredPolicyOids.some((p) => policies.includes(p))) {
      throw new TrustError('the signing certificate carries none of the required policies');
    }
    // A CA that restricts policies must allow the required one (or anyPolicy) for the whole path.
    for (let i = 1; i < (direct ? 1 : chain.length); i++) {
      const caPolicies = chain[i].px.getExtension(x509.CertificatePolicyExtension)?.policies;
      if (caPolicies && !caPolicies.includes(ANY_POLICY) && !opts.requiredPolicyOids.some((p) => caPolicies.includes(p))) {
        throw new TrustError(`certificate ${i} in x5c does not allow the required policies`);
      }
    }
  }
  const eku = leaf.px.getExtension(x509.ExtendedKeyUsageExtension);
  if (eku) {
    const usages = eku.usages.map(String);
    if (opts.requiredEkus?.length) {
      if (!opts.requiredEkus.some((u) => usages.includes(u))) throw new TrustError('the signing certificate has none of the required extended key usages');
    } else if (eku.critical) {
      throw new TrustError('the signing certificate has a critical extended key usage that cannot be checked');
    }
  }
  if (!namesIdentity(leaf, name)) throw new TrustError(`the signing certificate does not name ${name}`);

  const jwk = leaf.node.publicKey.export({ format: 'jwk' }) as JWK;
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new TrustError('the signing key must be EC P-256');
  return {
    jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    via: 'x5c',
    subject: leaf.node.subject,
    chain: path.map((c) => c.node.raw.toString('base64')),
  };
}

function revocationEnabled(trust: TrustConfig): boolean {
  return trust.certificateRevocation !== undefined && trust.certificateRevocation.policy !== 'off';
}

/**
 * Resolves the key that must have signed a JWT with this header, for the identity `name`.
 * `name` always comes from the verifier's context (the PID `iss`, the status list origin), never from
 * an unverified claim that may be absent. x5c is used when present and anchors are configured;
 * otherwise `name` must be listed in `trustedIssuers`.
 * It cannot check revocation: with `certificateRevocation` enabled it refuses x5c signers, so use
 * `resolveSigningKeyAsync`.
 */
export function resolveSigningKey(header: Record<string, unknown>, name: string, trust: TrustConfig, now: number): ResolvedKey {
  if (typeof name !== 'string' || name.length === 0) throw new TrustError('the signer identity to check is missing');
  if (header.x5c !== undefined && trust.trustAnchors?.length) {
    if (revocationEnabled(trust)) throw new TrustError('certificate revocation checking needs resolveSigningKeyAsync');
    return x5cKey(header, name, trust, now);
  }
  const listed = trust.trustedIssuers?.find((t) => t.iss === name);
  if (listed) return { jwk: listed.jwk, via: 'issuer' };
  throw new TrustError(`${name} is not trusted`);
}

function x5cKey(header: Record<string, unknown>, name: string, trust: TrustConfig, now: number): ResolvedKey {
  return verifyX5c(header.x5c, trust.trustAnchors ?? [], now, name, {
    requiredPolicyOids: trust.requiredPolicyOids,
    requiredEkus: trust.requiredEkus,
  });
}

/**
 * `resolveSigningKey`, plus CRL/OCSP checking of the x5c path when `trust.certificateRevocation` is
 * enabled. The path is validated first, so revocation data is only requested from URLs that a trusted CA
 * put in its certificates.
 */
export async function resolveSigningKeyAsync(
  header: Record<string, unknown>,
  name: string,
  trust: TrustConfig,
  now: number,
): Promise<ResolvedKey> {
  if (!revocationEnabled(trust) || header.x5c === undefined || !trust.trustAnchors?.length) {
    return resolveSigningKey(header, name, trust, now);
  }
  if (typeof name !== 'string' || name.length === 0) throw new TrustError('the signer identity to check is missing');
  const key = x5cKey(header, name, trust, now);
  key.revocation = await checkChainRevocation(key.chain ?? [], trust.certificateRevocation!, now);
  return key;
}

/** Runs the revocation check on a validated path and maps its failures to TrustError. */
export async function checkChainRevocation(chain: string[], opts: CertificateRevocationOptions, now: number): Promise<RevocationReport> {
  try {
    return await checkCertificateRevocation(chain, opts, now);
  } catch (e) {
    if (e instanceof RevocationError) throw new TrustError(e.message);
    throw new TrustError('certificate revocation could not be checked');
  }
}
