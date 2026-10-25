/**
 * Test doubles for a PID provider and an EUDI Wallet.
 * They produce real SD-JWT VC PIDs, X.509 chains, status lists, key binding JWTs and OpenID4VP responses,
 * so the verifier runs unchanged, but every key is generated locally: never use them outside development.
 */
import 'reflect-metadata';
import { createHash, KeyObject, sign as cryptoSign, webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { AlgorithmIdentifier, Certificate, Extension } from '@peculiar/asn1-x509';
import {
  BasicOCSPResponse,
  CertID,
  CertStatus,
  OCSPResponse,
  OCSPResponseStatus,
  ResponderID,
  ResponseBytes,
  ResponseData,
  RevokedInfo,
  SingleResponse,
  id_kp_OCSPSigning,
  id_pkix_ocsp_basic,
  id_pkix_ocsp_nonce,
} from '@peculiar/asn1-ocsp';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { calculateJwkThumbprint, CompactEncrypt, decodeJwt, importJWK, type JWK } from 'jose';
import { sha256 } from './encoding.js';
import type { RepresentationClaims } from './legal.js';
import { encodeMandateTransactionData, nowSeconds } from './mandate.js';
import { StatusListPublisher, type StatusFetcher, type StatusReference } from './status.js';
import {
  EMANDATE_TX_DATA_TYPE,
  PID_VCT,
  REPRESENTATION_VCT,
  TX_DATA_TYPE,
  type Mandate,
  type RootAuthorization,
  type TrustedIssuer,
} from './types.js';
import { fromBase64url } from './encoding.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIG = { name: 'ECDSA', hash: 'SHA-256' } as const;

export interface PidClaims {
  given_name: string;
  family_name: string;
  birthdate?: string;
  nationality?: string;
  [claim: string]: unknown;
}

export interface TestLeafOptions {
  notAfter?: Date;
  /** Key usage flags; default digitalSignature. */
  keyUsage?: number;
  /** Issue the leaf as a CA (for negative tests). */
  ca?: boolean;
  /** Subject alternative names; default the URI `iss` and its DNS host. */
  san?: Array<{ type: 'url' | 'dns'; value: string }>;
  /** Certificate policy OIDs. */
  policies?: string[];
  /** Extended key usage OIDs, and whether the extension is critical. */
  eku?: { usages: string[]; critical?: boolean };
  /** CRL distribution point URLs. */
  crlUrls?: string[];
  /** OCSP responder URLs (authority information access). */
  ocspUrls?: string[];
}

export interface TestCrlOptions {
  /** Serial numbers (hex, as returned by `issueLeaf`) to list as revoked. */
  revoked?: string[];
  thisUpdate?: Date;
  /** Default one day after thisUpdate. */
  nextUpdate?: Date;
  /** Sign with another key (negative tests). */
  signingKey?: CryptoKey;
  extensions?: x509.Extension[];
}

export interface TestOcspResponseOptions {
  /** Base64 DER of the certificate the response is about (issued by this CA). */
  certificate: string;
  status: 'good' | 'revoked' | 'unknown';
  /** A delegated responder; default the CA itself. */
  responder?: { certificate: string; privateKey: CryptoKey };
  thisUpdate?: Date;
  /** Default one hour after thisUpdate; null to omit. */
  nextUpdate?: Date | null;
  /** Nonce to echo. */
  nonce?: Uint8Array;
  /** Sign with another key while naming the expected responder (negative tests). */
  signingKey?: CryptoKey;
  /** Answer with an error status instead of a response. */
  responseStatus?: 'tryLater' | 'internalError' | 'unauthorized';
}

export interface TestCertificateAuthority {
  /** PEM of the root, to configure as a trust anchor. */
  anchorPem: string;
  /** Issues an EC P-256 leaf certificate naming `iss` (as URI and DNS), returning the x5c chain and keys. */
  issueLeaf(
    iss: string,
    opts?: TestLeafOptions,
  ): Promise<{ x5c: string[]; certificate: string; serialNumber: string; privateKey: CryptoKey; privateJwk: JWK; publicJwk: JWK }>;
  /** Issues an intermediate CA below this one; its leaves carry the full chain up to (excluding) the anchor. */
  issueIntermediate(
    name: string,
    opts?: { pathLength?: number; policies?: string[]; crlUrls?: string[]; ocspUrls?: string[] },
  ): Promise<TestCertificateAuthority>;
  /** This CA's own certificate as base64 DER, for building chains by hand. */
  certificateB64: string;
  /** This CA's private key, for signing revocation data in tests. */
  privateKey: CryptoKey;
  /** Issues a CRL signed by this CA. */
  createCrl(opts?: TestCrlOptions): Promise<Uint8Array>;
  /** Issues a delegated OCSP responder certificate; `ocspSigning: false` leaves out the OCSPSigning EKU. */
  issueOcspResponder(opts?: { ocspSigning?: boolean }): Promise<{ certificate: string; privateKey: CryptoKey }>;
  /** Produces a DER OCSP response about a certificate this CA issued. */
  createOcspResponse(opts: TestOcspResponseOptions): Promise<Uint8Array>;
}

/** Positive serial number with a non-zero first byte, so its hex form is its DER content. */
function testSerial(): string {
  const b = webcrypto.getRandomValues(new Uint8Array(8));
  b[0] = (b[0] & 0x7f) | 0x01;
  return Buffer.from(b).toString('hex');
}

function revocationPointers(o: { crlUrls?: string[]; ocspUrls?: string[] }): x509.Extension[] {
  return [
    ...(o.crlUrls?.length ? [new x509.CRLDistributionPointsExtension(o.crlUrls)] : []),
    ...(o.ocspUrls?.length ? [new x509.AuthorityInfoAccessExtension({ ocsp: o.ocspUrls })] : []),
  ];
}

function signDer(data: ArrayBuffer, key: CryptoKey): ArrayBuffer {
  const sig = cryptoSign('sha256', Buffer.from(data), KeyObject.from(key as unknown as webcrypto.CryptoKey));
  return new Uint8Array(sig).buffer;
}

async function makeCa(
  cert: x509.X509Certificate,
  keys: CryptoKeyPair,
  anchorPem: string,
  above: string[],
): Promise<TestCertificateAuthority> {
  const own = Buffer.from(cert.rawData).toString('base64');
  const caAsn = AsnConvert.parse(cert.rawData, Certificate);
  const caKeyBits = Buffer.from(caAsn.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey);
  // Certificates between a leaf and the anchor: this CA (unless it is the anchor) and those above it.
  const chainTail = cert.toString('pem') === anchorPem ? [] : [own, ...above];
  const self: TestCertificateAuthority = {
    anchorPem,
    certificateB64: own,
    async issueLeaf(iss, opts = {}) {
      const leafKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
      const host = new URL(iss).hostname;
      const leaf = await x509.X509CertificateGenerator.create({
        serialNumber: testSerial(),
        subject: `CN=${host}`,
        issuer: cert.subject,
        notBefore: new Date(Date.now() - 3600_000),
        notAfter: opts.notAfter ?? new Date(Date.now() + 365 * 24 * 3600_000),
        signingAlgorithm: SIG,
        publicKey: leafKeys.publicKey,
        signingKey: keys.privateKey,
        extensions: [
          new x509.BasicConstraintsExtension(opts.ca ?? false, undefined, true),
          new x509.KeyUsagesExtension(opts.keyUsage ?? x509.KeyUsageFlags.digitalSignature, true),
          new x509.SubjectAlternativeNameExtension(
            opts.san ?? [
              { type: 'url', value: iss },
              { type: 'dns', value: host },
            ],
          ),
          ...(opts.policies ? [new x509.CertificatePolicyExtension(opts.policies)] : []),
          ...(opts.eku ? [new x509.ExtendedKeyUsageExtension(opts.eku.usages, opts.eku.critical ?? false)] : []),
          ...revocationPointers(opts),
        ],
      });
      const privateJwk = (await webcrypto.subtle.exportKey('jwk', leafKeys.privateKey)) as JWK;
      const publicJwk = (await webcrypto.subtle.exportKey('jwk', leafKeys.publicKey)) as JWK;
      return {
        x5c: [Buffer.from(leaf.rawData).toString('base64'), ...chainTail],
        certificate: Buffer.from(leaf.rawData).toString('base64'),
        serialNumber: leaf.serialNumber,
        privateKey: leafKeys.privateKey as unknown as CryptoKey,
        privateJwk,
        publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y },
      };
    },
    async issueIntermediate(name, opts = {}) {
      const subKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
      const sub = await x509.X509CertificateGenerator.create({
        serialNumber: testSerial(),
        subject: `CN=${name}`,
        issuer: cert.subject,
        notBefore: new Date(Date.now() - 3600_000),
        notAfter: new Date(Date.now() + 2 * 365 * 24 * 3600_000),
        signingAlgorithm: SIG,
        publicKey: subKeys.publicKey,
        signingKey: keys.privateKey,
        extensions: [
          new x509.BasicConstraintsExtension(true, opts.pathLength, true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
          ...(opts.policies ? [new x509.CertificatePolicyExtension(opts.policies)] : []),
          ...revocationPointers(opts),
        ],
      });
      return makeCa(sub, subKeys, anchorPem, chainTail);
    },
    privateKey: keys.privateKey,
    async createCrl(opts = {}) {
      const thisUpdate = opts.thisUpdate ?? new Date(Date.now() - 60_000);
      const crl = await x509.X509CrlGenerator.create({
        issuer: cert.subject,
        thisUpdate,
        nextUpdate: opts.nextUpdate ?? new Date(thisUpdate.getTime() + 24 * 3600_000),
        signingAlgorithm: SIG,
        signingKey: opts.signingKey ?? keys.privateKey,
        entries: (opts.revoked ?? []).map((serialNumber) => ({ serialNumber, revocationDate: new Date(thisUpdate.getTime() - 1000) })),
        extensions: opts.extensions,
      });
      return new Uint8Array(crl.rawData);
    },
    async issueOcspResponder(opts = {}) {
      const rKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
      const r = await x509.X509CertificateGenerator.create({
        serialNumber: testSerial(),
        subject: 'CN=Plenipo Test OCSP Responder',
        issuer: cert.subject,
        notBefore: new Date(Date.now() - 3600_000),
        notAfter: new Date(Date.now() + 30 * 24 * 3600_000),
        signingAlgorithm: SIG,
        publicKey: rKeys.publicKey,
        signingKey: keys.privateKey,
        extensions: [
          new x509.BasicConstraintsExtension(false, undefined, true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
          new x509.ExtendedKeyUsageExtension(opts.ocspSigning === false ? ['1.3.6.1.5.5.7.3.2'] : [id_kp_OCSPSigning]),
        ],
      });
      return { certificate: Buffer.from(r.rawData).toString('base64'), privateKey: rKeys.privateKey };
    },
    async createOcspResponse(opts) {
      if (opts.responseStatus) {
        return new Uint8Array(AsnConvert.serialize(new OCSPResponse({ responseStatus: OCSPResponseStatus[opts.responseStatus] })));
      }
      const leaf = AsnConvert.parse(Buffer.from(opts.certificate, 'base64'), Certificate);
      const sha1 = (d: ArrayBuffer | Uint8Array) => new Uint8Array(createHash('sha1').update(Buffer.from(d as ArrayBuffer)).digest()).buffer;
      const certID = new CertID({
        hashAlgorithm: new AlgorithmIdentifier({ algorithm: '1.3.14.3.2.26', parameters: null }),
        issuerNameHash: new OctetString(sha1(AsnConvert.serialize(leaf.tbsCertificate.issuer))),
        issuerKeyHash: new OctetString(sha1(caKeyBits)),
        serialNumber: leaf.tbsCertificate.serialNumber,
      });
      const thisUpdate = opts.thisUpdate ?? new Date(Date.now() - 60_000);
      const nextUpdate = opts.nextUpdate === null ? undefined : (opts.nextUpdate ?? new Date(thisUpdate.getTime() + 3600_000));
      const certStatus =
        opts.status === 'good'
          ? new CertStatus({ good: null })
          : opts.status === 'revoked'
            ? new CertStatus({ revoked: new RevokedInfo({ revocationTime: new Date(thisUpdate.getTime() - 1000) }) })
            : new CertStatus({ unknown: null });
      const responderCert = opts.responder ? AsnConvert.parse(Buffer.from(opts.responder.certificate, 'base64'), Certificate) : undefined;
      const responderKeyBits = responderCert ? Buffer.from(responderCert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey) : caKeyBits;
      const data = new ResponseData({
        responderID: new ResponderID({ byKey: new OctetString(sha1(responderKeyBits)) }),
        producedAt: new Date(Math.floor(Date.now() / 1000) * 1000),
        responses: [new SingleResponse({ certID, certStatus, thisUpdate, ...(nextUpdate ? { nextUpdate } : {}) })],
        ...(opts.nonce
          ? { responseExtensions: [new Extension({ extnID: id_pkix_ocsp_nonce, critical: false, extnValue: new OctetString(AsnConvert.serialize(new OctetString(opts.nonce))) })] }
          : {}),
      });
      const signingKey = opts.signingKey ?? opts.responder?.privateKey ?? keys.privateKey;
      const basic = new BasicOCSPResponse({
        tbsResponseData: data,
        signatureAlgorithm: new AlgorithmIdentifier({ algorithm: '1.2.840.10045.4.3.2' }),
        signature: signDer(AsnConvert.serialize(data), signingKey),
        ...(responderCert ? { certs: [responderCert] } : {}),
      });
      return new Uint8Array(
        AsnConvert.serialize(
          new OCSPResponse({
            responseStatus: OCSPResponseStatus.successful,
            responseBytes: new ResponseBytes({ responseType: id_pkix_ocsp_basic, response: new OctetString(AsnConvert.serialize(basic)) }),
          }),
        ),
      );
    },
  };
  return self;
}

/** A throwaway CA, standing in for the CA of a PID provider on an EU trusted list. */
export async function createTestCertificateAuthority(
  name = 'Plenipo Test Trust Anchor',
  opts: { pathLength?: number } = {},
): Promise<TestCertificateAuthority> {
  const caKeys = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const now = new Date();
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${name}`,
    notBefore: new Date(now.getTime() - 3600_000),
    notAfter: new Date(now.getTime() + 5 * 365 * 24 * 3600_000),
    signingAlgorithm: SIG,
    keys: caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, opts.pathLength, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return makeCa(ca, caKeys, ca.toString('pem'), []);
}

export interface TestPidProvider {
  iss: string;
  /** Explicit trust entry, for verifiers configured with `trustedIssuers`. */
  trusted: TrustedIssuer;
  /** Trust anchor PEM, for verifiers configured with `trustAnchors`. Present when created with `x5c: true`. */
  anchorPem?: string;
  /** Present when created with `statusList: true`. */
  statusList?: StatusListPublisher;
  /** Serves the provider's status list, for `statusFetcher`. */
  statusFetcher: StatusFetcher;
  issuePid(holderJwk: JWK, claims: PidClaims, opts?: { exp?: number; omitIss?: boolean }): Promise<string>;
  /** Signs a status list token with this provider's key, for any URI (negative tests). */
  signStatusList(publisher: { uri: string; size?: number }, revoked?: number[]): Promise<string>;
  /** Status reference of the last PID issued. */
  lastStatus?: StatusReference;
}

export async function createTestPidProvider(
  iss = 'https://pid-provider.test',
  opts: { x5c?: boolean; statusList?: boolean; ca?: TestCertificateAuthority; leaf?: TestLeafOptions } = {},
): Promise<TestPidProvider> {
  let privateJwk: JWK;
  let publicJwk: JWK;
  let x5c: string[] | undefined;
  let signingKey: CryptoKey;
  let anchorPem: string | undefined;
  if (opts.x5c) {
    const ca = opts.ca ?? (await createTestCertificateAuthority());
    const leaf = await ca.issueLeaf(iss, opts.leaf);
    privateJwk = leaf.privateJwk;
    publicJwk = leaf.publicJwk;
    x5c = leaf.x5c;
    signingKey = leaf.privateKey;
    anchorPem = ca.anchorPem;
  } else {
    const keys = await ES256.generateKeyPair();
    privateJwk = keys.privateKey as JWK;
    publicJwk = keys.publicKey as JWK;
    signingKey = (await importJWK(privateJwk, 'ES256')) as CryptoKey;
  }
  const statusUri = `${iss}/status/1`;
  const statusList = opts.statusList
    ? new StatusListPublisher({ uri: statusUri, signingKey, iss, ...(x5c ? { x5c } : {}) })
    : undefined;

  const sdjwt = new SDJwtVcInstance({
    signer: await ES256.getSigner(privateJwk),
    signAlg: 'ES256',
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });

  const provider: TestPidProvider = {
    iss,
    // A provider created without a status list declares it, so verifiers accept its PIDs without status.
    trusted: { iss, jwk: publicJwk, ...(statusList ? {} : { withoutStatusList: true }) },
    anchorPem,
    statusList,
    statusFetcher: async (uri) => {
      if (!statusList || uri !== statusUri) throw new Error(`unknown status list ${uri}`);
      return statusList.token();
    },
    async issuePid(holderJwk, claims, o = {}) {
      const iat = nowSeconds();
      const status = statusList?.allocate();
      provider.lastStatus = status;
      const payload = {
        ...(o.omitIss ? {} : { iss }),
        iat,
        exp: o.exp ?? iat + 365 * 24 * 3600,
        vct: PID_VCT,
        cnf: { jwk: holderJwk },
        ...(status ? { status } : {}),
        ...claims,
      };
      return sdjwt.issue(payload as any, { _sd: Object.keys(claims) } as any, x5c ? { header: { x5c } } : undefined);
    },
    async signStatusList(target, revoked = []) {
      const p = new StatusListPublisher({ uri: target.uri, signingKey, iss, size: target.size ?? 16384, ...(x5c ? { x5c } : {}) });
      for (const idx of revoked) p.revoke({ status_list: { uri: target.uri, idx } });
      return p.token();
    },
  };
  return provider;
}

/** An issuer of SD-JWT VC attestations other than the PID: a business register, a bank. */
export interface TestAttestationIssuer {
  iss: string;
  vct: string;
  trusted: TrustedIssuer;
  /** Present when created with `x5c: true`. */
  anchorPem?: string;
  /** Present when created with `statusList: true`. */
  statusList?: StatusListPublisher;
  statusFetcher: StatusFetcher;
  /** Status reference of the last attestation issued. */
  lastStatus?: StatusReference;
  /**
   * Issues an attestation to `holderJwk`. `disclosable` lists the selectively disclosable claims by path:
   * top-level names, or `parent.child` for one level of nesting.
   */
  issue(
    holderJwk: JWK,
    claims: Record<string, unknown>,
    opts?: { exp?: number; nbf?: number; vct?: string; disclosable?: string[]; omitStatus?: boolean },
  ): Promise<string>;
}

export async function createTestAttestationIssuer(
  iss: string,
  vct: string,
  opts: { x5c?: boolean; statusList?: boolean; ca?: TestCertificateAuthority } = {},
): Promise<TestAttestationIssuer> {
  let privateJwk: JWK;
  let publicJwk: JWK;
  let x5c: string[] | undefined;
  let signingKey: CryptoKey;
  let anchorPem: string | undefined;
  if (opts.x5c) {
    const ca = opts.ca ?? (await createTestCertificateAuthority(`${new URL(iss).hostname} test CA`));
    const leaf = await ca.issueLeaf(iss);
    ({ privateJwk, publicJwk, x5c } = leaf);
    signingKey = leaf.privateKey;
    anchorPem = ca.anchorPem;
  } else {
    const keys = await ES256.generateKeyPair();
    privateJwk = keys.privateKey as JWK;
    publicJwk = keys.publicKey as JWK;
    signingKey = (await importJWK(privateJwk, 'ES256')) as CryptoKey;
  }
  const statusUri = `${iss}/status/1`;
  const statusList = opts.statusList ? new StatusListPublisher({ uri: statusUri, signingKey, iss, ...(x5c ? { x5c } : {}) }) : undefined;
  const sdjwt = new SDJwtVcInstance({
    signer: await ES256.getSigner(privateJwk),
    signAlg: 'ES256',
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });
  const issuer: TestAttestationIssuer = {
    iss,
    vct,
    trusted: { iss, jwk: publicJwk },
    anchorPem,
    statusList,
    statusFetcher: async (uri) => {
      if (!statusList || uri !== statusUri) throw new Error(`unknown status list ${uri}`);
      return statusList.token();
    },
    async issue(holderJwk, claims, o = {}) {
      const iat = nowSeconds();
      const status = o.omitStatus ? undefined : statusList?.allocate();
      issuer.lastStatus = status;
      const payload = {
        iss,
        iat,
        ...(o.nbf !== undefined ? { nbf: o.nbf } : {}),
        exp: o.exp ?? iat + 365 * 24 * 3600,
        vct: o.vct ?? vct,
        cnf: { jwk: holderJwk },
        ...(status ? { status } : {}),
        ...claims,
      };
      const frame: Record<string, any> = { _sd: [] as string[] };
      for (const path of o.disclosable ?? []) {
        const [a, b] = path.split('.');
        if (b === undefined) frame._sd.push(a);
        else (frame[a] ??= { _sd: [] })._sd.push(b);
      }
      return sdjwt.issue(payload as any, frame as any, x5c ? { header: { x5c } } : undefined);
    },
  };
  return issuer;
}

export interface TestRegister extends TestAttestationIssuer {
  /** Issues a `urn:plenipo:representation:1` attestation; names and the representative's claims are disclosable. */
  issueRepresentation(
    holderJwk: JWK,
    claims: RepresentationClaims,
    opts?: { exp?: number; nbf?: number; vct?: string; omitStatus?: boolean },
  ): Promise<string>;
}

/** A throwaway business register issuing representation attestations. */
export async function createTestRegister(
  iss = 'https://register.test',
  opts: { x5c?: boolean; statusList?: boolean; ca?: TestCertificateAuthority } = {},
): Promise<TestRegister> {
  const base = await createTestAttestationIssuer(iss, REPRESENTATION_VCT, { statusList: true, ...opts });
  return Object.assign(base, {
    issueRepresentation(holderJwk: JWK, claims: RepresentationClaims, o: { exp?: number; nbf?: number; vct?: string; omitStatus?: boolean } = {}) {
      const disclosable = [
        ...(claims.legal_person_name !== undefined ? ['legal_person_name'] : []),
        ...Object.keys(claims.representative ?? {}).map((k) => `representative.${k}`),
      ];
      return base.issue(holderJwk, claims as unknown as Record<string, unknown>, { ...o, disclosable });
    },
  });
}

/** Stand-in for the SCA attestation type a bank would define in its rulebook. */
export const TEST_SCA_VCT = 'https://bank.test/sca/payment-account';

/** A throwaway payer PSP issuing SCA attestations (TS12 section 2.2) that accept the e-mandate type. */
export async function createTestScaIssuer(
  iss = 'https://bank.test',
  opts: { x5c?: boolean; statusList?: boolean; ca?: TestCertificateAuthority } = {},
): Promise<TestAttestationIssuer & { transactionDataTypes: string[] }> {
  const base = await createTestAttestationIssuer(iss, TEST_SCA_VCT, opts);
  return Object.assign(base, { transactionDataTypes: [EMANDATE_TX_DATA_TYPE] });
}

export interface WalletRequestPolicy {
  /** Decide whether the person approves the mandate; default approve. */
  approve?: (mandate: Mandate) => boolean;
  /** Decide whether the person approves any decoded transaction data object (e.g. an e-mandate); default approve. */
  approveTransaction?: (transactionData: Record<string, unknown>) => boolean;
  /** Test hook: changes a key binding JWT payload before signing, to simulate a misbehaving wallet. */
  tamperKeyBinding?: (queryId: string, payload: Record<string, unknown>) => void;
}

export interface TestWalletOptions {
  /**
   * Accept TS12 e-mandates bound to the PID. TS12 wallets accept them only for SCA attestations whose type
   * metadata lists the type, which is the default behaviour.
   */
  emandateOnPid?: boolean;
}

export interface TestWallet {
  holderJwk: JWK;
  storePid(pid: string): void;
  /**
   * Stores another credential, presented with the holder key its `cnf` names (one of this wallet's keys).
   * `transactionDataTypes` stands in for the TS12 type metadata that lists the transaction data types the
   * credential may sign.
   */
  storeCredential(sdjwt: string, opts?: { transactionDataTypes?: string[] }): void;
  /** Generates another holder key, kept by this wallet, for credentials not bound to the PID key. */
  generateHolderKey(): Promise<JWK>;
  /** Shortcut without the protocol: returns the root authorization directly. */
  approveMandate(mandate: Mandate, opts?: { disclose?: string[]; aud?: string; nonce?: string }): Promise<RootAuthorization>;
  /**
   * Handles an OpenID4VP request (request object JWT or parameters) the way a wallet does: reads the DCQL query
   * and the transaction data, asks the person, and returns the body to POST to response_uri.
   */
  respond(request: string | Record<string, unknown>, policy?: WalletRequestPolicy): Promise<Record<string, unknown>>;
}

interface HeldCredential {
  sdjwt: string;
  vct: string;
  /** Private key that signs the key binding JWT. */
  privateJwk: JWK;
  transactionDataTypes: string[];
}

const TS12_EMANDATE_KEYS = ['transaction_id', 'date_time', 'start_date', 'end_date', 'reference_number', 'creditor_id', 'purpose', 'payment_payload'];
const TS12_PAYMENT_KEYS = ['transaction_id', 'date_time', 'payee', 'pisp', 'execution_date', 'currency', 'amount', 'amount_estimated', 'amount_earmarked', 'sct_inst', 'recurrence'];

/** The checks a TS12 wallet runs against the published JSON schema before showing an e-mandate. */
function ts12EmandateValid(p: any): boolean {
  const str = (x: unknown, max: number) => typeof x === 'string' && x.length >= 1 && x.length <= max;
  if (typeof p !== 'object' || p === null || Array.isArray(p)) return false;
  if (!Object.keys(p).every((k) => TS12_EMANDATE_KEYS.includes(k))) return false;
  if (!str(p.transaction_id, 36)) return false;
  if (p.reference_number !== undefined && !str(p.reference_number, 50)) return false;
  if (p.purpose !== undefined && (typeof p.purpose !== 'string' || p.purpose.length > 1000)) return false;
  if (p.purpose === undefined && p.payment_payload === undefined) return false;
  const pp = p.payment_payload;
  if (pp !== undefined) {
    if (typeof pp !== 'object' || pp === null || !Object.keys(pp).every((k) => TS12_PAYMENT_KEYS.includes(k))) return false;
    if (!str(pp.transaction_id, 36) || typeof pp.payee?.name !== 'string' || typeof pp.payee?.id !== 'string') return false;
    if (typeof pp.currency !== 'string' || !/^[A-Z]{3}$/.test(pp.currency) || typeof pp.amount !== 'number') return false;
  }
  return true;
}

function claimsFrame(claims: Array<{ path: unknown[] }> | undefined): Record<string, unknown> {
  const frame: Record<string, any> = {};
  for (const c of claims ?? []) {
    const [a, b] = c.path as string[];
    if (b === undefined) frame[a] = true;
    else if (frame[a] !== true) (frame[a] ??= {})[b] = true;
  }
  return frame;
}

export async function createTestWallet(walletOpts: TestWalletOptions = {}): Promise<TestWallet> {
  const holder = await ES256.generateKeyPair();
  const keys = new Map<string, JWK>([[await calculateJwkThumbprint(holder.publicKey as JWK), holder.privateKey as JWK]]);
  let pid: string | undefined;
  const others: HeldCredential[] = [];

  async function presentWith(sdjwtCred: string, privateJwk: JWK, frame: Record<string, unknown>, kb: Record<string, unknown>): Promise<string> {
    const instance = new SDJwtVcInstance({
      hasher: digest,
      hashAlg: 'sha-256',
      kbSigner: await ES256.getSigner(privateJwk),
      kbSignAlg: 'ES256',
    });
    return instance.present(sdjwtCred, frame as any, { kb: { payload: kb as any } });
  }

  async function present(disclose: string[], aud: string, nonce: string, txData: string[]): Promise<string> {
    if (!pid) throw new Error('wallet has no PID');
    const frame = Object.fromEntries(disclose.map((k) => [k, true]));
    return presentWith(pid, holder.privateKey as JWK, frame, {
      iat: nowSeconds(),
      aud,
      nonce,
      transaction_data_hashes: txData.map((t) => sha256(t)),
      transaction_data_hashes_alg: 'sha-256',
    });
  }

  return {
    holderJwk: holder.publicKey as JWK,
    storePid(p) {
      pid = p;
    },
    storeCredential(sdjwtCred, o = {}) {
      const payload = decodeJwt(sdjwtCred.split('~')[0]) as Record<string, any>;
      const cnf = payload.cnf?.jwk as JWK | undefined;
      others.push({
        sdjwt: sdjwtCred,
        vct: String(payload.vct),
        // A credential bound to a key this wallet does not hold is presented with the main key, and fails.
        privateJwk: (cnf && keysByJwk(cnf)) ?? (holder.privateKey as JWK),
        transactionDataTypes: o.transactionDataTypes ?? [],
      });
      function keysByJwk(jwk: JWK): JWK | undefined {
        for (const [, priv] of keys) if (priv.x === jwk.x && priv.y === jwk.y) return priv;
        return undefined;
      }
    },
    async generateHolderKey() {
      const pair = await ES256.generateKeyPair();
      keys.set(await calculateJwkThumbprint(pair.publicKey as JWK), pair.privateKey as JWK);
      return pair.publicKey as JWK;
    },
    async approveMandate(mandate, opts = {}) {
      const transaction_data = encodeMandateTransactionData(mandate);
      const presentation = await present(
        opts.disclose ?? ['given_name', 'family_name'],
        opts.aud ?? 'plenipo:mandate-request',
        opts.nonce ?? crypto.randomUUID(),
        [transaction_data],
      );
      return { transaction_data, presentation };
    },
    async respond(request, policy = {}) {
      const params = (typeof request === 'string' ? decodeJwt(request) : request) as Record<string, any>;
      const state = params.state;
      const queries = params.dcql_query?.credentials;
      const first = Array.isArray(queries) ? queries[0] : undefined;
      if (!first || first.format !== 'dc+sd-jwt' || !first.meta?.vct_values?.includes(PID_VCT)) {
        return { error: 'invalid_request', state };
      }
      if (!pid) return { error: 'access_denied', state };
      // Match every credential query against what the wallet holds.
      const held = new Map<string, HeldCredential>();
      held.set(first.id, { sdjwt: pid, vct: PID_VCT, privateJwk: holder.privateKey as JWK, transactionDataTypes: [] });
      for (const q of queries.slice(1)) {
        if (q?.format !== 'dc+sd-jwt' || typeof q.id !== 'string' || held.has(q.id)) return { error: 'invalid_request', state };
        const c =
          others.find((o) => q.meta?.vct_values?.includes(o.vct)) ??
          (q.meta?.vct_values?.includes(PID_VCT) ? held.get(first.id) : undefined);
        if (!c) return { error: 'access_denied', state };
        held.set(q.id, c);
      }

      const txData: string[] = params.transaction_data ?? [];
      const boundTo = new Map<string, string[]>(); // query id -> transaction data it signs
      for (const t of txData) {
        let decoded: Record<string, any>;
        try {
          decoded = JSON.parse(fromBase64url(t));
        } catch {
          return { error: 'invalid_transaction_data', state };
        }
        const ids: unknown = decoded.credential_ids;
        const targets = Array.isArray(ids) ? ids.filter((i): i is string => typeof i === 'string' && held.has(i)) : [];
        // A real wallet refuses transaction data types it does not support.
        if (decoded.type === TX_DATA_TYPE) {
          if (policy.approve && !policy.approve(decoded.mandate)) return { error: 'access_denied', state };
          if (targets.length === 0) targets.push(first.id);
        } else if (decoded.type === EMANDATE_TX_DATA_TYPE || targets.some((id) => held.get(id)!.transactionDataTypes.includes(decoded.type))) {
          if (targets.length === 0 || !Array.isArray(ids) || targets.length !== ids.length) return { error: 'invalid_transaction_data', state };
          for (const id of targets) {
            const c = held.get(id)!;
            const allowed = c.transactionDataTypes.includes(decoded.type) || (walletOpts.emandateOnPid === true && c.vct === PID_VCT && decoded.type === EMANDATE_TX_DATA_TYPE);
            if (!allowed) return { error: 'invalid_transaction_data', state };
          }
          if (!ts12EmandateValid(decoded.payload)) return { error: 'invalid_transaction_data', state };
        } else {
          return { error: 'invalid_transaction_data', state };
        }
        if (policy.approveTransaction && !policy.approveTransaction(decoded)) return { error: 'access_denied', state };
        for (const id of targets) boundTo.set(id, [...(boundTo.get(id) ?? []), t]);
      }

      const vpToken: Record<string, string[]> = {};
      for (const q of queries) {
        const c = held.get(q.id)!;
        const signs = boundTo.get(q.id) ?? [];
        const kb: Record<string, unknown> = { iat: nowSeconds(), aud: params.client_id, nonce: params.nonce };
        if (signs.length) {
          kb.transaction_data_hashes = signs.map((t) => sha256(t));
          kb.transaction_data_hashes_alg = 'sha-256';
        }
        if (c.transactionDataTypes.length) {
          // TS12 section 3.6: authentication code, response mode and the factors used.
          kb.jti = crypto.randomUUID();
          kb.response_mode = params.response_mode;
          kb.amr = [{ knowledge: 'pin_6_or_more_digits' }, { possession: 'key_in_local_native_wscd' }];
        }
        policy.tamperKeyBinding?.(q.id, kb);
        vpToken[q.id] = [await presentWith(c.sdjwt, c.privateJwk, claimsFrame(q.claims), kb)];
      }
      const result = { vp_token: vpToken, state };
      if (params.response_mode === 'direct_post.jwt') {
        const encJwk = params.client_metadata?.jwks?.keys?.find((k: JWK) => k.use === 'enc');
        if (!encJwk) return { error: 'invalid_request', state };
        const key = await importJWK(encJwk, 'ECDH-ES');
        const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(result)))
          .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: encJwk.kid })
          .encrypt(key);
        return { response: jwe };
      }
      return result;
    },
  };
}

export interface TestListOperator {
  /** PEM of the list signing certificate, to pass as `signerCertificates`. */
  certificatePem: string;
  certificateB64: string;
  privateKey: CryptoKey;
  /**
   * Signs a LoTE JSON document as a compact JWS (JAdES baseline B shape: x5c, x5t#S256, sigT in crit).
   * `header` overrides or adds protected header parameters (negative tests).
   */
  sign(lote: unknown, opts?: { header?: Record<string, unknown> }): Promise<string>;
}

/** A throwaway trusted list operator with a self-signed signing certificate. */
export async function createTestListOperator(name = 'Plenipo Test Scheme Operator', country = 'EU'): Promise<TestListOperator> {
  const k = (await webcrypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: testSerial(),
    name: `C=${country}, O=${name}, CN=${name} List Signer`,
    notBefore: new Date(Date.now() - 3600_000),
    notAfter: new Date(Date.now() + 365 * 24 * 3600_000),
    signingAlgorithm: SIG,
    keys: k,
    extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true)],
  });
  const b64 = Buffer.from(cert.rawData).toString('base64');
  return {
    certificatePem: cert.toString('pem'),
    certificateB64: b64,
    privateKey: k.privateKey,
    async sign(lote, opts = {}) {
      const header = {
        alg: 'ES256',
        typ: 'trustlist+jwt',
        x5c: [b64],
        'x5t#S256': createHash('sha256').update(Buffer.from(cert.rawData)).digest('base64url'),
        sigT: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        crit: ['sigT'],
        ...opts.header,
      };
      for (const [key, v] of Object.entries(header)) if (v === undefined) delete (header as Record<string, unknown>)[key];
      // Signed by hand rather than with jose, which refuses to emit crit parameters it does not know.
      const input = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(lote)).toString('base64url')}`;
      const sig = cryptoSign('sha256', Buffer.from(input), { key: KeyObject.from(k.privateKey as unknown as webcrypto.CryptoKey), dsaEncoding: 'ieee-p1363' });
      return `${input}.${sig.toString('base64url')}`;
    },
  };
}

/** Builds a minimal LoTE document listing services by type and certificates (base64 DER). */
export function buildTestLoTE(opts: {
  type?: string;
  sequenceNumber?: number;
  issued?: Date;
  nextUpdate?: Date | null;
  operator?: string;
  territory?: string;
  entities: Array<{ name: string; services: Array<{ type: string; certificates?: string[]; publicKeys?: JWK[]; supplyPoints?: string[]; status?: string }> }>;
}): Record<string, unknown> {
  const issued = opts.issued ?? new Date(Date.now() - 3600_000);
  const operator = opts.operator ?? 'Plenipo Test Scheme Operator';
  return {
    LoTE: {
      ListAndSchemeInformation: {
        LoTEVersionIdentifier: 1,
        LoTESequenceNumber: opts.sequenceNumber ?? 1,
        LoTEType: opts.type ?? 'http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList',
        SchemeOperatorName: [{ lang: 'en', value: operator }],
        SchemeTerritory: opts.territory ?? 'EU',
        ListIssueDateTime: issued.toISOString(),
        NextUpdate: opts.nextUpdate === null ? null : (opts.nextUpdate ?? new Date(issued.getTime() + 30 * 24 * 3600_000)).toISOString(),
      },
      TrustedEntitiesList: opts.entities.map((e) => ({
        TrustedEntityInformation: {
          TEName: [{ lang: 'en', value: e.name }],
          TEAddress: { TEPostalAddress: [], TEElectronicAddress: [] },
        },
        TrustedEntityServices: e.services.map((s) => ({
          ServiceInformation: {
            ServiceName: [{ lang: 'en', value: `${e.name} service` }],
            ServiceTypeIdentifier: s.type,
            ...(s.status ? { ServiceStatus: s.status } : {}),
            ServiceDigitalIdentity: {
              ...(s.certificates ? { X509Certificates: s.certificates.map((val) => ({ val })) } : {}),
              ...(s.publicKeys ? { PublicKeyValues: s.publicKeys } : {}),
            },
            ...(s.supplyPoints ? { ServiceSupplyPoints: s.supplyPoints.map((uriValue) => ({ ServiceType: s.type, uriValue })) } : {}),
          },
        })),
      })),
    },
  };
}
