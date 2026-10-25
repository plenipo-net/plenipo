import 'reflect-metadata';
import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { createHash, sign as cryptoSign, KeyObject, webcrypto, X509Certificate as NodeCert } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { GeneralName, GeneralSubtree, GeneralSubtrees, NameConstraints } from '@peculiar/asn1-x509';
import { OCSPRequest, id_pkix_ocsp_nonce } from '@peculiar/asn1-ocsp';
import { createLoTE, service, signLoTE, trustedEntity, addTrustedEntity } from '@owf/eudi-lote';
import { decodeProtectedHeader } from 'jose';
import {
  checkCertificateRevocation,
  checkStatus,
  createInvocation,
  createMandate,
  fetchTrustedList,
  generateAgentKey,
  httpRevocationFetcher,
  InMemoryNonceStore,
  listedServices,
  loadTrustedList,
  LOTE_SERVICE_TYPE,
  LOTE_TYPE,
  nowSeconds,
  resolveSigningKey,
  resolveSigningKeyAsync,
  RevocationCache,
  StatusListCache,
  StatusListPublisher,
  trustConfigFromLists,
  TrustError,
  TrustListError,
  verifyAuthorization,
  verifyRoot,
  verifyX5c,
  type AgentKey,
  type CertificateRevocationOptions,
  type Mandate,
  type MandateChain,
  type RevocationFetcher,
} from '../src/index.js';
import {
  buildTestLoTE,
  createTestCertificateAuthority,
  createTestListOperator,
  createTestPidProvider,
  createTestWallet,
  type TestCertificateAuthority,
  type TestListOperator,
  type TestPidProvider,
} from '../src/testing.js';

const AUD = 'https://rail.example';
const now = () => nowSeconds();
const pem = (b64: string) => new NodeCert(Buffer.from(b64, 'base64')).toString();

let agent: AgentKey;
beforeAll(async () => {
  agent = await generateAgentKey();
});

function mandate(overrides: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate {
  return createMandate({ agentJwk: agent.publicJwk, actions: ['travel.*'], counterparties: ['rail.example'], ...overrides });
}

function invocation(chain: MandateChain, m: Mandate) {
  return createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', aud: AUD });
}

async function rootFrom(provider: TestPidProvider, m: Mandate) {
  const w = await createTestWallet();
  w.storePid(await provider.issuePid(w.holderJwk, { given_name: 'Mario', family_name: 'Rossi' }));
  return w.approveMandate(m);
}

/** The x5c a test PID provider signs with, read from a PID it issued. */
async function providerX5c(provider: TestPidProvider): Promise<string[]> {
  const w = await createTestWallet();
  const pid = await provider.issuePid(w.holderJwk, { given_name: 'A', family_name: 'B' });
  return decodeProtectedHeader(pid.split('~')[0]).x5c as string[];
}

/** An in-memory fetcher: URL -> bytes (or a function producing them), counting calls. */
function memoryFetcher(crls: Record<string, Uint8Array | (() => Uint8Array)>, ocsp?: (url: string, req: Uint8Array) => Promise<Uint8Array>) {
  const calls: string[] = [];
  const f: RevocationFetcher = {
    async crl(url) {
      calls.push(url);
      const v = crls[url];
      if (!v) throw new Error('unreachable');
      return typeof v === 'function' ? v() : v;
    },
    async ocsp(url, req) {
      calls.push(url);
      if (!ocsp) throw new Error('unreachable');
      return ocsp(url, req);
    },
  };
  return { fetcher: f, calls };
}

const ROOT_CRL = 'http://crl.test/root.crl';
const INTER_CRL = 'http://crl.test/inter.crl';
const OCSP_URL = 'http://ocsp.test/';

// ---------------------------------------------------------------------------------------------------------

describe('direct signing certificates as anchors', () => {
  let ca: TestCertificateAuthority;
  beforeAll(async () => {
    ca = await createTestCertificateAuthority();
  });

  it('trusts a leaf listed as an anchor, byte for byte, without its CA', async () => {
    const leaf = await ca.issueLeaf('https://pid.example');
    const k = verifyX5c(leaf.x5c, [pem(leaf.certificate)], now(), 'https://pid.example');
    expect(k.via).toBe('x5c');
    expect(k.chain).toEqual([leaf.certificate]);
  });

  it('does not trust another leaf of the same CA through a direct anchor', async () => {
    const listed = await ca.issueLeaf('https://pid.example');
    const other = await ca.issueLeaf('https://pid.example');
    expect(() => verifyX5c(other.x5c, [pem(listed.certificate)], now(), 'https://pid.example')).toThrow(/trusted anchor/);
  });

  it('still requires the listed leaf to name the issuer and to be fit to sign', async () => {
    const leaf = await ca.issueLeaf('https://pid.example');
    expect(() => verifyX5c(leaf.x5c, [pem(leaf.certificate)], now(), 'https://other.example')).toThrow(/does not name/);
    const noSig = await ca.issueLeaf('https://pid.example', { keyUsage: x509.KeyUsageFlags.keyAgreement });
    expect(() => verifyX5c(noSig.x5c, [pem(noSig.certificate)], now(), 'https://pid.example')).toThrow(/digitalSignature/);
  });

  it('rejects an expired listed leaf', async () => {
    const leaf = await ca.issueLeaf('https://pid.example', { notAfter: new Date(Date.now() + 60_000) });
    expect(() => verifyX5c(leaf.x5c, [pem(leaf.certificate)], now() + 3600, 'https://pid.example')).toThrow(/not valid now/);
  });

  it('never lets a non-CA anchor vouch for a certificate it signed', async () => {
    const listed = await ca.issueLeaf('https://pid.example');
    const subKeys = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const forged = await x509.X509CertificateGenerator.create({
      serialNumber: '0102',
      subject: 'CN=pid.example',
      issuer: new x509.X509Certificate(Buffer.from(listed.certificate, 'base64')).subject,
      notBefore: new Date(Date.now() - 3600_000),
      notAfter: new Date(Date.now() + 3600_000),
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      publicKey: subKeys.publicKey,
      signingKey: listed.privateKey,
      extensions: [
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.SubjectAlternativeNameExtension([{ type: 'url', value: 'https://pid.example' }]),
      ],
    });
    const x5c = [Buffer.from(forged.rawData).toString('base64')];
    expect(() => verifyX5c(x5c, [pem(listed.certificate)], now(), 'https://pid.example')).toThrow(/not a CA|trusted anchor/);
    expect(() => verifyX5c([...x5c, listed.certificate], [pem(listed.certificate)], now(), 'https://pid.example')).toThrow(/not a CA|broken/);
  });

  it('keeps refusing a CA anchor presented as the signer', () => {
    expect(() => verifyX5c([ca.certificateB64], [ca.anchorPem], now(), 'https://pid.example')).toThrow(/anchor/);
  });

  it('authorizes end to end with the PID provider certificate as the only anchor', async () => {
    const provider = await createTestPidProvider('https://pid-direct.example', { x5c: true });
    const [leaf] = await providerX5c(provider);
    const m = mandate();
    const chain = { root: await rootFrom(provider, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      trustAnchors: [pem(leaf)],
      // The test provider issues PIDs without status: declare it (requirePidStatus is on by default).
      pidProvidersWithoutStatus: [provider.iss],
      audience: AUD,
      nonces: new InMemoryNonceStore(),
    });
    expect(d.decision).toBe('ALLOW');
  });
});

describe('name constraints stay unsupported', () => {
  it('rejects a chain whose intermediate carries name constraints', async () => {
    const ca = await createTestCertificateAuthority();
    const keys = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const nc = new NameConstraints({ permittedSubtrees: new GeneralSubtrees([new GeneralSubtree({ base: new GeneralName({ dNSName: 'example' }) })]) });
    const inter = await x509.X509CertificateGenerator.create({
      serialNumber: '0a0b',
      subject: 'CN=Constrained CA',
      issuer: new x509.X509Certificate(ca.anchorPem).subject,
      notBefore: new Date(Date.now() - 3600_000),
      notAfter: new Date(Date.now() + 3600_000 * 24),
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      publicKey: keys.publicKey,
      signingKey: ca.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(true, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
        new x509.Extension('2.5.29.30', true, AsnConvert.serialize(nc)),
      ],
    });
    const leafKeys = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const leaf = await x509.X509CertificateGenerator.create({
      serialNumber: '0c0d',
      subject: 'CN=pid.example',
      issuer: inter.subject,
      notBefore: new Date(Date.now() - 3600_000),
      notAfter: new Date(Date.now() + 3600_000),
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      publicKey: leafKeys.publicKey,
      signingKey: keys.privateKey,
      extensions: [
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.SubjectAlternativeNameExtension([{ type: 'url', value: 'https://pid.example' }]),
      ],
    });
    const x5c = [leaf, inter].map((c) => Buffer.from(c.rawData).toString('base64'));
    expect(() => verifyX5c(x5c, [ca.anchorPem], now(), 'https://pid.example')).toThrow(/name constraints/);
    // Listing the constrained CA itself as an anchor does not help either.
    expect(() => verifyX5c(x5c.slice(0, 1), [inter.toString('pem')], now(), 'https://pid.example')).toThrow(/name constraints/);
  });
});

// ---------------------------------------------------------------------------------------------------------

describe('CRL checking', () => {
  let root: TestCertificateAuthority;
  let inter: TestCertificateAuthority;
  let leaf: Awaited<ReturnType<TestCertificateAuthority['issueLeaf']>>;
  let chain: string[];
  let interSerial: string;

  beforeAll(async () => {
    root = await createTestCertificateAuthority();
    inter = await root.issueIntermediate('Plenipo Test Intermediate', { crlUrls: [ROOT_CRL] });
    leaf = await inter.issueLeaf('https://pid.example', { crlUrls: [INTER_CRL] });
    chain = verifyX5c(leaf.x5c, [root.anchorPem], now(), 'https://pid.example').chain!;
    interSerial = new x509.X509Certificate(Buffer.from(inter.certificateB64, 'base64')).serialNumber;
  });

  const opts = (fetcher: RevocationFetcher, extra: Partial<CertificateRevocationOptions> = {}): CertificateRevocationOptions => ({
    policy: 'hard-fail',
    fetcher,
    ...extra,
  });

  it('returns the full validated path, ending with the anchor', () => {
    expect(chain).toHaveLength(3);
    expect(chain[2]).toBe(root.certificateB64);
  });

  it('accepts a chain whose CRLs list nothing', async () => {
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: await inter.createCrl() });
    const report = await checkCertificateRevocation(chain, opts(fetcher), now());
    expect(report.certificates.map((c) => [c.status, c.via])).toEqual([
      ['good', 'crl'],
      ['good', 'crl'],
    ]);
  });

  it('rejects a revoked leaf, under hard-fail and soft-fail alike', async () => {
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: await inter.createCrl({ revoked: [leaf.serialNumber] }) });
    await expect(checkCertificateRevocation(chain, opts(fetcher), now())).rejects.toThrow(/revoked/);
    await expect(checkCertificateRevocation(chain, opts(fetcher, { policy: 'soft-fail' }), now())).rejects.toThrow(/revoked/);
  });

  it('rejects a revoked intermediate', async () => {
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl({ revoked: [interSerial] }), [INTER_CRL]: await inter.createCrl() });
    await expect(checkCertificateRevocation(chain, opts(fetcher), now())).rejects.toThrow(/Intermediate is revoked/);
  });

  it('rejects a stale CRL, even under soft-fail', async () => {
    const stale = await inter.createCrl({ thisUpdate: new Date(Date.now() - 3 * 86400_000), nextUpdate: new Date(Date.now() - 86400_000) });
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: stale });
    await expect(checkCertificateRevocation(chain, opts(fetcher), now())).rejects.toThrow(/stale/);
    await expect(checkCertificateRevocation(chain, opts(fetcher, { policy: 'soft-fail' }), now())).rejects.toThrow(/stale/);
  });

  it('rejects a CRL from the future', async () => {
    const future = await inter.createCrl({ thisUpdate: new Date(Date.now() + 86400_000), nextUpdate: new Date(Date.now() + 2 * 86400_000) });
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: future });
    await expect(checkCertificateRevocation(chain, opts(fetcher), now())).rejects.toThrow(/future/);
  });

  it('rejects a CRL signed by the wrong key', async () => {
    const other = await createTestCertificateAuthority('Someone Else');
    const forged = await inter.createCrl({ signingKey: other.privateKey });
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: forged });
    await expect(checkCertificateRevocation(chain, opts(fetcher, { policy: 'soft-fail' }), now())).rejects.toThrow(/signature does not verify/);
  });

  it('rejects a CRL issued by another CA served at the distribution point', async () => {
    const other = await createTestCertificateAuthority('Someone Else');
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: await other.createCrl() });
    await expect(checkCertificateRevocation(chain, opts(fetcher), now())).rejects.toThrow(/another CA/);
  });

  it('rejects garbage at the distribution point', async () => {
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: new Uint8Array([0x30, 0x82, 0xff, 0xff, 1, 2]) });
    await expect(checkCertificateRevocation(chain, opts(fetcher), now())).rejects.toThrow(/malformed/);
  });

  it('refuses delta CRLs and unknown critical CRL extensions', async () => {
    const delta = await inter.createCrl({ extensions: [new x509.Extension('2.5.29.27', true, new Uint8Array([2, 1, 1]))] });
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: delta });
    await expect(checkCertificateRevocation(chain, opts(fetcher), now())).rejects.toThrow(/delta/);
    const odd = await inter.createCrl({ extensions: [new x509.Extension('1.2.3.4.5', true, new Uint8Array([5, 0]))] });
    const f2 = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: odd });
    await expect(checkCertificateRevocation(chain, opts(f2.fetcher), now())).rejects.toThrow(/critical extension/);
  });

  it('soft-fail accepts an unreachable distribution point, hard-fail does not', async () => {
    const { fetcher } = memoryFetcher({});
    const report = await checkCertificateRevocation(chain, opts(fetcher, { policy: 'soft-fail' }), now());
    expect(report.certificates.every((c) => c.status === 'undetermined')).toBe(true);
    await expect(checkCertificateRevocation(chain, opts(fetcher), now())).rejects.toThrow(/could not be determined/);
  });

  it('does no network access without a fetcher, and uses CRLs supplied out of band', async () => {
    await expect(checkCertificateRevocation(chain, { policy: 'hard-fail' }, now())).rejects.toThrow(/no fetcher/);
    const crls = [await root.createCrl(), Buffer.from(await inter.createCrl({ revoked: [leaf.serialNumber] })).toString('base64')];
    await expect(checkCertificateRevocation(chain, { policy: 'hard-fail', crls }, now())).rejects.toThrow(/revoked/);
    const clean = [await root.createCrl(), await inter.createCrl()];
    await expect(checkCertificateRevocation(chain, { policy: 'hard-fail', crls: clean }, now())).resolves.toBeDefined();
  });

  it('caches verified results until nextUpdate', async () => {
    const { fetcher, calls } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: await inter.createCrl() });
    const cache = new RevocationCache();
    await checkCertificateRevocation(chain, opts(fetcher, { cache }), now());
    await checkCertificateRevocation(chain, opts(fetcher, { cache }), now());
    expect(calls).toHaveLength(2);
    // After nextUpdate (one day) the cached status is not used any more.
    await expect(checkCertificateRevocation(chain, opts(fetcher, { cache }), now() + 2 * 86400)).rejects.toThrow();
    expect(calls.length).toBeGreaterThan(2);
  });

  it('treats a CRL larger than the limit as unavailable', async () => {
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl(), [INTER_CRL]: await inter.createCrl() });
    await expect(checkCertificateRevocation(chain, opts(fetcher, { maxCrlBytes: 50 }), now())).rejects.toThrow(/too large/);
  });

  it('rejects a misspelt policy instead of skipping the check', async () => {
    await expect(checkCertificateRevocation(chain, { policy: 'hard' as never }, now())).rejects.toThrow(/policy/);
  });

  it('a leaf without any CRL or OCSP pointer is undetermined', async () => {
    const bare = await inter.issueLeaf('https://pid.example');
    const c = verifyX5c(bare.x5c, [root.anchorPem], now(), 'https://pid.example').chain!;
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await root.createCrl() });
    await expect(checkCertificateRevocation(c, opts(fetcher), now())).rejects.toThrow(/no OCSP responder; no CRL distribution point/);
    const soft = await checkCertificateRevocation(c, opts(fetcher, { policy: 'soft-fail' }), now());
    expect(soft.certificates[0].status).toBe('undetermined');
  });
});

// ---------------------------------------------------------------------------------------------------------

describe('OCSP checking', () => {
  let ca: TestCertificateAuthority;
  let leaf: Awaited<ReturnType<TestCertificateAuthority['issueLeaf']>>;
  let chain: string[];

  beforeAll(async () => {
    ca = await createTestCertificateAuthority();
    leaf = await ca.issueLeaf('https://pid.example', { ocspUrls: [OCSP_URL] });
    chain = verifyX5c(leaf.x5c, [ca.anchorPem], now(), 'https://pid.example').chain!;
  });

  const responding = (produce: (req: Uint8Array) => Promise<Uint8Array>) => memoryFetcher({}, (_u, req) => produce(req));
  const hard = (fetcher: RevocationFetcher, extra: Partial<CertificateRevocationOptions> = {}): CertificateRevocationOptions => ({
    policy: 'hard-fail',
    fetcher,
    methods: ['ocsp'],
    ...extra,
  });

  it('accepts a good response signed by the CA', async () => {
    const { fetcher, calls } = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good' }));
    const r = await checkCertificateRevocation(chain, hard(fetcher), now());
    expect(r.certificates[0]).toMatchObject({ status: 'good', via: 'ocsp' });
    expect(calls).toEqual([OCSP_URL]);
  });

  it('sends a well-formed request for the right certificate', async () => {
    let seen: OCSPRequest | undefined;
    const { fetcher } = responding(async (req) => {
      seen = AsnConvert.parse(req, OCSPRequest);
      return ca.createOcspResponse({ certificate: leaf.certificate, status: 'good' });
    });
    await checkCertificateRevocation(chain, hard(fetcher), now());
    const id = seen!.tbsRequest.requestList[0].reqCert;
    expect(Buffer.from(id.serialNumber).toString('hex')).toBe(leaf.serialNumber);
  });

  it('rejects a revoked certificate', async () => {
    const { fetcher } = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'revoked' }));
    await expect(checkCertificateRevocation(chain, hard(fetcher, { policy: 'soft-fail' }), now())).rejects.toThrow(/revoked/);
  });

  it('rejects an unknown certificate, even under soft-fail', async () => {
    const { fetcher } = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'unknown' }));
    await expect(checkCertificateRevocation(chain, hard(fetcher, { policy: 'soft-fail' }), now())).rejects.toThrow(/does not know/);
  });

  it('accepts a delegated responder with the OCSPSigning extended key usage', async () => {
    const responder = await ca.issueOcspResponder();
    const { fetcher } = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', responder }));
    await expect(checkCertificateRevocation(chain, hard(fetcher), now())).resolves.toBeDefined();
  });

  it('rejects a delegated responder without the OCSPSigning extended key usage', async () => {
    const responder = await ca.issueOcspResponder({ ocspSigning: false });
    const { fetcher } = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'revoked', responder }));
    await expect(checkCertificateRevocation(chain, hard(fetcher), now())).rejects.toThrow(/OCSPSigning/);
    const good = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', responder }));
    await expect(checkCertificateRevocation(chain, hard(good.fetcher, { policy: 'soft-fail' }), now())).rejects.toThrow(/OCSPSigning/);
  });

  it('rejects a responder certified by another CA', async () => {
    const other = await createTestCertificateAuthority('Someone Else');
    const responder = await other.issueOcspResponder();
    const { fetcher } = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', responder }));
    await expect(checkCertificateRevocation(chain, hard(fetcher), now())).rejects.toThrow(/not issued by the certificate issuer/);
  });

  it('rejects a response signed by the wrong key', async () => {
    const other = await createTestCertificateAuthority('Someone Else');
    const { fetcher } = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', signingKey: other.privateKey }));
    await expect(checkCertificateRevocation(chain, hard(fetcher), now())).rejects.toThrow(/signature does not verify/);
  });

  it('rejects a response about another certificate', async () => {
    const other = await ca.issueLeaf('https://pid.example');
    const { fetcher } = responding(() => ca.createOcspResponse({ certificate: other.certificate, status: 'good' }));
    await expect(checkCertificateRevocation(chain, hard(fetcher), now())).rejects.toThrow(/does not cover/);
  });

  it('rejects a stale response and an old one without nextUpdate', async () => {
    const stale = responding(() =>
      ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', thisUpdate: new Date(Date.now() - 7200_000), nextUpdate: new Date(Date.now() - 3600_000) }),
    );
    await expect(checkCertificateRevocation(chain, hard(stale.fetcher), now())).rejects.toThrow(/stale/);
    const old = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', thisUpdate: new Date(Date.now() - 7200_000), nextUpdate: null }));
    await expect(checkCertificateRevocation(chain, hard(old.fetcher), now())).rejects.toThrow(/stale/);
    const fresh = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', nextUpdate: null }));
    await expect(checkCertificateRevocation(chain, hard(fresh.fetcher), now())).resolves.toBeDefined();
  });

  it('checks the nonce when asked to', async () => {
    const nonceOf = (req: Uint8Array) => {
      const ext = AsnConvert.parse(req, OCSPRequest).tbsRequest.requestExtensions!.find((e) => e.extnID === id_pkix_ocsp_nonce)!;
      return new Uint8Array(AsnConvert.parse(ext.extnValue.buffer, OctetString).buffer);
    };
    const echo = responding((req) => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', nonce: nonceOf(req) }));
    await expect(checkCertificateRevocation(chain, hard(echo.fetcher, { ocspNonce: true }), now())).resolves.toBeDefined();
    const replayed = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', nonce: new Uint8Array(32) }));
    await expect(checkCertificateRevocation(chain, hard(replayed.fetcher, { ocspNonce: true }), now())).rejects.toThrow(/nonce/);
    const none = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good' }));
    await expect(checkCertificateRevocation(chain, hard(none.fetcher, { ocspNonce: true }), now())).rejects.toThrow(/nonce/);
  });

  it('soft-fail accepts an unreachable or busy responder, hard-fail does not', async () => {
    const down = responding(async () => {
      throw new Error('ECONNREFUSED');
    });
    expect((await checkCertificateRevocation(chain, hard(down.fetcher, { policy: 'soft-fail' }), now())).certificates[0].status).toBe('undetermined');
    await expect(checkCertificateRevocation(chain, hard(down.fetcher), now())).rejects.toThrow(/could not be determined/);
    const busy = responding(() => ca.createOcspResponse({ certificate: leaf.certificate, status: 'good', responseStatus: 'tryLater' }));
    expect((await checkCertificateRevocation(chain, hard(busy.fetcher, { policy: 'soft-fail' }), now())).certificates[0].status).toBe('undetermined');
    await expect(checkCertificateRevocation(chain, hard(busy.fetcher), now())).rejects.toThrow(/tryLater/);
  });

  it('falls back to the CRL when the responder is busy', async () => {
    const both = await ca.issueLeaf('https://pid.example', { ocspUrls: [OCSP_URL], crlUrls: [ROOT_CRL] });
    const c = verifyX5c(both.x5c, [ca.anchorPem], now(), 'https://pid.example').chain!;
    const crl = await ca.createCrl();
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: crl }, () => ca.createOcspResponse({ certificate: both.certificate, status: 'good', responseStatus: 'tryLater' }));
    const r = await checkCertificateRevocation(c, { policy: 'hard-fail', fetcher }, now());
    expect(r.certificates[0].via).toBe('crl');
  });

  it('rejects garbage from the responder', async () => {
    const { fetcher } = responding(async () => new Uint8Array([1, 2, 3]));
    await expect(checkCertificateRevocation(chain, hard(fetcher, { policy: 'soft-fail' }), now())).rejects.toThrow(/malformed/);
  });
});

// ---------------------------------------------------------------------------------------------------------

describe('revocation wired into verification', () => {
  let ca: TestCertificateAuthority;
  let provider: TestPidProvider;
  let pidSerial: string;

  beforeAll(async () => {
    ca = await createTestCertificateAuthority();
    provider = await createTestPidProvider('https://pid-crl.example', { x5c: true, ca, leaf: { crlUrls: [ROOT_CRL] } });
    const [leafB64] = await providerX5c(provider);
    pidSerial = new x509.X509Certificate(Buffer.from(leafB64, 'base64')).serialNumber;
  });

  // The test provider issues PIDs without status: declare it (requirePidStatus is on by default).
  const base = () => ({ trustAnchors: [ca.anchorPem], pidProvidersWithoutStatus: [provider.iss], audience: AUD, nonces: new InMemoryNonceStore() });

  it('keeps the earlier behaviour by default: no check, no network', async () => {
    const m = mandate();
    const chain = { root: await rootFrom(provider, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), base());
    expect(d.decision).toBe('ALLOW');
  });

  it('allows a PID whose provider certificate is good', async () => {
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await ca.createCrl() });
    const m = mandate();
    const chain = { root: await rootFrom(provider, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...base(),
      certificateRevocation: { policy: 'hard-fail', fetcher },
    });
    expect(d.decision).toBe('ALLOW');
  });

  it('denies a PID whose provider certificate is revoked', async () => {
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await ca.createCrl({ revoked: [pidSerial] }) });
    const m = mandate();
    const chain = { root: await rootFrom(provider, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...base(),
      certificateRevocation: { policy: 'soft-fail', fetcher },
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_ISSUER_UNTRUSTED' });
  });

  it('denies under hard-fail when the CRL cannot be fetched', async () => {
    const { fetcher } = memoryFetcher({});
    const m = mandate();
    const chain = { root: await rootFrom(provider, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...base(),
      certificateRevocation: { policy: 'hard-fail', fetcher },
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_ISSUER_UNTRUSTED' });
  });

  it('fetches nothing for a caller whose invocation does not verify', async () => {
    const { fetcher, calls } = memoryFetcher({ [ROOT_CRL]: await ca.createCrl() });
    const m = mandate();
    const other = await generateAgentKey();
    const chain = { root: await rootFrom(provider, m), delegations: [] };
    const bad = await createInvocation(other.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', aud: AUD });
    const d = await verifyAuthorization(chain, bad, {
      ...base(),
      certificateRevocation: { policy: 'hard-fail', fetcher },
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'INVOCATION_SIGNATURE_INVALID' });
    expect(calls).toHaveLength(0);
  });

  it('checks inline when verifyRoot is used on its own', async () => {
    const { fetcher } = memoryFetcher({ [ROOT_CRL]: await ca.createCrl({ revoked: [pidSerial] }) });
    const root = await rootFrom(provider, mandate());
    await expect(verifyRoot(root, { now: now(), trustAnchors: [ca.anchorPem], pidProvidersWithoutStatus: [provider.iss], certificateRevocation: { policy: 'hard-fail', fetcher } })).rejects.toMatchObject({
      code: 'PID_ISSUER_UNTRUSTED',
    });
    const ok = memoryFetcher({ [ROOT_CRL]: await ca.createCrl() });
    const r = await verifyRoot(root, { now: now(), trustAnchors: [ca.anchorPem], pidProvidersWithoutStatus: [provider.iss], certificateRevocation: { policy: 'hard-fail', fetcher: ok.fetcher } });
    expect(r.pidCertificateChain).toHaveLength(2);
  });

  it('fetches nothing for a presentation that does not verify', async () => {
    const { fetcher, calls } = memoryFetcher({ [ROOT_CRL]: await ca.createCrl() });
    const a = await rootFrom(provider, mandate());
    const b = await rootFrom(provider, mandate());
    const mixed = { transaction_data: b.transaction_data, presentation: a.presentation };
    await expect(verifyRoot(mixed, { now: now(), trustAnchors: [ca.anchorPem], pidProvidersWithoutStatus: [provider.iss], certificateRevocation: { policy: 'hard-fail', fetcher } })).rejects.toMatchObject({
      code: 'TX_DATA_MISMATCH',
    });
    expect(calls).toHaveLength(0);
  });

  it('fails closed on a misspelt policy', async () => {
    const m = mandate();
    const chain = { root: await rootFrom(provider, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...base(),
      certificateRevocation: { policy: 'strict' as never },
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_ISSUER_UNTRUSTED' });
  });

  it('refuses the synchronous resolver when revocation is enabled', async () => {
    const x5c = await providerX5c(provider);
    const trust = { trustAnchors: [ca.anchorPem], certificateRevocation: { policy: 'hard-fail' as const } };
    expect(() => resolveSigningKey({ x5c }, 'https://pid-crl.example', trust, now())).toThrow(/resolveSigningKeyAsync/);
    await expect(resolveSigningKeyAsync({ x5c }, 'https://pid-crl.example', trust, now())).rejects.toThrow(TrustError);
    const ok = await resolveSigningKeyAsync({ x5c }, 'https://pid-crl.example', { ...trust, certificateRevocation: { policy: 'hard-fail', crls: [await ca.createCrl()] } }, now());
    expect(ok.revocation?.certificates[0].status).toBe('good');
  });

  it('checks the certificate of a mandate status list signer', async () => {
    const statusCa = await createTestCertificateAuthority('Status CA');
    const signer = await statusCa.issueLeaf('https://status.example', { crlUrls: [INTER_CRL] });
    const publisher = new StatusListPublisher({ uri: 'https://status.example/list/1', signingKey: signer.privateKey, x5c: signer.x5c });
    const ref = publisher.allocate();
    const fetcherFor = (crl: Uint8Array) => memoryFetcher({ [INTER_CRL]: crl }).fetcher;
    const token = await publisher.token();
    const trust = (crl: Uint8Array) => ({
      trustAnchors: [statusCa.anchorPem],
      statusOrigins: ['https://status.example'],
      certificateRevocation: { policy: 'hard-fail' as const, fetcher: fetcherFor(crl) },
    });
    const check = (crl: Uint8Array, cache?: StatusListCache) =>
      checkStatus(ref, { trust: trust(crl), signer: 'https://status.example', allowedOrigins: ['https://status.example'], fetcher: async () => token, now: now(), cache });
    await expect(check(await statusCa.createCrl())).resolves.toBe(0);
    await expect(check(await statusCa.createCrl({ revoked: [signer.serialNumber] }))).rejects.toThrow(/revoked/);

    // A list cached under a trust without revocation is not served to a check that requires it.
    const cache = new StatusListCache();
    await checkStatus(ref, { trust: { trustAnchors: [statusCa.anchorPem] }, signer: 'https://status.example', allowedOrigins: ['https://status.example'], fetcher: async () => token, now: now(), cache });
    await expect(check(await statusCa.createCrl({ revoked: [signer.serialNumber] }), cache)).rejects.toThrow(/revoked/);

    // End to end: a mandate whose status list signer has been revoked is denied.
    const pidProvider = await createTestPidProvider('https://pid-ms.example');
    const m = mandate({ status: ref });
    const chain = { root: await rootFrom(pidProvider, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      trustedIssuers: [pidProvider.trusted],
      mandateStatusTrust: trust(await statusCa.createCrl({ revoked: [signer.serialNumber] })),
      statusFetcher: async () => token,
      audience: AUD,
      nonces: new InMemoryNonceStore(),
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'REVOKED' });
  });

  it('checks the PID provider certificate on its status list signature too', async () => {
    const p = await createTestPidProvider('https://pid-sl.example', { x5c: true, statusList: true, ca, leaf: { crlUrls: [INTER_CRL] } });
    const [leafB64] = await providerX5c(p);
    const serial = new x509.X509Certificate(Buffer.from(leafB64, 'base64')).serialNumber;
    // The PID path itself is good (served at ROOT_CRL), the status list signer path is checked again.
    const { fetcher, calls } = memoryFetcher({ [INTER_CRL]: await ca.createCrl() });
    const m = mandate();
    const chain = { root: await rootFrom(p, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...base(),
      statusFetcher: p.statusFetcher,
      certificateRevocation: { policy: 'hard-fail', fetcher },
    });
    expect(d.decision).toBe('ALLOW');
    expect(calls.length).toBeGreaterThanOrEqual(2);
    const revoked = memoryFetcher({ [INTER_CRL]: await ca.createCrl({ revoked: [serial] }) });
    const m2 = mandate();
    const chain2 = { root: await rootFrom(p, m2), delegations: [] };
    const d2 = await verifyAuthorization(chain2, await invocation(chain2, m2), {
      ...base(),
      statusFetcher: p.statusFetcher,
      certificateRevocation: { policy: 'hard-fail', fetcher: revoked.fetcher },
    });
    expect(d2).toMatchObject({ decision: 'DENY', code: 'PID_ISSUER_UNTRUSTED' });
  });
});

// ---------------------------------------------------------------------------------------------------------

describe('the HTTP revocation fetcher', () => {
  let server: Server;
  let base: string;
  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url === '/crl') {
        res.writeHead(200, { 'content-type': 'application/pkix-crl' });
        res.end(Buffer.from([1, 2, 3]));
      } else if (req.url === '/big') {
        res.writeHead(200);
        res.end(Buffer.alloc(2048));
      } else if (req.url === '/redirect') {
        res.writeHead(302, { location: '/crl' });
        res.end();
      } else if (req.url === '/ocsp' && req.method === 'POST') {
        const chunks: Buffer[] = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          res.writeHead(200, { 'content-type': 'application/ocsp-response' });
          res.end(Buffer.concat(chunks).subarray(0, 4));
        });
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const addr = server.address() as { port: number };
    base = `http://127.0.0.1:${addr.port}`;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  it('fetches CRLs and posts OCSP requests', async () => {
    const f = httpRevocationFetcher();
    expect([...(await f.crl(`${base}/crl`))]).toEqual([1, 2, 3]);
    expect([...(await f.ocsp(`${base}/ocsp`, new Uint8Array([9, 8, 7, 6, 5])))]).toEqual([9, 8, 7, 6]);
  });

  it('refuses redirects, oversized bodies, other schemes, credentials and hosts not allowed', async () => {
    const f = httpRevocationFetcher({ maxCrlBytes: 1024 });
    await expect(f.crl(`${base}/redirect`)).rejects.toThrow();
    await expect(f.crl(`${base}/big`)).rejects.toThrow(/too large/);
    await expect(f.crl('file:///etc/passwd')).rejects.toThrow(/http/);
    await expect(f.crl(`http://user:pw@127.0.0.1/crl`)).rejects.toThrow(/credentials/);
    await expect(httpRevocationFetcher({ allowedHosts: ['crl.example'] }).crl(`${base}/crl`)).rejects.toThrow(/not allowed/);
    await expect(httpRevocationFetcher({ allowHttp: false }).crl(`${base}/crl`)).rejects.toThrow(/http/);
  });
});

// ---------------------------------------------------------------------------------------------------------

describe('Lists of Trusted Entities (ETSI TS 119 602)', () => {
  let op: TestListOperator;
  let pidCa: TestCertificateAuthority;
  let walletCa: TestCertificateAuthority;
  let provider: TestPidProvider;

  beforeAll(async () => {
    op = await createTestListOperator();
    pidCa = await createTestCertificateAuthority('IT PID CA');
    walletCa = await createTestCertificateAuthority('Wallet CA');
    provider = await createTestPidProvider('https://pid-lote.example', { x5c: true, ca: pidCa });
  });

  const lote = (extra: Partial<Parameters<typeof buildTestLoTE>[0]> = {}) =>
    buildTestLoTE({
      type: LOTE_TYPE.pidProviders,
      entities: [
        { name: 'IT PID Provider', services: [{ type: LOTE_SERVICE_TYPE.pidIssuance, certificates: [pidCa.certificateB64] }] },
        { name: 'Wallet Provider', services: [{ type: LOTE_SERVICE_TYPE.walletIssuance, certificates: [walletCa.certificateB64] }] },
      ],
      ...extra,
    });

  it('verifies a signed list and builds a trust configuration that authorizes the PID', async () => {
    const list = await loadTrustedList(await op.sign(lote()), { signerCertificates: [op.certificatePem], expectedType: LOTE_TYPE.pidProviders });
    expect(list.verification).toMatchObject({ kind: 'jades-compact', alg: 'ES256' });
    expect(list.entities.map((e) => e.names[0])).toEqual(['IT PID Provider', 'Wallet Provider']);
    const trust = trustConfigFromLists(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance] });
    expect(trust.trustAnchors).toHaveLength(1);
    const m = mandate();
    const chain = { root: await rootFrom(provider, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...trust,
      pidProvidersWithoutStatus: [provider.iss],
      audience: AUD,
      nonces: new InMemoryNonceStore(),
    });
    expect(d.decision).toBe('ALLOW');
  });

  it('does not let a wallet provider CA vouch for PIDs', async () => {
    const list = await loadTrustedList(await op.sign(lote()), { signerCertificates: [op.certificatePem] });
    const trust = trustConfigFromLists(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance] });
    const intruder = await createTestPidProvider('https://pid-lote.example', { x5c: true, ca: walletCa });
    const m = mandate();
    const chain = { root: await rootFrom(intruder, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...trust,
      audience: AUD,
      nonces: new InMemoryNonceStore(),
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_ISSUER_UNTRUSTED' });
  });

  it('accepts a list that publishes the provider signing certificate directly', async () => {
    const [leaf] = await providerX5c(provider);
    const doc = buildTestLoTE({ entities: [{ name: 'IT PID Provider', services: [{ type: LOTE_SERVICE_TYPE.pidIssuance, certificates: [leaf] }] }] });
    const list = await loadTrustedList(await op.sign(doc), { signerCertificates: [op.certificatePem] });
    const m = mandate();
    const chain = { root: await rootFrom(provider, m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...trustConfigFromLists(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance] }),
      pidProvidersWithoutStatus: [provider.iss],
      audience: AUD,
      nonces: new InMemoryNonceStore(),
    });
    expect(d.decision).toBe('ALLOW');
  });

  it('keeps the settings of a base configuration', async () => {
    const list = await loadTrustedList(await op.sign(lote()), { signerCertificates: [op.certificatePem] });
    const trust = trustConfigFromLists(list, {
      serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance],
      base: { requiredPolicyOids: ['1.2.3'], certificateRevocation: { policy: 'hard-fail' } },
    });
    expect(trust.requiredPolicyOids).toEqual(['1.2.3']);
    expect(trust.certificateRevocation?.policy).toBe('hard-fail');
  });

  it('rejects a tampered list', async () => {
    const jws = await op.sign(lote());
    const [h, p, s] = jws.split('.');
    const doc = JSON.parse(Buffer.from(p, 'base64url').toString());
    doc.LoTE.TrustedEntitiesList[0].TrustedEntityServices[0].ServiceInformation.ServiceDigitalIdentity.X509Certificates[0].val = walletCa.certificateB64;
    const tampered = `${h}.${Buffer.from(JSON.stringify(doc)).toString('base64url')}.${s}`;
    await expect(loadTrustedList(tampered, { signerCertificates: [op.certificatePem] })).rejects.toThrow(/does not verify/);
    const badSig = `${h}.${p}.${s.slice(0, -4)}AAAA`;
    await expect(loadTrustedList(badSig, { signerCertificates: [op.certificatePem] })).rejects.toThrow(/does not verify/);
  });

  it('rejects a list signed by someone who is not an expected signer', async () => {
    const other = await createTestListOperator('Rogue Operator');
    await expect(loadTrustedList(await other.sign(lote()), { signerCertificates: [op.certificatePem] })).rejects.toThrow(/not an expected list signer/);
    // Naming the expected certificate does not help when the signature is made with another key.
    const lying = await other.sign(lote(), { header: { x5c: [op.certificateB64], 'x5t#S256': undefined } });
    await expect(loadTrustedList(lying, { signerCertificates: [op.certificatePem] })).rejects.toThrow(/does not verify/);
    // x5c and x5t#S256 must agree.
    const mixed = await op.sign(lote(), { header: { 'x5t#S256': createHash('sha256').update(Buffer.from(other.certificateB64, 'base64')).digest('base64url') } });
    await expect(loadTrustedList(mixed, { signerCertificates: [op.certificatePem, other.certificatePem] })).rejects.toThrow(/not an expected list signer/);
  });

  it('requires the header to identify the signing certificate', async () => {
    const anon = await op.sign(lote(), { header: { x5c: undefined, 'x5t#S256': undefined } });
    await expect(loadTrustedList(anon, { signerCertificates: [op.certificatePem] })).rejects.toThrow(/does not identify/);
    const thumbOnly = await op.sign(lote(), { header: { x5c: undefined } });
    await expect(loadTrustedList(thumbOnly, { signerCertificates: [op.certificatePem] })).resolves.toBeDefined();
  });

  it('refuses header parameters it cannot honour', async () => {
    const sign = (header: Record<string, unknown>) => op.sign(lote(), { header });
    const opts = { signerCertificates: [op.certificatePem] };
    await expect(loadTrustedList(await sign({ crit: ['sigT', 'sigPl'], sigPl: {} }), opts)).rejects.toThrow(/critical/);
    await expect(loadTrustedList(await sign({ sigX5ts: [] }), opts)).rejects.toThrow(/sigX5ts/);
    await expect(loadTrustedList(await sign({ sigT: '2020-01-01T00:00:00.123Z' }), opts)).rejects.toThrow(/sigT/);
    await expect(loadTrustedList(await sign({ sigT: '2099-01-01T00:00:00Z' }), opts)).rejects.toThrow(/future/);
    await expect(loadTrustedList(await sign({}), { ...opts, algorithms: ['ES384'] })).rejects.toThrow(/algorithm/);
    const unsignedJws = `${Buffer.from(JSON.stringify({ alg: 'none', x5c: [op.certificateB64] })).toString('base64url')}.${Buffer.from(JSON.stringify(lote())).toString('base64url')}.`;
    await expect(loadTrustedList(unsignedJws, opts)).rejects.toThrow(/algorithm/);
  });

  it('rejects an expired list, a closed list and a list from the future', async () => {
    const opts = { signerCertificates: [op.certificatePem] };
    const expired = lote({ issued: new Date(Date.now() - 40 * 86400_000), nextUpdate: new Date(Date.now() - 86400_000) });
    await expect(loadTrustedList(await op.sign(expired), opts)).rejects.toThrow(/expired/);
    await expect(loadTrustedList(await op.sign(lote({ nextUpdate: null })), opts)).rejects.toThrow(/closed/);
    const future = lote({ issued: new Date(Date.now() + 86400_000), nextUpdate: new Date(Date.now() + 2 * 86400_000) });
    await expect(loadTrustedList(await op.sign(future), opts)).rejects.toThrow(/future/);
    // The same list is fine before its NextUpdate, and refused at it.
    const list = await loadTrustedList(await op.sign(lote()), opts);
    await expect(loadTrustedList(await op.sign(lote()), { ...opts, now: list.nextUpdate })).rejects.toThrow(/expired/);
  });

  it('enforces type, sequence number and validity limits', async () => {
    const opts = { signerCertificates: [op.certificatePem] };
    await expect(loadTrustedList(await op.sign(lote()), { ...opts, expectedType: LOTE_TYPE.walletProviders })).rejects.toThrow(/type/);
    await expect(loadTrustedList(await op.sign(lote({ sequenceNumber: 3 })), { ...opts, minSequenceNumber: 4 })).rejects.toThrow(/older/);
    await expect(loadTrustedList(await op.sign(lote()), { ...opts, maxValiditySeconds: 86400 })).rejects.toThrow(/validity/);
  });

  it('checks the signer names against the scheme operator when asked to', async () => {
    const opts = { signerCertificates: [op.certificatePem], requireSignerMatchesOperator: true };
    await expect(loadTrustedList(await op.sign(lote()), opts)).resolves.toBeDefined();
    await expect(loadTrustedList(await op.sign(lote({ operator: 'Another Operator' })), opts)).rejects.toThrow(/organisation/);
    await expect(loadTrustedList(await op.sign(lote({ territory: 'IT' })), opts)).rejects.toThrow(/country/);
  });

  it('never accepts an unsigned list without the explicit testing flag', async () => {
    const json = JSON.stringify(lote());
    await expect(loadTrustedList(json, { signerCertificates: [op.certificatePem] })).rejects.toThrow(/not signed/);
    const list = await loadTrustedList(new TextEncoder().encode(json), { unsigned: 'accept-for-testing' });
    expect(list.verification.kind).toBe('unsigned-accepted-for-testing');
    await expect(loadTrustedList(await op.sign(lote()), { unsigned: 'accept-for-testing' })).rejects.toThrow(/no signer certificates/);
  });

  it('refuses formats it does not verify, oversized and malformed documents', async () => {
    const opts = { signerCertificates: [op.certificatePem] };
    await expect(loadTrustedList('<TrustServiceStatusList/>', opts)).rejects.toThrow(/XML/);
    await expect(loadTrustedList(JSON.stringify({ payload: 'x', signatures: [] }), opts)).rejects.toThrow(/JSON serialization/);
    await expect(loadTrustedList(await op.sign(lote()), { ...opts, maxBytes: 100 })).rejects.toThrow(/too large/);
    await expect(loadTrustedList('a.b', opts)).rejects.toThrow(/compact JWS/);
    await expect(loadTrustedList(new Uint8Array([0xff, 0xfe, 0x00]), opts)).rejects.toThrow(/UTF-8/);
    const bad = lote();
    delete (bad as any).LoTE.ListAndSchemeInformation.SchemeOperatorName;
    await expect(loadTrustedList(await op.sign(bad), opts)).rejects.toThrow(/schema/);
    const huge = buildTestLoTE({ entities: Array.from({ length: 10_001 }, (_, i) => ({ name: `E${i}`, services: [{ type: 'x', certificates: [] }] })) });
    await expect(loadTrustedList(JSON.stringify(huge), { unsigned: 'accept-for-testing' })).rejects.toThrow(/schema/);
  });

  it('takes only active services of the requested types', async () => {
    const doc = buildTestLoTE({
      entities: [
        {
          name: 'X',
          services: [
            { type: LOTE_SERVICE_TYPE.pidIssuance, certificates: [pidCa.certificateB64] },
            { type: LOTE_SERVICE_TYPE.pidIssuance, certificates: [walletCa.certificateB64], status: 'http://example.org/withdrawn' },
            { type: LOTE_SERVICE_TYPE.pidRevocation, certificates: [walletCa.certificateB64] },
          ],
        },
      ],
    });
    const list = await loadTrustedList(JSON.stringify(doc), { unsigned: 'accept-for-testing' });
    expect(listedServices(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance] })).toHaveLength(1);
    expect(listedServices(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance], acceptedStatuses: ['http://example.org/withdrawn'] })).toHaveLength(2);
    expect(trustConfigFromLists(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidRevocation] }).trustAnchors).toEqual([pem(walletCa.certificateB64)]);
    expect(() => listedServices(list, { serviceTypes: [] })).toThrow(TrustListError);
  });

  it('turns published public keys into trusted issuers only when asked, and never keeps private parts', async () => {
    const doc = buildTestLoTE({
      entities: [
        {
          name: 'X',
          services: [
            { type: LOTE_SERVICE_TYPE.pidIssuance, publicKeys: [provider.trusted.jwk, { ...provider.trusted.jwk, d: 'secret' }], supplyPoints: ['https://pid-lote.example', 'http://plain.example'] },
          ],
        },
      ],
    });
    const list = await loadTrustedList(JSON.stringify(doc), { unsigned: 'accept-for-testing' });
    expect(trustConfigFromLists(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance] }).trustedIssuers).toBeUndefined();
    const t = trustConfigFromLists(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance], publicKeysAsIssuersOfSupplyPoints: true });
    expect(t.trustedIssuers).toEqual([{ iss: 'https://pid-lote.example', jwk: provider.trusted.jwk }]);
  });

  it('reads a list made and signed with the OpenWallet Foundation LoTE SDK', async () => {
    let doc = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Plenipo Test Scheme Operator' }],
      LoTEType: LOTE_TYPE.pidProviders,
      SchemeTerritory: 'EU',
    });
    doc = addTrustedEntity(
      doc,
      trustedEntity()
        .name('IT PID Provider')
        .postalAddress({ StreetAddress: 'Via Roma 1', Locality: 'Roma', PostalCode: '00100', Country: 'IT' })
        .email('pid@example.it')
        .addService(service().name('PID issuance').type(LOTE_SERVICE_TYPE.pidIssuance).addCertificate(pidCa.certificateB64).build())
        .build(),
    );
    const key = KeyObject.from(op.privateKey as unknown as webcrypto.CryptoKey);
    const signed = await signLoTE({
      lote: doc,
      keyId: 'test',
      certificates: [op.certificatePem],
      signer: async (input: string | Uint8Array) =>
        cryptoSign('sha256', Buffer.from(input as string), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url'),
    } as any);
    const list = await loadTrustedList(signed.jws, { signerCertificates: [op.certificatePem], expectedType: LOTE_TYPE.pidProviders });
    const trust = trustConfigFromLists(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance] });
    expect(trust.trustAnchors).toEqual([pidCa.anchorPem.replace(/\r/g, '')].map((p) => new NodeCert(p).toString()));
  });

  it('fetches lists over https only', async () => {
    await expect(fetchTrustedList('http://lists.example/pid.jwt')).rejects.toThrow(/https/);
    await expect(fetchTrustedList('not a url')).rejects.toThrow(/not valid/);
    await expect(fetchTrustedList('https://u:p@lists.example/pid.jwt')).rejects.toThrow(/https/);
  });
});
