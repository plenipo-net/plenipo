/** Regression tests for the findings of the v0.2 security review. */
import 'reflect-metadata';
import { describe, expect, it, beforeAll, vi } from 'vitest';
import { exportJWK, generateKeyPair } from 'jose';
import * as x509 from '@peculiar/x509';
import {
  createInvocation,
  createMandate,
  createMandateRequest,
  delegateMandate,
  generateAgentKey,
  handleMandateResponse,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  nowSeconds,
  StatusListCache,
  StatusListPublisher,
  verifyAuthorization,
  verifyRoot,
  verifyX5c,
  type AgentKey,
  type Mandate,
  type MandateChain,
} from '../src/index.js';
import { guardTool, META_KEY } from '../src/mcp.js';
import { createTestCertificateAuthority, createTestPidProvider, createTestWallet, type TestWallet } from '../src/testing.js';

const AUD = 'https://rail.example';
let agent: AgentKey;
beforeAll(async () => {
  agent = await generateAgentKey();
});

const mandate = (o: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate =>
  createMandate({ agentJwk: agent.publicJwk, actions: ['travel.*'], maxDepth: 1, ...o });
const inv = (chain: MandateChain, m: Mandate, key = agent.privateKey) =>
  createInvocation(key, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', aud: AUD });
const common = () => ({ audience: AUD, ledger: new InMemorySpendingLedger(), nonces: new InMemoryNonceStore() });

async function walletFor(p: Awaited<ReturnType<typeof createTestPidProvider>>, o: { omitIss?: boolean } = {}): Promise<TestWallet> {
  const w = await createTestWallet();
  w.storePid(await p.issuePid(w.holderJwk, { given_name: 'Mario', family_name: 'Rossi' }, o));
  return w;
}

describe('1. a status list must be signed by the PID provider itself', () => {
  it('rejects a list for A signed by provider B under the same anchor (x5c)', async () => {
    const ca = await createTestCertificateAuthority();
    const a = await createTestPidProvider('https://pid-a.example', { x5c: true, statusList: true, ca });
    const b = await createTestPidProvider('https://pid-b.example', { x5c: true, ca });
    const w = await walletFor(a);
    const ref = a.lastStatus!;
    a.statusList!.revoke(ref);
    const forged = await b.signStatusList({ uri: ref.status_list.uri }); // says "all valid"
    const m = mandate();
    const chain = { root: await w.approveMandate(m), delegations: [] };
    const d = await verifyAuthorization(chain, await inv(chain, m), {
      ...common(),
      trustAnchors: [ca.anchorPem],
      statusFetcher: async () => forged,
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_REVOKED' });
  });

  it('rejects a list for A signed by another trusted issuer (trustedIssuers)', async () => {
    const a = await createTestPidProvider('https://pid-a.example', { statusList: true });
    const b = await createTestPidProvider('https://pid-b.example');
    const w = await walletFor(a);
    a.statusList!.revoke(a.lastStatus!);
    const forged = await b.signStatusList({ uri: a.lastStatus!.status_list.uri });
    const m = mandate();
    const chain = { root: await w.approveMandate(m), delegations: [] };
    const d = await verifyAuthorization(chain, await inv(chain, m), {
      ...common(),
      trustedIssuers: [a.trusted, b.trusted],
      statusFetcher: async () => forged,
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_REVOKED' });
  });

  it('accepts a separate status signer only when configured, and only from its origins', async () => {
    const a = await createTestPidProvider('https://pid-a.example', { statusList: true });
    const w = await walletFor(a);
    const statusKeys = await generateKeyPair('ES256', { extractable: true });
    const STATUS = 'https://status.pid-a.example';
    const m = mandate();
    const chain = { root: await w.approveMandate(m), delegations: [] };
    // The PID points to a list under the provider's own origin, so a separate signer must be configured
    // for that origin explicitly.
    const sep = new StatusListPublisher({ uri: a.lastStatus!.status_list.uri, signingKey: statusKeys.privateKey });
    const pidStatusTrust = { trustedIssuers: [{ iss: 'https://pid-a.example', jwk: await exportJWK(statusKeys.publicKey) }] };
    const ok = await verifyAuthorization(chain, await inv(chain, m), {
      ...common(),
      trustedIssuers: [a.trusted],
      pidStatusTrust,
      statusFetcher: () => sep.token(),
    });
    expect(ok.decision).toBe('ALLOW');
    const wrongOrigin = await verifyAuthorization(chain, await inv(chain, m), {
      ...common(),
      trustedIssuers: [a.trusted],
      pidStatusTrust: { ...pidStatusTrust, statusOrigins: [STATUS] },
      statusFetcher: () => sep.token(),
    });
    expect(wrongOrigin).toMatchObject({ code: 'PID_REVOKED' });
  });

  it('rejects a status list token without exp', async () => {
    const a = await createTestPidProvider('https://pid-a.example', { statusList: true });
    const w = await walletFor(a);
    const signer = await generateKeyPair('ES256', { extractable: true });
    const payload = JSON.parse(Buffer.from((await a.statusList!.token()).split('.')[1], 'base64url').toString());
    delete payload.exp;
    const { SignJWT } = await import('jose');
    const noExp = await new SignJWT(payload).setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' }).sign(signer.privateKey);
    const m = mandate();
    const chain = { root: await w.approveMandate(m), delegations: [] };
    const d = await verifyAuthorization(chain, await inv(chain, m), {
      ...common(),
      trustedIssuers: [a.trusted],
      pidStatusTrust: { trustedIssuers: [{ iss: 'https://pid-a.example', jwk: await exportJWK(signer.publicKey) }] },
      statusFetcher: async () => noExp,
    });
    expect(d).toMatchObject({ code: 'PID_REVOKED' });
    expect(d.decision === 'DENY' && d.detail).toMatch(/exp/);
  });
});

describe('2. no fetches to URLs chosen by a delegator', () => {
  it('refuses a delegated mandate whose status list is on a foreign origin, without fetching', async () => {
    const p = await createTestPidProvider();
    const w = await walletFor(p);
    const platform = await generateKeyPair('ES256', { extractable: true });
    const parent = mandate();
    const sub = await generateAgentKey();
    const child = createMandate({
      agentJwk: sub.publicJwk,
      actions: ['travel.book'],
      nbf: parent.nbf,
      exp: parent.exp,
      status: { status_list: { uri: 'https://169.254.169.254/latest/meta-data/iam', idx: 0 } },
    });
    const chain = {
      root: await w.approveMandate(parent),
      delegations: [await delegateMandate({ parent, parentAgentKey: agent.privateKey, child })],
    };
    const fetcher = vi.fn(async () => '');
    const d = await verifyAuthorization(chain, await inv(chain, child, sub.privateKey), {
      ...common(),
      trustedIssuers: [p.trusted],
      mandateStatusTrust: { trustedIssuers: [{ iss: 'https://agents.example', jwk: await exportJWK(platform.publicKey) }] },
      statusFetcher: fetcher,
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'REVOKED' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('does not fetch anything for an invocation that is not signed', async () => {
    const p = await createTestPidProvider('https://pid-s.example', { statusList: true });
    const w = await walletFor(p);
    const m = mandate();
    const fetcher = vi.fn(p.statusFetcher);
    const d = await verifyAuthorization({ root: await w.approveMandate(m), delegations: [] }, 'not-even-a-jws', {
      ...common(),
      trustedIssuers: [p.trusted],
      statusFetcher: fetcher,
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'INVOCATION_SIGNATURE_INVALID' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('keeps fetch errors out of the reason the MCP guard returns', async () => {
    const p = await createTestPidProvider('https://pid-s.example', { statusList: true });
    const w = await walletFor(p);
    const m = mandate();
    let seen: unknown;
    const tool = guardTool(async () => ({ content: [{ type: 'text', text: 'ok' }] }), {
      action: 'travel.book',
      counterparty: () => 'rail.example',
      amount: null,
      ...common(),
      trustedIssuers: [p.trusted],
      statusFetcher: async () => {
        throw new Error('connect ECONNREFUSED 127.0.0.1:6379');
      },
      onDecision: (d) => (seen = d),
    });
    const chain = { root: await w.approveMandate(m), delegations: [] };
    const invocation = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', aud: AUD, args: {} });
    const res = await tool({}, { _meta: { [META_KEY]: { chain, invocation } } });
    expect(res.content[0].text).not.toMatch(/ECONNREFUSED|127\.0\.0\.1/);
    expect(seen).toMatchObject({ detail: expect.stringMatching(/ECONNREFUSED/) });
  });

  it('refuses http status references', () => {
    expect(() => mandate({ status: { status_list: { uri: 'http://agents.example/s', idx: 1 } } })).toThrow(/status/);
  });
});

describe('3. x5c leaves must be fit to sign PIDs', () => {
  it('rejects a PID without iss', async () => {
    const p = await createTestPidProvider('https://pid-x.example', { x5c: true });
    const w = await walletFor(p, { omitIss: true });
    await expect(verifyRoot(await w.approveMandate(mandate()), { now: nowSeconds(), trustAnchors: [p.anchorPem!] })).rejects.toThrow(/no iss/);
  });

  it('rejects a leaf without digitalSignature', async () => {
    const ca = await createTestCertificateAuthority();
    const leaf = await ca.issueLeaf('https://pid.example', { keyUsage: x509.KeyUsageFlags.keyAgreement });
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example')).toThrow(/digitalSignature/);
  });

  it('rejects a leaf that is a CA, even alone', async () => {
    const ca = await createTestCertificateAuthority();
    const leaf = await ca.issueLeaf('https://pid.example', { ca: true, keyUsage: x509.KeyUsageFlags.digitalSignature });
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example')).toThrow(/CA/);
  });

  it('rejects the anchor presented as the signer', async () => {
    const ca = await createTestCertificateAuthority();
    expect(() => verifyX5c([ca.certificateB64], [ca.anchorPem], nowSeconds(), 'https://pid.example')).toThrow(/anchor/);
  });

  it('requires the configured certificate policy', async () => {
    const ca = await createTestCertificateAuthority();
    const leaf = await ca.issueLeaf('https://pid.example');
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example', { requiredPolicyOids: ['1.2.3.4'] })).toThrow(/policies/);
  });
});

describe('5. path validation', () => {
  it('accepts a chain through an intermediate', async () => {
    const ca = await createTestCertificateAuthority();
    const sub = await ca.issueIntermediate('PID Issuing CA');
    const leaf = await sub.issueLeaf('https://pid.example');
    expect(leaf.x5c).toHaveLength(2);
    expect(verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example').via).toBe('x5c');
  });

  it('enforces the anchor path length', async () => {
    const ca = await createTestCertificateAuthority('Anchor pathLen 0', { pathLength: 0 });
    const sub = await ca.issueIntermediate('Not allowed');
    const leaf = await sub.issueLeaf('https://pid.example');
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example')).toThrow(/intermediate CAs/);
  });

  it('enforces an intermediate path length', async () => {
    const ca = await createTestCertificateAuthority();
    const sub = await ca.issueIntermediate('Sub pathLen 0', { pathLength: 0 });
    const subsub = await sub.issueIntermediate('Not allowed');
    const leaf = await subsub.issueLeaf('https://pid.example');
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example')).toThrow(/intermediate CAs/);
  });
});

describe('4. the status cache does not mix trust domains', () => {
  it('does not serve a list verified under mandate trust to the PID check', async () => {
    const p = await createTestPidProvider('https://pid-c.example', { statusList: true });
    const w = await walletFor(p);
    const pidRef = p.lastStatus!;
    p.statusList!.revoke(pidRef);
    // An agent platform key that is (wrongly) also allowed to sign lists on the PID provider origin.
    const platform = await generateKeyPair('ES256', { extractable: true });
    const fake = new StatusListPublisher({ uri: pidRef.status_list.uri, signingKey: platform.privateKey, iss: 'https://pid-c.example' });
    const mandateStatusTrust = { trustedIssuers: [{ iss: 'https://pid-c.example', jwk: await exportJWK(platform.publicKey) }] };
    const cache = new StatusListCache(60);
    const fetcher = async (uri: string) => (uri === pidRef.status_list.uri ? fake.token() : '');
    // First verification caches the fake list under mandate trust.
    const m1 = mandate({ status: { status_list: { uri: pidRef.status_list.uri, idx: 3 } } });
    const plain = await createTestPidProvider('https://pid-plain.example');
    const w1 = await walletFor(plain);
    const chain = { root: await w1.approveMandate(m1), delegations: [] };
    await verifyAuthorization(chain, await inv(chain, m1), {
      ...common(),
      trustedIssuers: [plain.trusted],
      mandateStatusTrust,
      statusFetcher: fetcher,
      statusCache: cache,
    });
    // Then the revoked PID is checked with the same cache and the genuine fetcher.
    const m2 = mandate();
    const chain2 = { root: await w.approveMandate(m2), delegations: [] };
    const d = await verifyAuthorization(chain2, await inv(chain2, m2), {
      ...common(),
      trustedIssuers: [p.trusted],
      statusFetcher: p.statusFetcher,
      statusCache: cache,
    });
    expect(d).toMatchObject({ code: 'PID_REVOKED' });
  });
});

describe('6. OpenID4VP sessions', () => {
  it('redeems a response only once, checks state before errors, and sanitises error codes', async () => {
    const p = await createTestPidProvider('https://pid-vp.example', { x5c: true });
    const w = await walletFor(p);
    const req = await createMandateRequest({ mandate: mandate(), clientId: 'redirect_uri:https://agents.example/cb', responseUri: 'https://agents.example/cb', encryptResponse: false });
    // The test provider issues PIDs without status: declare it (requirePidStatus is on by default).
    const opts = { now: nowSeconds(), trustAnchors: [p.anchorPem!], pidProvidersWithoutStatus: [p.iss], sessions: new InMemoryNonceStore() };
    await expect(handleMandateResponse({ error: 'access_denied' }, req.session, opts)).rejects.toThrow(/state/);
    await expect(handleMandateResponse({ error: 'x\nFAKE LOG LINE', state: req.session.state }, req.session, opts)).rejects.toThrow(/unknown_error/);
    const body = await w.respond(req.params);
    await handleMandateResponse(body, req.session, opts);
    await expect(handleMandateResponse(body, req.session, opts)).rejects.toThrow(/already been answered/);
  });

  it('lets a relying party restrict the platforms whose roots it accepts', async () => {
    const p = await createTestPidProvider();
    const w = await walletFor(p);
    const m = mandate();
    const root = await w.approveMandate(m, { aud: 'x509_san_dns:other-platform.example' });
    const chain = { root, delegations: [] };
    const d = await verifyAuthorization(chain, await inv(chain, m), {
      ...common(),
      trustedIssuers: [p.trusted],
      acceptedRootAudiences: ['x509_san_dns:agents.example'],
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'ROOT_INVALID' });
  });
});

describe('re-review: policies, EKU and deferred PID status', () => {
  const POLICY = '1.3.6.1.4.1.99999.1.1';

  it('enforces requiredPolicyOids through verifyAuthorization', async () => {
    const p = await createTestPidProvider('https://pid-pol.example', { x5c: true });
    const w = await walletFor(p);
    const m = mandate();
    const chain = { root: await w.approveMandate(m), delegations: [] };
    const d = await verifyAuthorization(chain, await inv(chain, m), {
      ...common(),
      trustAnchors: [p.anchorPem!],
      requiredPolicyOids: [POLICY],
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_ISSUER_UNTRUSTED' });
  });

  it('rejects a required policy that an intermediate CA does not allow', async () => {
    const ca = await createTestCertificateAuthority();
    const sub = await ca.issueIntermediate('Relying party CA', { policies: ['1.3.6.1.4.1.99999.2'] });
    const leaf = await sub.issueLeaf('https://pid.example', { policies: [POLICY] });
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example', { requiredPolicyOids: [POLICY] })).toThrow(/does not allow/);
    const pidCa = await ca.issueIntermediate('PID CA', { policies: [POLICY] });
    const ok = await pidCa.issueLeaf('https://pid.example', { policies: [POLICY] });
    expect(verifyX5c(ok.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example', { requiredPolicyOids: [POLICY] }).via).toBe('x5c');
  });

  it('rejects a leaf with a critical EKU it cannot check, and checks requiredEkus', async () => {
    const ca = await createTestCertificateAuthority();
    const serverAuth = '1.3.6.1.5.5.7.3.1';
    const leaf = await ca.issueLeaf('https://pid.example', { eku: { usages: [serverAuth], critical: true } });
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example')).toThrow(/extended key usage/);
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example', { requiredEkus: ['1.0.18013.5.1.2'] })).toThrow(/extended key usage/);
  });

  it('checks PID status in handleMandateResponse even when asked to defer', async () => {
    const p = await createTestPidProvider('https://pid-def.example', { x5c: true, statusList: true });
    const w = await walletFor(p);
    p.statusList!.revoke(p.lastStatus!);
    const req = await createMandateRequest({ mandate: mandate(), clientId: 'redirect_uri:https://agents.example/cb', responseUri: 'https://agents.example/cb', encryptResponse: false });
    const body = await w.respond(req.params);
    await expect(
      handleMandateResponse(body, req.session, {
        now: nowSeconds(),
        trustAnchors: [p.anchorPem!],
        statusFetcher: p.statusFetcher,
        sessions: new InMemoryNonceStore(),
        pidStatus: 'defer',
      }),
    ).rejects.toThrow(/PID status/);
  });
});
