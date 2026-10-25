import { describe, expect, it, beforeAll } from 'vitest';
import { generateKeyPair, SignJWT } from 'jose';
import {
  createInvocation,
  createMandate,
  createMandateRequest,
  generateAgentKey,
  handleMandateResponse,
  authorizationRequestUrl,
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
  type StatusFetcher,
} from '../src/index.js';
import {
  createTestCertificateAuthority,
  createTestPidProvider,
  createTestWallet,
  type TestPidProvider,
  type TestWallet,
} from '../src/testing.js';

const AUD = 'https://rail.example';
const PLATFORM = 'https://agents.example';
const CLIENT_ID = 'x509_san_dns:agents.example';

let agent: AgentKey;

beforeAll(async () => {
  agent = await generateAgentKey();
});

function mandate(overrides: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['travel.*'],
    counterparties: ['rail.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
    ...overrides,
  });
}

function invocation(chain: MandateChain, m: Mandate, value = 100) {
  return createInvocation(agent.privateKey, { chain,
    mandateId: m.id,
    action: 'travel.book',
    counterparty: 'rail.example',
    amount: { value, currency: 'EUR' },
    aud: AUD,
  });
}

async function walletWithPid(provider: TestPidProvider): Promise<TestWallet> {
  const w = await createTestWallet();
  w.storePid(await provider.issuePid(w.holderJwk, { given_name: 'Mario', family_name: 'Rossi' }));
  return w;
}

function common() {
  return { audience: AUD, ledger: new InMemorySpendingLedger(), nonces: new InMemoryNonceStore() };
}

describe('trust through x5c chains', () => {
  let provider: TestPidProvider;
  let wallet: TestWallet;
  beforeAll(async () => {
    provider = await createTestPidProvider('https://pid.example.it', { x5c: true });
    wallet = await walletWithPid(provider);
  });

  it('accepts a PID whose certificate chains to a configured anchor', async () => {
    const m = mandate();
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    // The test provider issues PIDs without status: declare it (requirePidStatus is on by default).
    const d = await verifyAuthorization(chain, await invocation(chain, m), { ...common(), trustAnchors: [provider.anchorPem!], pidProvidersWithoutStatus: [provider.iss] });
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') {
      expect(d.pid_trusted_via).toBe('x5c');
      expect(d.pid_issuer).toBe('https://pid.example.it');
    }
  });

  it('rejects a chain to another anchor', async () => {
    const otherCa = await createTestCertificateAuthority('Somebody else');
    const m = mandate();
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), { ...common(), trustAnchors: [otherCa.anchorPem] });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_ISSUER_UNTRUSTED' });
  });

  it('rejects a certificate that does not name the issuer', async () => {
    const ca = await createTestCertificateAuthority();
    const leaf = await ca.issueLeaf('https://pid.example.it');
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://impostor.example')).toThrow(/does not name/);
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example.it/tenant-b')).toThrow(/does not name/);
    expect(verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example.it').via).toBe('x5c');
  });

  it('rejects an expired leaf certificate', async () => {
    const ca = await createTestCertificateAuthority();
    const leaf = await ca.issueLeaf('https://pid.example.it', { notAfter: new Date(Date.now() - 1000) });
    expect(() => verifyX5c(leaf.x5c, [ca.anchorPem], nowSeconds(), 'https://pid.example.it')).toThrow();
  });

  it('rejects a self-signed leaf even if it names the issuer', async () => {
    const rogue = await createTestCertificateAuthority();
    const leaf = await rogue.issueLeaf('https://pid.example.it');
    expect(() => verifyX5c(leaf.x5c, [provider.anchorPem!], nowSeconds(), 'https://pid.example.it')).toThrow();
  });
});

describe('PID status', () => {
  let provider: TestPidProvider;
  beforeAll(async () => {
    provider = await createTestPidProvider('https://pid-status.example', { statusList: true });
  });

  it('allows a PID whose status is valid', async () => {
    const wallet = await walletWithPid(provider);
    const m = mandate();
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...common(),
      trustedIssuers: [provider.trusted],
      statusFetcher: provider.statusFetcher,
    });
    expect(d.decision).toBe('ALLOW');
  });

  it('denies a revoked PID', async () => {
    const wallet = await walletWithPid(provider);
    const status = provider.lastStatus!;
    const m = mandate();
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    provider.statusList!.revoke(status);
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...common(),
      trustedIssuers: [provider.trusted],
      statusFetcher: provider.statusFetcher,
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_REVOKED' });
  });

  it('denies a suspended PID and allows it again once reinstated', async () => {
    const wallet = await walletWithPid(provider);
    const status = provider.lastStatus!;
    provider.statusList!.suspend(status);
    const opts = () => ({ ...common(), trustedIssuers: [provider.trusted], statusFetcher: provider.statusFetcher });
    const m = mandate();
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    expect(await verifyAuthorization(chain, await invocation(chain, m), opts())).toMatchObject({ code: 'PID_REVOKED' });
    provider.statusList!.reinstate(status);
    expect((await verifyAuthorization(chain, await invocation(chain, m), opts())).decision).toBe('ALLOW');
  });

  it('denies when the status list cannot be fetched', async () => {
    const wallet = await walletWithPid(provider);
    const m = mandate();
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...common(),
      trustedIssuers: [provider.trusted],
      statusFetcher: async () => {
        throw new Error('network down');
      },
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'STATUS_UNAVAILABLE' });
  });

  it('denies a status list signed by someone else', async () => {
    const wallet = await walletWithPid(provider);
    const m = mandate();
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const { privateKey } = await generateKeyPair('ES256');
    const forged = new StatusListPublisher({ uri: provider.lastStatus!.status_list.uri, signingKey: privateKey, iss: provider.iss });
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...common(),
      trustedIssuers: [provider.trusted],
      statusFetcher: () => forged.token(),
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_REVOKED' });
  });

  it('works with x5c trust and a status list together', async () => {
    const p = await createTestPidProvider('https://pid-both.example', { x5c: true, statusList: true });
    const wallet = await walletWithPid(p);
    const m = mandate();
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const opts = () => ({ ...common(), trustAnchors: [p.anchorPem!], statusFetcher: p.statusFetcher });
    expect((await verifyAuthorization(chain, await invocation(chain, m), opts())).decision).toBe('ALLOW');
    p.statusList!.revoke(p.lastStatus!);
    expect(await verifyAuthorization(chain, await invocation(chain, m), opts())).toMatchObject({ code: 'PID_REVOKED' });
  });
});

describe('mandate revocation through a status list', () => {
  let provider: TestPidProvider;
  let wallet: TestWallet;
  let platformKey: CryptoKey;
  let platformJwk: JsonWebKey;
  let publisher: StatusListPublisher;
  let fetcher: StatusFetcher;

  beforeAll(async () => {
    provider = await createTestPidProvider();
    wallet = await walletWithPid(provider);
    const pair = await generateKeyPair('ES256', { extractable: true });
    platformKey = pair.privateKey as unknown as CryptoKey;
    const { exportJWK } = await import('jose');
    platformJwk = await exportJWK(pair.publicKey);
    publisher = new StatusListPublisher({ uri: `${PLATFORM}/mandates/status`, signingKey: pair.privateKey, iss: PLATFORM });
    fetcher = async (uri) => {
      if (uri === publisher.uri) return publisher.token();
      throw new Error(`unknown ${uri}`);
    };
  });

  const trust = () => ({ trustedIssuers: [{ iss: PLATFORM, jwk: platformJwk as any }] });

  it('allows a mandate whose entry is valid, then denies it once revoked', async () => {
    const ref = publisher.allocate();
    const m = mandate({ status: ref });
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const opts = () => ({ ...common(), trustedIssuers: [provider.trusted], mandateStatusTrust: trust(), statusFetcher: fetcher });
    expect((await verifyAuthorization(chain, await invocation(chain, m), opts())).decision).toBe('ALLOW');
    publisher.revoke(ref);
    expect(await verifyAuthorization(chain, await invocation(chain, m), opts())).toMatchObject({ decision: 'DENY', code: 'REVOKED' });
  });

  it('refuses to evaluate a mandate with status when no status trust is configured', async () => {
    const m = mandate({ status: publisher.allocate() });
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), { ...common(), trustedIssuers: [provider.trusted], statusFetcher: fetcher });
    expect(d).toMatchObject({ decision: 'DENY', code: 'CONFIGURATION' });
  });

  it('honours the cache lifetime, then sees the revocation', async () => {
    const ref = publisher.allocate();
    const m = mandate({ status: ref });
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const cache = new StatusListCache(60);
    const opts = () => ({
      ...common(),
      trustedIssuers: [provider.trusted],
      mandateStatusTrust: trust(),
      statusFetcher: fetcher,
      statusCache: cache,
    });
    expect((await verifyAuthorization(chain, await invocation(chain, m), opts())).decision).toBe('ALLOW');
    publisher.revoke(ref);
    // Still cached: a verifier accepts staleness up to the cache age, by design.
    expect((await verifyAuthorization(chain, await invocation(chain, m), opts())).decision).toBe('ALLOW');
    const fresh = { ...opts(), statusCache: new StatusListCache(60) };
    expect(await verifyAuthorization(chain, await invocation(chain, m), fresh)).toMatchObject({ code: 'REVOKED' });
  });

  it('rejects a status reference that is not a URL', () => {
    expect(() => mandate({ status: { status_list: { uri: 'file:///etc/passwd', idx: 1 } } })).toThrow(/status/);
    expect(() => mandate({ status: { status_list: { uri: 'https://x.example', idx: -1 } } })).toThrow(/status/);
  });
});

describe('OpenID4VP round trip', () => {
  let provider: TestPidProvider;
  let wallet: TestWallet;
  let signer: { key: CryptoKey };

  beforeAll(async () => {
    provider = await createTestPidProvider('https://pid-vp.example', { x5c: true, statusList: true });
    wallet = await walletWithPid(provider);
    const { privateKey } = await generateKeyPair('ES256');
    signer = { key: privateKey };
  });

  const rootOpts = () => ({
    now: nowSeconds(),
    trustAnchors: [provider.anchorPem!],
    statusFetcher: provider.statusFetcher,
    sessions: new InMemoryNonceStore(),
  });

  it('turns an encrypted wallet response into a verified root that authorizes the agent', async () => {
    const m = mandate();
    const req = await createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp`, signer });
    expect(req.requestObject).toBeTypeOf('string');
    expect(req.params.response_mode).toBe('direct_post.jwt');
    const body = await wallet.respond(req.requestObject!);
    expect(body).toHaveProperty('response');
    const { root, verified } = await handleMandateResponse(body, req.session, rootOpts());
    expect(verified.principal).toEqual({ given_name: 'Mario', family_name: 'Rossi' });
    expect(verified.keyBinding.aud).toBe(CLIENT_ID);

    const chain = { root, delegations: [] };
    const d = await verifyAuthorization(chain, await invocation(chain, m), {
      ...common(),
      trustAnchors: [provider.anchorPem!],
      statusFetcher: provider.statusFetcher,
    });
    expect(d.decision).toBe('ALLOW');
  });

  it('works without encryption when asked', async () => {
    const m = mandate();
    const req = await createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp`, encryptResponse: false });
    const body = await wallet.respond(req.params);
    expect(body).toHaveProperty('vp_token');
    const { verified } = await handleMandateResponse(body, req.session, rootOpts());
    expect(verified.mandate.id).toBe(m.id);
  });

  it('rejects a response with the wrong state', async () => {
    const req = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp`, encryptResponse: false });
    const body = await wallet.respond({ ...req.params, state: 'other' });
    await expect(handleMandateResponse(body, req.session, rootOpts())).rejects.toThrow(/state/);
  });

  it('rejects a presentation made for another request nonce', async () => {
    const req = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp`, encryptResponse: false });
    const body = await wallet.respond({ ...req.params, nonce: 'replayed-nonce' });
    await expect(handleMandateResponse(body, req.session, rootOpts())).rejects.toThrow(/nonce/);
  });

  it('rejects a presentation made for another verifier', async () => {
    const req = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp`, encryptResponse: false });
    const body = await wallet.respond({ ...req.params, client_id: 'x509_san_dns:evil.example' });
    await expect(handleMandateResponse(body, req.session, rootOpts())).rejects.toThrow(/audience/);
  });

  it('rejects a response for another mandate', async () => {
    const reqA = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp`, encryptResponse: false });
    const reqB = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp`, encryptResponse: false });
    const body = await wallet.respond(reqB.params);
    await expect(handleMandateResponse(body, reqA.session, rootOpts())).rejects.toThrow();
  });

  it('rejects a plaintext response when encryption was requested', async () => {
    const req = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp` });
    const body = await wallet.respond({ ...req.params, response_mode: 'direct_post' });
    await expect(handleMandateResponse(body, req.session, rootOpts())).rejects.toThrow(/encrypted/);
  });

  it('rejects a response encrypted to another key', async () => {
    const req = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp` });
    const other = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp` });
    const body = await wallet.respond({ ...req.params, client_metadata: other.params.client_metadata });
    await expect(handleMandateResponse(body, req.session, rootOpts())).rejects.toThrow(/decrypted/);
  });

  it('surfaces a refusal by the person', async () => {
    const req = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp`, encryptResponse: false });
    const body = await wallet.respond(req.params, { approve: () => false });
    expect(body.error).toBe('access_denied');
    await expect(handleMandateResponse(body, req.session, rootOpts())).rejects.toThrow(/access_denied/);
  });

  it('rejects an expired request session', async () => {
    const req = await createMandateRequest({ mandate: mandate(), clientId: CLIENT_ID, responseUri: `${PLATFORM}/vp`, encryptResponse: false });
    const body = await wallet.respond(req.params);
    await expect(handleMandateResponse(body, req.session, { ...rootOpts(), now: nowSeconds() + 3600 })).rejects.toThrow(/expired/);
  });

  it('builds a wallet invocation URL', () => {
    const url = authorizationRequestUrl(CLIENT_ID, `${PLATFORM}/request/abc`);
    expect(url).toMatch(/^openid4vp:\/\/\?client_id=x509_san_dns%3Aagents.example&request_uri=/);
  });

  it('keeps verifyRoot independent of the protocol', async () => {
    const m = mandate();
    const root = await wallet.approveMandate(m);
    const r = await verifyRoot(root, rootOpts());
    expect(r.trustedVia).toBe('x5c');
  });
});

// Keep SignJWT imported for future forged-token cases.
void SignJWT;
