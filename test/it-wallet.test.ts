import { describe, expect, it, beforeAll } from 'vitest';
import { decodeProtectedHeader } from 'jose';
import {
  createInvocation,
  createMandate,
  createMandateRequest,
  generateAgentKey,
  handleMandateResponse,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  verifyAuthorization,
  x509HashClientId,
  DEFAULT_CLAIM_PURPOSES,
  type AgentKey,
  type Mandate,
  type MandateResponseOptions,
} from '../src/index.js';
import {
  IT_WALLET_DEFAULT_CLAIMS,
  IT_WALLET_PID_VCT,
  itWalletRequestOptions,
  itWalletRequestProblems,
  itWalletVerifyDefaults,
} from '../src/experimental.js';
import {
  createTestCertificateAuthority,
  createTestPidProvider,
  createTestWallet,
  type TestCertificateAuthority,
  type TestPidProvider,
  type TestWallet,
} from '../src/testing.js';

const RESPONSE_URI = 'https://agents.example/response';
const AUD = 'https://bank.example';

let agent: AgentKey;
let ca: TestCertificateAuthority;
let rp: Awaited<ReturnType<TestCertificateAuthority['issueLeaf']>>;
let otherRp: Awaited<ReturnType<TestCertificateAuthority['issueLeaf']>>;
let itProvider: TestPidProvider;
let euProvider: TestPidProvider;
let itWallet: TestWallet;

async function walletWith(provider: TestPidProvider, opts: Parameters<typeof createTestWallet>[0] = {}): Promise<TestWallet> {
  const w = await createTestWallet(opts);
  w.storePid(
    await provider.issuePid(w.holderJwk, {
      given_name: 'Maria',
      family_name: 'Rossi',
      birth_date: '1984-03-12',
      personal_administrative_number: 'RSSMRA84C52H501X',
    }),
  );
  return w;
}

function mandate(): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.sepa'],
    counterparties: ['lumen.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
    purpose: 'Pay the electricity bills',
  });
}

function responseOptions(over: Partial<MandateResponseOptions> = {}): MandateResponseOptions {
  return {
    trustedIssuers: [itProvider.trusted],
    now: Math.floor(Date.now() / 1000),
    sessions: new InMemoryNonceStore(),
    ...itWalletVerifyDefaults(),
    ...over,
  };
}

beforeAll(async () => {
  agent = await generateAgentKey();
  ca = await createTestCertificateAuthority();
  rp = await ca.issueLeaf('https://agents.example');
  otherRp = await ca.issueLeaf('https://other.example');
  itProvider = await createTestPidProvider('https://pid.it.test', { vct: IT_WALLET_PID_VCT });
  euProvider = await createTestPidProvider('https://pid.eu.test');
  itWallet = await walletWith(itProvider, { clientIdPrefixes: ['openid_federation', 'x509_hash'], checkX509Hash: true });
});

describe('x509_hash client identifier', () => {
  it('is the base64url SHA-256 of the DER certificate, from an x5c entry or from PEM', () => {
    const fromX5c = x509HashClientId(rp.x5c[0]);
    expect(fromX5c).toMatch(/^x509_hash:[A-Za-z0-9_-]{43}$/);
    expect(x509HashClientId(rp.certificate)).toBe(fromX5c);
    expect(x509HashClientId(otherRp.x5c[0])).not.toBe(fromX5c);
  });

  it('refuses a value that is not a certificate', () => {
    expect(() => x509HashClientId('bm90IGEgY2VydGlmaWNhdGU')).toThrow();
    expect(() => x509HashClientId('')).toThrow();
  });

  it('createMandateRequest refuses an x509_hash that does not match the signing certificate', async () => {
    const base = { mandate: mandate(), responseUri: RESPONSE_URI };
    await expect(createMandateRequest({ ...base, clientId: x509HashClientId(rp.x5c[0]) })).rejects.toThrow(/signer/);
    await expect(
      createMandateRequest({ ...base, clientId: x509HashClientId(otherRp.x5c[0]), signer: { key: rp.privateKey, x5c: rp.x5c } }),
    ).rejects.toThrow(/does not match/);
    const ok = await createMandateRequest({ ...base, clientId: x509HashClientId(rp.x5c[0]), signer: { key: rp.privateKey, x5c: rp.x5c } });
    expect(decodeProtectedHeader(ok.requestObject!).x5c).toEqual(rp.x5c);
  });
});

describe('claim purposes', () => {
  it('reports every requested claim with its purpose', async () => {
    const req = await createMandateRequest({
      mandate: mandate(),
      clientId: 'x509_san_dns:agents.example',
      responseUri: RESPONSE_URI,
      disclose: ['given_name', 'family_name', 'birth_date'],
      claimPurposes: { birth_date: 'Checks that the person is of age for the payment service.' },
    });
    expect(req.disclosure).toEqual([
      { credential: 'pid', claim: 'given_name', purpose: DEFAULT_CLAIM_PURPOSES.given_name },
      { credential: 'pid', claim: 'family_name', purpose: DEFAULT_CLAIM_PURPOSES.family_name },
      { credential: 'pid', claim: 'birth_date', purpose: 'Checks that the person is of age for the payment service.' },
    ]);
  });

  it('leaves a claim without purpose unexplained, and refuses it when purposes are required', async () => {
    const base = { mandate: mandate(), clientId: 'x509_san_dns:agents.example', responseUri: RESPONSE_URI, disclose: ['given_name', 'nationalities'] };
    const req = await createMandateRequest(base);
    expect(req.disclosure.find((d) => d.claim === 'nationalities')).toEqual({ credential: 'pid', claim: 'nationalities' });
    await expect(createMandateRequest({ ...base, requireClaimPurposes: true })).rejects.toThrow(/nationalities/);
  });

  it('a claim named like an object property gets no inherited purpose', async () => {
    const req = await createMandateRequest({
      mandate: mandate(),
      clientId: 'x509_san_dns:agents.example',
      responseUri: RESPONSE_URI,
      disclose: ['toString'],
    });
    expect(req.disclosure).toEqual([{ credential: 'pid', claim: 'toString' }]);
  });

  it('asks for the PID types given, and refuses an empty list', async () => {
    const base = { mandate: mandate(), clientId: 'x509_san_dns:agents.example', responseUri: RESPONSE_URI };
    const req = await createMandateRequest({ ...base, pidVcts: [IT_WALLET_PID_VCT, 'urn:eudi:pid:1'] });
    const q = (req.params.dcql_query as any).credentials[0];
    expect(q.meta.vct_values).toEqual([IT_WALLET_PID_VCT, 'urn:eudi:pid:1']);
    await expect(createMandateRequest({ ...base, pidVcts: [] })).rejects.toThrow(/pidVcts/);
    await expect(createMandateRequest({ ...base, pidVcts: [''] })).rejects.toThrow(/pidVcts/);
  });
});

describe('profile it-wallet-1', () => {
  it('builds a request with no problem the profile knows of', async () => {
    const req = await createMandateRequest(itWalletRequestOptions({ mandate: mandate(), responseUri: RESPONSE_URI, signer: { key: rp.privateKey, x5c: rp.x5c } }));
    expect(req.params.client_id).toBe(x509HashClientId(rp.x5c[0]));
    expect(req.params.response_mode).toBe('direct_post.jwt');
    expect((req.params.dcql_query as any).credentials[0].meta.vct_values).toEqual([IT_WALLET_PID_VCT]);
    expect(req.disclosure.map((d) => d.claim)).toEqual([...IT_WALLET_DEFAULT_CLAIMS]);
    expect(req.disclosure.every((d) => typeof d.purpose === 'string' && d.purpose.length > 0)).toBe(true);
    expect(itWalletRequestProblems(req.params, req.requestObject)).toEqual([]);
  });

  it('names what breaks the profile in other requests', async () => {
    const req = await createMandateRequest({ mandate: mandate(), clientId: 'x509_san_dns:agents.example', responseUri: RESPONSE_URI, encryptResponse: false });
    const problems = itWalletRequestProblems(req.params, req.requestObject);
    expect(problems).toContain('client_id prefix must be one of openid_federation, x509_hash');
    expect(problems).toContain('response_mode must be direct_post.jwt');
    expect(problems).toContain('the request object must be signed');
  });

  it('refuses a claim the person is asked for without a purpose', () => {
    expect(() =>
      itWalletRequestOptions({ mandate: mandate(), responseUri: RESPONSE_URI, signer: { key: rp.privateKey, x5c: rp.x5c }, disclose: ['given_name', 'nationalities'] }),
    ).not.toThrow();
    return expect(
      createMandateRequest(
        itWalletRequestOptions({ mandate: mandate(), responseUri: RESPONSE_URI, signer: { key: rp.privateKey, x5c: rp.x5c }, disclose: ['given_name', 'nationalities'] }),
      ),
    ).rejects.toThrow(/nationalities/);
  });

  it('end to end: a wallet holding an Italian-type PID approves, the bank allows within the mandate', async () => {
    const m = mandate();
    const req = await createMandateRequest(itWalletRequestOptions({ mandate: m, responseUri: RESPONSE_URI, signer: { key: rp.privateKey, x5c: rp.x5c } }));
    const body = await itWallet.respond(req.requestObject!);
    const { root, verified } = await handleMandateResponse(body, req.session, responseOptions());
    expect(verified.principal.personal_administrative_number).toBe('RSSMRA84C52H501X');
    expect(verified.principal.birth_date).toBeUndefined();

    const chain = { root, delegations: [] };
    const nonces = new InMemoryNonceStore();
    const verify = (value: number) =>
      createInvocation(agent.privateKey, {
        chain,
        mandateId: m.id,
        action: 'payments.sepa',
        counterparty: 'lumen.example',
        amount: { value, currency: 'EUR' },
        aud: AUD,
        nonce: crypto.randomUUID(),
      }).then((invocation) =>
        verifyAuthorization(chain, invocation, {
          trustedIssuers: [itProvider.trusted],
          audience: AUD,
          nonces,
          ledger: new InMemorySpendingLedger(),
          ...itWalletVerifyDefaults(),
          expected: { action: 'payments.sepa', counterparty: 'lumen.example', amount: { value, currency: 'EUR' } },
        }),
      );
    expect((await verify(8430)).decision).toBe('ALLOW');
    const deny = await verify(18000);
    expect(deny.decision).toBe('DENY');
    expect(deny.decision === 'DENY' && deny.code).toBe('LIMIT_PER_OPERATION');
  });

  it('a verifier left on the EU PID type refuses the Italian one', async () => {
    const req = await createMandateRequest(itWalletRequestOptions({ mandate: mandate(), responseUri: RESPONSE_URI, signer: { key: rp.privateKey, x5c: rp.x5c } }));
    const body = await itWallet.respond(req.requestObject!);
    await expect(handleMandateResponse(body, req.session, responseOptions({ acceptedVcts: undefined }))).rejects.toThrow(/not an accepted PID type/);
  });

  it('a wallet restricted to the Italian prefixes refuses x509_san_dns, and a forged x509_hash', async () => {
    const plain = await createMandateRequest({
      mandate: mandate(),
      clientId: 'x509_san_dns:agents.example',
      responseUri: RESPONSE_URI,
      pidVcts: [IT_WALLET_PID_VCT],
      signer: { key: rp.privateKey, x5c: rp.x5c },
    });
    expect(await itWallet.respond(plain.requestObject!)).toMatchObject({ error: 'invalid_client' });

    const req = await createMandateRequest(itWalletRequestOptions({ mandate: mandate(), responseUri: RESPONSE_URI, signer: { key: rp.privateKey, x5c: rp.x5c } }));
    const forged = { ...req.params, client_id: x509HashClientId(otherRp.x5c[0]) };
    expect(await itWallet.respond(forged)).toMatchObject({ error: 'invalid_request' });
  });

  it('a wallet holding only an EU-type PID does not answer an Italian-type request', async () => {
    const euWallet = await walletWith(euProvider);
    const req = await createMandateRequest(itWalletRequestOptions({ mandate: mandate(), responseUri: RESPONSE_URI, signer: { key: rp.privateKey, x5c: rp.x5c } }));
    expect(await euWallet.respond(req.requestObject!)).toMatchObject({ error: 'invalid_request' });
  });

  it('the key binding audience is the x509_hash client identifier: a response for another relying party is refused', async () => {
    const m = mandate();
    const mine = await createMandateRequest(itWalletRequestOptions({ mandate: m, responseUri: RESPONSE_URI, signer: { key: rp.privateKey, x5c: rp.x5c } }));
    const theirs = await createMandateRequest(itWalletRequestOptions({ mandate: m, responseUri: RESPONSE_URI, signer: { key: otherRp.privateKey, x5c: otherRp.x5c } }));
    const plainWallet = await walletWith(itProvider);
    // The wallet answers the other relying party; that answer is replayed against this one's session.
    const body = await plainWallet.respond({ ...theirs.params, nonce: mine.session.nonce, state: mine.session.state, response_mode: 'direct_post' });
    const session = { ...mine.session, responseMode: 'direct_post' as const, decryptionKey: undefined };
    await expect(handleMandateResponse(body, session, responseOptions())).rejects.toThrow(/audience/);
  });
});
