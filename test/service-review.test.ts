/**
 * Regression tests for the security review of the service area (gateway, Express adapter, policy export,
 * audit log, status service). Each test started as a proof of concept that passed while the bug existed;
 * these assert the safe behaviour.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, request as httpRequest, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { generateKeyPair } from 'jose';
import {
  AuditLog,
  auditRecordHash,
  authorizationHeaders,
  createGateway,
  createInvocation,
  createMandate,
  createMandateRequest,
  createStatusService,
  expressMiddleware,
  generateAgentKey,
  handleMandateResponse,
  InMemoryAuditStore,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  mandateHash,
  nowSeconds,
  plenipoRoute,
  publisherSource,
  StatusListPublisher,
  toCedarRequest,
  toNodeListener,
  toOpaInput,
  verifyAuditLog,
  verifyAuthorization,
  type AgentKey,
  type AuditRecord,
  type AuditStore,
  type Decision,
  type GatewayOptions,
  type GatewayRoute,
  type Mandate,
  type MandateChain,
  type PlenipoRequestContext,
  type StatusFetcher,
} from '../src/index.js';
import {
  createLegalMandate,
} from '../src/experimental.js';
import { createTestPidProvider, createTestRegister, createTestWallet, type TestPidProvider, type TestRegister, type TestWallet } from '../src/testing.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      plenipo?: PlenipoRequestContext;
    }
  }
}

const API = 'https://api.bank.example';
const PATH = '/accounts/acc-1/payments';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let agent: AgentKey;
let provider: TestPidProvider;
let wallet: TestWallet;
const servers: Server[] = [];

beforeAll(async () => {
  agent = await generateAgentKey();
  provider = await createTestPidProvider('https://pid.example.it');
  wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Maria', family_name: 'Bianchi', birthdate: '1980-01-01' }));
});

afterAll(async () => {
  for (const s of servers) {
    s.closeAllConnections();
    await new Promise((r) => s.close(r));
  }
});

async function listen(handler: Parameters<typeof createServer>[1]): Promise<string> {
  const s = createServer(handler);
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  servers.push(s);
  return `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
}

const paymentRoute: GatewayRoute = {
  method: 'POST',
  path: '/accounts/:account/payments',
  action: 'payments.transfer',
  counterparty: (r) => (r.json() as { creditor?: string }).creditor,
  amount: (r) => {
    const b = r.json() as { amount?: number; currency?: string };
    return typeof b.amount === 'number' ? { value: b.amount, currency: b.currency ?? '' } : undefined;
  },
};
const balanceRoute: GatewayRoute = { method: 'GET', path: '/accounts/:account/balance', action: 'accounts.read', counterparty: null, amount: null };

const verify = (ledger: InMemorySpendingLedger): GatewayOptions['verify'] => ({
  audience: API,
  nonces: new InMemoryNonceStore(),
  ledger,
  trustedIssuers: [provider.trusted],
});

function mandate(): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.*', 'accounts.read'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 50_000, total: 100_000 },
  });
}

async function chainFor(m: Mandate): Promise<MandateChain> {
  return { root: await wallet.approveMandate(m), delegations: [] };
}

async function signedHeaders(m: Mandate, chain: MandateChain, body: Record<string, unknown>, path = PATH, mediaType: string | null = 'application/json') {
  const inv = await createInvocation(agent.privateKey, {
    chain,
    mandateId: m.id,
    action: 'payments.transfer',
    counterparty: body.creditor as string,
    amount: { value: body.amount as number, currency: body.currency as string },
    aud: API,
    args: { method: 'POST', path, query: {}, media_type: mediaType, body },
  });
  return authorizationHeaders(chain, inv);
}

function jsonRequest(headers: Record<string, string>, body: unknown, path = PATH, extra: RequestInit = {}): Request {
  return new Request(API + path, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify(body), ...extra });
}

/** Sends a request and destroys the socket once `hangUp` resolves, as an agent that hangs up mid-request would. */
function postAndHangUp(base: string, path: string, headers: Record<string, string>, body: string, hangUp: Promise<unknown>): Promise<number | undefined> {
  return new Promise((resolve) => {
    const u = new URL(path, base);
    const req = httpRequest(
      { host: u.hostname, port: u.port, path: u.pathname, method: 'POST', headers: { ...headers, 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } },
      (res) => {
        res.resume();
        resolve(res.statusCode);
      },
    );
    req.on('error', () => resolve(undefined));
    req.end(body);
    void hangUp.then(() => {
      req.destroy();
      resolve(undefined);
    });
  });
}

describe('OPS-GW-1: Express middleware and client hang-ups', () => {
  it('keeps the reservation when the client hangs up while the handler executes: the total limit holds', async () => {
    const ledger = new InMemorySpendingLedger();
    const gw = createGateway({ routes: [paymentRoute], verify: verify(ledger) });
    const executed: number[] = [];
    let started: () => void = () => undefined;
    const app = express();
    app.use(express.json());
    app.use(expressMiddleware(gw, { origin: API }));
    app.post('/accounts/:account/payments', async (req, res) => {
      started();
      await sleep(150);
      executed.push(req.body.amount);
      res.status(201).json({ ok: true });
    });
    const base = await listen(app);

    const m = mandate(); // per_operation 500.00 EUR, total 1,000.00 EUR
    const chain = await chainFor(m);
    const statuses: Array<number | undefined> = [];
    for (let i = 0; i < 4; i++) {
      const body = { creditor: 'shop.example', amount: 50_000, currency: 'EUR', n: i };
      const handlerStarted = new Promise<void>((r) => (started = r));
      // Requests the gateway refuses never start the handler; time out the hang-up for them.
      statuses.push(await postAndHangUp(base, PATH, await signedHeaders(m, chain, body), JSON.stringify(body), Promise.race([handlerStarted, sleep(300).then(() => new Promise(() => undefined))])));
      await sleep(250);
    }
    expect(executed.reduce((a, b) => a + b, 0)).toBe(100_000); // only what the total allows
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(100_000); // and the ledger knows it
    expect(statuses.slice(2)).toEqual([403, 403]); // limit_total
  });

  it('lets the handler state the outcome explicitly, which overrides the status code', async () => {
    const ledger = new InMemorySpendingLedger();
    const gw = createGateway({ routes: [paymentRoute], verify: verify(ledger) });
    const app = express();
    app.use(express.json());
    app.use(expressMiddleware(gw, { origin: API }));
    app.post('/accounts/:account/payments', async (req, res) => {
      // The core system refused before acting, but the API reports it as a 503.
      await req.plenipo!.settle('not-executed');
      res.status(503).end();
    });
    const base = await listen(app);
    const m = mandate();
    const body = { creditor: 'shop.example', amount: 10_000, currency: 'EUR' };
    const res = await fetch(base + PATH, { method: 'POST', headers: { ...(await signedHeaders(m, await chainFor(m), body)), 'content-type': 'application/json' }, body: JSON.stringify(body) });
    expect(res.status).toBe(503);
    await sleep(20);
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);
  });
});

describe('OPS-GW-2: gateway.handle settlement', () => {
  it('does not forward the client abort signal; the executed action stays counted', async () => {
    const ledger = new InMemorySpendingLedger();
    const executed: number[] = [];
    let onStart: () => void = () => undefined;
    const gw = createGateway({
      routes: [paymentRoute],
      verify: verify(ledger),
      async downstream(req) {
        const body = (await req.json()) as { amount: number };
        executed.push(body.amount);
        onStart();
        await new Promise((resolve, reject) => {
          const t = setTimeout(resolve, 100);
          req.signal.addEventListener('abort', () => {
            clearTimeout(t);
            reject(new Error('aborted'));
          });
        });
        return new Response(null, { status: 201 });
      },
    });
    const m = mandate();
    const chain = await chainFor(m);
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) {
      const body = { creditor: 'shop.example', amount: 50_000, currency: 'EUR', n: i };
      const ac = new AbortController();
      onStart = () => setTimeout(() => ac.abort(), 20);
      statuses.push((await gw.handle(jsonRequest(await signedHeaders(m, chain, body), body, PATH, { signal: ac.signal }))).status);
    }
    expect(statuses).toEqual([201, 201, 403]);
    expect(executed.reduce((a, b) => a + b, 0)).toBe(100_000);
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(100_000);
  });

  it('leaves a throw and a 5xx pending, releases a 4xx, and honours the outcome header', async () => {
    const ledger = new InMemorySpendingLedger();
    const audit = new InMemoryAuditStore();
    const gw = createGateway({
      routes: [paymentRoute],
      verify: verify(ledger),
      audit: new AuditLog({ store: audit }),
      async downstream(req) {
        const { mode } = (await req.json()) as { mode: string };
        if (mode === 'throw') throw new Error('socket hang up');
        if (mode === '502') return new Response(null, { status: 502 });
        if (mode === '422') return new Response(null, { status: 422 });
        if (mode === '500-not-executed') return new Response(null, { status: 500, headers: { 'Plenipo-Outcome': 'not-executed' } });
        if (mode === '202-unknown') return new Response(null, { status: 202, headers: { 'Plenipo-Outcome': 'unknown' } });
        return new Response(null, { status: 201 });
      },
    });
    const cases: Array<[string, number, number]> = [
      ['throw', 500, 1_000],
      ['502', 502, 1_000],
      ['422', 422, 0],
      ['500-not-executed', 500, 0],
      ['202-unknown', 202, 1_000],
    ];
    for (const [mode, status, kept] of cases) {
      const m = mandate();
      const body = { creditor: 'shop.example', amount: 1_000, currency: 'EUR', mode };
      const res = await gw.handle(jsonRequest(await signedHeaders(m, await chainFor(m), body), body));
      expect(res.status, mode).toBe(status);
      expect(res.headers.has('plenipo-outcome'), mode).toBe(false);
      expect(ledger.spent(mandateHash(m), 'EUR'), mode).toBe(kept);
    }
    const settlements = (await audit.readAll()).filter((r) => r.event === 'settlement').map((r) => r.settlement);
    expect(settlements).toEqual(['pending', 'pending', 'release', 'release', 'pending']);
  });

  it("with clientErrorOutcome 'pending' a 4xx keeps the reservation", async () => {
    const ledger = new InMemorySpendingLedger();
    const gw = createGateway({ routes: [paymentRoute], verify: verify(ledger), clientErrorOutcome: 'pending', downstream: () => new Response(null, { status: 409 }) });
    const m = mandate();
    const body = { creditor: 'shop.example', amount: 1_000, currency: 'EUR' };
    expect((await gw.handle(jsonRequest(await signedHeaders(m, await chainFor(m), body), body))).status).toBe(409);
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(1_000);
  });

  it('a later explicit commit or release still applies after a pending outcome', async () => {
    const ledger = new InMemorySpendingLedger();
    const gw = createGateway({ routes: [paymentRoute], verify: verify(ledger) });
    const m = mandate();
    const body = { creditor: 'shop.example', amount: 1_000, currency: 'EUR' };
    const r = await gw.authorize(jsonRequest(await signedHeaders(m, await chainFor(m), body), body));
    expect(r.kind).toBe('allow');
    if (r.kind !== 'allow') return;
    expect(r.request.signal.aborted).toBe(false);
    await r.settle({ error: new Error('timeout') });
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(1_000);
    await r.settle({ outcome: 'release' }); // reconciled: the core system never executed it
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);
    await r.settle({ outcome: 'commit' }); // final after release
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);
  });
});

describe("OPS-GW-3: routing differences cannot bypass the gateway", () => {
  it("Express with unmatched 'pass': trailing slash, letter case, HEAD, other methods and extensions are all checked", async () => {
    const gw = createGateway({ routes: [paymentRoute, balanceRoute], unmatched: 'pass', verify: verify(new InMemorySpendingLedger()) });
    const hits: string[] = [];
    const app = express();
    app.use(express.json());
    app.use(expressMiddleware(gw, { origin: API }));
    app.post('/accounts/:account/payments', (req, res) => {
      hits.push(`payment by ${req.plenipo ? 'agent' : 'NOBODY'}`);
      res.status(201).json({ ok: true });
    });
    app.put('/accounts/:account/payments', (_req, res) => {
      hits.push('put by NOBODY');
      res.status(200).end();
    });
    app.post('/accounts/:account/payments/:id/confirm', (_req, res) => {
      hits.push('confirm by NOBODY');
      res.status(200).end();
    });
    app.get('/accounts/:account/balance', (req, res) => {
      hits.push(`balance by ${req.plenipo ? 'agent' : 'NOBODY'}`);
      res.json({ balance: 123 });
    });
    app.get('/health', (_req, res) => {
      hits.push('health');
      res.json({ ok: true });
    });
    const base = await listen(app);
    const body = JSON.stringify({ creditor: 'evil.example', amount: 9_999_999, currency: 'EUR' });
    const send = (p: string, method = 'POST') => fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: method === 'GET' || method === 'HEAD' ? undefined : body });

    expect((await send(PATH)).status).toBe(401);
    expect((await send(PATH + '/')).status).toBe(401);
    expect((await send('/Accounts/acc-1/Payments')).status).toBe(401);
    expect((await send('/accounts/acc-1/%70ayments')).status).toBe(401);
    expect((await send(PATH, 'PUT')).status).toBe(404);
    expect((await send(PATH + '/p1/confirm')).status).toBe(404);
    expect((await send('/accounts/acc-1/balance', 'GET')).status).toBe(401);
    expect((await send('/accounts/acc-1/balance', 'HEAD')).status).toBe(401);
    expect((await send('/health', 'GET')).status).toBe(200);
    expect(hits).toEqual(['health']);
  });

  it('plenipoRoute protects one Express route with Express doing the routing', async () => {
    const ledger = new InMemorySpendingLedger();
    const app = express();
    app.use(express.json());
    const executed: unknown[] = [];
    app.post('/accounts/:account/payments', plenipoRoute(paymentRoute, { verify: verify(ledger) }, { origin: API }), (req, res) => {
      executed.push((req.body as { amount: number }).amount);
      res.status(201).end();
    });
    const base = await listen(app);
    const m = mandate();
    const body = { creditor: 'shop.example', amount: 1_000, currency: 'EUR' };
    const unsigned = await fetch(base + '/ACCOUNTS/acc-1/payments/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    expect(unsigned.status).toBe(401);
    const signed = await fetch(base + PATH, { method: 'POST', headers: { ...(await signedHeaders(m, await chainFor(m), body)), 'content-type': 'application/json' }, body: JSON.stringify(body) });
    expect(signed.status).toBe(201);
    expect(executed).toEqual([1_000]);
  });
});

describe('OPS-GW-4: the body is checked as the API will read it', () => {
  it('refuses a JSON-signed body sent as a form (415) and never calls the API', async () => {
    const executed: unknown[] = [];
    const api = express();
    api.use(express.json());
    api.use(express.urlencoded({ extended: false }));
    api.post('/accounts/:account/payments', (req, res) => {
      executed.push({ creditor: req.body.creditor, amount: Number(req.body.amount), contentType: req.headers['content-type'] });
      res.status(201).json({ ok: true });
    });
    const apiBase = await listen(api);
    const ledger = new InMemorySpendingLedger();
    const gw = createGateway({
      routes: [paymentRoute],
      verify: verify(ledger),
      downstream: (req) => fetch(apiBase + new URL(req.url).pathname, { method: req.method, headers: req.headers, body: req.body, duplex: 'half' } as RequestInit),
    });
    const gwBase = await listen(toNodeListener(gw.handle, { origin: API }));
    const m = mandate();
    const chain = await chainFor(m);
    const body = { creditor: 'shop.example', amount: 100, currency: 'EUR', memo: 'x&creditor=evil.example&amount=900000&currency=EUR&z=' };
    const form = await fetch(gwBase + PATH, {
      method: 'POST',
      headers: { ...(await signedHeaders(m, chain, body)), 'content-type': 'application/x-www-form-urlencoded' },
      body: JSON.stringify(body),
    });
    expect(form.status).toBe(415);
    expect((await form.json()).code).toBe('unsupported_media_type');
    expect(executed).toEqual([]);
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);

    // A JSON body with parameters is accepted and forwarded with one normalised Content-Type.
    const ok = await fetch(gwBase + PATH, {
      method: 'POST',
      headers: { ...(await signedHeaders(m, chain, body)), 'content-type': 'Application/JSON; charset=UTF-8' },
      body: JSON.stringify(body),
    });
    expect(ok.status).toBe(201);
    expect(executed).toEqual([{ creditor: 'shop.example', amount: 100, contentType: 'application/json' }]);
  });

  it('binds the media type into the default arguments and refuses compressed or ambiguous types', async () => {
    const ledger = new InMemorySpendingLedger();
    const gw = createGateway({ routes: [paymentRoute], verify: verify(ledger), downstream: () => new Response(null, { status: 201 }) });
    const m = mandate();
    const chain = await chainFor(m);
    const body = { creditor: 'shop.example', amount: 100, currency: 'EUR' };
    const send = (headers: Record<string, string>, ct: string) =>
      gw.handle(new Request(API + PATH, { method: 'POST', headers: { ...headers, 'content-type': ct }, body: JSON.stringify(body) }));
    // Signed as application/json, sent as application/merchant+json: a different request.
    expect((await send(await signedHeaders(m, chain, body), 'application/merchant+json')).status).toBe(422);
    expect((await send(await signedHeaders(m, chain, body), 'application/json, text/plain')).status).toBe(415);
    expect((await send(await signedHeaders(m, chain, body), 'application/json; charset=latin1')).status).toBe(415);
    const gz = await gw.handle(
      new Request(API + PATH, { method: 'POST', headers: { ...(await signedHeaders(m, chain, body)), 'content-type': 'application/json', 'content-encoding': 'gzip' }, body: JSON.stringify(body) }),
    );
    expect(gz.status).toBe(415);
    expect((await send(await signedHeaders(m, chain, body), 'application/json')).status).toBe(201);
  });
});

describe('OPS-GW-5: Express handlers never see the Plenipo headers', () => {
  it('removes them from req.headers and req.rawHeaders', async () => {
    const gw = createGateway({ routes: [paymentRoute], verify: verify(new InMemorySpendingLedger()) });
    let seen: unknown;
    let raw: string[] = [];
    const app = express();
    app.use(express.json());
    app.use(expressMiddleware(gw, { origin: API }));
    app.post('/accounts/:account/payments', (req, res) => {
      seen = req.headers['plenipo-chain'] ?? req.headers['plenipo-invocation'];
      raw = req.rawHeaders.filter((_, i) => i % 2 === 0).map((h) => h.toLowerCase());
      res.status(201).end();
    });
    const base = await listen(app);
    const m = mandate();
    const body = { creditor: 'shop.example', amount: 100, currency: 'EUR' };
    const res = await fetch(base + PATH, { method: 'POST', headers: { ...(await signedHeaders(m, await chainFor(m), body)), 'content-type': 'application/json' }, body: JSON.stringify(body) });
    expect(res.status).toBe(201);
    expect(seen).toBeUndefined();
    expect(raw).not.toContain('plenipo-chain');
    expect(raw).not.toContain('plenipo-invocation');
  });
});

describe('OPS-MW-1: a placeholder req.body does not hide the real, unread body', () => {
  it('reads the stream itself and refuses a form body that a later parser would execute', async () => {
    const gw = createGateway({ routes: [paymentRoute], verify: verify(new InMemorySpendingLedger()) });
    const executed: unknown[] = [];
    const app = express();
    // body-parser 1.x json(): for a non-JSON type it sets req.body = {} and leaves the stream unread.
    app.use((req, _res, next) => {
      if (!(req.headers['content-type'] ?? '').includes('json')) req.body = {};
      next();
    });
    app.use(expressMiddleware(gw, { origin: API }));
    app.use(express.urlencoded({ extended: false }));
    app.post('/accounts/:account/payments', (req, res) => {
      executed.push(req.body);
      res.status(201).end();
    });
    const base = await listen(app);
    const m = mandate();
    // The agent signs an empty JSON body; the request carries a form the API would execute.
    const res = await fetch(base + PATH, {
      method: 'POST',
      headers: { ...(await signedHeaders(m, await chainFor(m), {})), 'content-type': 'application/x-www-form-urlencoded' },
      body: 'creditor=evil.example&amount=900000&currency=EUR',
    });
    expect(res.status).toBe(415);
    expect(executed).toEqual([]);
  });

  it('a JSON body read by the middleware is what the handler gets, and later parsers skip it', async () => {
    const gw = createGateway({ routes: [paymentRoute], verify: verify(new InMemorySpendingLedger()) });
    const executed: unknown[] = [];
    const app = express();
    app.use(expressMiddleware(gw, { origin: API }));
    app.use(express.json());
    app.post('/accounts/:account/payments', (req, res) => {
      executed.push(req.body);
      res.status(201).end();
    });
    const base = await listen(app);
    const m = mandate();
    const body = { creditor: 'shop.example', amount: 100, currency: 'EUR' };
    const res = await fetch(base + PATH, { method: 'POST', headers: { ...(await signedHeaders(m, await chainFor(m), body)), 'content-type': 'application/json' }, body: JSON.stringify(body) });
    expect(res.status).toBe(201);
    expect(executed).toEqual([body]);
  });
});

describe('OPS-POL-1: principal identity in policy export and audit', () => {
  const AUD = 'https://bank.example';
  const CLIENT_ID = 'x509_san_dns:agents.example';
  const DAY = 24 * 3600;
  type Allow = Extract<Decision, { decision: 'ALLOW' }>;
  let pidProvider: TestPidProvider;
  let register: TestRegister;
  let statusFetcher: StatusFetcher;

  beforeAll(async () => {
    pidProvider = await createTestPidProvider('https://pid.test');
    register = await createTestRegister('https://register.test');
    statusFetcher = async (uri) => {
      if (uri.startsWith(`${register.iss}/`)) return register.statusFetcher(uri);
      throw new Error('unknown status list');
    };
  });

  async function person(given: string, family: string, birthdate: string, extra: Record<string, unknown> = {}): Promise<TestWallet> {
    const w = await createTestWallet();
    w.storePid(await pidProvider.issuePid(w.holderJwk, { given_name: given, family_name: family, birthdate, ...extra }));
    return w;
  }

  async function allow(w: TestWallet, m: Mandate, legal = false, disclose?: string[]): Promise<Allow> {
    let root;
    if (legal) {
      const req = await createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: 'https://agents.example/vp' });
      const body = await w.respond(req.params);
      root = (
        await handleMandateResponse(body, req.session, {
          trustedIssuers: [pidProvider.trusted],
          now: nowSeconds(),
          sessions: new InMemoryNonceStore(),
          statusFetcher,
          representation: { trust: { trustedIssuers: [register.trusted] } },
        })
      ).root;
    } else {
      root = await w.approveMandate(m, disclose ? { disclose } : {});
    }
    const chain = { root, delegations: [] };
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.sepa', counterparty: 'shop.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, {
      trustedIssuers: [pidProvider.trusted],
      audience: AUD,
      nonces: new InMemoryNonceStore(),
      ledger: new InMemorySpendingLedger(),
      statusFetcher,
      representation: { trust: { trustedIssuers: [register.trusted] } },
    });
    expect(d.decision).toBe('ALLOW');
    return d as Allow;
  }

  const plain = () =>
    createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'], limits: { currency: 'EUR', per_operation: 15000, total: 30000 } });

  function legalMandate(euid: string): Mandate {
    return createLegalMandate({
      agentJwk: agent.publicJwk,
      actions: ['payments.sepa'],
      counterparties: ['shop.example'],
      limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
      principal: { type: 'legal_person', euid, role: 'managing_director' } as never,
    });
  }

  async function director(euid: string, name: string, given: string, family: string): Promise<TestWallet> {
    const w = await person(given, family, '1970-05-05');
    w.storeCredential(
      await register.issueRepresentation(w.holderJwk, {
        legal_person_id: euid,
        legal_person_name: name,
        representative: { given_name: given, family_name: family },
        role: { code: 'managing_director', name: 'Amministratore delegato', basis: 'legal_representation', valid_until: nowSeconds() + 180 * DAY },
        powers: { actions: ['payments.*'], limits: { currency: 'EUR', per_operation: 100000, total: 500000 }, max_delegation_depth: 2 },
      } as never),
    );
    return w;
  }

  it('two people with the same name are two principals', async () => {
    const a = await allow(await person('Mario', 'Rossi', '1950-01-01'), plain());
    const b = await allow(await person('Mario', 'Rossi', '1999-12-31'), plain());
    expect(a.pid_holder_jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const id = (c: Awaited<ReturnType<typeof toCedarRequest>>) => c.entities.find((e) => e.uid.type === 'Plenipo::Person')!.uid.id;
    expect(id(await toCedarRequest(a))).not.toBe(id(await toCedarRequest(b)));
    const oa = await toOpaInput(a);
    const ob = await toOpaInput(b);
    expect(oa.principal).toMatchObject({ type: 'natural_person', id_basis: 'holder_key' });
    expect(oa.principal.id).not.toBe(ob.principal.id);
    expect(oa.principal.id).not.toContain('Rossi');
  });

  it('a configured unique claim identifies the person across PID copies', async () => {
    const w1 = await person('Anna', 'Neri', '1985-02-02', { personal_administrative_number: 'IT-123' });
    const w2 = await person('Anna', 'Neri', '1985-02-02', { personal_administrative_number: 'IT-123' });
    const disclose = ['given_name', 'family_name', 'personal_administrative_number'];
    const a = await toOpaInput(await allow(w1, plain(), false, disclose));
    const b = await toOpaInput(await allow(w2, plain(), false, disclose));
    expect(a.principal).toMatchObject({ id_basis: 'claim:personal_administrative_number' });
    expect(a.principal.id).toBe(b.principal.id);
  });

  it('legal persons are identified by EUID, with role and representative; the audit record keeps them', async () => {
    const acme = await allow(await director('ITRM.RM1234567', 'Acme S.p.A.', 'Mario', 'Rossi'), legalMandate('ITRM.RM1234567'), true);
    const globex = await allow(await director('ITMI.MI7654321', 'Globex S.r.l.', 'Anna', 'Verdi'), legalMandate('ITMI.MI7654321'), true);

    const oa = await toOpaInput(acme);
    expect(oa.principal).toMatchObject({
      type: 'legal_person',
      id: 'ITRM.RM1234567',
      id_basis: 'euid',
      euid: 'ITRM.RM1234567',
      legal_name: 'Acme S.p.A.',
      role: { code: 'managing_director' },
      representative: { id_basis: 'holder_key', claims: { given_name: 'Mario', family_name: 'Rossi' } },
    });
    expect((await toOpaInput(globex)).principal).toMatchObject({ euid: 'ITMI.MI7654321', representative: { claims: { family_name: 'Verdi' } } });

    const ca = await toCedarRequest(acme);
    const cg = await toCedarRequest(globex);
    const legalId = (c: typeof ca) => c.entities.find((e) => e.uid.type === 'Plenipo::LegalPerson')!.uid.id;
    expect(legalId(ca)).toBe('ITRM.RM1234567');
    expect(legalId(cg)).toBe('ITMI.MI7654321');
    const company = ca.entities.find((e) => e.uid.type === 'Plenipo::LegalPerson')!;
    expect(company.attrs).toMatchObject({ legal_name: 'Acme S.p.A.', role_code: 'managing_director', representative: { __entity: { type: 'Plenipo::Person' } } });
    expect(ca.context.principal_type).toBe('legal_person');

    const store = new InMemoryAuditStore();
    await new AuditLog({ store }).recordDecision({ decision: acme });
    const [rec] = await store.readAll();
    expect(rec.principal).toMatchObject({
      type: 'legal_person',
      euid: 'ITRM.RM1234567',
      legal_name: 'Acme S.p.A.',
      representative: { given_name: 'Mario', family_name: 'Rossi' },
    });
    expect(rec.principal_id).toBe(oa.principal.type === 'legal_person' ? oa.principal.representative.id : '');
  });
});

describe('OPS-AUDIT-1: a key makes signatures mandatory', () => {
  async function signedLog() {
    const pair = await generateKeyPair('ES256', { extractable: true });
    const store = new InMemoryAuditStore();
    const log = new AuditLog({ store, signer: { key: pair.privateKey } });
    await log.append({ event: 'decision', decision: 'DENY', code: 'LIMIT_TOTAL', reason: 'amount 900000 would exceed a total' });
    await log.append({ event: 'decision', decision: 'ALLOW', mandate_ids: ['m1'] });
    await log.append({ event: 'settlement', settlement: 'commit' });
    return { pair, records: await store.readAll() };
  }

  function rewrite(records: AuditRecord[], dropFrom = 0): AuditRecord[] {
    const out: AuditRecord[] = [];
    let prev = records[0].prev;
    for (const r of records) {
      if (r.seq < dropFrom) {
        out.push(r);
        prev = r.hash;
        continue;
      }
      const { sig: _s, hash: _h, ...rest } = r;
      const body = { ...rest, prev, ...(r.seq === dropFrom ? { decision: 'ALLOW' as const, code: undefined, reason: undefined } : {}) };
      const clean = Object.fromEntries(Object.entries(body).filter(([, v]) => v !== undefined)) as Omit<AuditRecord, 'hash'>;
      const hash = auditRecordHash(clean);
      out.push({ ...clean, hash } as AuditRecord);
      prev = hash;
    }
    return out;
  }

  it('refuses a rewritten log whose signatures were stripped', async () => {
    const { pair, records } = await signedLog();
    expect(await verifyAuditLog(records, { key: pair.publicKey })).toMatchObject({ valid: true, unauthenticated: 0 });
    const forged = rewrite(records);
    expect(await verifyAuditLog(forged, { key: pair.publicKey })).toMatchObject({ valid: false, index: 0 });
    expect(await verifyAuditLog(forged, { key: pair.publicKey, requireSignatures: 'head' })).toMatchObject({ valid: false });
  });

  it('refuses unsigned records after signed ones, and reports them when signatures are explicitly optional', async () => {
    const { pair, records } = await signedLog();
    const forged = rewrite(records, 1);
    expect(await verifyAuditLog(forged, { key: pair.publicKey })).toMatchObject({ valid: false, index: 1 });
    expect(await verifyAuditLog(forged, { key: pair.publicKey, requireSignatures: 'none' })).toMatchObject({ valid: true, signedThrough: 0, unauthenticated: 2 });
  });
});

describe('OPS-AUDIT-2: agent-chosen values cannot make a decision unrecordable', () => {
  const route: GatewayRoute = {
    method: 'POST',
    path: '/pay',
    action: 'payments.transfer',
    counterparty: (r) => (r.json() as { creditor: string }).creditor,
    amount: (r) => ({ value: (r.json() as { amount: number }).amount, currency: 'EUR' }),
  };

  async function lonelySurrogatePayment(gw: ReturnType<typeof createGateway>) {
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.*'], counterparties: ['shop.example'], limits: { currency: 'EUR', per_operation: 50_000 } });
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const body = { creditor: 'shop.example', amount: 40_000 };
    const inv = await createInvocation(agent.privateKey, {
      chain,
      mandateId: m.id,
      action: 'payments.transfer',
      counterparty: 'shop.example',
      amount: { value: 40_000, currency: 'EUR' },
      aud: API,
      nonce: 'n-\ud800',
      args: { method: 'POST', path: '/pay', query: {}, media_type: 'application/json', body },
    });
    return gw.handle(new Request(API + '/pay', { method: 'POST', headers: { ...authorizationHeaders(chain, inv), 'content-type': 'application/json' }, body: JSON.stringify(body) }));
  }

  it('records the decision of an invocation whose nonce holds a lone surrogate', async () => {
    const store = new InMemoryAuditStore();
    const executed: number[] = [];
    const gw = createGateway({
      routes: [route],
      verify: { audience: API, nonces: new InMemoryNonceStore(), ledger: new InMemorySpendingLedger(), trustedIssuers: [provider.trusted] },
      audit: new AuditLog({ store }),
      auditFailure: 'continue',
      async downstream(req) {
        executed.push(((await req.json()) as { amount: number }).amount);
        return new Response(null, { status: 201 });
      },
    });
    expect((await lonelySurrogatePayment(gw)).status).toBe(201);
    const recs = await store.readAll();
    const decision = recs.find((r) => r.event === 'decision')!;
    expect(decision).toMatchObject({ decision: 'ALLOW', invocation: { nonce: 'n-�' } });
    expect(Object.keys(decision.invocation!).sort()).toEqual(['action', 'amount', 'aud', 'iat', 'mandate', 'nonce', 'args_hash', 'chain_hash', 'counterparty'].sort());
    expect(await verifyAuditLog(recs)).toMatchObject({ valid: true });
  });

  it("with auditFailure 'continue', a failed full record is followed by a minimal one", async () => {
    const inner = new InMemoryAuditStore();
    let failNext = true;
    const flaky: AuditStore = {
      last: () => inner.last(),
      readAll: () => inner.readAll(),
      append: async (r) => {
        if (failNext && r.event === 'decision') {
          failNext = false;
          throw new Error('transient');
        }
        return inner.append(r);
      },
    };
    const gw = createGateway({
      routes: [route],
      verify: { audience: API, nonces: new InMemoryNonceStore(), ledger: new InMemorySpendingLedger(), trustedIssuers: [provider.trusted] },
      audit: new AuditLog({ store: flaky }),
      auditFailure: 'continue',
      downstream: () => new Response(null, { status: 201 }),
    });
    expect((await lonelySurrogatePayment(gw)).status).toBe(201);
    const recs = await inner.readAll();
    expect(recs[0]).toMatchObject({ event: 'decision', decision: 'ALLOW', reason: 'full decision record failed' });
    expect(recs[0].mandate_ids).toHaveLength(1);
  });
});

describe('OPS-STATUS-1: publisherSource honours the publisher state', () => {
  it('refuses to reinstate an entry revoked directly on the publisher, and unallocated entries', async () => {
    const pair = await generateKeyPair('ES256', { extractable: true });
    const uri = 'https://platform.example/status/mandates';
    const publisher = new StatusListPublisher({ uri, signingKey: pair.privateKey, size: 64 });
    const ref = publisher.allocate();
    publisher.revoke(ref);
    const svc = createStatusService({ lists: { mandates: publisherSource(publisher) }, authorize: () => ({ actor: 'ops' }) });
    const admin = (idx: number, op: string) => svc.handle(new Request(`https://platform.example/admin/status/mandates/entries/${idx}/${op}`, { method: 'POST' }));

    const res = await admin(ref.status_list.idx, 'reinstate');
    expect(res.status).toBe(409);
    expect((await res.json()).code).toBe('entry_revoked');
    expect((await admin(ref.status_list.idx, 'suspend')).status).toBe(409);
    expect(publisher.getStatus(ref.status_list.idx)).toBe(1);

    let unallocated = 0;
    while (publisher.isAllocated(unallocated)) unallocated++;
    expect((await admin(unallocated, 'revoke')).status).toBe(404);
    expect(publisher.getStatus(unallocated)).toBe(0);
    expect((await admin(63, 'revoke')).status).toBe(publisher.isAllocated(63) ? 200 : 404);
  });
});
