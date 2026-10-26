import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type IncomingMessage, type RequestListener, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportJWK, generateKeyPair } from 'jose';
import {
  argsHash,
  canonicalize,
  sha256,
  AuditLog,
  authorizationHeaders,
  auditRecordHash,
  createGateway,
  createInvocation,
  createMandate,
  createStatusService,
  delegateMandate,
  DENY_PROBLEMS,
  expressMiddleware,
  generateAgentKey,
  InMemoryAuditStore,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  InMemoryStatusListStore,
  JsonlFileAuditStore,
  ManagedStatusList,
  mandateHash,
  parseAuthorizationHeaders,
  problemForDecision,
  publisherSource,
  StatusListPublisher,
  toCedarRequest,
  toNodeListener,
  toOpaInput,
  verifyAuditLog,
  type AgentKey,
  type AuditRecord,
  type Decision,
  type DenyCode,
  type GatewayOptions,
  type GatewayRoute,
  type Mandate,
  type MandateChain,
  type StatusFetcher,
} from '../src/index.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';

const API = 'https://api.bank.example';
const PLATFORM = 'https://platform.example';
const PATH = '/accounts/acc-1/payments';

interface Server {
  url: string;
  close(): Promise<void>;
}

async function listen(listener: RequestListener): Promise<Server> {
  // Node limits request headers to 16 KiB by default; a gateway that accepts larger chains must raise it.
  const server = createServer({ maxHeaderSize: 512 * 1024 }, listener);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

let agent: AgentKey;
let provider: TestPidProvider;
let wallet: TestWallet;
let statusServer: Server;
let gatewayServer: Server;
let statusList: ManagedStatusList;
let ledger: InMemorySpendingLedger;
let auditStore: InMemoryAuditStore;
let platformJwk: Record<string, unknown>;
const ADMIN_TOKEN = 'Bearer s3cret-admin';
const downstreamCalls: Array<{ path: string; headers: Record<string, string>; body: unknown }> = [];

// Status lists are https URLs in mandates; the test fetcher maps them to the local http server.
const fetcher: StatusFetcher = async (uri) => {
  const u = new URL(uri);
  if (u.origin !== PLATFORM) throw new Error('unexpected origin');
  const res = await fetch(statusServer.url + u.pathname, { redirect: 'error' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.text()).trim();
};

const paymentRoute: GatewayRoute = {
  method: 'POST',
  path: '/accounts/:account/payments',
  action: 'payments.transfer',
  counterparty: (r) => (r.json() as { creditor?: string }).creditor,
  amount: (r) => {
    const b = r.json() as { amount?: number; currency?: string };
    return b.amount === undefined ? undefined : { value: b.amount, currency: b.currency ?? '' };
  },
};

const balanceRoute: GatewayRoute = {
  method: 'GET',
  path: '/accounts/:account/balance',
  action: 'accounts.read',
  counterparty: null,
  amount: null,
};

function verifyOptions(): GatewayOptions['verify'] {
  return {
    audience: API,
    nonces: new InMemoryNonceStore(),
    ledger,
    trustedIssuers: [provider.trusted],
    mandateStatusTrust: { trustedIssuers: [{ iss: PLATFORM, jwk: platformJwk }] },
    statusFetcher: fetcher,
  };
}

function mandate(overrides: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.*', 'accounts.read'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 50_000, total: 100_000 },
    ...overrides,
  });
}

async function chainFor(m: Mandate): Promise<MandateChain> {
  return { root: await wallet.approveMandate(m), delegations: [] };
}

/** Approves a root for `m` and returns the headers of a payment signed for that chain. */
async function paymentHeaders(m: Mandate, body: Record<string, unknown>, opts: { path?: string; nonce?: string } = {}) {
  const chain = await chainFor(m);
  return authorizationHeaders(chain, await signPayment(chain, m, body, opts));
}

function paymentBody(amount: number, extra: Record<string, unknown> = {}) {
  return { creditor: 'shop.example', amount, currency: 'EUR', ...extra };
}

async function signPayment(chain: MandateChain, m: Mandate, body: Record<string, unknown>, opts: { path?: string; nonce?: string } = {}) {
  const path = opts.path ?? PATH;
  return createInvocation(agent.privateKey, { chain,
    mandateId: m.id,
    action: 'payments.transfer',
    counterparty: body.creditor as string,
    amount: { value: body.amount as number, currency: body.currency as string },
    aud: API,
    nonce: opts.nonce,
    args: { method: 'POST', path, query: {}, media_type: 'application/json', body },
  });
}

async function post(path: string, headers: Record<string, string>, body: unknown): Promise<Response> {
  return fetch(gatewayServer.url + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

beforeAll(async () => {
  agent = await generateAgentKey();
  provider = await createTestPidProvider('https://pid.example.it');
  wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Maria', family_name: 'Bianchi', birthdate: '1980-01-01' }));
  const pair = await generateKeyPair('ES256', { extractable: true });
  platformJwk = (await exportJWK(pair.publicKey)) as Record<string, unknown>;
  statusList = new ManagedStatusList({
    id: 'mandates',
    uri: `${PLATFORM}/status/mandates`,
    signingKey: pair.privateKey,
    iss: PLATFORM,
    store: new InMemoryStatusListStore(),
    size: 1024,
    ttlSeconds: 60,
  });
  const statusService = createStatusService({
    lists: { mandates: statusList },
    authorize: (req) => (req.headers.get('authorization') === ADMIN_TOKEN ? { actor: 'ops@bank' } : false),
  });
  statusServer = await listen(toNodeListener(statusService.handle));

  ledger = new InMemorySpendingLedger();
  auditStore = new InMemoryAuditStore();
  const gateway = createGateway({
    routes: [paymentRoute, balanceRoute],
    verify: verifyOptions(),
    audit: new AuditLog({ store: auditStore }),
    maxChainHeaderBytes: 64 * 1024,
    async downstream(req, ctx) {
      const body = req.method === 'POST' ? await req.json() : null;
      downstreamCalls.push({ path: new URL(req.url).pathname, headers: Object.fromEntries(req.headers), body });
      const mode = (body as { mode?: string } | null)?.mode;
      if (mode === 'throw') throw new Error('core banking timeout at 10.0.0.7');
      if (mode === 'fail') return new Response('{"error":"rejected"}', { status: 500 });
      return Response.json({ ok: true, by: ctx?.decision.principal.family_name }, { status: req.method === 'POST' ? 201 : 200 });
    },
  });
  gatewayServer = await listen(toNodeListener(gateway.handle, { origin: API }));
});

afterAll(async () => {
  await gatewayServer?.close();
  await statusServer?.close();
});

function expectProblemShape(body: Record<string, unknown>) {
  const allowed = new Set(['type', 'title', 'status', 'code', 'at']);
  for (const k of Object.keys(body)) expect(allowed.has(k), `unexpected member ${k}`).toBe(true);
  expect(body.type).toBe(`https://plenipo.net/problems/${body.code}`);
}

describe('gateway over HTTP', () => {
  it('allows a bound payment and commits the reservation on 2xx', async () => {
    const m = mandate();
    const body = paymentBody(12_000);
    const res = await post(PATH, await paymentHeaders(m, body), body);
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ ok: true, by: 'Bianchi' });
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(12_000);
    // The PID-bearing headers are not forwarded to the API.
    const call = downstreamCalls[downstreamCalls.length - 1];
    expect(call.headers['plenipo-chain']).toBeUndefined();
    expect(call.headers['plenipo-invocation']).toBeUndefined();
    expect(call.body).toEqual(body);
    const records = await auditStore.readAll();
    const tail = records.slice(-2);
    expect(tail[0]).toMatchObject({ event: 'decision', decision: 'ALLOW', mandate_ids: [m.id] });
    expect(tail[1]).toMatchObject({ event: 'settlement', settlement: 'commit', http: { status: 201 } });
  });

  it('denies with problem+json and never leaks reason or detail', async () => {
    const m = mandate();
    const body = { ...paymentBody(100), creditor: 'evil.example' };
    const chain = await chainFor(m);
    const inv = await createInvocation(agent.privateKey, { chain,
      mandateId: m.id,
      action: 'payments.transfer',
      counterparty: 'evil.example',
      amount: { value: 100, currency: 'EUR' },
      aud: API,
      args: { method: 'POST', path: PATH, query: {}, media_type: 'application/json', body },
    });
    const res = await post(PATH, authorizationHeaders(chain, inv), body);
    expect(res.status).toBe(403);
    expect(res.headers.get('content-type')).toBe('application/problem+json');
    const p = (await res.json()) as Record<string, unknown>;
    expectProblemShape(p);
    expect(p).toMatchObject({ code: 'counterparty_not_permitted', status: 403, at: 0 });
    expect(JSON.stringify(p)).not.toContain('evil.example');
    const last = (await auditStore.readAll()).at(-1)!;
    expect(last).toMatchObject({ decision: 'DENY', code: 'COUNTERPARTY_NOT_PERMITTED', problem: 'counterparty_not_permitted' });
    expect(last.reason).toContain('evil.example');
  });

  it('maps an unreachable status list to 503 without the network error', async () => {
    const ref = await statusList.allocate();
    const m = mandate({ status: { status_list: { uri: `${PLATFORM}/status/missing`, idx: ref.status_list.idx } } });
    const body = paymentBody(100);
    const res = await post(PATH, await paymentHeaders(m, body), body);
    expect(res.status).toBe(503);
    expect(res.headers.get('retry-after')).toBe('5');
    const text = await res.text();
    expect(text).not.toMatch(/HTTP 404|could not be verified/);
    expectProblemShape(JSON.parse(text));
    expect(JSON.parse(text).code).toBe('status_unavailable');
    expect((await auditStore.readAll()).at(-1)!.detail).toContain('HTTP 404');
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);
  });

  // Changed in the security review fix: a 5xx or a throw no longer releases. The API may have acted before
  // failing, so the reservation stays pending (it keeps counting) until reconciled or swept as spent.
  it('keeps the reservation pending when the API answers 500', async () => {
    const m = mandate();
    const body = paymentBody(30_000, { mode: 'fail' });
    const res = await post(PATH, await paymentHeaders(m, body), body);
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: 'rejected' });
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(30_000);
    expect((await auditStore.readAll()).at(-1)).toMatchObject({ event: 'settlement', settlement: 'pending', http: { status: 500 } });
  });

  it('keeps the reservation pending when the API throws, and hides the error', async () => {
    const m = mandate();
    const body = paymentBody(30_000, { mode: 'throw' });
    const res = await post(PATH, await paymentHeaders(m, body), body);
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(text).not.toContain('10.0.0.7');
    expect(JSON.parse(text).code).toBe('processing_error');
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(30_000);
  });

  it('refuses a chain header above the limit with 431', async () => {
    const m = mandate();
    const body = paymentBody(100);
    const headers = await paymentHeaders(m, body);
    headers['Plenipo-Chain'] = 'A'.repeat(64 * 1024 + 1);
    const res = await post(PATH, headers, body);
    expect(res.status).toBe(431);
    expect((await res.json()).code).toBe('header_too_large');
  });

  it('refuses malformed base64url and malformed chain shapes with 400', async () => {
    const m = mandate();
    const body = paymentBody(100);
    const inv = await signPayment(await chainFor(m), m, body);
    for (const chainHeader of [
      'not*base64',
      'eyJyb290Ijp7fX0=', // padded
      Buffer.from('{"root":{},"delegations":[]}').toString('base64url'),
      Buffer.from('[1,2]').toString('base64url'),
      Buffer.from(JSON.stringify({ ...(await chainFor(m)), extra: 1 })).toString('base64url'),
    ]) {
      const res = await post(PATH, { 'Plenipo-Chain': chainHeader, 'Plenipo-Invocation': inv }, body);
      expect(res.status, chainHeader).toBe(400);
      expect((await res.json()).code).toBe('malformed_authorization');
    }
  });

  it('answers 401 with a challenge when the headers are missing', async () => {
    const res = await post(PATH, {}, paymentBody(1));
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('Plenipo error="authorization_required"');
  });

  it('refuses a replayed invocation with 409 and leaves the limits as they were', async () => {
    const m = mandate();
    const body = paymentBody(10_000);
    const headers = await paymentHeaders(m, body);
    expect((await post(PATH, headers, body)).status).toBe(201);
    const again = await post(PATH, headers, body);
    expect(again.status).toBe(409);
    expect((await again.json()).code).toBe('replay');
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(10_000);
  });

  it('binds the invocation to the request: amount, path and body changes are refused', async () => {
    const m = mandate();
    const signed = paymentBody(1_000);
    const chain = await chainFor(m);
    // Same signed invocation, higher amount in the body.
    let res = await post(PATH, authorizationHeaders(chain, await signPayment(chain, m, signed)), { ...signed, amount: 49_000 });
    expect(res.status).toBe(422);
    expect((await res.json()).code).toBe('invocation_mismatch');
    // Same amount and counterparty, different debtor account in the path.
    res = await post('/accounts/acc-2/payments', authorizationHeaders(chain, await signPayment(chain, m, signed)), signed);
    expect(res.status).toBe(422);
    // A field the agent did not sign.
    res = await post(PATH, authorizationHeaders(chain, await signPayment(chain, m, signed)), { ...signed, iban: 'IT00X' });
    expect(res.status).toBe(422);
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);
  });

  it('refuses a request whose route mapping cannot read the counterparty', async () => {
    const m = mandate();
    const signed = paymentBody(1_000);
    const res = await post(PATH, await paymentHeaders(m, signed), { amount: 1000, currency: 'EUR' });
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('request_unmapped');
  });

  it('refuses an invocation that names a counterparty on a route without one', async () => {
    // The route declares counterparty and amount null, so a mandate with limits and a counterparty list
    // authorises the read without a reservation.
    const m = mandate();
    const url = '/accounts/acc-1/balance';
    const chain = await chainFor(m);
    const inv = await createInvocation(agent.privateKey, { chain,
      mandateId: m.id,
      action: 'accounts.read',
      counterparty: 'shop.example',
      aud: API,
      args: { method: 'GET', path: url, query: {}, media_type: null, body: null },
    });
    const res = await fetch(gatewayServer.url + url, { headers: authorizationHeaders(chain, inv) });
    expect(res.status).toBe(422);
    const ok = await createInvocation(agent.privateKey, { chain,
      mandateId: m.id,
      action: 'accounts.read',
      aud: API,
      args: { method: 'GET', path: url, query: {}, media_type: null, body: null },
    });
    const good = await fetch(gatewayServer.url + url, { headers: authorizationHeaders(chain, ok) });
    expect(good.status).toBe(200);
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);
  });

  it('answers 404 for a path no route protects', async () => {
    const res = await fetch(gatewayServer.url + '/admin/everything', { method: 'DELETE' });
    expect(res.status).toBe(404);
    expect((await res.json()).code).toBe('no_route');
  });

  it('accepts a delegated chain and reports the depth to the policy hook, which can refuse', async () => {
    const sub = await generateAgentKey();
    const root = mandate({ maxDepth: 1 });
    const child = createMandate({
      agentJwk: sub.publicJwk,
      actions: ['payments.transfer'],
      counterparties: ['shop.example'],
      limits: { currency: 'EUR', per_operation: 5_000, total: 10_000 },
    });
    const chain = { root: await wallet.approveMandate(root), delegations: [await delegateMandate({ parent: root, parentAgentKey: agent.privateKey, child })] };
    const pledger = new InMemorySpendingLedger();
    const seen: number[] = [];
    const gw = createGateway({
      routes: [paymentRoute],
      verify: { ...verifyOptions(), ledger: pledger },
      policy: async (d) => {
        const input = await toOpaInput(d, { ledger: pledger });
        seen.push(input.chain.depth);
        return input.amount!.value <= 2_000;
      },
      downstream: () => new Response(null, { status: 204 }),
    });
    const send = async (amount: number) => {
      const body = paymentBody(amount);
      const inv = await createInvocation(sub.privateKey, { chain,
        mandateId: child.id,
        action: 'payments.transfer',
        counterparty: 'shop.example',
        amount: { value: amount, currency: 'EUR' },
        aud: API,
        args: { method: 'POST', path: PATH, query: {}, media_type: 'application/json', body },
      });
      return gw.handle(
        new Request(API + PATH, { method: 'POST', headers: { ...authorizationHeaders(chain, inv), 'content-type': 'application/json' }, body: JSON.stringify(body) }),
      );
    };
    expect((await send(1_500)).status).toBe(204);
    const refused = await send(3_000);
    expect(refused.status).toBe(403);
    expect((await refused.json()).code).toBe('policy_denied');
    expect(seen).toEqual([1, 1]);
    expect(pledger.spent(mandateHash(child), 'EUR')).toBe(1_500);
    expect(pledger.spent(mandateHash(root), 'EUR')).toBe(1_500);
  });

  it('denies an allowed request when the audit log cannot record it, and releases the reservation', async () => {
    const failing = { last: async () => undefined, append: async () => Promise.reject(new Error('disk full')), readAll: async () => [] };
    const l = new InMemorySpendingLedger();
    const gw = createGateway({
      routes: [paymentRoute],
      verify: { ...verifyOptions(), ledger: l },
      audit: new AuditLog({ store: failing }),
      downstream: () => new Response('should not run', { status: 200 }),
    });
    const m = mandate();
    const body = paymentBody(100);
    const res = await gw.handle(
      new Request(API + PATH, { method: 'POST', headers: { ...(await paymentHeaders(m, body)), 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    );
    expect(res.status).toBe(503);
    expect((await res.json()).code).toBe('audit_unavailable');
    expect(l.spent(mandateHash(m), 'EUR')).toBe(0);
  });

  it('forwards unmatched requests only when configured, and bounds the body', async () => {
    const gw = createGateway({
      routes: [paymentRoute],
      verify: verifyOptions(),
      unmatched: 'pass',
      maxBodyBytes: 64,
      downstream: (_req, ctx) => new Response(ctx ? 'protected' : 'public', { status: 200 }),
    });
    expect(await (await gw.handle(new Request(`${API}/health`))).text()).toBe('public');
    const m = mandate();
    const body = paymentBody(100, { note: 'x'.repeat(100) });
    const res = await gw.handle(
      new Request(API + PATH, { method: 'POST', headers: { ...(await paymentHeaders(m, body)), 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    );
    expect(res.status).toBe(413);
  });

  it('refuses route definitions that leave counterparty or amount unstated', () => {
    const base = { verify: verifyOptions() };
    expect(() => createGateway({ ...base, routes: [{ method: 'POST', path: '/x', action: 'a.b', amount: null } as unknown as GatewayRoute] })).toThrow(/counterparty/);
    expect(() => createGateway({ ...base, routes: [{ ...paymentRoute, action: 'payments.*' }] })).toThrow(/concrete/);
    expect(() => createGateway({ ...base, verify: { ...verifyOptions(), expected: { action: 'x' } } as never, routes: [paymentRoute] })).toThrow(/expected/);
  });
});

describe('Express-style middleware', () => {
  it('authorizes, exposes the decision, and settles when the response finishes', async () => {
    const l = new InMemorySpendingLedger();
    const gw = createGateway({ routes: [paymentRoute], verify: { ...verifyOptions(), ledger: l } });
    const mw = expressMiddleware(gw, { origin: API });
    // A minimal Express-like app: middleware, then a handler that fails for one creditor amount.
    const server = await listen((req: IncomingMessage, res: ServerResponse) => {
      mw(req, res, (err?: unknown) => {
        if (err) {
          res.statusCode = 500;
          res.end();
          return;
        }
        const r = req as IncomingMessage & { body?: { amount: number }; plenipo?: { decision: Decision } };
        res.statusCode = r.body!.amount === 666 ? 502 : r.body!.amount === 404 ? 422 : 201;
        res.end(JSON.stringify({ decision: r.plenipo?.decision.decision }));
      });
    });
    try {
      const m = mandate();
      for (const [amount, status] of [
        [700, 201],
        [666, 502],
        [404, 422],
      ] as const) {
        const body = paymentBody(amount);
        const res = await fetch(server.url + PATH, {
          method: 'POST',
          headers: { ...await paymentHeaders(m, body), 'content-type': 'application/json' },
          body: JSON.stringify(body),
        });
        expect(res.status).toBe(status);
      }
      await new Promise((r) => setTimeout(r, 20));
      // 201 commits, 422 releases (a refusal), 502 stays pending: the handler may have acted.
      expect(l.spent(mandateHash(m), 'EUR')).toBe(700 + 666);
      const denied = await fetch(server.url + PATH, { method: 'POST', body: '{}' });
      expect(denied.status).toBe(401);
    } finally {
      await server.close();
    }
  });
});

describe('status list service', () => {
  it('serves the token with the status list media type and cache headers bound to its ttl', async () => {
    const res = await fetch(statusServer.url + '/status/mandates');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/statuslist+jwt');
    const maxAge = Number(/max-age=(\d+)/.exec(res.headers.get('cache-control')!)![1]);
    expect(maxAge).toBeGreaterThan(0);
    expect(maxAge).toBeLessThanOrEqual(60);
    const etag = res.headers.get('etag')!;
    expect((await res.text()).split('.')).toHaveLength(3);
    const again = await fetch(statusServer.url + '/status/mandates', { headers: { 'if-none-match': etag } });
    expect(again.status).toBe(304);
    expect((await fetch(statusServer.url + '/status/other')).status).toBe(404);
    expect((await fetch(statusServer.url + '/status/mandates', { method: 'POST' })).status).toBe(405);
  });

  it('requires authorization to revoke, and a revocation stops the next payment', async () => {
    const ref = await statusList.allocate();
    const m = mandate({ status: ref });
    const chain = await chainFor(m);
    const body = paymentBody(100);
    expect((await post(PATH, authorizationHeaders(chain, await signPayment(chain, m, body)), body)).status).toBe(201);

    const url = `${statusServer.url}/admin/status/mandates/entries/${ref.status_list.idx}/revoke`;
    const anonymous = await fetch(url, { method: 'POST' });
    expect(anonymous.status).toBe(403);
    expect((await anonymous.json()).code).toBe('admin_forbidden');
    const wrong = await fetch(url, { method: 'POST', headers: { authorization: 'Bearer guess' } });
    expect(wrong.status).toBe(403);
    // Still valid after the refused attempts.
    expect((await post(PATH, authorizationHeaders(chain, await signPayment(chain, m, body)), body)).status).toBe(201);

    const ok = await fetch(url, { method: 'POST', headers: { authorization: ADMIN_TOKEN } });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ list: 'mandates', idx: ref.status_list.idx, status: 'invalid' });

    const after = await post(PATH, authorizationHeaders(chain, await signPayment(chain, m, body)), body);
    expect(after.status).toBe(401);
    expect(await after.json()).toMatchObject({ code: 'revoked', at: 0 });

    const undo = await fetch(url.replace(/revoke$/, 'reinstate'), { method: 'POST', headers: { authorization: ADMIN_TOKEN } });
    expect(undo.status).toBe(409);
    expect((await undo.json()).code).toBe('entry_revoked');
  });

  it('suspends and reinstates', async () => {
    const ref = await statusList.allocate();
    const m = mandate({ status: ref });
    const chain = await chainFor(m);
    const body = paymentBody(100);
    const admin = (op: string) =>
      fetch(`${statusServer.url}/admin/status/mandates/entries/${ref.status_list.idx}/${op}`, { method: 'POST', headers: { authorization: ADMIN_TOKEN } });
    expect((await admin('suspend')).status).toBe(200);
    expect((await post(PATH, authorizationHeaders(chain, await signPayment(chain, m, body)), body)).status).toBe(401);
    expect((await admin('reinstate')).status).toBe(200);
    expect((await post(PATH, authorizationHeaders(chain, await signPayment(chain, m, body)), body)).status).toBe(201);
  });

  it('refuses unallocated entries, unknown operations and prototype names', async () => {
    const h = { method: 'POST', headers: { authorization: ADMIN_TOKEN } };
    let unallocated = 0;
    const state = await new InMemoryStatusListStore().init('x', 4);
    expect(state.allocated).toEqual([]);
    // Find an index this list has not allocated.
    while ((await fetch(`${statusServer.url}/admin/status/mandates/entries/${unallocated}/revoke`, h)).status !== 404) unallocated++;
    expect((await fetch(`${statusServer.url}/admin/status/mandates/entries/1/constructor`, h)).status).toBe(404);
    expect((await fetch(`${statusServer.url}/admin/status/mandates/entries/01/revoke`, h)).status).toBe(404);
    expect((await fetch(`${statusServer.url}/admin/status/mandates/entries/1/revoke`, { method: 'GET', headers: h.headers })).status).toBe(405);
  });

  it('has no open default: the admin API needs an authorize function', () => {
    expect(() => createStatusService({ lists: {} } as never)).toThrow(/authorize/);
  });

  it('allocates through the admin API and records admin operations in the audit log', async () => {
    const store = new InMemoryAuditStore();
    const pair = await generateKeyPair('ES256');
    const publisher = new StatusListPublisher({ uri: `${PLATFORM}/status/legacy`, signingKey: pair.privateKey, iss: PLATFORM, size: 64 });
    const svc = createStatusService({
      lists: { legacy: publisherSource(publisher) },
      authorize: () => ({ actor: 'ops@bank' }),
      audit: new AuditLog({ store }),
    });
    const alloc = await svc.handleAdmin(new Request(`${API}/admin/status/legacy/allocate`, { method: 'POST' }));
    expect(alloc.status).toBe(201);
    const ref = (await alloc.json()) as { status_list: { uri: string; idx: number } };
    expect(ref.status_list.uri).toBe(`${PLATFORM}/status/legacy`);
    const rev = await svc.handleAdmin(new Request(`${API}/admin/status/legacy/entries/${ref.status_list.idx}/revoke`, { method: 'POST' }));
    expect(rev.status).toBe(200);
    expect((await svc.handleAdmin(new Request(`${API}/admin/status/legacy/entries/999/revoke`, { method: 'POST' }))).status).toBe(404);
    // The public handler does not expose the admin API.
    expect((await svc.handlePublic(new Request(`${API}/admin/status/legacy/allocate`, { method: 'POST' }))).status).toBe(404);
    const records = await store.readAll();
    expect(records.map((r) => r.context?.operation)).toEqual(['allocate', 'revoke', 'revoke']);
    expect(records[1].context).toMatchObject({ actor: 'ops@bank', result: 'ok' });
    expect((await verifyAuditLog(records)).valid).toBe(true);
  });
});

describe('audit log', () => {
  async function sampleLog(n: number, signer?: { key: CryptoKey; every?: number }) {
    const store = new InMemoryAuditStore();
    let t = Date.UTC(2026, 9, 19, 10, 0, 0);
    const log = new AuditLog({ store, signer, now: () => new Date((t += 1000)) });
    for (let i = 0; i < n; i++) {
      await log.append({ event: 'decision', decision: i % 2 ? 'DENY' : 'ALLOW', code: i % 2 ? 'LIMIT_TOTAL' : undefined, mandate_ids: [`m-${i}`] });
    }
    return { store, log, records: await store.readAll() };
  }

  it('verifies an intact chain', async () => {
    const { records } = await sampleLog(5);
    expect(await verifyAuditLog(records)).toEqual({ valid: true, count: 5, head: { seq: 4, hash: records[4].hash } });
    expect(records[0].prev).toBe('A'.repeat(43));
    expect(records[3].prev).toBe(records[2].hash);
  });

  it('detects an edited record', async () => {
    const { records } = await sampleLog(5);
    const edited = structuredClone(records);
    edited[2].decision = 'DENY';
    expect(await verifyAuditLog(edited)).toMatchObject({ valid: false, index: 2, error: expect.stringMatching(/hash/) });
    // Re-hashing the edited record breaks the link from the next one.
    edited[2].hash = auditRecordHash(edited[2]);
    expect(await verifyAuditLog(edited)).toMatchObject({ valid: false, index: 3 });
  });

  it('detects a deleted record and reordered records', async () => {
    const { records } = await sampleLog(5);
    const deleted = records.filter((_, i) => i !== 1);
    expect(await verifyAuditLog(deleted)).toMatchObject({ valid: false, index: 1, error: expect.stringMatching(/missing or out of order/) });
    const reordered = [records[0], records[2], records[1], records[3], records[4]];
    expect(await verifyAuditLog(reordered)).toMatchObject({ valid: false, index: 1 });
  });

  it('detects tail truncation against an expected head, and verifies a pruned log from an anchor', async () => {
    const { records } = await sampleLog(5);
    const head = { seq: 4, hash: records[4].hash };
    expect(await verifyAuditLog(records.slice(0, 4), { expectedHead: head })).toMatchObject({ valid: false });
    expect(await verifyAuditLog(records.slice(2), { anchor: { seq: 1, hash: records[1].hash }, expectedHead: head })).toMatchObject({
      valid: true,
      count: 3,
    });
    expect(await verifyAuditLog(records.slice(2))).toMatchObject({ valid: false, index: 0 });
  });

  it('signatures catch a rewritten chain, and checkpoints sign every n-th record', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const { records } = await sampleLog(4, { key: privateKey });
    expect(await verifyAuditLog(records, { key: publicKey, requireSignatures: 'all' })).toMatchObject({ valid: true, signedThrough: 3 });
    // An attacker who rewrites and re-hashes everything cannot re-sign.
    const forged = structuredClone(records);
    forged[1].decision = 'ALLOW';
    for (let i = 1; i < forged.length; i++) {
      if (i > 1) forged[i].prev = forged[i - 1].hash;
      forged[i].hash = auditRecordHash(forged[i]);
    }
    expect(await verifyAuditLog(forged)).toMatchObject({ valid: true });
    expect(await verifyAuditLog(forged, { key: publicKey })).toMatchObject({ valid: false, index: 1, error: expect.stringMatching(/signature/) });

    const cp = await sampleLog(5, { key: privateKey, every: 2 });
    expect(cp.records.map((r) => r.sig !== undefined)).toEqual([false, true, false, true, false]);
    expect(await verifyAuditLog(cp.records, { key: publicKey, requireSignatures: 'head' })).toMatchObject({ valid: false });
    const checkpoint = await cp.log.checkpoint({ reason: 'shutdown' });
    expect(checkpoint.sig).toBeDefined();
    expect(await verifyAuditLog(await cp.store.readAll(), { key: await exportJWK(publicKey), requireSignatures: 'head' })).toMatchObject({
      valid: true,
      signedThrough: 5,
    });
  });

  it('serialises concurrent appends into one chain', async () => {
    const store = new InMemoryAuditStore();
    const log = new AuditLog({ store });
    await Promise.all(Array.from({ length: 20 }, (_, i) => log.append({ event: 'decision', decision: 'DENY', reason: String(i) })));
    expect(await verifyAuditLog(await store.readAll())).toMatchObject({ valid: true, count: 20 });
  });

  it('minimises principal data by default and keeps evidence only as configured', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const decision: Decision = {
      decision: 'ALLOW',
      principal: { given_name: 'Maria', family_name: 'Bianchi', birthdate: '1980-01-01', tax_id_code: 'XYZ' },
      pid_issuer: 'https://pid.example.it',
      pid_trusted_via: 'issuer',
      path: [{ depth: 0, mandate_id: m.id, actions: m.actions, exp: m.exp }],
      mandates: [m],
      invocation: { mandate: m.id, action: 'payments.transfer', aud: API, nonce: 'n', iat: 1, chain_hash: 'h' },
    };
    const store = new InMemoryAuditStore();
    const r = await new AuditLog({ store }).recordDecision({ decision, invocation: 'a.b.c', chain });
    expect(r.principal).toEqual({ given_name: 'Maria', family_name: 'Bianchi' });
    expect(r.pid_issuer).toBe('https://pid.example.it');
    expect(r.evidence).toEqual({ invocation: 'a.b.c' });
    expect(JSON.stringify(r)).not.toContain(chain.root.presentation.slice(0, 40));
    const full = await new AuditLog({ store: new InMemoryAuditStore(), redaction: { principalClaims: [], evidence: 'full' } }).recordDecision({
      decision,
      invocation: 'a.b.c',
      chain,
    });
    expect(full.principal).toEqual({});
    expect(full.evidence?.chain).toEqual(chain);
  });

  it('persists to a JSONL file with fsync, resumes the chain after a restart, and refuses a torn file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'plenipo-audit-'));
    try {
      const path = join(dir, 'audit.jsonl');
      const first = new AuditLog({ store: new JsonlFileAuditStore(path, { fsync: true }) });
      await first.append({ event: 'decision', decision: 'ALLOW' });
      await first.append({ event: 'decision', decision: 'DENY' });
      const second = new AuditLog({ store: new JsonlFileAuditStore(path, { fsync: true }) });
      const r = await second.append({ event: 'settlement', settlement: 'commit' });
      expect(r.seq).toBe(2);
      const records = await new JsonlFileAuditStore(path).readAll();
      expect(await verifyAuditLog(records)).toMatchObject({ valid: true, count: 3 });
      expect((await readFile(path, 'utf8')).split('\n')).toHaveLength(4);
      await writeFile(path, (await readFile(path, 'utf8')) + '{"v":1,"seq":3', 'utf8');
      await expect(new AuditLog({ store: new JsonlFileAuditStore(path) }).append({ event: 'decision' })).rejects.toThrow(/incomplete/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('error mapping', () => {
  const codes: DenyCode[] = Object.keys(DENY_PROBLEMS) as DenyCode[];

  it('covers every DenyCode with a stable lowercase code and a type URI', () => {
    expect(codes).toHaveLength(37);
    const seen = new Set<string>();
    for (const c of codes) {
      const p = DENY_PROBLEMS[c];
      expect(p.code).toBe(c.toLowerCase());
      expect(seen.has(p.code)).toBe(false);
      seen.add(p.code);
      expect([400, 401, 403, 409, 422, 500, 503]).toContain(p.status);
    }
    expect(DENY_PROBLEMS.REPLAY.status).toBe(409);
    expect(DENY_PROBLEMS.LIMIT_TOTAL.status).toBe(403);
    expect(DENY_PROBLEMS.LIMIT_PER_OPERATION.status).toBe(403);
    expect(DENY_PROBLEMS.CONFIGURATION.status).toBe(500);
  });

  it('maps infrastructure failures to their own codes', () => {
    const deny = (code: DenyCode, reason: string, detail?: string) =>
      problemForDecision({ decision: 'DENY', code, reason, path: [], ...(detail ? { detail } : {}) });
    expect(deny('REVOKED', 'mandate 0 is revoked in its status list')).toMatchObject({ status: 401, code: 'revoked' });
    // A list that was obtained but did not verify stays a denial of the credential, not an outage.
    expect(deny('REVOKED', 'status of mandate 0 could not be verified', 'wrong signer')).toMatchObject({ status: 401, code: 'revoked' });
    expect(deny('STATUS_UNAVAILABLE', 'PID status could not be verified', 'timeout')).toMatchObject({ status: 503, code: 'status_unavailable' });
    expect(deny('INTERNAL', 'the request could not be processed', 'ledger down')).toMatchObject({ status: 500, code: 'internal' });
    expect(deny('MALFORMED', 'chain must have root and delegations')).toMatchObject({ status: 400, code: 'malformed' });
    expect(deny('NOPE' as DenyCode, 'x')).toMatchObject({ status: 500, code: 'processing_error' });
    const p = deny('ROOT_INVALID', 'PID presentation does not verify', 'library stack');
    expect(Object.keys(p).sort()).toEqual(['code', 'status', 'title', 'type']);
  });

  it('parses headers strictly', () => {
    const h = (chain: string, inv = 'a.b.c') => new Headers({ 'plenipo-chain': chain, 'plenipo-invocation': inv });
    const good = Buffer.from(JSON.stringify({ root: { transaction_data: 'x', presentation: 'y' }, delegations: [] })).toString('base64url');
    expect(parseAuthorizationHeaders(h(good))).toMatchObject({ ok: true });
    expect(parseAuthorizationHeaders(h(`${good}, ${good}`))).toMatchObject({ ok: false });
    expect(parseAuthorizationHeaders(h(good, 'a.b'))).toMatchObject({ ok: false });
    expect(parseAuthorizationHeaders(h(good), { maxChainHeaderBytes: 10 })).toMatchObject({ ok: false, problem: { status: 431 } });
    const sixDelegations = Buffer.from(JSON.stringify({ root: { transaction_data: 'x', presentation: 'y' }, delegations: Array(6).fill('a.b.c') })).toString('base64url');
    expect(parseAuthorizationHeaders(h(sixDelegations))).toMatchObject({ ok: false });
  });
});

describe('policy engine export', () => {
  // Fixed key and time, so the documents can be compared in full.
  const leafJwk = { kty: 'EC', crv: 'P-256', x: 'E8AUsmJ4GtBTu_pRDMT5T3xxZSMH__01wPGY5sxFMB0', y: 'oZISQDW9pkcRGIuYrjjaibwxOf2Ap9nB6hZeCx-jHRM' };
  const rootJwk = { kty: 'EC', crv: 'P-256', x: 'TVzjfWaQ0bS21k3kw6eY86YrTgvU6thTiSkl-rnzAOU', y: 'r2COVLlcW27l1y6IE3puEGcVxN2Wa2r1Hmik6AkjAVQ' };
  const NOW = 1792449000; // 2026-10-19T22:30:00Z, 00:30 on Tuesday in Rome
  const root: Mandate = {
    v: '0.1',
    id: 'm-root',
    agent: { jwk: rootJwk },
    actions: ['payments.*'],
    counterparties: ['*.example'],
    limits: { currency: 'EUR', per_operation: 100_000, total: 500_000 },
    nbf: NOW - 3600,
    exp: NOW + 86_400,
    delegation: { max_depth: 1 },
  };
  const leaf: Mandate = {
    v: '0.1',
    id: 'm-leaf',
    agent: { jwk: leafJwk },
    actions: ['payments.sepa.transfer'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', total: 200_000 },
    nbf: NOW - 3600,
    exp: NOW + 3600,
  };
  const decision: Extract<Decision, { decision: 'ALLOW' }> = {
    decision: 'ALLOW',
    principal: { given_name: 'Maria', family_name: 'Bianchi', birthdate: '1980-01-01' },
    pid_issuer: 'https://pid.example.it',
    pid_trusted_via: 'x5c',
    path: [],
    mandates: [root, leaf],
    invocation: {
      mandate: 'm-leaf',
      action: 'payments.sepa.transfer',
      counterparty: 'shop.example',
      amount: { value: 150_000, currency: 'EUR' },
      aud: API,
      nonce: 'nonce-1',
      iat: NOW - 5,
      args_hash: argsHash({ x: 1 }),
      chain_hash: 'h',
    },
    reservation: 'r-1',
    pid_holder_jkt: 'holder-jkt-1',
  };
  // The person is identified by the PID holder key here (no unique claim disclosed), hashed with the issuer.
  const PERSON_ID = sha256(canonicalize({ iss: 'https://pid.example.it', basis: 'holder_key', value: 'holder-jkt-1' }));

  async function ledgerWithSpending() {
    const l = new InMemorySpendingLedger();
    l.reserve([{ key: mandateHash(root), total: 500_000 }, { key: mandateHash(leaf), total: 200_000 }], { value: 150_000, currency: 'EUR' });
    return l;
  }

  it('builds the OPA input document', async () => {
    const input = await toOpaInput(decision, {
      ledger: await ledgerWithSpending(),
      now: NOW,
      timeZone: 'Europe/Rome',
      request: { method: 'POST', path: PATH },
    });
    expect(input).toEqual({
      plenipo: '1',
      principal: {
        type: 'natural_person',
        id: PERSON_ID,
        id_basis: 'holder_key',
        issuer: 'https://pid.example.it',
        trusted_via: 'x5c',
        claims: { given_name: 'Maria', family_name: 'Bianchi' },
      },
      root: { type: 'eudi_pid', mandate_id: 'm-root' },
      chain: { depth: 1, mandate_ids: ['m-root', 'm-leaf'], exp: NOW + 3600 },
      agent: { jkt: 'pXz5NctsqokDuRsZLRaDTHA3xlfhlFBchmhagn_b_HQ', root_jkt: 'iV-amotG7c2mu43WYTEYOhnXyD4DGnGoZRb4UhxJ5ls' },
      action: 'payments.sepa.transfer',
      counterparty: 'shop.example',
      amount: { value: 150_000, currency: 'EUR' },
      limits: [
        { depth: 0, mandate_id: 'm-root', currency: 'EUR', per_operation: 100_000, total: 500_000, spent: 150_000, residual: 350_000 },
        { depth: 1, mandate_id: 'm-leaf', currency: 'EUR', total: 200_000, spent: 150_000, residual: 50_000 },
      ],
      invocation: { aud: API, iat: NOW - 5, nonce: 'nonce-1', args_hash: argsHash({ x: 1 }) },
      time: { epoch: NOW, iso: '2026-10-19T22:30:00.000Z', time_zone: 'Europe/Rome', local_hour: 0, weekday: 2 },
      request: { method: 'POST', path: PATH },
    });
  });

  it('builds Cedar entities and context in the JSON entity format', async () => {
    const req = await toCedarRequest(decision, { ledger: await ledgerWithSpending(), now: NOW, timeZone: 'Europe/Rome' });
    const principalId = PERSON_ID;
    const operationId = req.resource.id;
    expect(principalId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(operationId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(req).toEqual({
      principal: { type: 'Plenipo::Agent', id: 'pXz5NctsqokDuRsZLRaDTHA3xlfhlFBchmhagn_b_HQ' },
      action: { type: 'Plenipo::Action', id: 'payments.sepa.transfer' },
      resource: { type: 'Plenipo::Operation', id: operationId },
      context: {
        depth: 1,
        chain_length: 2,
        root_type: 'eudi_pid',
        principal_type: 'natural_person',
        pid_trusted_via: 'x5c',
        time: NOW,
        local_hour: 0,
        weekday: 2,
        chain_exp: NOW + 3600,
        amount: 150_000,
        currency: 'EUR',
        min_residual: 50_000,
      },
      entities: [
        {
          uid: { type: 'Plenipo::Person', id: principalId },
          attrs: { id_basis: 'holder_key', issuer: 'https://pid.example.it', trusted_via: 'x5c', claims: { given_name: 'Maria', family_name: 'Bianchi' } },
          parents: [],
        },
        {
          uid: { type: 'Plenipo::Mandate', id: 'm-root' },
          attrs: {
            depth: 0,
            actions: ['payments.*'],
            counterparties: ['*.example'],
            nbf: NOW - 3600,
            exp: NOW + 86_400,
            currency: 'EUR',
            per_operation: 100_000,
            total: 500_000,
            spent: 150_000,
            residual: 350_000,
          },
          parents: [{ type: 'Plenipo::Person', id: principalId }],
        },
        {
          uid: { type: 'Plenipo::Mandate', id: 'm-leaf' },
          attrs: {
            depth: 1,
            actions: ['payments.sepa.transfer'],
            counterparties: ['shop.example'],
            nbf: NOW - 3600,
            exp: NOW + 3600,
            currency: 'EUR',
            total: 200_000,
            spent: 150_000,
            residual: 50_000,
          },
          parents: [{ type: 'Plenipo::Mandate', id: 'm-root' }],
        },
        {
          uid: { type: 'Plenipo::Agent', id: 'pXz5NctsqokDuRsZLRaDTHA3xlfhlFBchmhagn_b_HQ' },
          attrs: { depth: 1, mandate: { __entity: { type: 'Plenipo::Mandate', id: 'm-leaf' } } },
          parents: [
            { type: 'Plenipo::Mandate', id: 'm-leaf' },
            { type: 'Plenipo::Person', id: principalId },
          ],
        },
        { uid: { type: 'Plenipo::Action', id: 'payments' }, attrs: {}, parents: [] },
        { uid: { type: 'Plenipo::Action', id: 'payments.sepa' }, attrs: {}, parents: [{ type: 'Plenipo::Action', id: 'payments' }] },
        { uid: { type: 'Plenipo::Action', id: 'payments.sepa.transfer' }, attrs: {}, parents: [{ type: 'Plenipo::Action', id: 'payments.sepa' }] },
        { uid: { type: 'Plenipo::Counterparty', id: 'shop.example' }, attrs: { host: 'shop.example' }, parents: [] },
        {
          uid: { type: 'Plenipo::Operation', id: operationId },
          attrs: { amount: 150_000, currency: 'EUR', counterparty: 'shop.example' },
          parents: [{ type: 'Plenipo::Counterparty', id: 'shop.example' }],
        },
      ],
    });
    // Identifiers are hashes: names never appear in them.
    expect(principalId).not.toContain('Maria');
  });

  it('refuses to export a DENY decision', async () => {
    await expect(toOpaInput({ decision: 'DENY', code: 'EXPIRED', reason: 'x', path: [] } as never)).rejects.toThrow(/ALLOW/);
  });
});
