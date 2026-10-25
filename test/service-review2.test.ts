/**
 * Regression tests for the second security review of the service area. They started as proofs of concept
 * that passed while the bugs existed (review2/test/poc2-gateway-paths.test.ts); these assert the safe behaviour.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { generateKeyPair } from 'jose';
import {
  AuditLog,
  authorizationHeaders,
  createGateway,
  createInvocation,
  createMandate,
  expressMiddleware,
  generateAgentKey,
  hasDuplicateJsonKeys,
  InMemoryAuditStore,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  plenipoRoute,
  principalIdentity,
  PrincipalIdentityError,
  toNodeListener,
  toOpaInput,
  urlFromRawTarget,
  verifyAuditLog,
  type AgentKey,
  type Decision,
  type GatewayOptions,
  type GatewayRoute,
  type Mandate,
  type MandateChain,
} from '../src/index.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';

const API = 'https://api.bank.example';
let agent: AgentKey;
let provider: TestPidProvider;
let wallet: TestWallet;
const servers: Server[] = [];

beforeAll(async () => {
  agent = await generateAgentKey();
  provider = await createTestPidProvider('https://pid.example.it');
  wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Maria', family_name: 'Bianchi' }));
});
afterAll(async () => {
  for (const s of servers) {
    s.closeAllConnections();
    await new Promise((r) => s.close(r));
  }
});

async function listen(handler: Parameters<typeof createServer>[1]): Promise<number> {
  const s = createServer(handler);
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  servers.push(s);
  return (s.address() as AddressInfo).port;
}

/** Sends a raw HTTP/1.1 request, so the request target reaches the server byte for byte. */
function raw(port: number, method: string, target: string, headers: Record<string, string>, body = ''): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () => {
      const h = { host: 'api.bank.example', connection: 'close', 'content-length': String(Buffer.byteLength(body)), ...headers };
      s.write(Buffer.from(`${method} ${target} HTTP/1.1\r\n${Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n${body}`, 'utf8'));
    });
    let data = '';
    s.on('data', (c) => (data += c));
    s.on('end', () => {
      const [head, ...rest] = data.split('\r\n\r\n');
      resolve({ status: Number(head.split(' ')[1]), body: rest.join('\r\n\r\n') });
    });
    s.on('error', reject);
  });
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

const verify = (): GatewayOptions['verify'] => ({
  audience: API,
  nonces: new InMemoryNonceStore(),
  ledger: new InMemorySpendingLedger(),
  trustedIssuers: [provider.trusted],
});

function mandate(actions = ['payments.*']): Mandate {
  return createMandate({ agentJwk: agent.publicJwk, actions, counterparties: ['shop.example'], limits: { currency: 'EUR', per_operation: 50_000, total: 100_000 } });
}

async function signedPayment(m: Mandate, chain: MandateChain, path: string, body: Record<string, unknown>) {
  return createInvocation(agent.privateKey, {
    chain,
    mandateId: m.id,
    action: 'payments.transfer',
    counterparty: 'shop.example',
    amount: { value: body.amount as number, currency: 'EUR' },
    aud: API,
    args: { method: 'POST', path, query: {}, media_type: 'application/json', body },
  });
}

const AMBIGUOUS_TARGETS = [
  '/accounts/123\\../payments',
  '/accounts/123\\..\\456/payments',
  '/accounts/123/../456/payments',
  '/accounts/123/%2e%2e/456/payments',
  '/accounts/123/.%2E/456/payments',
  '/accounts/123/%2E/payments',
  '/accounts/123%2f456/payments',
  '/accounts/123%5C456/payments',
  '/accounts/123%00/payments',
  '//accounts/123/payments',
  '/accounts/1{2}3/payments',
];

describe('P2-1: the checked path is the routed path, byte for byte', () => {
  it("unmatched 'pass' never runs a protected handler through backslashes, dot segments or encoded slashes", async () => {
    const gw = createGateway({ routes: [paymentRoute], unmatched: 'pass', verify: verify() });
    const executed: string[] = [];
    const app = express();
    app.use(express.json());
    app.use(expressMiddleware(gw, { origin: API }));
    app.post('/accounts/:account/payments', (req, res) => {
      executed.push(req.params.account);
      res.status(201).json({ ok: true });
    });
    const port = await listen(app);
    const body = JSON.stringify({ creditor: 'evil.example', amount: 9_000_000, currency: 'EUR' });
    expect((await raw(port, 'POST', '/accounts/123/payments', { 'content-type': 'application/json' }, body)).status).toBe(401);
    for (const t of AMBIGUOUS_TARGETS) {
      const r = await raw(port, 'POST', t, { 'content-type': 'application/json' }, body);
      expect(r.status, t).toBe(400);
    }
    // Raw non-ASCII: refused, by Node's parser or by the adapter.
    expect((await raw(port, 'POST', '/accounts/12é/payments', { 'content-type': 'application/json' }, body)).status).toBe(400);
    expect(executed).toEqual([]);
  });

  it('plenipoRoute refuses a target that would verify one account and execute another; handlers get verified params', async () => {
    const m = mandate();
    const chain: MandateChain = { root: await wallet.approveMandate(m), delegations: [] };
    const seen: Array<{ verified: Record<string, string>; express: string }> = [];
    const app = express();
    app.use(express.json());
    app.post('/accounts/:account/payments', plenipoRoute(paymentRoute, { verify: verify() }, { origin: API }), (req, res) => {
      seen.push({ verified: (req as unknown as { plenipo: { params: Record<string, string> } }).plenipo.params, express: req.params.account });
      res.status(201).json({ ok: true });
    });
    const port = await listen(app);
    const body = { creditor: 'shop.example', amount: 10_000, currency: 'EUR' };
    const inv = await signedPayment(m, chain, '/accounts/456/payments', body);
    const r = await raw(port, 'POST', '/accounts/123\\..\\456/payments', { ...authorizationHeaders(chain, inv), 'content-type': 'application/json' }, JSON.stringify(body));
    expect(r.status).toBe(400);
    expect(r.body).toContain('"code":"malformed_target"');
    expect(seen).toEqual([]);
    // The clean target works, and the verified params equal Express's.
    const ok = await raw(port, 'POST', '/accounts/456/payments', { ...authorizationHeaders(chain, inv), 'content-type': 'application/json' }, JSON.stringify(body));
    expect(ok.status).toBe(201);
    expect(seen).toEqual([{ verified: { account: '456' }, express: '456' }]);
  });

  it('the Node listener refuses the same targets before the gateway sees them', async () => {
    const executed: string[] = [];
    const gw = createGateway({ routes: [paymentRoute], unmatched: 'pass', verify: verify(), downstream: (req) => (executed.push(req.url), new Response(null, { status: 204 })) });
    const port = await listen(toNodeListener(gw.handle, { origin: API }));
    for (const t of AMBIGUOUS_TARGETS) expect((await raw(port, 'POST', t, { 'content-type': 'application/json' }, '{}')).status, t).toBe(400);
    expect((await raw(port, 'GET', '/health', {})).status).toBe(204);
    expect(executed).toEqual([`${API}/health`]);
  });

  it('the gateway itself refuses encoded slashes and controls that survive URL parsing', async () => {
    const gw = createGateway({ routes: [paymentRoute], unmatched: 'pass', verify: verify(), downstream: () => new Response(null, { status: 204 }) });
    const res = await gw.handle(new Request(`${API}/accounts/1%2F2/payments`, { method: 'POST', body: '{}' }));
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('malformed_target');
  });

  it('urlFromRawTarget accepts only targets that URL parsing leaves unchanged', () => {
    expect(urlFromRawTarget('/accounts/a-1/payments?x=1&y=2', API).href).toBe(`${API}/accounts/a-1/payments?x=1&y=2`);
    expect(urlFromRawTarget('/a/%41b', API).pathname).toBe('/a/%41b');
    for (const t of [...AMBIGUOUS_TARGETS, 'http://evil.example/x', '/a?b c', '/a#f']) expect(() => urlFromRawTarget(t, API), t).toThrow();
  });
});

describe('P2-6: no body on GET or HEAD', () => {
  it('refuses a GET body instead of handing an unbound body to the handler', async () => {
    const m = mandate(['accounts.read']);
    const chain: MandateChain = { root: await wallet.approveMandate(m), delegations: [] };
    const route: GatewayRoute = { method: 'GET', path: '/accounts/:account/statements', action: 'accounts.read', counterparty: null, amount: null };
    const seen: unknown[] = [];
    const app = express();
    app.use(express.json());
    app.get('/accounts/:account/statements', plenipoRoute(route, { verify: verify() }, { origin: API }), (req, res) => {
      seen.push(req.body);
      res.json({ ok: true });
    });
    const port = await listen(app);
    const inv = await createInvocation(agent.privateKey, {
      chain,
      mandateId: m.id,
      action: 'accounts.read',
      aud: API,
      args: { method: 'GET', path: '/accounts/456/statements', query: {}, media_type: null, body: null },
    });
    const headers = { ...authorizationHeaders(chain, inv), 'content-type': 'application/json' };
    const r = await raw(port, 'GET', '/accounts/456/statements', headers, JSON.stringify({ deliver_to: 'exfil@evil.example' }));
    expect(r.status).toBe(400);
    expect(r.body).toContain('"code":"body_not_allowed"');
    expect(seen).toEqual([]);
    const ok = await raw(port, 'GET', '/accounts/456/statements', authorizationHeaders(chain, inv));
    expect(ok.status).toBe(200);
  });
});

describe('Hardening: client-supplied Plenipo-Outcome', () => {
  it('is removed before the API sees the request, in both adapters', async () => {
    const m = mandate();
    const chain: MandateChain = { root: await wallet.approveMandate(m), delegations: [] };
    const body = { creditor: 'shop.example', amount: 100, currency: 'EUR' };
    let fetchSeen: string | null = 'unset';
    const gw = createGateway({ routes: [paymentRoute], verify: verify(), downstream: (req) => ((fetchSeen = req.headers.get('plenipo-outcome')), new Response(null, { status: 201 })) });
    const res = await gw.handle(
      new Request(API + '/accounts/1/payments', {
        method: 'POST',
        headers: { ...authorizationHeaders(chain, await signedPayment(m, chain, '/accounts/1/payments', body)), 'content-type': 'application/json', 'plenipo-outcome': 'not-executed' },
        body: JSON.stringify(body),
      }),
    );
    expect(res.status).toBe(201);
    expect(fetchSeen).toBeNull();

    let expressSeen: unknown = 'unset';
    const app = express();
    app.use(expressMiddleware(createGateway({ routes: [paymentRoute], verify: verify() }), { origin: API }));
    app.post('/accounts/:account/payments', (req, res) => {
      expressSeen = req.headers['plenipo-outcome'];
      res.status(201).end();
    });
    const port = await listen(app);
    const r = await raw(
      port,
      'POST',
      '/accounts/2/payments',
      { ...authorizationHeaders(chain, await signedPayment(m, chain, '/accounts/2/payments', body)), 'content-type': 'application/json', 'plenipo-outcome': 'not-executed' },
      JSON.stringify(body),
    );
    expect(r.status).toBe(201);
    expect(expressSeen).toBeUndefined();
  });
});

describe('Hardening: JSON bodies with duplicate member names', () => {
  it('detects duplicates at any depth, after unescaping, without false positives', () => {
    expect(hasDuplicateJsonKeys('{"a":1,"a":2}')).toBe(true);
    expect(hasDuplicateJsonKeys('{"x":{"a":1,"b":{"c":[{"a":1,"a":2}]}}}')).toBe(true);
    expect(hasDuplicateJsonKeys('{"a":1,"\\u0061":2}')).toBe(true);
    expect(hasDuplicateJsonKeys('{"a":{"a":1},"b":{"a":2},"c":["a","a"],"d":"a"}')).toBe(false);
    expect(hasDuplicateJsonKeys('{"k\\"":1,"k":2}')).toBe(false);
    expect(hasDuplicateJsonKeys('[{"a":1},{"a":1}]')).toBe(false);
  });

  it('refuses such a body with 400 before verification', async () => {
    const m = mandate();
    const chain: MandateChain = { root: await wallet.approveMandate(m), delegations: [] };
    const ledger = new InMemorySpendingLedger();
    const gw = createGateway({ routes: [paymentRoute], verify: { ...verify(), ledger }, downstream: () => new Response(null, { status: 201 }) });
    const body = { creditor: 'shop.example', amount: 100, currency: 'EUR' };
    const text = '{"creditor":"shop.example","amount":100,"currency":"EUR","amount":900000}';
    const res = await gw.handle(
      new Request(API + '/accounts/1/payments', {
        method: 'POST',
        headers: { ...authorizationHeaders(chain, await signedPayment(m, chain, '/accounts/1/payments', body)), 'content-type': 'application/json' },
        body: text,
      }),
    );
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('malformed_body');
  });
});

describe('Hardening: principal identity', () => {
  const base = (principal: Record<string, unknown>, extra: Partial<Extract<Decision, { decision: 'ALLOW' }>> = {}) =>
    ({
      decision: 'ALLOW',
      principal,
      pid_issuer: 'https://pid.example.it',
      pid_trusted_via: 'issuer',
      path: [],
      mandates: [mandate()],
      invocation: { mandate: 'm', action: 'payments.transfer', aud: API, nonce: 'n', iat: 1 },
      ...extra,
    }) as Extract<Decision, { decision: 'ALLOW' }>;

  it('a natural person whose PID discloses type/euid claims is not a legal person', () => {
    const id = principalIdentity(base({ type: 'legal_person', euid: 'ITRM.RM1234567', given_name: 'Eve' }, { pid_holder_jkt: 'jkt' }));
    expect(id.type).toBe('natural_person');
    expect(id.id_basis).toBe('holder_key');
  });

  it('a legal-person decision needs a legal-person principal', () => {
    const representation = { register: 'https://register.test', trusted_via: 'issuer' as const, holder_binding: 'cnf' as const };
    expect(() => principalIdentity(base({ given_name: 'Eve' }, { representation }))).toThrow(PrincipalIdentityError);
  });

  it('requireIdClaim refuses instead of falling back', async () => {
    const d = base({ given_name: 'Mario', family_name: 'Rossi' }, { pid_holder_jkt: 'jkt' });
    expect(() => principalIdentity(d, { requireIdClaim: true })).toThrow(PrincipalIdentityError);
    await expect(toOpaInput(d, { requireIdClaim: true })).rejects.toThrow(PrincipalIdentityError);
    const withClaim = base({ given_name: 'Mario', personal_administrative_number: 'IT-1' });
    expect(principalIdentity(withClaim, { requireIdClaim: true }).id_basis).toBe('claim:personal_administrative_number');
  });
});

describe('Hardening: audit tail truncation', () => {
  it('a log cut back to an earlier signed record verifies with its key; only expectedHead detects it', async () => {
    const pair = await generateKeyPair('ES256', { extractable: true });
    const store = new InMemoryAuditStore();
    const log = new AuditLog({ store, signer: { key: pair.privateKey } });
    for (let i = 0; i < 4; i++) await log.append({ event: 'decision', decision: 'ALLOW', mandate_ids: [`m${i}`] });
    const records = await store.readAll();
    const head = { seq: 3, hash: records[3].hash };
    const truncated = records.slice(0, 2);
    expect(await verifyAuditLog(truncated, { key: pair.publicKey, requireSignatures: 'head' })).toMatchObject({ valid: true });
    expect(await verifyAuditLog(truncated, { key: pair.publicKey, expectedHead: head })).toMatchObject({ valid: false });
  });
});
