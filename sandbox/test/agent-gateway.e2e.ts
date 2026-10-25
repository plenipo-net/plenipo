/**
 * The hosted MCP gateway, driven by remote MCP clients over Streamable HTTP the way Claude on the web
 * drives a remote connector. A mandate journey gets its demo code at request_mandate; its feed shows that
 * journey and nothing else; every root mandate has its own copy of the account; a later connection can
 * take a journey over with its code.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startSandbox, type Sandbox } from '../src/sandbox.js';

const TOKEN = 'test-token-0123456789abcdef';
const ADMIN = 'admin-secret';
const SESSIONS_PER_HOUR = 20;
let sb: Sandbox;
let opened = 0;

type Result = { content: Array<{ text: string }>; isError?: boolean; structuredContent?: Record<string, any> };
const text = (r: Result) => r.content.map((c) => c.text).join('\n');
const codeIn = (t: string) => /Demo code ([A-HJ-NP-Z2-9]{6})/.exec(t)?.[1];

async function connect(path = `/mcp/${TOKEN}`) {
  const client = new Client({ name: 'remote-claude', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${sb.urls.agent}${path}`)));
  opened++;
  const call = async (name: string, args: Record<string, unknown> = {}) => (await client.callTool({ name, arguments: args })) as Result;
  return { client, call };
}

const MANDATE = { payees: ['lumen-energia.example'], per_payment_eur: 100, total_eur: 150, days: 7, purpose: 'Pay the electricity bill, up to 100 euro' };

async function approve(d: Record<string, any>, person: string) {
  const w = await fetch(`${sb.urls.wallet}/api/requests`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_id: d.client_id, request_uri: d.request_uri, person }),
  });
  const wr = (await w.json()) as { id: string };
  const res = await fetch(`${sb.urls.wallet}/api/requests/${wr.id}/decision`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ decision: 'approve', person }),
  });
  return (await res.json()) as { state: string; outcome: string };
}

/** A connection that requested a mandate and had Maria approve it: returns its demo code. */
async function journey(s: Awaited<ReturnType<typeof connect>>, mandate = MANDATE) {
  const req = await s.call('request_mandate', mandate);
  expect(req.isError).toBeFalsy();
  await approve(req.structuredContent!, 'maria');
  expect(text(await s.call('mandate_status'))).toMatch(/Mandate active, granted by Maria Rossi/);
  return codeIn(text(req))!;
}

async function feed(code: string) {
  const res = await fetch(`${sb.urls.dashboard}/api/demo/${code}`);
  expect(res.headers.get('access-control-allow-origin')).toBe('*');
  return (await res.json()) as { known: boolean; events: Array<Record<string, any>> };
}

async function until<T>(f: () => Promise<T>, ok: (v: T) => boolean, ms = 5000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (ok(v) || Date.now() > end) return v;
    await new Promise((r) => setTimeout(r, 100));
  }
}

beforeAll(async () => {
  sb = await startSandbox({
    ports: { dashboard: 0, pid: 0, wallet: 0, platform: 0, bank: 0, agent: 0 },
    statusCacheSeconds: 1,
    adminToken: ADMIN,
    accountScope: 'mandate',
    agentGateway: { token: TOKEN, sessionsPerHour: SESSIONS_PER_HOUR, publicScenarios: true },
  });
});

afterAll(async () => {
  await sb?.close();
});

describe('hosted MCP gateway', () => {
  it('serves the endpoint only under its token', async () => {
    const health = await fetch(`${sb.urls.agent}/health`);
    expect(health.status).toBe(200);
    for (const path of ['/mcp', '/mcp/wrong-token-0123456789abc']) {
      const r = await fetch(`${sb.urls.agent}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: '{}' });
      expect(r.status).toBe(404);
    }
    const noSession = await fetch(`${sb.urls.agent}/mcp/${TOKEN}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    expect(noSession.status).toBe(400);
  });

  it('refuses dashboard events without the admin token', async () => {
    const r = await fetch(`${sb.urls.dashboard}/api/agent-events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'note', demo_code: 'ABCDEF' }) });
    expect(r.status).toBe(401);
  });

  it('gives a demo code with the first mandate request, and a feed that shows only that journey', async () => {
    const a = await connect();
    const b = await connect();
    // No code before a journey starts: a connection the client opens and never uses has none.
    expect(a.client.getInstructions()).not.toMatch(/Demo code/);
    expect([...sb.agentGateway!.sessions().values()]).toEqual(['', '']);

    const { tools } = await a.client.listTools();
    expect(tools.map((t) => t.name)).toContain('transfer');

    const req = await a.call('request_mandate', MANDATE);
    expect(req.isError).toBeFalsy();
    const code = codeIn(text(req))!;
    expect(code).toBeTruthy();
    expect(text(req)).toContain(`/demo/${code}`);
    expect(text(req)).toMatch(/approving gives you permission and pays nothing/);
    expect(text(await a.call('mandate_status'))).toMatch(/Nothing has been paid/);
    // The other connection has no mandate of its own.
    expect(text(await b.call('mandate_status'))).toMatch(/No mandate yet/);

    const approved = await approve(req.structuredContent!, 'maria');
    expect(approved.outcome).toMatch(/Nothing has been paid yet/);
    const status = await a.call('mandate_status');
    expect(text(status)).toMatch(/Mandate active, granted by Maria Rossi/);
    expect(status.structuredContent!.demo_code).toBe(code);

    // The bills are said in words, open or not.
    const before = await a.call('list_payees', { category: 'utilities' });
    expect(text(before)).toMatch(/^Open bills for Maria Rossi: 2, total € 125\.50\./);
    expect(text(before)).toMatch(/lumen-energia\.example \(.*\): open bills € 84\.30 for 2026-09/);
    const paid = await a.call('transfer', { payee: 'lumen-energia.example', amount_cents: 8430, reference: 'Electricity bill' });
    expect(paid.isError).toBeFalsy();
    const after = await a.call('list_payees', { category: 'utilities' });
    expect(text(after)).toMatch(/lumen-energia\.example \(.*\): no open bill/);
    const denied = await a.call('transfer', { payee: 'acquaviva.example', amount_cents: 1000, reference: 'Water bill' });
    expect(text(denied)).toMatch(/COUNTERPARTY_NOT_PERMITTED/);

    const fa = await until(
      () => feed(code),
      (f) => f.events.some((e) => e.type === 'payment_executed') && f.events.filter((e) => e.type === 'decision').length >= 4,
    );
    const types = fa.events.map((e) => `${e.source}:${e.type}`);
    for (const t of ['agent:session_started', 'platform:mandate_requested', 'wallet:consent_approved', 'platform:mandate_approved', 'bank:decision', 'bank:payment_executed', 'agent:tool_result']) {
      expect(types).toContain(t);
    }
    const decisions = fa.events.filter((e) => e.type === 'decision').map((e) => e.decision);
    expect(decisions).toEqual(['ALLOW', 'ALLOW', 'ALLOW', 'DENY']);
    expect(fa.events.find((e) => e.type === 'tool_result' && e.decision === 'DENY')?.code).toBe('COUNTERPARTY_NOT_PERMITTED');
    // In the order things happened.
    const ts = fa.events.map((e) => e.ts as string);
    expect([...ts].sort()).toEqual(ts);
    expect((await feed('ZZZZZZ')).known).toBe(false);

    const revoked = await a.call('revoke_mandate');
    expect(text(revoked)).toMatch(/within 1 second on this bank/);

    await a.client.close();
    await b.client.close();
  });

  it('opens a fresh account for every root mandate, whatever others paid before', async () => {
    // A visitor's scenario pays all of Maria's bills first.
    const run = await fetch(`${sb.urls.agent}/scenarios/total-limit/run`, { method: 'POST' });
    const { code } = (await run.json()) as { code: string };
    await until(
      () => feed(code),
      (x) => x.events.some((e) => e.type === 'scenario_result'),
      15000,
    );
    // Two Claude conversations at the same time: each finds the bill open and pays it.
    const c = await connect();
    const d = await connect();
    await Promise.all([journey(c), journey(d)]);
    for (const s of [c, d]) {
      expect(text(await s.call('get_balance'))).toMatch(/€ 2,450\.00/);
      expect(text(await s.call('list_payees', { category: 'utilities' }))).toMatch(/open bills € 84\.30/);
    }
    const [pc, pd] = await Promise.all([c, d].map((s) => s.call('transfer', { payee: 'lumen-energia.example', amount_cents: 8430, reference: 'Lumen 2026-09' })));
    expect(pc.isError).toBeFalsy();
    expect(pd.isError).toBeFalsy();
    expect(text(await c.call('get_balance'))).toMatch(/€ 2,365\.70/);
    await c.client.close();
    await d.client.close();
  });

  it('lets a later connection take a journey over with its demo code', async () => {
    const first = await connect();
    const code = await journey(first);
    await first.client.close();

    const later = await connect();
    expect((await later.call('mandate_status', { demo_code: 'ZZZZZZ' })).isError).toBe(true);
    const status = await later.call('mandate_status', { demo_code: code.toLowerCase() });
    expect(text(status)).toMatch(/Mandate active, granted by Maria Rossi/);
    const paid = await later.call('transfer', { payee: 'lumen-energia.example', amount_cents: 8430, reference: 'Lumen 2026-09' });
    expect(paid.isError).toBeFalsy();
    // Once it follows a journey, it cannot switch to another.
    expect((await later.call('mandate_status', { demo_code: 'ABCDEF' })).isError).toBe(true);
    const f = await until(
      () => feed(code),
      (x) => x.events.some((e) => e.type === 'payment_executed'),
    );
    expect(f.events.some((e) => e.type === 'note' && /took over/.test(e.text))).toBe(true);
    await later.client.close();
  });

  it('leaves no trace for connections that never act', async () => {
    const started = () => sb.dashboard.merged().filter((e) => e.type === 'session_started').length;
    const n = started();
    const idle = await connect();
    await idle.client.listTools();
    await new Promise((r) => setTimeout(r, 200));
    expect(started()).toBe(n);
    await idle.client.close();
  });

  it('streams a feed over SSE, also to a browser that opened it before the journey', async () => {
    const ctrl = new AbortController();
    const watch = async (code: string, until: string) => {
      const res = await fetch(`${sb.urls.dashboard}/api/demo/${code}/stream`, { signal: ctrl.signal });
      expect(res.headers.get('content-type')).toMatch(/event-stream/);
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
      const reader = res.body!.getReader();
      let got = '';
      const done = (async () => {
        while (!got.includes(until)) {
          const { value, done } = await reader.read();
          if (done) break;
          got += new TextDecoder().decode(value);
        }
        return got;
      })();
      return () => Promise.race([done, new Promise<string>((r) => setTimeout(() => r(got), 5000))]);
    };

    const early = await watch('QWERTY', 'early bird');
    await fetch(`${sb.urls.dashboard}/api/agent-events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${ADMIN}` },
      body: JSON.stringify({ type: 'note', text: 'early bird', demo_code: 'QWERTY' }),
    });
    const e = await early();
    expect(e).toContain('event: hello');
    expect(e).toContain('early bird');

    const s = await connect();
    const req = await s.call('request_mandate', { payees: ['telenord.example'], per_payment_eur: 50, total_eur: 50, days: 1, purpose: 'Pay the phone bill' });
    const live = await watch(codeIn(text(req))!, 'mandate_approved');
    await approve(req.structuredContent!, 'maria');
    expect(await live()).toContain('mandate_approved');
    ctrl.abort();
    await s.client.close();
  });

  it('runs a scripted scenario on request, under its own demo code', async () => {
    const list = await fetch(`${sb.urls.agent}/scenarios`);
    expect(list.headers.get('access-control-allow-origin')).toBe('*');
    const ids = ((await list.json()) as { scenarios: Array<{ id: string }> }).scenarios.map((s) => s.id);
    expect(ids).toContain('prompt-injection');
    expect(ids).not.toContain('expired');
    expect(ids).not.toContain('pid-revoked');
    expect((await fetch(`${sb.urls.agent}/scenarios/expired/run`, { method: 'POST' })).status).toBe(404);

    const r = await fetch(`${sb.urls.agent}/scenarios/prompt-injection/run`, { method: 'POST' });
    expect(r.status).toBe(202);
    const { code, watch_url } = (await r.json()) as { code: string; watch_url: string };
    expect(code).toMatch(/^[A-HJ-NP-Z2-9]{6}$/);
    expect(watch_url).toContain(`/demo/${code}`);
    const f = await until(
      () => feed(code),
      (x) => x.events.some((e) => e.type === 'scenario_result') && x.events.some((e) => e.type === 'decision' && e.decision === 'ALLOW'),
      15000,
    );
    expect(f.events.find((e) => e.type === 'scenario_result')?.pass).toBe(true);
    const decisions = f.events.filter((e) => e.type === 'decision').map((e) => e.code ?? e.decision);
    expect(decisions).toContain('COUNTERPARTY_NOT_PERMITTED');
    expect(f.events.some((e) => e.source === 'wallet' && e.type === 'consent_approved')).toBe(true);
  });

  it('limits new sessions for all clients together, not per address', async () => {
    // Everything above came from one address and was accepted; the global hourly cap still holds.
    const extra = [];
    while (opened < SESSIONS_PER_HOUR) extra.push(await connect());
    await expect(connect()).rejects.toThrow(/503|too many new connections/i);
    for (const s of extra) await s.client.close();
  });
});
