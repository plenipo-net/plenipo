/**
 * The hosted MCP gateway, driven by two remote MCP clients over Streamable HTTP the way Claude on the
 * web drives a remote connector. Each session gets its own bridge and demo code; the dashboard feed of
 * one code shows that session and nothing of the other.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startSandbox, type Sandbox } from '../src/sandbox.js';

const TOKEN = 'test-token-0123456789abcdef';
const ADMIN = 'admin-secret';
let sb: Sandbox;

type Result = { content: Array<{ text: string }>; isError?: boolean; structuredContent?: Record<string, any> };
const text = (r: Result) => r.content.map((c) => c.text).join('\n');

async function connect(path = `/mcp/${TOKEN}`) {
  const client = new Client({ name: 'remote-claude', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${sb.urls.agent}${path}`)));
  const call = async (name: string, args: Record<string, unknown> = {}) => (await client.callTool({ name, arguments: args })) as Result;
  return { client, call, code: /Demo code of this session: ([A-Z0-9]{6})/.exec(client.getInstructions() ?? '')?.[1] };
}

async function approve(d: Record<string, any>, person: string) {
  const w = await fetch(`${sb.urls.wallet}/api/requests`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_id: d.client_id, request_uri: d.request_uri, person }),
  });
  const wr = (await w.json()) as { id: string };
  await fetch(`${sb.urls.wallet}/api/requests/${wr.id}/decision`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ decision: 'approve', person }),
  });
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
    agentGateway: { token: TOKEN, sessionsPerHour: 5, publicScenarios: true },
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

  it('gives each session its own bridge and a feed that shows only that session', async () => {
    const a = await connect();
    const b = await connect();
    expect(a.code).toMatch(/^[A-HJ-NP-Z2-9]{6}$/);
    expect(b.code).toMatch(/^[A-HJ-NP-Z2-9]{6}$/);
    expect(a.code).not.toBe(b.code);
    expect(sb.agentGateway!.sessions().size).toBe(2);

    const { tools } = await a.client.listTools();
    expect(tools.map((t) => t.name)).toContain('transfer');

    const req = await a.call('request_mandate', {
      payees: ['lumen-energia.example'],
      per_payment_eur: 100,
      total_eur: 150,
      days: 7,
      purpose: 'Pay the electricity bill, up to 100 euro',
    });
    expect(req.isError).toBeFalsy();
    expect(text(req)).toContain(`Demo code ${a.code}`);
    expect(text(req)).toContain(`/demo/${a.code}`);
    // The other session has no mandate of its own.
    expect(text(await b.call('mandate_status'))).toMatch(/No mandate yet/);

    await approve(req.structuredContent!, 'maria');
    expect(text(await a.call('mandate_status'))).toMatch(/Mandate active, granted by Maria Rossi/);
    const paid = await a.call('transfer', { payee: 'lumen-energia.example', amount_cents: 4200, reference: 'Electricity bill' });
    expect(paid.isError).toBeFalsy();
    const denied = await a.call('transfer', { payee: 'acquaviva.example', amount_cents: 1000, reference: 'Water bill' });
    expect(text(denied)).toMatch(/COUNTERPARTY_NOT_PERMITTED/);

    const fa = await until(
      () => feed(a.code!),
      (f) => f.events.some((e) => e.type === 'payment_executed') && f.events.filter((e) => e.type === 'decision').length >= 2,
    );
    const types = fa.events.map((e) => `${e.source}:${e.type}`);
    for (const t of ['agent:session_started', 'platform:mandate_requested', 'wallet:consent_approved', 'platform:mandate_approved', 'bank:decision', 'bank:payment_executed', 'agent:tool_result']) {
      expect(types).toContain(t);
    }
    const decisions = fa.events.filter((e) => e.type === 'decision').map((e) => e.decision);
    expect(decisions).toEqual(['ALLOW', 'DENY']);
    expect(fa.events.find((e) => e.type === 'tool_result' && e.decision === 'DENY')?.code).toBe('COUNTERPARTY_NOT_PERMITTED');
    // In arrival order, and nothing from session b.
    const ids = fa.events.map((e) => e.id);
    expect([...ids].sort((x, y) => x - y)).toEqual(ids);
    expect(fa.events.some((e) => e.demo_code === b.code)).toBe(false);

    const fb = await feed(b.code!);
    expect(fb.events.some((e) => e.source === 'bank' || e.source === 'platform')).toBe(false);
    expect((await feed('ZZZZZZ')).known).toBe(false);

    await a.client.close();
    await b.client.close();
  });

  it('streams a feed over SSE, also to a browser that opened it before the session', async () => {
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

    // A page watching a code nobody uses yet gets the events once a session with that code posts.
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
    const live = await watch(s.code!, 'mandate_requested');
    await s.call('request_mandate', { payees: ['telenord.example'], per_payment_eur: 50, total_eur: 50, days: 1, purpose: 'Pay the phone bill' });
    expect(await live()).toContain('mandate_requested');
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

  it('limits new sessions per address', async () => {
    // Three sessions were opened above; the limit is five per hour.
    const extra = [];
    for (let i = 0; i < 2; i++) extra.push(await connect());
    await expect(connect()).rejects.toThrow();
    for (const s of extra) await s.client.close();
  });
});
