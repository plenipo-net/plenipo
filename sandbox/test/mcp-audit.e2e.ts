/**
 * The audit log of the hosted MCP gateway: what it records for a registry check, a real session and a
 * scan of other paths; that it keeps no secret (path token, session ids, tool argument values, full
 * addresses); that its files survive a restart and expire; that only the audit token reads it.
 */
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startSandbox, type Sandbox } from '../src/sandbox.js';
import { clip, McpAudit, truncateIp } from '../src/services/mcp-audit.js';

const TOKEN = 'path-token-0123456789abcdef';
const AUDIT = 'audit-secret-0123456789';
const ADMIN = 'admin-secret';

describe('audit helpers', () => {
  it('truncates addresses and keeps strings printable', () => {
    expect(truncateIp('203.0.113.77')).toBe('203.0.113.0');
    expect(truncateIp('::ffff:198.51.100.9')).toBe('198.51.100.0');
    expect(truncateIp('2001:db8:85a3:8d3:1319:8a2e:370:7348')).toBe('2001:db8:85a3::/48');
    expect(truncateIp('2001:db8::1')).toBe('2001:db8::/48');
    expect(clip('a\u0000b\nc')).toBe('a b c');
    expect(clip('x'.repeat(300))!.length).toBe(201);
    expect(clip(42)).toBeUndefined();
  });

  it('writes a file per day, reads it back after a restart, and drops days past the retention', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'plenipo-audit-'));
    try {
      let now = Date.parse('2026-11-01T10:00:00Z');
      const a = new McpAudit({ dir, retentionDays: 3, hashKey: 'k', now: () => now });
      const caller = a.caller('203.0.113.77', 'probe/1.0');
      expect(caller).toMatchObject({ ip: '203.0.113.0', ua: 'probe/1.0' });
      expect(caller.ip_hash).toMatch(/^[0-9a-f]{12}$/);
      // Same key, same address: the same hash in another process.
      expect(new McpAudit({ hashKey: 'k' }).caller('203.0.113.77', '').ip_hash).toBe(caller.ip_hash);
      expect(new McpAudit({ hashKey: 'other' }).caller('203.0.113.77', '').ip_hash).not.toBe(caller.ip_hash);
      expect(new McpAudit({ ipMode: 'none' }).caller('203.0.113.77', '').ip).toBeUndefined();

      a.record({ ev: 'initialize', sid: 'aaaaaaaa', client: { name: 'glama', version: '1' }, ...caller });
      a.record({ ev: 'rpc', sid: 'aaaaaaaa', method: 'tools/list', ...caller });
      now = Date.parse('2026-11-04T09:00:00Z');
      a.record({ ev: 'initialize', sid: 'bbbbbbbb', client: { name: 'claude-ai', version: '0.1.0' }, ...caller });
      a.record({ ev: 'tool', sid: 'bbbbbbbb', tool: 'transfer', ok: false, decision: 'DENY', code: 'PAYEE_NOT_ALLOWED', ...caller });
      a.record({ ev: 'probe', method: 'GET', path: '/sse', ...caller });
      await a.flush();
      expect((await readdir(dir)).sort()).toEqual(['mcp-2026-11-01.jsonl', 'mcp-2026-11-04.jsonl']);

      const b = new McpAudit({ dir, retentionDays: 3, hashKey: 'k', now: () => now });
      const s = await b.summary({ from: '2026-11-01' });
      expect(s.persistent).toBe(true);
      expect(s.totals).toMatchObject({ sessions: 2, used_sessions: 1, tool_calls: 1, probes: 1, callers: 1 });
      expect(s.sessions.find((x) => x.sid === 'aaaaaaaa')?.kind).toBe('listed');
      expect(s.sessions.find((x) => x.sid === 'bbbbbbbb')?.kind).toBe('used');
      expect(s.tools.transfer).toMatchObject({ calls: 1, deny: 1 });
      expect(s.clients.map((c) => c.client).sort()).toEqual(['claude-ai 0.1.0', 'glama 1']);
      expect((await b.events({ from: '2026-11-01', ev: 'probe' })).events).toHaveLength(1);

      // A cut line (a crash mid-write) is skipped, not fatal.
      await writeFile(join(dir, 'mcp-2026-11-03.jsonl'), '{"ts":"2026-11-03T00:00:00Z","ev":"probe","path":"/x"}\n{"ts":"2026-11-0');
      expect((await b.events({ from: '2026-11-03', to: '2026-11-03' })).events).toHaveLength(1);

      expect(await b.sweep()).toBe(1);
      expect((await readdir(dir)).sort()).toEqual(['mcp-2026-11-03.jsonl', 'mcp-2026-11-04.jsonl']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('sends the line alone in the text format, and stops at the hourly limit', async () => {
    const got: Array<{ type: string; body: string }> = [];
    const srv = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        got.push({ type: String(req.headers['content-type']), body });
        res.end();
      });
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    try {
      const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/topic`;
      const a = new McpAudit({ webhookUrl: url, webhookFormat: 'text', webhooksPerHour: 2 });
      for (const name of ['one', 'two', 'three']) a.record({ ev: 'initialize', sid: name, client: { name, version: '1' } });
      const until = Date.now() + 3000;
      while (got.length < 2 && Date.now() < until) await new Promise((r) => setTimeout(r, 20));
      await new Promise((r) => setTimeout(r, 200));
      expect(got).toHaveLength(2);
      expect(got[0].type).toMatch(/^text\/plain/);
      expect(got.map((g) => g.body)).toEqual(['Plenipo MCP: new client one 1', 'Plenipo MCP: new client two 1']);
    } finally {
      await new Promise((r) => srv.close(r));
    }
  });

  it('keeps working in memory when the directory cannot be written', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'plenipo-audit-'));
    try {
      const notADir = join(dir, 'file');
      await writeFile(notADir, 'x');
      const lines: string[] = [];
      const a = new McpAudit({ dir: notADir, log: (l) => lines.push(l) });
      a.record({ ev: 'probe', method: 'GET', path: '/' });
      await a.flush();
      expect(a.persistent).toBe(false);
      expect(lines.join('\n')).toMatch(/memory only/);
      expect((await a.events()).events).toHaveLength(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('audit of the hosted MCP gateway', () => {
  let sb: Sandbox;
  let dir: string;
  let hook: Server;
  const heard: Array<{ text: string; event: Record<string, unknown> }> = [];

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'plenipo-audit-gw-'));
    hook = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        heard.push(JSON.parse(body));
        res.end('ok');
      });
    });
    await new Promise<void>((r) => hook.listen(0, '127.0.0.1', r));
    sb = await startSandbox({
      ports: { dashboard: 0, pid: 0, wallet: 0, platform: 0, bank: 0, agent: 0 },
      statusCacheSeconds: 1,
      adminToken: ADMIN,
      accountScope: 'mandate',
      agentGateway: {
        token: TOKEN,
        audit: { dir, token: AUDIT, webhookUrl: `http://127.0.0.1:${(hook.address() as AddressInfo).port}/hook` },
      },
    });
  });

  afterAll(async () => {
    await sb?.close();
    await new Promise((r) => hook?.close(r));
    await rm(dir, { recursive: true, force: true });
  });

  const api = (path: string, token = AUDIT) => fetch(`${sb.urls.agent}/admin/mcp-audit${path}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });

  async function connect(name: string) {
    const client = new Client({ name, version: '2.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(`${sb.urls.agent}/mcp/${TOKEN}`), {
      requestInit: { headers: { 'user-agent': `${name}-agent/2.1` } },
    });
    await client.connect(transport);
    return { client, transport };
  }

  it('records a registry check, a real session and a scan, and keeps no secret', async () => {
    const check = await connect('registry-check');
    const tools = await check.client.listTools();
    expect(tools.tools.map((t) => t.name)).toContain('request_mandate');
    await check.transport.terminateSession();
    await check.client.close();

    const use = await connect('claude-test');
    const purpose = 'Pay the electricity bill for flat 3B, private note';
    const r = (await use.client.callTool({
      name: 'request_mandate',
      arguments: { payees: ['lumen-energia.example'], per_payment_eur: 50, total_eur: 50, days: 1, purpose },
    })) as { isError?: boolean };
    expect(r.isError).toBeFalsy();
    // No mandate approved yet: the bridge refuses before the bank.
    await use.client.callTool({ name: 'transfer', arguments: { payee: 'lumen-energia.example', amount_cents: 100 } });

    for (const path of ['/.well-known/oauth-protected-resource', '/sse', '/mcp', '/mcp/not-the-token']) await fetch(`${sb.urls.agent}${path}`);
    const stale = await fetch(`${sb.urls.agent}/mcp/${TOKEN}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-session-id': '00000000-0000-0000-0000-000000000000' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    expect(stale.status).toBe(404);

    await sb.agentGateway!.audit.flush();
    const s = await (await api('/summary')).json();
    expect(s.persistent).toBe(true);
    const sessions = s.sessions as Array<Record<string, any>>;
    const listed = sessions.find((x) => x.client === 'registry-check 2.1.0');
    const used = sessions.find((x) => x.client === 'claude-test 2.1.0');
    expect(listed).toMatchObject({ kind: 'listed', ua: 'registry-check-agent/2.1' });
    expect(listed!.methods['tools/list']).toBe(1);
    expect(used).toMatchObject({ kind: 'used', tools: ['request_mandate', 'transfer'] });
    expect(used!.demo).toMatch(/^[A-HJ-NP-Z2-9]{6}$/);
    expect(s.tools.request_mandate.ok).toBe(1);
    expect(s.tools.transfer.error).toBe(1);
    expect(s.rejects.unknown_session).toBe(1);
    const probes = (s.probes as Array<{ path: string }>).map((p) => p.path);
    expect(probes).toEqual(expect.arrayContaining(['GET /.well-known/oauth-protected-resource', 'GET /sse', 'GET /mcp', 'GET /mcp/not-the-token']));
    expect(s.clients.map((c: { client: string }) => c.client)).toEqual(expect.arrayContaining(['registry-check 2.1.0', 'claude-test 2.1.0']));

    const files = await readdir(dir);
    expect(files).toHaveLength(1);
    const raw = await readFile(join(dir, files[0]), 'utf8');
    expect(raw).not.toContain(TOKEN);
    expect(raw).not.toContain(purpose);
    expect(raw).not.toContain(check.transport.sessionId!);
    expect(raw).toContain('"args":["payees","per_payment_eur","total_eur","days","purpose"]');
    for (const line of raw.trim().split('\n')) expect(() => JSON.parse(line)).not.toThrow();

    const day = files[0].slice(4, 14);
    const dl = await api(`/raw/${day}`);
    expect(dl.status).toBe(200);
    expect(await dl.text()).toBe(raw);
    const ev = await (await api(`/events?ev=initialize`)).json();
    expect(ev.events.every((e: { ev: string }) => e.ev === 'initialize')).toBe(true);
    await use.client.close();
  });

  it('tells the webhook about new clients and first tool calls, once each', async () => {
    const until = Date.now() + 5000;
    while (heard.length < 3 && Date.now() < until) await new Promise((r) => setTimeout(r, 50));
    const texts = heard.map((h) => h.text);
    expect(texts).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/new client registry-check 2\.1\.0 \(registry-check-agent\/2\.1\)/),
        expect.stringMatching(/new client claude-test 2\.1\.0/),
        expect.stringMatching(/claude-test 2\.1\.0 called request_mandate, demo code [A-Z2-9]{6}/),
      ]),
    );
    expect(texts.filter((t) => /called/.test(t))).toHaveLength(1);
  });

  it('serves the log only with the audit token, and the page without data', async () => {
    expect((await api('/summary', '')).status).toBe(401);
    expect((await api('/summary', ADMIN)).status).toBe(401);
    expect((await api('/events', 'wrong')).status).toBe(401);
    const page = await fetch(`${sb.urls.agent}/admin/mcp-audit`);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('Plenipo MCP audit');
    expect(html).not.toContain('registry-check');
    expect((await api('/raw/not-a-day')).status).toBe(404);
  });
});
