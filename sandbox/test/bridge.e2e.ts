/**
 * The built stdio bridge (dist/bridge.js), driven by an MCP client the way Claude Desktop drives it:
 * request a mandate, approve it through the wallet's HTTP API, pay within the limits, exceed them,
 * revoke, and be refused.
 */
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startSandbox, type Sandbox } from '../src/sandbox.js';

let sb: Sandbox;
let client: Client;
let stderr = '';
const statePath = join(mkdtempSync(join(tmpdir(), 'plenipo-bridge-')), 'state.json');

type Result = { content: Array<{ text: string }>; isError?: boolean; structuredContent?: Record<string, any> };
const call = async (name: string, args: Record<string, unknown> = {}) => (await client.callTool({ name, arguments: args })) as Result;
const text = (r: Result) => r.content.map((c) => c.text).join('\n');

beforeAll(async () => {
  sb = await startSandbox({ ports: { dashboard: 0, pid: 0, wallet: 0, platform: 0, bank: 0 }, statusCacheSeconds: 1 });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(import.meta.dirname, '..', 'dist', 'bridge.js')],
    env: {
      PATH: process.env.PATH ?? '',
      PLENIPO_PLATFORM_URL: sb.urls.platform,
      PLENIPO_BANK_URL: sb.urls.bank,
      PLENIPO_DASHBOARD_URL: sb.urls.dashboard,
      PLENIPO_BRIDGE_STATE: statePath,
    },
    stderr: 'pipe',
  });
  transport.stderr?.on('data', (d) => (stderr += String(d)));
  client = new Client({ name: 'test-claude', version: '1.0.0' });
  await client.connect(transport);
});

afterAll(async () => {
  await client?.close();
  await sb?.close();
});

describe('MCP bridge over stdio', () => {
  it('lists its own tools and mirrors the bank tools', async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(
      ['block_card', 'explain_last_decision', 'get_balance', 'list_payees', 'mandate_status', 'request_mandate', 'revoke_mandate', 'transfer'].sort(),
    );
    const transfer = tools.find((t) => t.name === 'transfer')!;
    expect(Object.keys(transfer.inputSchema.properties ?? {}).sort()).toEqual(['amount_cents', 'payee', 'reference']);
  });

  it('refuses bank calls before a mandate', async () => {
    const r = await call('get_balance');
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/request_mandate/);
  });

  it('requests a mandate with its own key, the person approves, and the bridge acts within it', async () => {
    const req = await call('request_mandate', {
      payees: ['lumen-energia.example', 'acquaviva.example'],
      per_payment_eur: 100,
      total_eur: 150,
      days: 7,
      purpose: 'Pay the electricity and water bills, up to 100 euro each and 150 in total',
    });
    expect(req.isError).toBeFalsy();
    const d = req.structuredContent!;
    expect(text(req)).toContain(d.wallet_url);
    expect(text(await call('mandate_status'))).toMatch(/Still waiting/);

    // The person opens the link and approves in the wallet (its HTTP API stands in for the tap).
    const w = await fetch(`${sb.urls.wallet}/api/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_id: d.client_id, request_uri: d.request_uri, person: 'maria' }),
    });
    const wr = (await w.json()) as { id: string };
    await fetch(`${sb.urls.wallet}/api/requests/${wr.id}/decision`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ decision: 'approve', person: 'maria' }),
    });
    const status = await call('mandate_status');
    expect(status.isError).toBeFalsy();
    expect(text(status)).toMatch(/Mandate active, granted by Maria Rossi/);

    // The key never left the bridge: the platform cannot sign for this agent, and the state file is private.
    const sign = await fetch(`${sb.urls.platform}/api/mandates/${d.mandate_id}/invocations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'payments.transfer', aud: 'x' }),
    });
    expect(sign.status).toBe(409);
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    expect(state.agent.privateJwk.d).toBeTypeOf('string');
    expect(statSync(statePath).mode & 0o077).toBe(0);

    expect(text(await call('get_balance'))).toMatch(/Balance of IT/);
    const ok = await call('transfer', { payee: 'lumen-energia.example', amount_cents: 8430, reference: 'Lumen 2026-09' });
    expect(ok.isError).toBeFalsy();
    expect(text(ok)).toMatch(/Paid € 84.30 to lumen-energia.example/);

    const tooMuch = await call('transfer', { payee: 'acquaviva.example', amount_cents: 12000, reference: 'AcquaViva' });
    expect(text(tooMuch)).toMatch(/^plenipo: DENY LIMIT_PER_OPERATION/);
    expect(text(await call('explain_last_decision'))).toMatch(/per-payment limit/);

    const total = await call('transfer', { payee: 'acquaviva.example', amount_cents: 7000, reference: 'AcquaViva' });
    expect(text(total)).toMatch(/^plenipo: DENY LIMIT_TOTAL/);

    const outside = await call('transfer', { payee: 'telenord.example', amount_cents: 2990, reference: 'TeleNord' });
    expect(text(outside)).toMatch(/^plenipo: DENY COUNTERPARTY_NOT_PERMITTED/);
  });

  it('revokes the mandate, after which the bank refuses', async () => {
    expect(text(await call('revoke_mandate'))).toMatch(/revoked/);
    await new Promise((r) => setTimeout(r, 2200)); // the bank's status cache in this test: 1 s
    const after = await call('transfer', { payee: 'acquaviva.example', amount_cents: 4120, reference: 'AcquaViva' });
    expect(text(after)).toMatch(/^plenipo: DENY REVOKED/);
    const explained = text(await call('explain_last_decision'));
    expect(explained).toMatch(/DENY REVOKED/);
    expect(explained).toMatch(/chain hash/);
  });

  it('keeps the mandate when the person opens the link twice and approves again', async () => {
    const req = await call('request_mandate', {
      payees: ['lumen-energia.example', 'acquaviva.example', 'telenord.example'],
      per_payment_eur: 100,
      total_eur: 200,
      days: 7,
      purpose: "Pay this month's electricity, water and phone bills",
    });
    const d = req.structuredContent!;
    const open = async () =>
      (await (
        await fetch(`${sb.urls.wallet}/api/requests`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ client_id: d.client_id, request_uri: d.request_uri, person: 'maria' }),
        })
      ).json()) as { id: string; state: string };
    const approve = (id: string) =>
      fetch(`${sb.urls.wallet}/api/requests/${id}/decision`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ decision: 'approve', person: 'maria' }),
      });
    const first = await open();
    expect((await approve(first.id)).status).toBe(200);
    const second = await open();
    expect(second).toMatchObject({ id: first.id, state: 'approved' });
    expect((await approve(second.id)).status).toBe(409);

    const status = await call('mandate_status');
    expect(status.isError).toBeFalsy();
    expect(text(status)).toMatch(/Mandate active, granted by Maria Rossi/);
    const ok = await call('transfer', { payee: 'telenord.example', amount_cents: 2990, reference: 'TeleNord 2026-10' });
    expect(text(ok)).toMatch(/Paid € 29.90 to telenord.example/);
  });

  it('logs to stderr only', () => {
    expect(stderr).toMatch(/\[plenipo-bridge\] ready/);
  });
});

describe('MCP bridge started before the bank', () => {
  it('announces the bank tools once the bank answers', async () => {
    const { createServer } = await import('node:net');
    const port = await new Promise<number>((resolve) => {
      const s = createServer().listen(0, '127.0.0.1', () => {
        const p = (s.address() as { port: number }).port;
        s.close(() => resolve(p));
      });
    });
    const { ToolListChangedNotificationSchema } = await import('@modelcontextprotocol/sdk/types.js');
    const late = new Client({ name: 'late-claude', version: '1.0.0' });
    let changed!: () => void;
    const announced = new Promise<void>((r) => (changed = r));
    late.setNotificationHandler(ToolListChangedNotificationSchema, async () => changed());
    await late.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [join(import.meta.dirname, '..', 'dist', 'bridge.js')],
        env: { PATH: process.env.PATH ?? '', PLENIPO_BANK_URL: `http://127.0.0.1:${port}`, PLENIPO_DASHBOARD_URL: '', PLENIPO_BRIDGE_STATE: `${statePath}.late` },
        stderr: 'pipe',
      }),
    );
    expect((await late.listTools()).tools.map((t) => t.name)).not.toContain('transfer');
    const lateSandbox = await startSandbox({ ports: { dashboard: 0, pid: 0, wallet: 0, platform: 0, bank: port } });
    try {
      await announced;
      expect((await late.listTools()).tools.map((t) => t.name)).toContain('transfer');
    } finally {
      await late.close();
      await lateSandbox.close();
    }
  }, 30_000);
});

describe('MCP bridge restarted after a payment with an unknown outcome', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'plenipo-bridge-restart-')), 'state.json');
  const start = async () => {
    const c = new Client({ name: 'restart-claude', version: '1.0.0' });
    await c.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [join(import.meta.dirname, '..', 'dist', 'bridge.js')],
        env: { PATH: process.env.PATH ?? '', PLENIPO_PLATFORM_URL: sb.urls.platform, PLENIPO_BANK_URL: sb.urls.bank, PLENIPO_DASHBOARD_URL: '', PLENIPO_BRIDGE_STATE: path },
        stderr: 'pipe',
      }),
    );
    return c;
  };
  const run = async (c: Client, name: string, args: Record<string, unknown> = {}) => (await c.callTool({ name, arguments: args })) as Result;

  it('reuses the idempotency key after the restart, so the bank never pays twice', async () => {
    let c = await start();
    const req = await run(c, 'request_mandate', { payees: ['lumen-energia.example'], per_payment_eur: 100, total_eur: 300, days: 7, purpose: 'Pay the electricity bill' });
    const d = req.structuredContent!;
    const w = await fetch(`${sb.urls.wallet}/api/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_id: d.client_id, request_uri: d.request_uri, person: 'luca' }),
    });
    const wr = (await w.json()) as { id: string };
    await fetch(`${sb.urls.wallet}/api/requests/${wr.id}/decision`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ decision: 'approve', person: 'luca' }) });
    expect(text(await run(c, 'mandate_status'))).toMatch(/Mandate active/);
    const before = Number((await run(c, 'get_balance')).structuredContent!.balance_cents);

    await fetch(`${sb.urls.bank}/admin/fail-next-transfer`, { method: 'POST' });
    const pay = { payee: 'lumen-energia.example', amount_cents: 6230, reference: 'Lumen 2026-09' };
    const crashed = await run(c, 'transfer', pay);
    expect(crashed.isError).toBe(true);
    const openKeys = () => Object.values(JSON.parse(readFileSync(path, 'utf8')).open ?? {}).map((v) => (v as { idem: string }).idem);
    expect(openKeys()).toHaveLength(1);
    const key = openKeys()[0];

    // The host restarts: a new bridge process on the same state file.
    await c.close();
    c = await start();
    const retry = await run(c, 'transfer', pay);
    expect(text(retry)).toMatch(/^plenipo: DENY IDEMPOTENCY_UNRESOLVED/);
    expect(openKeys()).toEqual([key]);
    expect(text(await run(c, 'explain_last_decision'))).toMatch(/does not know yet/);

    // The bank reconciles: the debit is in its books.
    const open = (await (await fetch(`${sb.urls.bank}/api/idempotency`)).json()) as { unresolved: Array<{ key: string; attempt: string }> };
    for (const r of open.unresolved) {
      await fetch(`${sb.urls.bank}/admin/idempotency/${encodeURIComponent(r.key)}/resolve`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ outcome: 'executed', attempt: r.attempt }),
      });
    }
    expect(text(await run(c, 'transfer', pay))).toMatch(/^plenipo: DENY ALREADY_EXECUTED/);
    expect(openKeys()).toEqual([]);
    const after = Number((await run(c, 'get_balance')).structuredContent!.balance_cents);
    expect(before - after).toBe(6230);

    // A deliberate second payment of the same amount is a new call with a new key.
    const again = await run(c, 'transfer', pay);
    expect(again.isError).toBeFalsy();
    expect(Number((await run(c, 'get_balance')).structuredContent!.balance_cents)).toBe(after - 6230);
    await c.close();
  }, 30_000);
});
