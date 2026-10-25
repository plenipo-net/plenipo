/**
 * The sandbox on the library's shared stores: a throwaway Postgres cluster and a redis-server on free
 * ports (the same helpers as the library's store tests). For each engine the bank's ledger and nonces and
 * the platform's OpenID4VP sessions live in the engine; a few scenarios run end to end, then a transfer
 * whose outcome is unknown shows the sweep and reconciliation. Skipped when an engine cannot start.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startPostgres, startRedis, type Engine } from '../../test/stores-engines.js';
import { SandboxAgentClient } from '../src/agent/client.js';
import { startSandbox, type Sandbox } from '../src/sandbox.js';
import { formatResult, runScenario, SCENARIOS } from '../src/scenarios.js';

const PORTS = { dashboard: 0, pid: 0, wallet: 0, platform: 0, bank: 0 };

for (const [kind, start] of [
  ['postgres', startPostgres],
  ['redis', startRedis],
] as const) {
  describe(`sandbox on ${kind}`, () => {
    let engine: Engine;
    let sb: Sandbox | undefined;
    let client: SandboxAgentClient;

    beforeAll(async () => {
      engine = await start();
      if (!engine.ok) return;
      sb = await startSandbox({
        ports: PORTS,
        statusCacheSeconds: 1,
        sweepSeconds: 3600, // swept by hand below
        stores: { kind, url: engine.url, prefix: kind === 'postgres' ? 'sbx_' : `sbx${Date.now()}`, pendingTtlSeconds: 1 },
      });
      client = new SandboxAgentClient({ platform: sb.urls.platform, wallet: sb.urls.wallet, bank: sb.urls.bank, dashboard: sb.urls.dashboard });
    }, 120_000);

    afterAll(async () => {
      await client?.close();
      await sb?.close();
      if (engine?.ok) await engine.stop();
    });

    for (const id of ['happy-path', 'total-limit', 'replay', 'concurrent', 'reads-without-reservation', 'wallet-refusal']) {
      it(`scenario ${id}`, async (ctx) => {
        if (!sb) return ctx.skip(engine.ok ? 'sandbox did not start' : engine.reason);
        const r = await runScenario(SCENARIOS.find((s) => s.id === id)!, {
          client,
          bankHost: sb.identities.bankHost,
          audiences: sb.bank.audiences,
          urls: sb.urls,
          statusCacheSeconds: sb.statusCacheSeconds,
        });
        if (!r.pass) console.log(formatResult(r, false));
        expect(r.pass).toBe(true);
      });
    }

    it('a transfer with an unknown outcome stays counted until reconciled', async (ctx) => {
      if (!sb) return ctx.skip(engine.ok ? 'sandbox did not start' : engine.reason);
      expect(sb.stores.kind).toBe(kind);
      const m = await client.obtainMandate({
        agentName: 'Bill assistant',
        person: 'maria',
        spec: { actions: ['payments.transfer'], counterparties: ['lumen-energia.example', 'acquaviva.example'], limits: { currency: 'EUR', per_operation: 10000, total: 10000 }, ttlSeconds: 3600 },
      });
      await fetch(`${sb.urls.bank}/admin/fail-next-transfer`, { method: 'POST' });
      const timedOut = await client.callTool(m, 'transfer', { payee: 'lumen-energia.example', amount_cents: 6000, reference: 'Lumen' });
      expect(timedOut.isError).toBe(true);
      expect(timedOut.text).toMatch(/did not answer in time/);
      // Pending past its 1 s TTL, the sweep turns it into expired_spent: still counted against the total.
      await new Promise((r) => setTimeout(r, 1500));
      await sb.bank.sweep();
      const listed = (await (await fetch(`${sb.urls.bank}/api/reservations`)).json()) as { unresolved: Array<{ id: string; state: string; amount: { value: number } }> };
      expect(listed.unresolved.map((r) => [r.state, r.amount.value])).toEqual([['expired_spent', 6000]]);
      const blocked = await client.callTool(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 5000, reference: 'AcquaViva' });
      expect(`${blocked.decision} ${blocked.code}`).toBe('DENY LIMIT_TOTAL');
      // Reconciliation finds the payment never reached Lumen: the amount comes back.
      const rec = await fetch(`${sb.urls.bank}/admin/reservations/${listed.unresolved[0].id}/reconcile`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ outcome: 'not_executed' }),
      });
      expect(((await rec.json()) as { state: string }).state).toBe('released');
      const after = await client.callTool(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 5000, reference: 'AcquaViva' });
      expect(after.decision).toBe('ALLOW');
      const events = (await (await fetch(`${sb.urls.bank}/events`)).json()) as Array<{ type: string }>;
      expect(events.some((e) => e.type === 'reservations')).toBe(true);
    });
  });
}
