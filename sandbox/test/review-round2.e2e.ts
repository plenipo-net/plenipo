/**
 * Round 2 of the independent security review of 0.5: the bridge's open-calls map, kept as regression tests
 * for parallel tool calls and for the migration of the 0.5.0-draft `retry` slot.
 */
import { describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import {
  argsHash,
  createMandate,
  InMemoryIdempotencyStore,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  newIdempotencyKey,
  peekInvocation,
  type Amount,
  type Mandate,
} from 'plenipo';
import { guardTool, META_KEY } from 'plenipo/mcp';
import { createTestPidProvider, createTestWallet } from 'plenipo/testing';
import { BridgeCore, MemoryStateStore } from '../src/bridge/core.js';

const AUD = 'https://bank.example';
const EUR = (value: number): Amount => ({ value, currency: 'EUR' });
type T = { payee: string; amount_cents: number; reference: string };

async function setup() {
  const provider = await createTestPidProvider('https://pid-round2.example');
  const wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Ada', family_name: 'Lovelace' }));
  const pair = await generateKeyPair('ES256', { extractable: true });
  const privateJwk = await exportJWK(pair.privateKey);
  const publicJwk = { kty: 'EC', crv: 'P-256', x: privateJwk.x, y: privateJwk.y } as JWK;
  const m: Mandate = createMandate({
    agentJwk: publicJwk,
    actions: ['payments.transfer'],
    counterparties: ['shop.example', 'other.example'],
    limits: { currency: 'EUR', per_operation: 50_000, total: 1_000_000 },
  });
  const chain = { root: await wallet.approveMandate(m), delegations: [] };
  const idempotency = new InMemoryIdempotencyStore();
  const paid: string[] = [];
  const transfer = guardTool<T>(
    async (a) => {
      paid.push(`${a.payee}:${a.amount_cents}`);
      return { content: [{ type: 'text', text: `paid ${a.payee}` }] };
    },
    {
      trustedIssuers: [provider.trusted],
      audience: AUD,
      nonces: new InMemoryNonceStore(),
      ledger: new InMemorySpendingLedger(),
      idempotency,
      action: 'payments.transfer',
      counterparty: (a) => a.payee,
      amount: (a) => EUR(a.amount_cents),
    },
  );
  const bank = { drop: new Set<string>(), sent: [] as Array<{ payee: string; idem: string }> };
  const fakeClient = {
    async callTool(req: { name: string; arguments: T; _meta: Record<string, unknown> }) {
      bank.sent.push({ payee: req.arguments.payee, idem: peekInvocation((req._meta[META_KEY] as { invocation: string }).invocation).idem ?? '' });
      const res = await transfer(req.arguments, { _meta: req._meta });
      if (bank.drop.has(req.arguments.payee)) {
        bank.drop.delete(req.arguments.payee);
        throw new Error('socket hang up'); // the money left, the answer is lost
      }
      return res;
    },
  };
  const store = new MemoryStateStore();
  await store.save({ agent: { privateJwk, publicJwk }, mandate: { id: m.id, chain, mandate: m, approvedAt: new Date().toISOString() } });
  const bridge = new BridgeCore({ platformUrl: 'http://platform.invalid', bankUrl: 'http://bank.invalid', store });
  const binding = { action: 'payments.transfer', audience: AUD, counterparty: { arg: 'payee' }, amount: { arg: 'amount_cents', currency: 'EUR' }, idempotent: true };
  const schema = { type: 'object', properties: { payee: {}, amount_cents: {}, reference: {} } };
  Object.assign(bridge as unknown as Record<string, unknown>, { tools: [{ name: 'transfer', inputSchema: schema, binding }], bankClient: async () => fakeClient });
  return { bridge, bank, paid, store, m, idempotency };
}

const billA = { payee: 'shop.example', amount_cents: 4_000, reference: 'bill A' };
const billB = { payee: 'other.example', amount_cents: 2_000, reference: 'bill B' };

describe('bridge open calls, round 2', () => {
  it('migrates a 0.5.0-draft `retry` slot so that the retry after an upgrade reuses its key', async () => {
    const { bridge, bank, store, m } = await setup();
    // State written by e16bc1e: the payment went out, the answer was lost, then the host was upgraded.
    const idem = newIdempotencyKey();
    const s = await store.load();
    // How e16bc1e computed args_hash for its slot: argsHash({ tool, args }).
    s.retry = { tool: 'transfer', args_hash: argsHash({ tool: 'transfer', args: billA }), idem, mandate_id: m.id, at: new Date().toISOString() };
    await store.save(s);
    await bridge.callBankTool('transfer', billA);
    expect(bank.sent[0].idem).toBe(idem);
  });

  it('does not lose the key of an unanswered payment when the agent pays two bills in parallel', async () => {
    const { bridge, bank, paid } = await setup();
    bank.drop.add('shop.example'); // bill A's answer is lost
    // Claude and other MCP clients issue parallel tool calls.
    await Promise.all([bridge.callBankTool('transfer', billA), bridge.callBankTool('transfer', billB)]);
    await bridge.callBankTool('transfer', billA); // the retry the bridge said was safe
    const keysForA = bank.sent.filter((x) => x.payee === 'shop.example').map((x) => x.idem);
    expect(paid.filter((p) => p === 'shop.example:4000')).toHaveLength(1);
    expect(new Set(keysForA).size).toBe(1);
  });
});
