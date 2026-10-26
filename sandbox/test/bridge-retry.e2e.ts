/**
 * The bridge's idempotency keys against a guarded tool, without the sandbox services: a bank whose answers
 * can be lost on the way back, and an agent that goes on with other calls before retrying.
 * Found by the 0.5 security review: a single open-call slot lost the key of an unanswered payment.
 */
import { describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import {
  createMandate,
  InMemoryIdempotencyStore,
  InMemoryNonceStore,
  InMemorySpendingLedger,
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

async function setup(opts: { deny?: () => string | undefined } = {}) {
  const provider = await createTestPidProvider('https://pid-bridge-retry.example');
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
      idempotency: new InMemoryIdempotencyStore(),
      action: 'payments.transfer',
      counterparty: (a) => a.payee,
      amount: (a) => EUR(a.amount_cents),
    },
  );
  const bank = { dropNextAnswer: false, sent: [] as string[] };
  const fakeClient = {
    async callTool(req: { name: string; arguments: T; _meta: Record<string, unknown> }) {
      bank.sent.push(peekInvocation((req._meta[META_KEY] as { invocation: string }).invocation).idem ?? '');
      // A denial before the bank looks at the key (a suspended mandate, for instance).
      const code = opts.deny?.();
      if (code) return { isError: true, content: [{ type: 'text', text: `plenipo: DENY ${code}` }], structuredContent: { plenipo: { decision: 'DENY', code } } };
      const res = await transfer(req.arguments, { _meta: req._meta });
      if (bank.dropNextAnswer) {
        bank.dropNextAnswer = false;
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
  return { bridge, bank, paid, store };
}

const billA = { payee: 'shop.example', amount_cents: 4_000, reference: 'bill A' };
const billB = { payee: 'other.example', amount_cents: 2_000, reference: 'bill B' };

describe('bridge idempotency keys', () => {
  it('keeps the key of an unanswered payment while the agent pays another bill', async () => {
    const { bridge, bank, paid } = await setup();
    bank.dropNextAnswer = true;
    expect((await bridge.callBankTool('transfer', billA)).isError).toBe(true);
    expect((await bridge.callBankTool('transfer', billB)).isError).toBeFalsy();
    const retry = await bridge.callBankTool('transfer', billA);
    expect(retry.text).toMatch(/already been executed/);
    expect(bank.sent[2]).toBe(bank.sent[0]);
    expect(paid).toEqual(['shop.example:4000', 'other.example:2000']);
  });

  it('keeps the key through a denial that comes before the bank looks at it', async () => {
    let denyNext = false;
    const { bridge, bank, paid } = await setup({ deny: () => (denyNext ? ((denyNext = false), 'REVOKED') : undefined) });
    bank.dropNextAnswer = true;
    await bridge.callBankTool('transfer', billA);
    denyNext = true;
    expect((await bridge.callBankTool('transfer', billA)).text).toMatch(/DENY REVOKED/);
    await bridge.callBankTool('transfer', billA);
    expect(new Set(bank.sent).size).toBe(1);
    expect(paid).toEqual(['shop.example:4000']);
  });

  it('makes a new payment of the same bill once the first one is settled', async () => {
    const { bridge, bank, paid, store } = await setup();
    await bridge.callBankTool('transfer', billA);
    expect(Object.keys((await store.load()).open ?? {})).toHaveLength(0);
    await bridge.callBankTool('transfer', billA);
    expect(bank.sent[0]).not.toBe(bank.sent[1]);
    expect(paid).toEqual(['shop.example:4000', 'shop.example:4000']);
  });
});
