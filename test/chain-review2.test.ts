// Regression tests for the second-round chain review (PoC2-MCP-1, PoC2-VERIFY-1 and JWS payload members).
// Each started as a reviewer proof of concept that passed while the bug existed; they now assert the safe behaviour.
import { beforeAll, describe, expect, it } from 'vitest';
import { SignJWT } from 'jose';
import {
  createInvocation,
  createMandate,
  delegateMandate,
  DELEGATION_TYP,
  generateAgentKey,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  mandateHash,
  nowSeconds,
  verifyAuthorization,
  type AgentKey,
  type Mandate,
  type MandateChain,
} from '../src/index.js';
import { guardTool, META_KEY, OUTCOME_META_KEY } from '../src/mcp.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';

const MCP_AUD = 'mcp://bank.example';
const AUD = 'https://bank.example';

let agent: AgentKey;
let sub: AgentKey;
let provider: TestPidProvider;
let wallet: TestWallet;
beforeAll(async () => {
  [agent, sub] = await Promise.all([generateAgentKey(), generateAgentKey()]);
  provider = await createTestPidProvider('https://pid.example.it');
  wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Maria', family_name: 'Bianchi' }));
});

const verifyOpts = (aud: string, ledger = new InMemorySpendingLedger()) => ({
  audience: aud,
  nonces: new InMemoryNonceStore(),
  ledger,
  trustedIssuers: [provider.trusted],
});

describe('PoC2-MCP-1: an executed tool that reports an error keeps its amount reserved', () => {
  type Args = { payee: string; amount: number; reference: string };
  type Result = { content: Array<{ type: 'text'; text: string }>; isError?: boolean; _meta?: Record<string, unknown> };

  async function setup(respond: (args: Args) => Result) {
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.transfer'], counterparties: ['shop.example'], limits: { currency: 'EUR', total: 100_000 } });
    const chain: MandateChain = { root: await wallet.approveMandate(m), delegations: [] };
    const ledger = new InMemorySpendingLedger();
    const moved: number[] = [];
    const tool = guardTool<Args>(
      async (args) => {
        const r = respond(args);
        if (r._meta?.[OUTCOME_META_KEY] !== 'not-executed') moved.push(args.amount);
        return r;
      },
      { ...verifyOpts(MCP_AUD, ledger), action: 'payments.transfer', counterparty: (a) => a.payee, amount: (a) => ({ value: a.amount, currency: 'EUR' }) },
    );
    const call = async (amount: number) => {
      const args = { payee: 'shop.example', amount, reference: 'x'.repeat(20) };
      const invocation = await createInvocation(agent.privateKey, {
        chain, mandateId: m.id, action: 'payments.transfer', counterparty: 'shop.example', amount: { value: amount, currency: 'EUR' }, aud: MCP_AUD, args,
      });
      return tool(args, { _meta: { [META_KEY]: { chain, invocation } } });
    };
    return { call, moved, spent: () => ledger.spent(mandateHash(m), 'EUR') };
  }

  it('two 600.00 EUR transfers cannot both run under a 1,000.00 EUR total when the receipt step fails', async () => {
    const t = await setup(() => ({ content: [{ type: 'text', text: 'transfer booked, receipt failed' }], isError: true }));
    expect((await t.call(60_000)).isError).toBe(true);
    expect(t.spent()).toBe(60_000);
    const second = await t.call(60_000);
    expect(second.structuredContent).toMatchObject({ plenipo: { decision: 'DENY', code: 'LIMIT_TOTAL' } });
    expect(t.moved).toEqual([60_000]);
  });

  it('settles from the stated outcome and strips it from the result', async () => {
    const said = (outcome: unknown, isError = false, other: Record<string, unknown> = {}) =>
      setup(() => ({ content: [{ type: 'text', text: 'r' }], isError, _meta: { ...other, [OUTCOME_META_KEY]: outcome } }));

    const notRun = await said('not-executed', true, { trace: 't1' });
    const r1 = await notRun.call(10_000);
    expect(notRun.spent()).toBe(0);
    expect(r1._meta).toEqual({ trace: 't1' });

    const ranThenFailed = await said('executed', true);
    const r2 = await ranThenFailed.call(10_000);
    expect(ranThenFailed.spent()).toBe(10_000);
    expect(r2).not.toHaveProperty('_meta');
    expect(r2.isError).toBe(true);

    for (const outcome of ['unknown', 'not_executed', 'NOT-EXECUTED', 1, null]) {
      const t = await said(outcome);
      const r = await t.call(10_000);
      expect(t.spent(), String(outcome)).toBe(10_000);
      expect(r).not.toHaveProperty('_meta');
    }

    const plain = await setup(() => ({ content: [{ type: 'text', text: 'ok' }] }));
    await plain.call(10_000);
    expect(plain.spent()).toBe(10_000);
  });
});

describe('PoC2-VERIFY-1: counterparty null does not lift counterparty restrictions on a call that moves money', () => {
  async function restricted() {
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.*', 'accounts.*'], counterparties: ['shop.example'], limits: { currency: 'EUR', per_operation: 50_000, total: 100_000 } });
    return { m, chain: { root: await wallet.approveMandate(m), delegations: [] } as MandateChain };
  }

  it('refuses a card top-up declared without counterparty under a mandate restricted to shop.example', async () => {
    const { m, chain } = await restricted();
    const args = { card: 'agent-controlled-card-77', amount: 50_000 };
    const invocation = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.card_topup', amount: { value: 50_000, currency: 'EUR' }, aud: AUD, args });
    const d = await verifyAuthorization(chain, invocation, {
      ...verifyOpts(AUD),
      expected: { action: 'payments.card_topup', counterparty: null, amount: { value: 50_000, currency: 'EUR' }, args },
    });
    expect(d).toMatchObject({ decision: 'DENY', code: 'COUNTERPARTY_NOT_PERMITTED', at: 0 });
    // An RP that does not state the amount is treated as one that may move money.
    const again = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.card_topup', amount: { value: 50_000, currency: 'EUR' }, aud: AUD, args });
    expect(await verifyAuthorization(chain, again, { ...verifyOpts(AUD), expected: { action: 'payments.card_topup', counterparty: null } })).toMatchObject({
      decision: 'DENY',
      code: 'COUNTERPARTY_NOT_PERMITTED',
    });
  });

  it('still allows a call that has neither a counterparty nor money, such as a balance read', async () => {
    const { m, chain } = await restricted();
    const invocation = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'accounts.read', aud: AUD });
    const d = await verifyAuthorization(chain, invocation, { ...verifyOpts(AUD), expected: { action: 'accounts.read', counterparty: null, amount: null } });
    expect(d.decision).toBe('ALLOW');
  });

  it('applies to the MCP guard: counterparty null with an amount extractor is refused under a restricted mandate', async () => {
    const { m, chain } = await restricted();
    let ran = 0;
    const tool = guardTool<{ cents: number }>(
      async () => {
        ran++;
        return { content: [{ type: 'text', text: 'topped up' }] };
      },
      { ...verifyOpts(MCP_AUD), action: 'payments.card_topup', counterparty: null, amount: (a) => ({ value: a.cents, currency: 'EUR' }) },
    );
    const args = { cents: 50_000 };
    const invocation = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.card_topup', amount: { value: 50_000, currency: 'EUR' }, aud: MCP_AUD, args });
    const res = await tool(args, { _meta: { [META_KEY]: { chain, invocation } } });
    expect(res.structuredContent).toMatchObject({ plenipo: { decision: 'DENY', code: 'COUNTERPARTY_NOT_PERMITTED' } });
    expect(ran).toBe(0);
  });
});

describe('JWS delegation payloads are closed', () => {
  it('refuses a JWS delegation with a payload member outside mandate, parent_id, parent_hash and iat', async () => {
    const parent = createMandate({ agentJwk: agent.publicJwk, actions: ['shop.*'], maxDepth: 1 });
    const child = createMandate({ agentJwk: sub.publicJwk, actions: ['shop.buy'], nbf: parent.nbf, exp: parent.exp });
    const sign = (extra: Record<string, unknown>) =>
      new SignJWT({ mandate: child, parent_id: parent.id, parent_hash: mandateHash(parent), iat: nowSeconds(), ...extra } as any)
        .setProtectedHeader({ alg: 'ES256', typ: DELEGATION_TYP })
        .sign(agent.privateKey);
    const root = await wallet.approveMandate(parent);
    for (const extra of [{ max_amount: 10 }, { exp: parent.exp }, { constraints: { only: 'shop.example' } }]) {
      const chain = { root, delegations: [await sign(extra)] };
      const inv = await createInvocation(sub.privateKey, { chain, mandateId: child.id, action: 'shop.buy', aud: AUD });
      const d = await verifyAuthorization(chain, inv, verifyOpts(AUD));
      expect(d).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(/unknown member/) });
    }
    const good = { root, delegations: [await delegateMandate({ parent, parentAgentKey: agent.privateKey, child: child as Mandate })] };
    const inv = await createInvocation(sub.privateKey, { chain: good, mandateId: child.id, action: 'shop.buy', aud: AUD });
    expect((await verifyAuthorization(good, inv, verifyOpts(AUD))).decision).toBe('ALLOW');
  });
});
