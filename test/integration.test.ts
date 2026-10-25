import { describe, expect, it, beforeAll } from 'vitest';
import {
  createInvocation,
  createMandate,
  encodeChainHeader,
  generateAgentKey,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  mandateHash,
  parseAuthorizationHeaders,
  verifyAuthorization,
  type AgentKey,
  type Decision,
} from '../src/index.js';
import {
  delegateMandateSdJwt,
} from '../src/experimental.js';
import { guardTool, META_KEY } from '../src/mcp.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';

const AUD = 'https://bank.example';

let provider: TestPidProvider;
let wallet: TestWallet;
let agent: AgentKey;

beforeAll(async () => {
  provider = await createTestPidProvider();
  wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Maria', family_name: 'Rossi' }));
  agent = await generateAgentKey();
});

describe('verifier failure paths', () => {
  it('releases the reservation when the nonce store throws', async () => {
    const m = createMandate({
      agentJwk: agent.publicJwk,
      actions: ['payments.transfer'],
      counterparties: ['acquaviva.example'],
      limits: { currency: 'EUR', per_operation: 10000, total: 10000 },
    });
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const ledger = new InMemorySpendingLedger();
    const failing = { consume: async () => { throw new Error('redis connection reset'); } };
    const inv = await createInvocation(agent.privateKey, { chain,
      mandateId: m.id, action: 'payments.transfer', counterparty: 'acquaviva.example',
      amount: { value: 6000, currency: 'EUR' }, aud: AUD,
    });
    const d = await verifyAuthorization(chain, inv, {
      trustedIssuers: [provider.trusted], audience: AUD, ledger, nonces: failing,
    });
    expect(d.decision).toBe('DENY');
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);
  });
});

describe('operations without money or counterparty', () => {
  async function billsChain() {
    const m = createMandate({
      agentJwk: agent.publicJwk,
      actions: ['payments.transfer', 'accounts.read'],
      counterparties: ['acquaviva.example'],
      limits: { currency: 'EUR', per_operation: 10000, total: 30000 },
    });
    return { m, chain: { root: await wallet.approveMandate(m), delegations: [] } };
  }

  it('lets a bills mandate read the balance when the bank declares the call moves no money', async () => {
    const { m, chain } = await billsChain();
    const ledger = new InMemorySpendingLedger();
    let seen: Decision | undefined;
    const tool = guardTool<{ account: string }>(
      async (_args, _extra, decision) => {
        seen = decision;
        return { content: [{ type: 'text', text: '1234.56 EUR' }] };
      },
      { action: 'accounts.read', counterparty: null, amount: null, audience: AUD, nonces: new InMemoryNonceStore(), ledger, trustedIssuers: [provider.trusted] },
    );
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'accounts.read', aud: AUD, args: { account: 'acc-1' } });
    const res = await tool({ account: 'acc-1' }, { _meta: { [META_KEY]: { chain, invocation: inv } } });
    expect(res.isError).toBeFalsy();
    expect(seen?.decision).toBe('ALLOW');
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);
  });

  it('still refuses a read when the agent slips an amount or a payee into it', async () => {
    const { m, chain } = await billsChain();
    const tool = guardTool<{ account: string }>(async () => ({ content: [{ type: 'text', text: 'x' }] }), {
      action: 'accounts.read', counterparty: null, amount: null, audience: AUD, nonces: new InMemoryNonceStore(), ledger: new InMemorySpendingLedger(), trustedIssuers: [provider.trusted],
    });
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'accounts.read', amount: { value: 1, currency: 'EUR' }, aud: AUD, args: { account: 'acc-1' } });
    const res = await tool({ account: 'acc-1' }, { _meta: { [META_KEY]: { chain, invocation: inv } } });
    expect(res.isError).toBe(true);
  });

  it('without the declaration, a mandate with limits still refuses a call that declares no amount', async () => {
    const { m, chain } = await billsChain();
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'accounts.read', counterparty: 'acquaviva.example', aud: AUD });
    const d = await verifyAuthorization(chain, inv, { trustedIssuers: [provider.trusted], audience: AUD, nonces: new InMemoryNonceStore(), ledger: new InMemorySpendingLedger() });
    expect(d).toMatchObject({ decision: 'DENY', code: 'LIMIT_PER_OPERATION' });
  });
});

describe('store retention', () => {
  it('refuses a nonce store that forgets nonces before invocations expire', async () => {
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['a.b'] });
    const chain = { root: await wallet.approveMandate(m), delegations: [] };
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'a.b', aud: AUD });
    const short = Object.assign(new InMemoryNonceStore(), { retentionSeconds: 100 });
    const d = await verifyAuthorization(chain, inv, { trustedIssuers: [provider.trusted], audience: AUD, nonces: short });
    expect(d).toMatchObject({ decision: 'DENY', code: 'CONFIGURATION' });
    const ok = Object.assign(new InMemoryNonceStore(), { retentionSeconds: 180 });
    expect((await verifyAuthorization(chain, inv, { trustedIssuers: [provider.trusted], audience: AUD, nonces: ok })).decision).toBe('ALLOW');
  });
});

describe('HTTP transport', () => {
  it('carries a chain with a Delegate SD-JWT link', async () => {
    const sub = await generateAgentKey();
    const parent = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.*'], maxDepth: 1 });
    const child = createMandate({ agentJwk: sub.publicJwk, actions: ['payments.transfer'], exp: parent.exp });
    const chain = {
      root: await wallet.approveMandate(parent),
      delegations: [await delegateMandateSdJwt({ parent, parentAgentKey: agent.privateKey, child })],
    };
    const inv = await createInvocation(sub.privateKey, { chain, mandateId: child.id, action: 'payments.transfer', aud: AUD });
    const parsed = parseAuthorizationHeaders(new Headers({ 'plenipo-chain': encodeChainHeader(chain), 'plenipo-invocation': inv }));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      const d = await verifyAuthorization(parsed.chain, parsed.invocation, { trustedIssuers: [provider.trusted], audience: AUD, nonces: new InMemoryNonceStore(), delegationFormats: ['jws', 'sd-jwt'] });
      expect(d.decision).toBe('ALLOW');
      const off = await verifyAuthorization(parsed.chain, parsed.invocation, { trustedIssuers: [provider.trusted], audience: AUD, nonces: new InMemoryNonceStore() });
      expect(off).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1 });
    }
  });
});
