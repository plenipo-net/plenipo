import { describe, expect, it, beforeAll } from 'vitest';
import { SignJWT } from 'jose';
import {
  createInvocation,
  createMandate,
  delegateMandate,
  generateAgentKey,
  InMemoryNonceStore,
  InMemoryRevocationRegistry,
  InMemorySpendingLedger,
  mandateHash,
  nowSeconds,
  verifyAuthorization,
  DELEGATION_TYP,
  encodeMandateTransactionData,
  type AgentKey,
  type Mandate,
  type MandateChain,
} from '../src/index.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';
import { guardTool, META_KEY } from '../src/mcp.js';

const AUD = 'https://rail.example';

let provider: TestPidProvider;
let wallet: TestWallet;
let agent: AgentKey;
let subAgent: AgentKey;

beforeAll(async () => {
  provider = await createTestPidProvider();
  wallet = await createTestWallet();
  wallet.storePid(
    await provider.issuePid(wallet.holderJwk, { given_name: 'Fabio', family_name: 'Lalli', birthdate: '1977-09-04' }),
  );
  agent = await generateAgentKey();
  subAgent = await generateAgentKey();
});

function rootMandate(overrides: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['travel.*'],
    counterparties: ['*.rail.example', 'rail.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
    maxDepth: 1,
    purpose: 'Book trains for the Milan trip',
    ...overrides,
  });
}

async function rootChain(m: Mandate): Promise<MandateChain> {
  return { root: await wallet.approveMandate(m), delegations: [] };
}

const baseOpts = () => ({
  trustedIssuers: [provider.trusted],
  audience: AUD,
  ledger: new InMemorySpendingLedger(),
  nonces: new InMemoryNonceStore(),
});

describe('root authorization', () => {
  it('allows an agent acting within a wallet-approved mandate', async () => {
    const m = rootMandate();
    const chain = await rootChain(m);
    const inv = await createInvocation(agent.privateKey, { chain,
      mandateId: m.id, action: 'travel.book', counterparty: 'www.rail.example',
      amount: { value: 8900, currency: 'EUR' }, aud: AUD,
    });
    const d = await verifyAuthorization(chain, inv, baseOpts());
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') {
      expect(d.principal).toEqual({ given_name: 'Fabio', family_name: 'Lalli' });
      expect(d.principal).not.toHaveProperty('birthdate');
      expect(d.path).toHaveLength(1);
    }
  });

  it('rejects a PID from an untrusted issuer', async () => {
    const m = rootMandate();
    const chain = await rootChain(m);
    const other = await createTestPidProvider('https://other.test');
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, { ...baseOpts(), trustedIssuers: [other.trusted] });
    expect(d).toMatchObject({ decision: 'DENY', code: 'PID_ISSUER_UNTRUSTED' });
  });

  it('rejects a mandate the wallet did not approve', async () => {
    const approved = rootMandate();
    const chain = await rootChain(approved);
    const swapped = { ...approved, limits: { currency: 'EUR', per_operation: 1_000_000, total: 1_000_000 } };
    chain.root.transaction_data = encodeMandateTransactionData(swapped as Mandate);
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: approved.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 900000, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, baseOpts());
    expect(d).toMatchObject({ decision: 'DENY', code: 'TX_DATA_MISMATCH' });
  });

  it('rejects a presentation without key binding', async () => {
    const m = rootMandate();
    const chain = await rootChain(m);
    const parts = chain.root.presentation.split('~');
    parts[parts.length - 1] = '';
    chain.root.presentation = parts.join('~');
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ decision: 'DENY', code: 'ROOT_INVALID' });
  });

  it('rejects a PID approved by a device that does not hold it', async () => {
    const thief = await createTestWallet();
    // The thief stores someone else's PID, bound to the victim's device key.
    thief.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Fabio', family_name: 'Lalli' }));
    const m = rootMandate();
    const chain = { root: await thief.approveMandate(m), delegations: [] };
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ decision: 'DENY', code: 'ROOT_INVALID' });
  });

  it('refuses mandates longer than the lifetime policy', () => {
    expect(() => rootMandate({ ttlSeconds: 200 * 24 * 3600 })).toThrow(/lifetime/);
  });

  it('rejects a mandate that outlives the PID', async () => {
    const shortWallet = await createTestWallet();
    shortWallet.storePid(await provider.issuePid(shortWallet.holderJwk, { given_name: 'A', family_name: 'B' }, { exp: nowSeconds() + 3600 }));
    const m = rootMandate({ ttlSeconds: 7200 });
    const chain = { root: await shortWallet.approveMandate(m), delegations: [] };
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, baseOpts());
    expect(d).toMatchObject({ decision: 'DENY', code: 'LIFETIME_POLICY' });
  });

  it('denies an expired mandate', async () => {
    const m = rootMandate({ ttlSeconds: 3600 });
    const chain = await rootChain(m);
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, { ...baseOpts(), now: m.exp, maxInvocationAgeSeconds: 10_000 });
    expect(d).toMatchObject({ decision: 'DENY', code: 'EXPIRED' });
  });
});

describe('delegation', () => {
  async function delegated(childOverrides: Partial<Mandate> = {}) {
    const parent = rootMandate();
    const child = createMandate({
      agentJwk: subAgent.publicJwk,
      actions: ['travel.book'],
      counterparties: ['www.rail.example'],
      limits: { currency: 'EUR', per_operation: 5000, total: 10000 },
      nbf: parent.nbf,
      exp: parent.exp - 60,
    });
    const merged = { ...child, ...childOverrides } as Mandate;
    const jws = await delegateMandate({ parent, parentAgentKey: agent.privateKey, child: merged });
    return { parent, child: merged, chain: { root: await wallet.approveMandate(parent), delegations: [jws] } as MandateChain };
  }

  it('allows a sub-agent within a narrower mandate', async () => {
    const { child, chain } = await delegated();
    const inv = await createInvocation(subAgent.privateKey, { chain, mandateId: child.id, action: 'travel.book', counterparty: 'www.rail.example', amount: { value: 4000, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, baseOpts());
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') expect(d.path.map((p) => p.depth)).toEqual([0, 1]);
  });

  it('refuses to sign a widening delegation', async () => {
    const parent = rootMandate();
    const child = createMandate({ agentJwk: subAgent.publicJwk, actions: ['purchase.order'], nbf: parent.nbf, exp: parent.exp });
    await expect(delegateMandate({ parent, parentAgentKey: agent.privateKey, child })).rejects.toThrow(/widens/);
  });

  it('rejects a forged widening delegation at verification', async () => {
    const parent = rootMandate();
    const child = createMandate({
      agentJwk: subAgent.publicJwk, actions: ['travel.book'], counterparties: ['www.rail.example'],
      limits: { currency: 'EUR', per_operation: 99999, total: 99999 }, nbf: parent.nbf, exp: parent.exp,
    });
    const forged = await new SignJWT({ mandate: child, parent_id: parent.id, parent_hash: mandateHash(parent), iat: nowSeconds() } as any)
      .setProtectedHeader({ alg: 'ES256', typ: DELEGATION_TYP })
      .sign(agent.privateKey);
    const chain = { root: await wallet.approveMandate(parent), delegations: [forged] };
    const inv = await createInvocation(subAgent.privateKey, { chain, mandateId: child.id, action: 'travel.book', counterparty: 'www.rail.example', amount: { value: 90000, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, baseOpts());
    expect(d).toMatchObject({ decision: 'DENY', code: 'ATTENUATION_VIOLATION', at: 1 });
  });

  it('rejects a delegation signed by someone other than the parent agent', async () => {
    const parent = rootMandate();
    const child = createMandate({ agentJwk: subAgent.publicJwk, actions: ['travel.book'], counterparties: ['www.rail.example'], limits: { currency: 'EUR', per_operation: 100, total: 100 }, nbf: parent.nbf, exp: parent.exp });
    const intruder = await generateAgentKey();
    const forged = await new SignJWT({ mandate: child, parent_id: parent.id, parent_hash: mandateHash(parent), iat: nowSeconds() } as any)
      .setProtectedHeader({ alg: 'ES256', typ: DELEGATION_TYP })
      .sign(intruder.privateKey);
    const chain = { root: await wallet.approveMandate(parent), delegations: [forged] };
    const inv = await createInvocation(subAgent.privateKey, { chain, mandateId: child.id, action: 'travel.book', counterparty: 'www.rail.example', amount: { value: 50, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, baseOpts());
    expect(d).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID' });
  });

  it('enforces the delegation depth', async () => {
    const parent = rootMandate({ maxDepth: 0 });
    const child = createMandate({ agentJwk: subAgent.publicJwk, actions: ['travel.book'], counterparties: ['www.rail.example'], limits: { currency: 'EUR', per_operation: 100, total: 100 }, nbf: parent.nbf, exp: parent.exp });
    await expect(delegateMandate({ parent, parentAgentKey: agent.privateKey, child })).rejects.toThrow(/sub-delegation/);
    const forged = await new SignJWT({ mandate: child, parent_id: parent.id, parent_hash: mandateHash(parent), iat: nowSeconds() } as any)
      .setProtectedHeader({ alg: 'ES256', typ: DELEGATION_TYP })
      .sign(agent.privateKey);
    const chain = { root: await wallet.approveMandate(parent), delegations: [forged] };
    const inv = await createInvocation(subAgent.privateKey, { chain, mandateId: child.id, action: 'travel.book', counterparty: 'www.rail.example', amount: { value: 50, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, baseOpts());
    expect(d).toMatchObject({ decision: 'DENY', code: 'DELEGATION_NOT_ALLOWED' });
  });

  it('revoking the parent revokes the sub-agent', async () => {
    const { parent, child, chain } = await delegated();
    const revocation = new InMemoryRevocationRegistry();
    revocation.revoke(parent.id);
    const inv = await createInvocation(subAgent.privateKey, { chain, mandateId: child.id, action: 'travel.book', counterparty: 'www.rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, { ...baseOpts(), revocation });
    expect(d).toMatchObject({ decision: 'DENY', code: 'REVOKED', at: 0 });
  });
});

describe('scope and invocation', () => {
  async function setup() {
    const m = rootMandate();
    return { m, chain: await rootChain(m) };
  }

  it('denies an action outside the mandate', async () => {
    const { m, chain } = await setup();
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'purchase.order', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ code: 'ACTION_NOT_PERMITTED' });
  });

  it('denies a counterparty outside the mandate', async () => {
    const { m, chain } = await setup();
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'evil.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ code: 'COUNTERPARTY_NOT_PERMITTED' });
  });

  it('denies an amount above the per-operation limit', async () => {
    const { m, chain } = await setup();
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 15001, currency: 'EUR' }, aud: AUD });
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ code: 'LIMIT_PER_OPERATION' });
  });

  it('denies once the total limit is used up', async () => {
    const { m, chain } = await setup();
    const opts = baseOpts();
    const r = opts.ledger.reserve([{ key: mandateHash(m), total: 30000 }], { value: 25000, currency: 'EUR' });
    opts.ledger.commit(r!);
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 6000, currency: 'EUR' }, aud: AUD });
    expect(await verifyAuthorization(chain, inv, opts)).toMatchObject({ code: 'LIMIT_TOTAL' });
  });

  it('denies an invocation signed by another key', async () => {
    const { m, chain } = await setup();
    const inv = await createInvocation(subAgent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ code: 'INVOCATION_SIGNATURE_INVALID' });
  });

  it('denies an invocation for another relying party', async () => {
    const { m, chain } = await setup();
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: 'https://other.example' });
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ code: 'AUDIENCE_MISMATCH' });
  });

  it('denies a replayed invocation', async () => {
    const { m, chain } = await setup();
    const nonces = new InMemoryNonceStore();
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD, nonce: 'n-1' });
    expect((await verifyAuthorization(chain, inv, { ...baseOpts(), nonces })).decision).toBe('ALLOW');
    expect(await verifyAuthorization(chain, inv, { ...baseOpts(), nonces })).toMatchObject({ code: 'REPLAY' });
  });
});

describe('MCP guard', () => {
  it('runs the tool on ALLOW, records spending, and denies a mismatched call', async () => {
    const m = rootMandate();
    const chain = await rootChain(m);
    const ledger = new InMemorySpendingLedger();
    let executed = 0;
    type Args = { route: string; host: string; price_cents: number };
    const tool = guardTool<Args>(
      async (args) => {
        executed++;
        return { content: [{ type: 'text', text: `booked ${args.route}` }] };
      },
      {
        action: 'travel.book',
        trustedIssuers: [provider.trusted],
        audience: AUD,
        ledger,
        nonces: new InMemoryNonceStore(),
        counterparty: (a) => a.host,
        amount: (a) => ({ value: a.price_cents, currency: 'EUR' }),
      },
    );
    const args: Args = { route: 'Roma-Milano', host: 'www.rail.example', price_cents: 8900 };
    const invocation = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: args.host, amount: { value: 8900, currency: 'EUR' }, aud: AUD, args });
    const ok = await tool(args, { _meta: { [META_KEY]: { chain, invocation } } });
    expect(ok.isError).toBeFalsy();
    expect(executed).toBe(1);
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(8900);

    const tampered = { ...args, price_cents: 14000 };
    const bad = await tool(tampered, { _meta: { [META_KEY]: { chain, invocation } } });
    expect(bad.isError).toBe(true);
    expect(executed).toBe(1);

    const missing = await tool(args, {});
    expect(missing.isError).toBe(true);
  });
});

describe('regressions from the security review', () => {
  async function setup() {
    const m = rootMandate();
    return { m, chain: await rootChain(m) };
  }
  async function signRaw(payload: Record<string, unknown>) {
    return new SignJWT(payload).setProtectedHeader({ alg: 'ES256', typ: 'plenipo-invocation+jwt' }).sign(agent.privateKey);
  }
  const raw = (m: Mandate, extra: Record<string, unknown>) => ({
    mandate: m.id, action: 'travel.book', counterparty: 'rail.example', aud: AUD, nonce: crypto.randomUUID(), iat: nowSeconds(), ...extra,
  });

  it.each([
    ['missing value', { currency: 'EUR' }],
    ['null value', { value: null, currency: 'EUR' }],
    ['string value', { value: 'abc', currency: 'EUR' }],
    ['negative value', { value: -30000, currency: 'EUR' }],
    ['fractional value', { value: 10.5, currency: 'EUR' }],
  ])('denies an invocation amount with %s', async (_label, amount) => {
    const { m, chain } = await setup();
    const inv = await signRaw(raw(m, { amount }));
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
  });

  it.each(['evil.example/.rail.example', 'evil.example?.rail.example', 'evil.example#.rail.example', 'https://evil.example/x.rail.example', '*.rail.example', 'WWW.RAIL.EXAMPLE'])(
    'denies a smuggled counterparty %s',
    async (cp) => {
      const { m, chain } = await setup();
      const inv = await signRaw(raw(m, { counterparty: cp, amount: { value: 100, currency: 'EUR' } }));
      expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
    },
  );

  it('denies a wildcard action in an invocation', async () => {
    const { m, chain } = await setup();
    const inv = await signRaw(raw(m, { action: 'travel.*', amount: { value: 100, currency: 'EUR' } }));
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
  });

  it('does not overspend under concurrent calls', async () => {
    const { m, chain } = await setup();
    const opts = baseOpts();
    const invs = await Promise.all(
      Array.from({ length: 5 }, () =>
        createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 15000, currency: 'EUR' }, aud: AUD }),
      ),
    );
    const decisions = await Promise.all(invs.map((inv) => verifyAuthorization(chain, inv, opts)));
    expect(decisions.filter((d) => d.decision === 'ALLOW')).toHaveLength(2);
    expect(decisions.filter((d) => d.decision === 'DENY' && d.code === 'LIMIT_TOTAL')).toHaveLength(3);
  });

  it('requires a nonce store', async () => {
    const { m, chain } = await setup();
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    const { nonces: _n, ...noNonces } = baseOpts();
    expect(await verifyAuthorization(chain, inv, noNonces as any)).toMatchObject({ decision: 'DENY', code: 'CONFIGURATION' });
  });

  it('binds the decision to what the relying party is about to do', async () => {
    const { m, chain } = await setup();
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, { ...baseOpts(), expected: { amount: { value: 9000, currency: 'EUR' } } });
    expect(d).toMatchObject({ decision: 'DENY', code: 'INVOCATION_MISMATCH' });
    const ok = await verifyAuthorization(chain, inv, { ...baseOpts(), expected: { action: 'travel.book', counterparty: 'rail.example' } });
    expect(ok.decision).toBe('ALLOW');
    if (ok.decision === 'ALLOW') expect(ok.invocation.amount).toEqual({ value: 100, currency: 'EUR' });
  });

  it('rejects non-canonical transaction data, such as duplicate keys', async () => {
    const { m, chain } = await setup();
    const json = `{"credential_ids":["pid"],"mandate":${JSON.stringify({ ...m, limits: { currency: 'EUR', per_operation: 100, total: 100 } })},"mandate":${JSON.stringify(m)},"type":"plenipo_mandate"}`;
    chain.root.transaction_data = Buffer.from(json).toString('base64url');
    const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'travel.book', counterparty: 'rail.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    expect(await verifyAuthorization(chain, inv, baseOpts())).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
  });

  it('caps the delegation depth', () => {
    expect(() => rootMandate({ maxDepth: 6 })).toThrow(/max_depth/);
  });
});
