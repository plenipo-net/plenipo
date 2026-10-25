// Regression tests for the "chain" security review (CHAIN-1 to CHAIN-6 and the revocation cache).
// Each started as a reviewer proof of concept that passed while the bug existed; they now assert the safe behaviour.
import 'reflect-metadata';
import { beforeAll, describe, expect, it } from 'vitest';
import { deflateSync } from 'node:zlib';
import { SignJWT } from 'jose';
import { StatusList } from '@owf/token-status-list';
import {
  chainHash,
  checkCertificateRevocation,
  checkStatus,
  createInvocation,
  createMandate,
  decodeStatusList,
  delegateMandate,
  generateAgentKey,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  INVOCATION_TYP,
  mandateHash,
  nowSeconds,
  readStatus,
  RevocationCache,
  StatusListCache,
  validateMandate,
  verifyAuthorization,
  verifyX5c,
  type AgentKey,
  type CertificateRevocationOptions,
  type Mandate,
  type MandateChain,
  type RevocationFetcher,
} from '../src/index.js';
import {
  createLegalMandate,
} from '../src/experimental.js';
import {
  createTestCertificateAuthority,
  createTestPidProvider,
  createTestWallet,
  type TestCertificateAuthority,
  type TestPidProvider,
  type TestWallet,
} from '../src/testing.js';
import { guardTool, META_KEY } from '../src/mcp.js';

const AUD = 'https://bank.example';

let provider: TestPidProvider;
let alice: TestWallet;
let mallory: TestWallet;
let orchestratorAlice: AgentKey;
let orchestratorMallory: AgentKey;
let executor: AgentKey;

beforeAll(async () => {
  provider = await createTestPidProvider();
  alice = await createTestWallet();
  alice.storePid(await provider.issuePid(alice.holderJwk, { given_name: 'Alice', family_name: 'Victim' }));
  mallory = await createTestWallet();
  mallory.storePid(await provider.issuePid(mallory.holderJwk, { given_name: 'Mallory', family_name: 'Attacker' }));
  [orchestratorAlice, orchestratorMallory, executor] = await Promise.all([generateAgentKey(), generateAgentKey(), generateAgentKey()]);
});

const opts = (ledger = new InMemorySpendingLedger()) => ({
  trustedIssuers: [provider.trusted],
  audience: AUD,
  ledger,
  nonces: new InMemoryNonceStore(),
});

async function rootChainFor(m: Mandate, wallet: TestWallet = alice): Promise<MandateChain> {
  return { root: await wallet.approveMandate(m), delegations: [] };
}

const ok = () => ({ content: [{ type: 'text' as const, text: 'ok' }] });

describe('CHAIN-1: the MCP guard binds counterparty and amount to the call', () => {
  type Args = { to?: string; other?: string; cents: number };

  function transferMandate(limits = { currency: 'EUR', per_operation: 100_000, total: 200_000 }) {
    return createMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['payments.transfer'], counterparties: ['landlord.example'], limits });
  }

  it('refuses to build a guard that does not say how it reads the counterparty and the amount', () => {
    const base = { ...opts(), action: 'payments.transfer' };
    expect(() => guardTool<Args>(async () => ok(), { ...base, amount: (a: Args) => ({ value: a.cents, currency: 'EUR' }) } as any)).toThrow(/counterparty and amount/);
    expect(() => guardTool<Args>(async () => ok(), { ...base, counterparty: (a: Args) => a.to } as any)).toThrow(/counterparty and amount/);
    expect(() => guardTool<Args>(async () => ok(), { ...base, counterparty: 'landlord.example', amount: null } as any)).toThrow(/functions or null/);
  });

  it('counterparty smuggling: the declared counterparty must be the one in the arguments', async () => {
    const m = transferMandate();
    const chain = await rootChainFor(m);
    const paid: string[] = [];
    const tool = guardTool<Args>(
      async (args) => {
        paid.push(args.to!);
        return ok();
      },
      { ...opts(), action: 'payments.transfer', counterparty: (a) => a.to, amount: (a) => ({ value: a.cents, currency: 'EUR' }) },
    );
    const args: Args = { to: 'attacker.example', cents: 90_000 };
    const invocation = await createInvocation(orchestratorAlice.privateKey, {
      chain, mandateId: m.id, action: 'payments.transfer', counterparty: 'landlord.example', amount: { value: 90_000, currency: 'EUR' }, aud: AUD, args,
    });
    const res = await tool(args, { _meta: { [META_KEY]: { chain, invocation } } });
    expect(res.isError).toBe(true);
    expect(res.structuredContent).toMatchObject({ plenipo: { code: 'INVOCATION_MISMATCH' } });
    expect(paid).toEqual([]);
  });

  it('amount smuggling: the declared amount must be the one in the arguments', async () => {
    const m = transferMandate({ currency: 'EUR', per_operation: 10_000, total: 20_000 });
    const chain = await rootChainFor(m);
    const ledger = new InMemorySpendingLedger();
    const sent: number[] = [];
    const tool = guardTool<Args>(
      async (args) => {
        sent.push(args.cents);
        return ok();
      },
      { ...opts(ledger), action: 'payments.transfer', counterparty: (a) => a.to, amount: (a) => ({ value: a.cents, currency: 'EUR' }) },
    );
    const args: Args = { to: 'landlord.example', cents: 5_000_000 };
    const invocation = await createInvocation(orchestratorAlice.privateKey, {
      chain, mandateId: m.id, action: 'payments.transfer', counterparty: 'landlord.example', amount: { value: 1, currency: 'EUR' }, aud: AUD, args,
    });
    const res = await tool(args, { _meta: { [META_KEY]: { chain, invocation } } });
    expect(res.structuredContent).toMatchObject({ plenipo: { code: 'INVOCATION_MISMATCH' } });
    expect(sent).toEqual([]);
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);
  });

  it('refuses the call when an extractor returns nothing, an invalid amount, or throws', async () => {
    const m = transferMandate();
    const chain = await rootChainFor(m);
    const ran: Args[] = [];
    const make = (counterparty: (a: Args) => string | undefined, amount: (a: Args) => any) =>
      guardTool<Args>(
        async (args) => {
          ran.push(args);
          return ok();
        },
        { ...opts(), action: 'payments.transfer', counterparty, amount },
      );
    const args: Args = { other: 'attacker.example', cents: 100 };
    const signed = async () =>
      createInvocation(orchestratorAlice.privateKey, {
        chain, mandateId: m.id, action: 'payments.transfer', counterparty: 'landlord.example', amount: { value: 100, currency: 'EUR' }, aud: AUD, args,
      });
    const eur = (a: Args) => ({ value: a.cents, currency: 'EUR' });
    const cases = [
      make((a) => a.to, eur),
      make(() => '', eur),
      make(() => 'landlord.example', () => undefined),
      make(() => 'landlord.example', () => ({ value: -100, currency: 'EUR' })),
      make(() => 'landlord.example', () => ({ value: 1.5, currency: 'EUR' })),
      make(() => 'landlord.example', () => ({ value: 100, currency: 'eur' })),
      make(() => 'landlord.example', () => ({ value: '100', currency: 'EUR' })),
      make(() => {
        throw new Error('boom');
      }, eur),
    ];
    for (const tool of cases) {
      const res = await tool(args, { _meta: { [META_KEY]: { chain, invocation: await signed() } } });
      expect(res.structuredContent).toMatchObject({ plenipo: { decision: 'DENY', code: 'INVOCATION_MISMATCH' } });
      expect(res.content[0].text).not.toMatch(/boom/);
    }
    expect(ran).toEqual([]);
  });

  it('with null, refuses an invocation that declares a counterparty or amount, and releases the reservation', async () => {
    const m = createMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['shop.buy'], limits: { currency: 'EUR', total: 10_000 } });
    const chain = await rootChainFor(m);
    const ledger = new InMemorySpendingLedger();
    let ran = 0;
    // A tool that moves no money and names no counterparty, wired by mistake under a mandate with limits.
    const tool = guardTool<{ cents: number }>(
      async () => {
        ran++;
        return ok();
      },
      { ...opts(ledger), action: 'shop.buy', counterparty: null, amount: null },
    );
    const args = { cents: 9_000 };
    const invocation = await createInvocation(orchestratorAlice.privateKey, { chain, mandateId: m.id, action: 'shop.buy', amount: { value: 9_000, currency: 'EUR' }, aud: AUD, args });
    const res = await tool(args, { _meta: { [META_KEY]: { chain, invocation } } });
    expect(res.structuredContent).toMatchObject({ plenipo: { code: 'INVOCATION_MISMATCH' } });
    expect(ran).toBe(0);
    expect(ledger.spent(mandateHash(m), 'EUR')).toBe(0);

    const host = createMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['shop.buy'] });
    const hostChain = await rootChainFor(host);
    const withHost = await createInvocation(orchestratorAlice.privateKey, { chain: hostChain, mandateId: host.id, action: 'shop.buy', counterparty: 'x.example', aud: AUD, args });
    expect((await tool(args, { _meta: { [META_KEY]: { chain: hostChain, invocation: withHost } } })).structuredContent).toMatchObject({ plenipo: { code: 'INVOCATION_MISMATCH' } });
    const plain = await createInvocation(orchestratorAlice.privateKey, { chain: hostChain, mandateId: host.id, action: 'shop.buy', aud: AUD, args });
    expect((await tool(args, { _meta: { [META_KEY]: { chain: hostChain, invocation: plain } } })).isError).toBeFalsy();
    expect(ran).toBe(1);
  });
});

describe('CHAIN-2: the invocation is bound to the whole chain', () => {
  it("an invocation the shared executor signed for Mallory's chain is refused on Alice's chain", async () => {
    const SHARED_ID = 'exec-task-00000001';
    const aliceRoot = createMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['shop.buy'], counterparties: ['*.market.example'], limits: { currency: 'EUR', per_operation: 50_000 }, maxDepth: 1 });
    const aliceLeaf = createMandate({ id: SHARED_ID, agentJwk: executor.publicJwk, actions: ['shop.buy'], counterparties: ['*.market.example'], limits: { currency: 'EUR', per_operation: 50_000 }, nbf: aliceRoot.nbf, exp: aliceRoot.exp });
    const aliceChain: MandateChain = {
      root: await alice.approveMandate(aliceRoot),
      delegations: [await delegateMandate({ parent: aliceRoot, parentAgentKey: orchestratorAlice.privateKey, child: aliceLeaf })],
    };
    const malloryRoot = createMandate({ agentJwk: orchestratorMallory.publicJwk, actions: ['shop.buy'], limits: { currency: 'EUR', per_operation: 50_000 }, maxDepth: 1 });
    const malloryLeaf = createMandate({ id: SHARED_ID, agentJwk: executor.publicJwk, actions: ['shop.buy'], limits: { currency: 'EUR', per_operation: 50_000 }, nbf: malloryRoot.nbf, exp: malloryRoot.exp });
    const malloryChain: MandateChain = {
      root: await mallory.approveMandate(malloryRoot),
      delegations: [await delegateMandate({ parent: malloryRoot, parentAgentKey: orchestratorMallory.privateKey, child: malloryLeaf })],
    };
    const inv = await createInvocation(executor.privateKey, {
      chain: malloryChain, mandateId: SHARED_ID, action: 'shop.buy', counterparty: 'mallory.market.example', amount: { value: 45_000, currency: 'EUR' }, aud: AUD,
    });
    expect(await verifyAuthorization(aliceChain, inv, opts())).toMatchObject({ decision: 'DENY', code: 'INVOCATION_MANDATE_MISMATCH' });
    expect((await verifyAuthorization(malloryChain, inv, opts())).decision).toBe('ALLOW');
  });

  it('requires chain_hash and binds every part of the chain', async () => {
    const m = createMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['shop.buy'] });
    const chain = await rootChainFor(m);
    const legacy = await new SignJWT({ mandate: m.id, action: 'shop.buy', aud: AUD, nonce: 'n-legacy', iat: nowSeconds() })
      .setProtectedHeader({ alg: 'ES256', typ: INVOCATION_TYP })
      .sign(orchestratorAlice.privateKey);
    expect(await verifyAuthorization(chain, legacy, opts())).toMatchObject({ decision: 'DENY', code: 'INVOCATION_MANDATE_MISMATCH' });
    // Another approval of the same mandate is another chain.
    const again = await rootChainFor(m);
    const inv = await createInvocation(orchestratorAlice.privateKey, { chain, mandateId: m.id, action: 'shop.buy', aud: AUD });
    expect(await verifyAuthorization(again, inv, opts())).toMatchObject({ decision: 'DENY', code: 'INVOCATION_MANDATE_MISMATCH' });
    expect((await verifyAuthorization(chain, inv, opts())).decision).toBe('ALLOW');

    const h = chainHash(chain);
    expect(chainHash({ root: { ...chain.root }, delegations: [...chain.delegations] })).toBe(h);
    expect(chainHash({ ...chain, delegations: ['x'] })).not.toBe(h);
    expect(chainHash({ ...chain, root: { ...chain.root, mandate: m } })).not.toBe(h);
    expect(chainHash({ ...chain, root: { ...chain.root, presentations: { sca: 'x' } } })).not.toBe(h);
    await expect(createInvocation(orchestratorAlice.privateKey, { mandateId: m.id, action: 'shop.buy', aud: AUD } as any)).rejects.toThrow(/chain/);
  });
});

describe('CHAIN-3: library messages stay out of the reason', () => {
  it('puts jose messages in detail only, for invocations and JWS delegations, including in the MCP guard', async () => {
    const m = createMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['shop.buy'], maxDepth: 1 });
    const chain = await rootChainFor(m);
    const bad = await new SignJWT({ mandate: m.id }).setProtectedHeader({ alg: 'ES256', typ: 'something-else' }).sign(orchestratorAlice.privateKey);
    const d = await verifyAuthorization(chain, bad, opts());
    expect(d).toMatchObject({ decision: 'DENY', code: 'INVOCATION_SIGNATURE_INVALID', reason: 'invocation is not signed by the leaf agent' });
    if (d.decision === 'DENY') expect(d.detail).toMatch(/typ/);

    const badLink = { ...chain, delegations: ['x.y.z'] };
    const d2 = await verifyAuthorization(badLink, bad, opts());
    expect(d2).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID', reason: 'delegation 1 is not signed by the parent agent' });
    if (d2.decision === 'DENY') expect(d2.detail).toBeTruthy();

    const tool = guardTool(async () => ok(), { ...opts(), action: 'shop.buy', counterparty: null, amount: null });
    const res = await tool({}, { _meta: { [META_KEY]: { chain, invocation: 'x.y.z' } } });
    expect(res.content[0].text).toBe('plenipo: DENY INVOCATION_SIGNATURE_INVALID: invocation is not signed by the leaf agent');
  });
});

describe('CHAIN-4: the MCP guard never leaves a reservation behind', () => {
  const setup = async (onDecision?: () => void, handler: () => any = ok) => {
    const m = createMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['shop.buy'], limits: { currency: 'EUR', total: 10_000 } });
    const chain = await rootChainFor(m);
    const ledger = new InMemorySpendingLedger();
    let ran = 0;
    const tool = guardTool<{ cents: number }>(
      async () => {
        ran++;
        return handler();
      },
      { ...opts(ledger), action: 'shop.buy', counterparty: null, amount: (a) => ({ value: a.cents, currency: 'EUR' }), onDecision },
    );
    const args = { cents: 9_000 };
    const invocation = await createInvocation(orchestratorAlice.privateKey, { chain, mandateId: m.id, action: 'shop.buy', amount: { value: 9_000, currency: 'EUR' }, aud: AUD, args });
    const call = () => tool(args, { _meta: { [META_KEY]: { chain, invocation } } });
    return { call, spent: () => ledger.spent(mandateHash(m), 'EUR'), ran: () => ran };
  };

  it('releases the reservation and refuses the call when onDecision throws', async () => {
    const t = await setup(() => {
      throw new Error('audit sink down');
    });
    const res = await t.call();
    expect(res.structuredContent).toMatchObject({ plenipo: { decision: 'DENY', code: 'INTERNAL' } });
    expect(res.content[0].text).not.toMatch(/audit sink/);
    expect(t.ran()).toBe(0);
    expect(t.spent()).toBe(0);
  });

  it('keeps the amount reserved when the handler throws or reports an error without an outcome, commits on success', async () => {
    const thrown = await setup(undefined, () => {
      throw new Error('downstream failed');
    });
    await expect(thrown.call()).rejects.toThrow(/downstream failed/);
    // The tool may have acted before throwing: the budget stays consumed until reconciled.
    expect(thrown.spent()).toBe(9_000);
    // Updated in round 2: an error result no longer releases by itself (it used to; see PoC2-MCP-1).
    const failed = await setup(undefined, () => ({ isError: true, content: [{ type: 'text', text: 'no' }] }));
    await failed.call();
    expect(failed.spent()).toBe(9_000);
    const good = await setup();
    expect((await good.call()).isError).toBeFalsy();
    expect(good.spent()).toBe(9_000);
  });
});

describe('CHAIN-5: unknown mandate members are refused', () => {
  it('refuses an unknown constraint in the root instead of dropping it', async () => {
    const m = createMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['shop.buy'], limits: { currency: 'EUR', per_operation: 100_000 } });
    (m as any).limits.daily = 100;
    (m as any).counterparty = ['only-this.example'];
    const chain = await rootChainFor(m);
    const inv = await createInvocation(orchestratorAlice.privateKey, {
      chain, mandateId: m.id, action: 'shop.buy', counterparty: 'anything.example', amount: { value: 99_999, currency: 'EUR' }, aud: AUD,
    });
    const d = await verifyAuthorization(chain, inv, opts());
    expect(d).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 0 });
    if (d.decision === 'DENY') expect(d.reason).toMatch(/unknown member counterparty.*unknown member limits\.daily|unknown member limits\.daily.*unknown member counterparty/);
  });

  it('checks every nested object and accepts every member Plenipo itself emits', () => {
    const full = createMandate({
      agentJwk: orchestratorAlice.publicJwk,
      actions: ['shop.buy'],
      counterparties: ['shop.example'],
      limits: { currency: 'EUR', per_operation: 1, total: 2 },
      maxDepth: 1,
      purpose: 'p',
      status: { status_list: { uri: 'https://status.example/1', idx: 1 } },
    });
    expect(validateMandate(full)).toEqual([]);
    const legal = createLegalMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['shop.buy'], principal: { type: 'legal_person', euid: 'DEHRB.HRB999' } });
    expect(validateMandate(legal)).toEqual([]);
    const variants: Array<[string, (m: any) => void]> = [
      ['agent.kid', (m) => (m.agent.kid = 'k')],
      ['limits.daily', (m) => (m.limits.daily = 1)],
      ['delegation.max_hops', (m) => (m.delegation.max_hops = 9)],
      ['status.extra', (m) => (m.status.extra = 1)],
      ['status.status_list.bits', (m) => (m.status.status_list.bits = 2)],
      ['expires', (m) => (m.expires = 1)],
    ];
    for (const [name, mutate] of variants) {
      const m = structuredClone(full);
      mutate(m);
      expect(validateMandate(m)).toContain(`unknown member ${name}`);
    }
  });

  it('refuses an unknown member in a delegated mandate', async () => {
    const parent = createMandate({ agentJwk: orchestratorAlice.publicJwk, actions: ['shop.*'], maxDepth: 1 });
    const child = { ...createMandate({ agentJwk: executor.publicJwk, actions: ['shop.buy'], nbf: parent.nbf, exp: parent.exp }), only_on_mondays: true } as Mandate;
    await expect(delegateMandate({ parent, parentAgentKey: orchestratorAlice.privateKey, child })).rejects.toThrow(/unknown member only_on_mondays/);
    const forged = await new SignJWT({ mandate: child, parent_id: parent.id, parent_hash: mandateHash(parent), iat: nowSeconds() } as any)
      .setProtectedHeader({ alg: 'ES256', typ: 'plenipo-delegation+jwt' })
      .sign(orchestratorAlice.privateKey);
    const chain = { root: await alice.approveMandate(parent), delegations: [forged] };
    const inv = await createInvocation(executor.privateKey, { chain, mandateId: child.id, action: 'shop.buy', aud: AUD });
    expect(await verifyAuthorization(chain, inv, opts())).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1 });
  });
});

describe('CHAIN-6: status lists are inflated within a bound and read without expansion', () => {
  const uri = 'https://platform.example/status/1';
  let issuerKey: AgentKey;
  beforeAll(async () => {
    issuerKey = await generateAgentKey();
  });
  const tokenFor = async (raw: Uint8Array, bits = 1) => {
    const now = nowSeconds();
    return new SignJWT({ sub: uri, iat: now, exp: now + 3600, status_list: { bits, lst: deflateSync(raw, { level: 9 }).toString('base64url') } })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
      .sign(issuerKey.privateKey);
  };
  const check = (token: string, idx: number, extra: Record<string, unknown> = {}) =>
    checkStatus(
      { status_list: { uri, idx } },
      {
        trust: { trustedIssuers: [{ iss: 'https://platform.example', jwk: issuerKey.publicJwk }] },
        signer: 'https://platform.example',
        allowedOrigins: ['https://platform.example'],
        fetcher: async () => token,
        now: nowSeconds(),
        ...extra,
      },
    );

  it('refuses a small token that inflates beyond the bound, quickly', async () => {
    const token = await tokenFor(new Uint8Array(2 * 1024 * 1024));
    expect(token.length).toBeLessThan(4096);
    const t = Date.now();
    await expect(check(token, 0)).rejects.toThrow(/cannot be inflated within 1048576 bytes/);
    expect(Date.now() - t).toBeLessThan(1000);
    // A caller may raise the bound deliberately.
    expect(await check(token, 0, { maxListBytes: 4 * 1024 * 1024 })).toBe(0);
  });

  it('reads a list at the bound without building an array of entries', async () => {
    const raw = new Uint8Array(1024 * 1024);
    raw[raw.length - 1] = 0b1000_0000; // the last entry at 1 bit
    const token = await tokenFor(raw);
    const t = Date.now();
    expect(await check(token, 8 * 1024 * 1024 - 1)).toBe(1);
    expect(await check(token, 8 * 1024 * 1024 - 2)).toBe(0);
    expect(Date.now() - t).toBeLessThan(1000);
    await expect(check(token, 8 * 1024 * 1024)).rejects.toThrow(/outside/);
  });

  it('reads entries in the same bit order as the Token Status List library, for every width', () => {
    for (const bits of [1, 2, 4, 8] as const) {
      const values = Array.from({ length: 203 }, (_, i) => (i * 7 + 3) % 2 ** bits);
      const list = new StatusList(values, bits);
      const decoded = decodeStatusList({ bits, lst: Buffer.from(list.compressStatusListToBytes()).toString('base64url') });
      for (let i = 0; i < values.length; i++) expect(readStatus(decoded, i)).toBe(list.getStatus(i));
    }
  });

  it('refuses invalid bits, invalid encodings and non-zlib data', () => {
    const lst = deflateSync(new Uint8Array(4)).toString('base64url');
    for (const bits of [0, 3, 16, '2', undefined]) expect(() => decodeStatusList({ bits, lst })).toThrow(/bits/);
    expect(() => decodeStatusList({ bits: 1, lst: 'a+b/' })).toThrow(/base64url/);
    expect(() => decodeStatusList({ bits: 1, lst: Buffer.from('not zlib').toString('base64url') })).toThrow(/inflated/);
    expect(() => decodeStatusList(null)).toThrow();
  });

  it('does not serve a list cached under a larger bound to a stricter check', async () => {
    const token = await tokenFor(new Uint8Array(2 * 1024 * 1024));
    const cache = new StatusListCache(60);
    expect(await check(token, 0, { maxListBytes: 4 * 1024 * 1024, cache })).toBe(0);
    await expect(check(token, 0, { cache })).rejects.toThrow(/inflated/);
  });
});

describe('revocation cache respects the options of each check', () => {
  const OCSP_URL = 'http://ocsp.test/';
  let ca: TestCertificateAuthority;
  let chain: string[];
  let leafCert: string;
  const now = () => nowSeconds();

  beforeAll(async () => {
    ca = await createTestCertificateAuthority();
    const leaf = await ca.issueLeaf('https://pid.example', { ocspUrls: [OCSP_URL] });
    leafCert = leaf.certificate;
    chain = verifyX5c(leaf.x5c, [ca.anchorPem], now(), 'https://pid.example').chain!;
  });

  const responding = (produce: () => Promise<Uint8Array>) => {
    let calls = 0;
    const fetcher: RevocationFetcher = {
      crl: async () => {
        throw new Error('unreachable');
      },
      ocsp: async () => {
        calls++;
        return produce();
      },
    };
    return { fetcher, calls: () => calls };
  };
  const hard = (fetcher: RevocationFetcher, extra: Partial<CertificateRevocationOptions>): CertificateRevocationOptions => ({
    policy: 'hard-fail',
    fetcher,
    methods: ['ocsp'],
    ...extra,
  });

  it('does not serve an answer obtained without a nonce to a check that requires one', async () => {
    const cache = new RevocationCache();
    const plain = responding(() => ca.createOcspResponse({ certificate: leafCert, status: 'good' }));
    await checkCertificateRevocation(chain, hard(plain.fetcher, { cache }), now());
    await checkCertificateRevocation(chain, hard(plain.fetcher, { cache }), now());
    expect(plain.calls()).toBe(1);
    // A replayed (nonce-less) answer must be fetched and refused, not taken from the cache.
    await expect(checkCertificateRevocation(chain, hard(plain.fetcher, { cache, ocspNonce: true }), now())).rejects.toThrow(/nonce/);
    expect(plain.calls()).toBe(2);
  });

  it('re-ages an answer without nextUpdate with the requesting maxAgeWithoutNextUpdate', async () => {
    const cache = new RevocationCache();
    const old = responding(() => ca.createOcspResponse({ certificate: leafCert, status: 'good', thisUpdate: new Date(Date.now() - 5400_000), nextUpdate: null }));
    await checkCertificateRevocation(chain, hard(old.fetcher, { cache, maxAgeWithoutNextUpdate: 7200 }), now());
    await expect(checkCertificateRevocation(chain, hard(old.fetcher, { cache, maxAgeWithoutNextUpdate: 3600 }), now())).rejects.toThrow(/stale/);
    expect(old.calls()).toBe(2);
  });

  it('does not serve a status to a check that does not allow the method it came from', async () => {
    const cache = new RevocationCache();
    const good = responding(() => ca.createOcspResponse({ certificate: leafCert, status: 'good' }));
    await checkCertificateRevocation(chain, hard(good.fetcher, { cache }), now());
    await expect(checkCertificateRevocation(chain, hard(good.fetcher, { cache, methods: ['crl'] }), now())).rejects.toThrow(/could not be determined/);
  });

  it('serves a cached revocation to every check', async () => {
    const cache = new RevocationCache();
    const revoked = responding(() => ca.createOcspResponse({ certificate: leafCert, status: 'revoked' }));
    await expect(checkCertificateRevocation(chain, hard(revoked.fetcher, { cache }), now())).rejects.toThrow(/revoked/);
    await expect(checkCertificateRevocation(chain, hard(revoked.fetcher, { cache, ocspNonce: true, methods: ['crl'] }), now())).rejects.toThrow(/revoked/);
    expect(revoked.calls()).toBe(1);
  });
});
