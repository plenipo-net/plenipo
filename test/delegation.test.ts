import { beforeAll, describe, expect, it } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, type CryptoKey, type JWK } from 'jose';
import {
  canonicalize,
  createInvocation,
  createMandate,
  delegateMandate,
  DELEGATION_TYP,
  generateAgentKey,
  InMemoryNonceStore,
  InMemoryRevocationRegistry,
  InMemorySpendingLedger,
  mandateHash,
  nowSeconds,
  verifyAuthorization,
  type AgentKey,
  type Mandate,
  type MandateChain,
} from '../src/index.js';
import {
  createDelegateTransactionData,
  delegateMandateSdJwt,
  DELEGATE_SDJWT_TYP,
  MAX_DELEGATION_LENGTH,
  parseDelegation,
} from '../src/experimental.js';
import type { DelegationFormat } from '../src/index.js';
import { DelegationError, issueDelegateSdJwt, verifyDelegateSdJwt } from '../src/delegate-sdjwt.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';

const AUD = 'https://rail.example';

let provider: TestPidProvider;
let wallet: TestWallet;
let agent: AgentKey;
let sub: AgentKey;
let subsub: AgentKey;
let intruder: AgentKey;

beforeAll(async () => {
  provider = await createTestPidProvider();
  wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Fabio', family_name: 'Lalli' }));
  [agent, sub, subsub, intruder] = await Promise.all([generateAgentKey(), generateAgentKey(), generateAgentKey(), generateAgentKey()]);
});

const opts = () => ({
  trustedIssuers: [provider.trusted],
  audience: AUD,
  ledger: new InMemorySpendingLedger(),
  nonces: new InMemoryNonceStore(),
  delegationFormats: ['jws', 'sd-jwt'] as DelegationFormat[],
});

function rootMandate(maxDepth = 2, overrides: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['travel.*'],
    counterparties: ['*.rail.example', 'rail.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
    maxDepth,
    ...overrides,
  });
}

function childOf(parent: Mandate, key: AgentKey, overrides: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate {
  return createMandate({
    agentJwk: key.publicJwk,
    actions: ['travel.book'],
    counterparties: ['www.rail.example'],
    limits: { currency: 'EUR', per_operation: 5000, total: 10000 },
    nbf: parent.nbf,
    exp: parent.exp - 60,
    maxDepth: Math.max(0, (parent.delegation?.max_depth ?? 0) - 1),
    ...overrides,
  });
}

type Format = 'jws' | 'sd-jwt';
const delegate = (format: Format) => (format === 'jws' ? delegateMandate : delegateMandateSdJwt);

async function invoke(chain: MandateChain, key: AgentKey, m: Mandate, value = 1000): Promise<string> {
  return createInvocation(key.privateKey, { chain,
    mandateId: m.id,
    action: 'travel.book',
    counterparty: 'www.rail.example',
    amount: { value, currency: 'EUR' },
    aud: AUD,
  });
}

// An independent encoder for the Plenipo profile, so the tests can craft tokens the library would refuse to build.
function b64(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}
function digestOf(disclosure: string): string {
  return createHash('sha256').update(disclosure, 'ascii').digest('base64url');
}
interface Craft {
  delegatePayload: Record<string, unknown>;
  outer?: Record<string, unknown>;
  header?: { alg: string; [k: string]: unknown };
  extraDisclosures?: string[];
  disclosureJson?: string;
  key?: CryptoKey;
}
async function craft(c: Craft): Promise<string> {
  const disclosure = b64(c.disclosureJson ?? canonicalize([randomBytes(16).toString('base64url'), c.delegatePayload]));
  const outer = c.outer ?? { iat: nowSeconds(), _sd_alg: 'sha-256', delegate_payload: [{ '...': digestOf(disclosure) }] };
  const jwt = await new SignJWT(outer)
    .setProtectedHeader(c.header ?? { alg: 'ES256', typ: DELEGATE_SDJWT_TYP })
    .sign(c.key ?? agent.privateKey);
  return [jwt, disclosure, ...(c.extraDisclosures ?? []), ''].join('~');
}
function delegatePayloadFor(parent: Mandate, child: Mandate, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    cnf: { jwk: child.agent.jwk },
    plenipo_mandate: child,
    parent_id: parent.id,
    parent_hash: mandateHash(parent),
    nbf: child.nbf,
    exp: child.exp,
    ...extra,
  };
}

async function oneHop(token: string, parent: Mandate, child: Mandate, key: AgentKey = sub, value = 1000) {
  const chain: MandateChain = { root: await wallet.approveMandate(parent), delegations: [token] };
  return verifyAuthorization(chain, await invoke(chain, key, child, value), opts());
}

describe.each(['jws', 'sd-jwt'] as const)('the same semantics for %s delegations', (format) => {
  it('allows a sub-agent within a narrower mandate', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegate(format)({ parent, parentAgentKey: agent.privateKey, child });
    expect(parseDelegation(token).format).toBe(format);
    const d = await oneHop(token, parent, child);
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') {
      expect(d.path.map((p) => p.depth)).toEqual([0, 1]);
      expect(d.mandates[1]).toEqual(child);
    }
  });

  it('refuses to sign a widening, invalid or non-delegable child', async () => {
    const parent = rootMandate();
    const wide = childOf(parent, sub, { limits: { currency: 'EUR', per_operation: 99999, total: 99999 } });
    await expect(delegate(format)({ parent, parentAgentKey: agent.privateKey, child: wide })).rejects.toThrow(/widens/);
    const leaf = rootMandate(0);
    await expect(delegate(format)({ parent: leaf, parentAgentKey: agent.privateKey, child: childOf(leaf, sub) })).rejects.toThrow(/sub-delegation/);
    const invalid = { ...childOf(parent, sub), actions: [] } as Mandate;
    await expect(delegate(format)({ parent, parentAgentKey: agent.privateKey, child: invalid })).rejects.toThrow(/invalid child/);
  });

  it('rejects a delegation signed by someone other than the parent agent', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegate(format)({ parent: { ...parent, agent: { jwk: intruder.publicJwk } }, parentAgentKey: intruder.privateKey, child });
    expect(await oneHop(token, parent, child)).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID', at: 1 });
  });

  it('rejects a delegation that refers to another parent', async () => {
    const parent = rootMandate();
    const other = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegate(format)({ parent: other, parentAgentKey: agent.privateKey, child });
    expect(await oneHop(token, parent, child)).toMatchObject({ decision: 'DENY', code: 'DELEGATION_PARENT_MISMATCH', at: 1 });
  });

  it('enforces max_depth', async () => {
    const parent = rootMandate(1);
    const child = childOf(parent, sub);
    const grandchild = childOf(child, subsub);
    const t1 = await delegate(format)({ parent, parentAgentKey: agent.privateKey, child });
    await expect(delegate(format)({ parent: child, parentAgentKey: sub.privateKey, child: grandchild })).rejects.toThrow(/sub-delegation/);
    const forged = format === 'jws'
      ? await new SignJWT({ mandate: grandchild, parent_id: child.id, parent_hash: mandateHash(child), iat: nowSeconds() } as any)
          .setProtectedHeader({ alg: 'ES256', typ: DELEGATION_TYP }).sign(sub.privateKey)
      : await issueDelegateSdJwt({ mandate: grandchild, parent_id: child.id, parent_hash: mandateHash(child), iat: nowSeconds() }, sub.privateKey);
    const chain: MandateChain = { root: await wallet.approveMandate(parent), delegations: [t1, forged] };
    const d = await verifyAuthorization(chain, await invoke(chain, subsub, grandchild), opts());
    expect(d).toMatchObject({ decision: 'DENY', code: 'DELEGATION_NOT_ALLOWED', at: 2 });
  });

  it('rejects a chain longer than the maximum depth', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegate(format)({ parent, parentAgentKey: agent.privateKey, child });
    const chain: MandateChain = { root: await wallet.approveMandate(parent), delegations: Array(6).fill(token) };
    expect(await verifyAuthorization(chain, await invoke(chain, sub, child), opts())).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
  });

  it('rejects a forged widening delegation at verification', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub, { limits: { currency: 'EUR', per_operation: 99999, total: 99999 } });
    const p = { mandate: child, parent_id: parent.id, parent_hash: mandateHash(parent), iat: nowSeconds() };
    const forged = format === 'jws'
      ? await new SignJWT(p as any).setProtectedHeader({ alg: 'ES256', typ: DELEGATION_TYP }).sign(agent.privateKey)
      : await issueDelegateSdJwt(p, agent.privateKey);
    expect(await oneHop(forged, parent, child, sub, 90000)).toMatchObject({ decision: 'DENY', code: 'ATTENUATION_VIOLATION', at: 1 });
  });

  it('applies time, revocation and the shared total limit to the child', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegate(format)({ parent, parentAgentKey: agent.privateKey, child });
    const chain: MandateChain = { root: await wallet.approveMandate(parent), delegations: [token] };
    const revocation = new InMemoryRevocationRegistry();
    await revocation.revoke(parent.id);
    expect(await verifyAuthorization(chain, await invoke(chain, sub, child), { ...opts(), revocation })).toMatchObject({ decision: 'DENY', code: 'REVOKED', at: 0 });
    expect(await verifyAuthorization(chain, await invoke(chain, sub, child), { ...opts(), now: child.exp })).toMatchObject({ decision: 'DENY', code: 'EXPIRED', at: 1 });
    const o = opts();
    expect((await verifyAuthorization(chain, await invoke(chain, sub, child, 5000), o)).decision).toBe('ALLOW');
    expect((await verifyAuthorization(chain, await invoke(chain, sub, child, 5000), o)).decision).toBe('ALLOW');
    expect(await verifyAuthorization(chain, await invoke(chain, sub, child, 1), o)).toMatchObject({ decision: 'DENY', code: 'LIMIT_TOTAL' });
  });

  it('rejects an invocation signed by the parent instead of the delegate', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegate(format)({ parent, parentAgentKey: agent.privateKey, child });
    expect(await oneHop(token, parent, child, agent)).toMatchObject({ decision: 'DENY', code: 'INVOCATION_SIGNATURE_INVALID' });
  });
});

describe('mixed chains', () => {
  it.each([
    ['jws', 'sd-jwt'],
    ['sd-jwt', 'jws'],
    ['sd-jwt', 'sd-jwt'],
  ] as const)('accepts a %s link followed by a %s link', async (f1, f2) => {
    const parent = rootMandate(2);
    const child = childOf(parent, sub);
    const grandchild = childOf(child, subsub, { limits: { currency: 'EUR', per_operation: 2000, total: 4000 } });
    const t1 = await delegate(f1)({ parent, parentAgentKey: agent.privateKey, child });
    const t2 = await delegate(f2)({ parent: child, parentAgentKey: sub.privateKey, child: grandchild });
    const chain: MandateChain = { root: await wallet.approveMandate(parent), delegations: [t1, t2] };
    const d = await verifyAuthorization(chain, await invoke(chain, subsub, grandchild, 1500), opts());
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') expect(d.path.map((p) => p.mandate_id)).toEqual([parent.id, child.id, grandchild.id]);
    expect(await verifyAuthorization(chain, await invoke(chain, subsub, grandchild, 2500), opts())).toMatchObject({ decision: 'DENY', code: 'LIMIT_PER_OPERATION', at: 2 });
  });

  it('rejects a mixed chain whose second link is signed by the root agent instead of the sub-agent', async () => {
    const parent = rootMandate(2);
    const child = childOf(parent, sub);
    const grandchild = childOf(child, subsub);
    const t1 = await delegateMandate({ parent, parentAgentKey: agent.privateKey, child });
    const t2 = await issueDelegateSdJwt({ mandate: grandchild, parent_id: child.id, parent_hash: mandateHash(child), iat: nowSeconds() }, agent.privateKey);
    const chain: MandateChain = { root: await wallet.approveMandate(parent), delegations: [t1, t2] };
    expect(await verifyAuthorization(chain, await invoke(chain, subsub, grandchild), opts())).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID', at: 2 });
  });
});

describe('Delegate SD-JWT wire format', () => {
  it('produces <KB-SD-JWT>~<Delegate Payload Disclosure>~ with the child mandate in visible claims', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegateMandateSdJwt({ parent, parentAgentKey: agent.privateKey, child });
    const [jwt, disclosure, tail, ...rest] = token.split('~');
    expect(tail).toBe('');
    expect(rest).toHaveLength(0);
    const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString());
    expect(header).toEqual({ alg: 'ES256', typ: 'kb+sd-jwt+kb' });
    const outer = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    expect(Object.keys(outer).sort()).toEqual(['_sd_alg', 'delegate_payload', 'iat']);
    expect(outer.delegate_payload).toEqual([{ '...': digestOf(disclosure) }]);
    const [salt, dp] = JSON.parse(Buffer.from(disclosure, 'base64url').toString());
    expect(typeof salt).toBe('string');
    expect(dp).toEqual(delegatePayloadFor(parent, child));
    expect(dp.cnf.jwk).toEqual(sub.publicJwk);
    const parsed = parseDelegation(token);
    expect(parsed).toMatchObject({ format: 'sd-jwt', payload: { mandate: child, parent_id: parent.id, parent_hash: mandateHash(parent) } });
  });

  it('accepts the hyphenated typ of the draft section 6 and refuses other typ values', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const dp = delegatePayloadFor(parent, child);
    const hyphen = await craft({ delegatePayload: dp, header: { alg: 'ES256', typ: 'kb-sd-jwt+kb' } });
    expect((await oneHop(hyphen, parent, child)).decision).toBe('ALLOW');
    const withCrit = await craft({ delegatePayload: dp, header: { alg: 'ES256', typ: DELEGATE_SDJWT_TYP, b64: true, crit: ['b64'] } });
    expect(await oneHop(withCrit, parent, child)).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID', at: 1 });
    for (const typ of ['kb+sd-jwt', 'kb+jwt', DELEGATION_TYP, undefined]) {
      const t = await craft({ delegatePayload: dp, header: { alg: 'ES256', ...(typ ? { typ } : {}) } });
      expect(await oneHop(t, parent, child)).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID', at: 1 });
    }
  });

  it('does not accept one format dressed as the other', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    // A JWS with the SD-JWT typ, and a valid JWS delegation with a tilde appended.
    const p = { mandate: child, parent_id: parent.id, parent_hash: mandateHash(parent), iat: nowSeconds() };
    const jwsWithSdTyp = await new SignJWT(p as any).setProtectedHeader({ alg: 'ES256', typ: DELEGATE_SDJWT_TYP }).sign(agent.privateKey);
    expect(await oneHop(jwsWithSdTyp, parent, child)).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID' });
    const jws = await delegateMandate({ parent, parentAgentKey: agent.privateKey, child });
    expect((await oneHop(`${jws}~`, parent, child)).decision).toBe('DENY');
    expect((await oneHop(`${jws}~e30~`, parent, child)).decision).toBe('DENY');
  });

  it('refuses a cnf key that is not the child mandate agent key', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const t = await craft({ delegatePayload: delegatePayloadFor(parent, child, { cnf: { jwk: intruder.publicJwk } }) });
    const d = await oneHop(t, parent, child);
    expect(d).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1 });
    if (d.decision === 'DENY') expect(d.reason).toMatch(/cnf/);
    // Neither may the intruder use it to act, nor may a cnf be missing or carry a private key.
    expect((await oneHop(t, parent, child, intruder)).decision).toBe('DENY');
    const { cnf: _, ...noCnf } = delegatePayloadFor(parent, child);
    expect(await oneHop(await craft({ delegatePayload: noCnf }), parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
    const priv = { ...sub.publicJwk, d: 'AAAA' };
    expect(await oneHop(await craft({ delegatePayload: delegatePayloadFor(parent, child, { cnf: { jwk: priv } }) }), parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
    // The same key with extra members is the same key (RFC 7638 thumbprint).
    const withKid = await craft({ delegatePayload: delegatePayloadFor(parent, child, { cnf: { jwk: { ...sub.publicJwk, kid: 'k1' } } }) });
    expect((await oneHop(withKid, parent, child)).decision).toBe('ALLOW');
  });

  it('refuses a constraint hidden behind an _sd digest, with or without its disclosure', async () => {
    // A parent without counterparty restriction delegates a child restricted to one host, but hides the
    // restriction. A verifier that ignored _sd would see a child valid for every counterparty.
    const parent = rootMandate(2, { counterparties: undefined });
    const child = childOf(parent, sub);
    const { counterparties, ...visible } = child;
    const hidden = b64(canonicalize(['c2FsdHNhbHRzYWx0', 'counterparties', counterparties]));
    const withSd = { ...visible, _sd: [digestOf(hidden)] } as unknown as Mandate;
    const dp = delegatePayloadFor(parent, withSd);
    for (const extra of [[], [hidden]]) {
      const t = await craft({ delegatePayload: dp, extraDisclosures: extra });
      const d = await oneHop(t, parent, withSd);
      expect(d).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(extra.length ? /Disclosure/ : /plainly visible/) });
    }
    const top = await craft({ delegatePayload: { ...delegatePayloadFor(parent, child), _sd: [digestOf(hidden)] } });
    expect(await oneHop(top, parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(/plainly visible/) });
    // Array element digests are refused too.
    const arr = await craft({ delegatePayload: delegatePayloadFor(parent, { ...child, actions: ['travel.book', { '...': digestOf(hidden) }] } as any) });
    expect(await oneHop(arr, parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(/plainly visible/) });
  });

  it('refuses constraints it does not understand and claims outside the profile', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const unknownConstraint = await craft({ delegatePayload: delegatePayloadFor(parent, child, { max_amount: 10 }) });
    expect(await oneHop(unknownConstraint, parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(/max_amount has no meaning/) });
    const disclosure = b64(canonicalize(['s4lt', delegatePayloadFor(parent, child)]));
    for (const extra of [{ sd_hash: 'abc' }, { issuer_jwt_hash: 'abc' }, { aud: AUD }, { exp: child.exp }]) {
      const outer = { iat: nowSeconds(), delegate_payload: [{ '...': digestOf(disclosure) }], ...extra };
      const t = await craft({ delegatePayload: {}, disclosureJson: canonicalize(['s4lt', delegatePayloadFor(parent, child)]), outer });
      expect(await oneHop(t, parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(/not allowed/) });
    }
  });

  it('refuses nbf or exp that differ from the mandate', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    for (const extra of [{ exp: child.exp + 1 }, { nbf: child.nbf - 1 }, { exp: undefined }]) {
      const dp = delegatePayloadFor(parent, child, extra);
      if ('exp' in extra && extra.exp === undefined) delete dp.exp;
      expect(await oneHop(await craft({ delegatePayload: dp }), parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(/nbf and exp/) });
    }
  });

  it('refuses a tampered disclosure', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegateMandateSdJwt({ parent, parentAgentKey: agent.privateKey, child });
    const [jwt, disclosure] = token.split('~');
    const [salt, dp] = JSON.parse(Buffer.from(disclosure, 'base64url').toString());
    dp.plenipo_mandate.actions = ['travel.*'];
    const swapped = `${jwt}~${b64(canonicalize([salt, dp]))}~`;
    expect(await oneHop(swapped, parent, child)).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID', at: 1, reason: expect.stringMatching(/signed digest/) });
    // A disclosure with the same JSON but another salt has another digest.
    const resalted = `${jwt}~${b64(canonicalize(['other', JSON.parse(Buffer.from(disclosure, 'base64url').toString())[1]]))}~`;
    expect(await oneHop(resalted, parent, child)).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID', at: 1 });
  });

  it('refuses non-canonical disclosures, other hash algorithms, decoys and extra disclosures', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const dp = delegatePayloadFor(parent, child);
    const pretty = JSON.stringify(['s4lt', dp], null, 1);
    expect(await oneHop(await craft({ delegatePayload: dp, disclosureJson: pretty }), parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', reason: expect.stringMatching(/canonical/) });
    // Duplicate keys: the last one would win in JSON.parse, another parser could read the first.
    const canon = canonicalize(['s4lt', dp]);
    const dup = canon.replace('"parent_hash"', '"exp":1,"parent_hash"');
    expect(await oneHop(await craft({ delegatePayload: dp, disclosureJson: dup }), parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', reason: expect.stringMatching(/canonical/) });

    const disclosure = b64(canon);
    const signedWith = async (outer: Record<string, unknown>, extra: string[] = []) =>
      oneHop(await craft({ delegatePayload: dp, disclosureJson: canon, outer, extraDisclosures: extra }), parent, child);
    const d = digestOf(disclosure);
    expect(await signedWith({ iat: nowSeconds(), _sd_alg: 'sha-512', delegate_payload: [{ '...': d }] })).toMatchObject({ decision: 'DENY', code: 'MALFORMED', reason: expect.stringMatching(/sha-256/) });
    expect(await signedWith({ iat: nowSeconds(), delegate_payload: [{ '...': d }, { '...': digestOf('decoy') }] })).toMatchObject({ decision: 'DENY', code: 'MALFORMED', reason: expect.stringMatching(/exactly one/) });
    expect(await signedWith({ iat: nowSeconds(), delegate_payload: [dp] })).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
    expect(await signedWith({ iat: nowSeconds(), delegate_payload: { '...': d } })).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
    expect(await signedWith({ delegate_payload: [{ '...': d }] })).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
    expect(await signedWith({ iat: nowSeconds(), delegate_payload: [{ '...': d }] }, [b64('["s","x",1]')])).toMatchObject({ decision: 'DENY', code: 'MALFORMED' });
    // Without _sd_alg the default sha-256 applies (RFC 9901).
    expect((await signedWith({ iat: nowSeconds(), delegate_payload: [{ '...': d }] })).decision).toBe('ALLOW');
  });

  it('refuses a key binding JWT appended to the delegation', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegateMandateSdJwt({ parent, parentAgentKey: agent.privateKey, child });
    const kb = await new SignJWT({ iat: nowSeconds(), aud: AUD, nonce: 'n' }).setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).sign(sub.privateKey);
    expect(await oneHop(token + kb, parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(/<KB-SD-JWT>/) });
    // Nor the draft's full concatenation with the root in front.
    const root = await wallet.approveMandate(parent);
    expect((await oneHop(`${root.presentation}~${token}`, parent, child)).decision).toBe('DENY');
  });

  it('refuses oversized tokens before parsing them', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const big = `${'a'.repeat(MAX_DELEGATION_LENGTH)}~b~`;
    expect(await oneHop(big, parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(/longer than/) });
  });

  it('refuses a deeply nested Delegate Payload', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    let deep: unknown = 'x';
    for (let i = 0; i < 40; i++) deep = [deep];
    const t = await craft({ delegatePayload: delegatePayloadFor(parent, { ...child, purpose: deep } as any) });
    expect(await oneHop(t, parent, child)).toMatchObject({ decision: 'DENY', code: 'MALFORMED', at: 1, reason: expect.stringMatching(/too deep/) });
  });

  it('never throws and never accepts a mutated token', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const token = await delegateMandateSdJwt({ parent, parentAgentKey: agent.privateKey, child });
    const original = await verifyDelegateSdJwt(token, agent.publicJwk);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~{}"[]';
    let seed = 42;
    const rnd = (n: number) => {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      return seed % n;
    };
    for (let i = 0; i < 300; i++) {
      const chars = token.split('');
      const kind = rnd(4);
      let mutated: string;
      if (kind === 0) {
        chars[rnd(chars.length)] = alphabet[rnd(alphabet.length)];
        mutated = chars.join('');
      } else if (kind === 1) {
        mutated = token.slice(0, rnd(token.length));
      } else if (kind === 2) {
        const at = rnd(token.length);
        mutated = token.slice(0, at) + alphabet[rnd(alphabet.length)] + token.slice(at);
      } else {
        chars.splice(rnd(chars.length), 1);
        mutated = chars.join('');
      }
      if (mutated === token) continue;
      try {
        // Base64url has spare bits in the last character of a segment, so a few mutations decode to the same bytes.
        const res = await verifyDelegateSdJwt(mutated, agent.publicJwk);
        expect(res).toEqual(original);
      } catch (e) {
        expect(e).toBeInstanceOf(DelegationError);
      }
    }
    for (const junk of ['~', '~~', 'a~b~', '..~..~', `${token}${token}`, '\u0000~\u0000~', 'e30.e30.e30~e30~']) {
      const d = await oneHop(junk, parent, child);
      expect(d.decision).toBe('DENY');
      if (d.decision === 'DENY') expect(['MALFORMED', 'DELEGATION_SIGNATURE_INVALID']).toContain(d.code);
    }
    const nonString = { root: await wallet.approveMandate(parent), delegations: [42 as unknown as string] };
    expect(await verifyAuthorization(nonString, await invoke(nonString, sub, child), opts())).toMatchObject({ decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID' });
  });
});

describe('parseDelegation', () => {
  it('detects the format and decodes without verifying', async () => {
    const parent = rootMandate();
    const child = childOf(parent, sub);
    const jws = await delegateMandate({ parent, parentAgentKey: agent.privateKey, child });
    expect(parseDelegation(jws)).toMatchObject({ format: 'jws', header: { typ: DELEGATION_TYP }, payload: { mandate: child } });
    const sd = await delegateMandateSdJwt({ parent, parentAgentKey: intruder.privateKey, child });
    expect(parseDelegation(sd)).toMatchObject({ format: 'sd-jwt', header: { typ: DELEGATE_SDJWT_TYP }, payload: { mandate: child }, cnf: { jwk: sub.publicJwk } });
    expect(() => parseDelegation('')).toThrow();
    expect(() => parseDelegation('a~b')).toThrow();
    expect(() => parseDelegation('not a jws')).toThrow();
  });
});

describe('OpenID4VP delegate transaction data (draft section 7.1)', () => {
  it('builds the transaction data and the digest the wallet must sign', () => {
    const cnf: { jwk: JWK } = { jwk: sub.publicJwk };
    const { transactionData, encoded, delegatePayloadDigest } = createDelegateTransactionData({
      credentialIds: ['pid'],
      delegatePayload: { cnf, merchant: 'rail.example' },
    });
    expect(transactionData).toMatchObject({ type: 'delegate', credential_ids: ['pid'], format: 'dSD-JWT+KB' });
    expect(transactionData).not.toHaveProperty('delegate_disclosures');
    const [salt, payload] = JSON.parse(Buffer.from(transactionData.delegate_payload_disclosure, 'base64url').toString());
    expect(typeof salt).toBe('string');
    expect(payload).toEqual({ cnf, merchant: 'rail.example' });
    expect(delegatePayloadDigest).toBe(digestOf(transactionData.delegate_payload_disclosure));
    expect(JSON.parse(Buffer.from(encoded, 'base64url').toString())).toEqual(transactionData);
  });

  it('validates its input', () => {
    expect(() => createDelegateTransactionData({ credentialIds: [], delegatePayload: {} })).toThrow(/credentialIds/);
    expect(() => createDelegateTransactionData({ credentialIds: ['pid'], delegatePayload: [] as any })).toThrow(/object/);
    expect(() => createDelegateTransactionData({ credentialIds: ['pid'], delegatePayload: {} })).toThrow(/cnf/);
    expect(() => createDelegateTransactionData({ credentialIds: ['pid'], delegatePayload: {}, format: 'x' as any })).toThrow(/format/);
    expect(() => createDelegateTransactionData({ credentialIds: ['pid'], delegatePayload: {}, format: 'dSD-JWT', delegateDisclosures: ['a b'] })).toThrow(/base64url/);
    const ok = createDelegateTransactionData({ credentialIds: ['pid'], delegatePayload: {}, format: 'dSD-JWT', delegateDisclosures: ['WyJzIiwieCIsMV0'] });
    expect(ok.transactionData.delegate_disclosures).toEqual(['WyJzIiwieCIsMV0']);
  });
});
