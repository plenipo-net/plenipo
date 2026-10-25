import { createHash } from 'node:crypto';
import { compactDecrypt } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  createInvocation,
  createMandate,
  createMandateRequest,
  delegateMandate,
  generateAgentKey,
  handleMandateResponse,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  mandateHash,
  nowSeconds,
  verifyAuthorization,
  verifyRoot,
  EMANDATE_TX_DATA_TYPE,
  type AgentKey,
  type Mandate,
  type MandateChain,
  type MandateRequest,
  type MandateRequestOptions,
  type MandateResponseOptions,
  type RootAuthorization,
  type StatusFetcher,
  type VerifyOptions,
} from '../src/index.js';
import {
  createLegalMandate,
  decodeCanonical,
  describeMandate,
  emandateViolations,
  encodeEmandateTransactionData,
  mandateToEmandate,
  parseDateTime,
  rolePowerViolations,
  toMajorUnits,
  toMinorUnits,
  type EmandatePayload,
  type RepresentationClaims,
} from '../src/experimental.js';
import {
  createTestPidProvider,
  createTestRegister,
  createTestScaIssuer,
  createTestWallet,
  TEST_SCA_VCT,
  type TestAttestationIssuer,
  type TestPidProvider,
  type TestRegister,
  type TestWallet,
  type WalletRequestPolicy,
} from '../src/testing.js';

const AUD = 'https://pay.example';
const CLIENT_ID = 'x509_san_dns:agents.example';
const RESPONSE_URI = 'https://agents.example/response';
const EUID = 'ITRM.RM1234567';
const DAY = 24 * 3600;

let agent: AgentKey;
let provider: TestPidProvider;
let bank: TestAttestationIssuer & { transactionDataTypes: string[] };
let register: TestRegister;
let rogueRegister: TestRegister;
let wallet: TestWallet;
let statusFetcher: StatusFetcher;

const representationClaims = (over: Partial<RepresentationClaims> = {}): RepresentationClaims => ({
  legal_person_id: EUID,
  legal_person_name: 'Acme S.p.A.',
  representative: { given_name: 'Mario', family_name: 'Rossi' },
  role: { code: 'managing_director', name: 'Amministratore delegato', basis: 'legal_representation', valid_until: nowSeconds() + 180 * DAY },
  powers: { actions: ['payments.*', 'travel.*'], limits: { currency: 'EUR', per_operation: 100000, total: 500000 }, max_delegation_depth: 2 },
  ...over,
});

async function newWallet(opts: { emandateOnPid?: boolean; sca?: boolean } = {}): Promise<TestWallet> {
  const w = await createTestWallet({ emandateOnPid: opts.emandateOnPid });
  w.storePid(await provider.issuePid(w.holderJwk, { given_name: 'Mario', family_name: 'Rossi', birthdate: '1980-01-01' }));
  if (opts.sca !== false) {
    // Bound to the PID holder key: the strongest SCA-to-PID binding. Other keys are tested separately.
    w.storeCredential(await bank.issue(w.holderJwk, { iban: 'IT60X0542811101000000123456' }), { transactionDataTypes: bank.transactionDataTypes });
  }
  return w;
}

beforeAll(async () => {
  agent = await generateAgentKey();
  provider = await createTestPidProvider('https://pid.test');
  bank = await createTestScaIssuer('https://bank.test', { statusList: true });
  register = await createTestRegister('https://register.test');
  rogueRegister = await createTestRegister('https://rogue-register.test');
  statusFetcher = async (uri) => {
    for (const i of [bank, register, rogueRegister]) if (uri.startsWith(`${i.iss}/`)) return i.statusFetcher(uri);
    throw new Error('unknown status list');
  };
  wallet = await newWallet();
});

function mandate(over: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.sepa'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
    purpose: 'Pay the shop invoices',
    maxDepth: 1,
    ...over,
  });
}

function legalMandate(over: Partial<Parameters<typeof createMandate>[0]> = {}, principal: Record<string, unknown> = {}): Mandate {
  return createLegalMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.sepa'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
    ...over,
    principal: { type: 'legal_person', euid: EUID, role: 'managing_director', ...principal } as any,
  });
}

function emandateTrust() {
  return { scaTrust: { trustedIssuers: [bank.trusted] }, scaVcts: [TEST_SCA_VCT] };
}
function representationTrust(extra: Record<string, unknown> = {}) {
  return { trust: { trustedIssuers: [register.trusted] }, ...extra };
}

function responseOptions(over: Partial<MandateResponseOptions> = {}): MandateResponseOptions {
  return {
    trustedIssuers: [provider.trusted],
    now: nowSeconds(),
    sessions: new InMemoryNonceStore(),
    statusFetcher,
    emandate: emandateTrust(),
    representation: representationTrust(),
    ...over,
  };
}

function verifyOptions(over: Partial<VerifyOptions> = {}): VerifyOptions {
  return {
    trustedIssuers: [provider.trusted],
    audience: AUD,
    nonces: new InMemoryNonceStore(),
    ledger: new InMemorySpendingLedger(),
    statusFetcher,
    emandate: emandateTrust(),
    representation: representationTrust(),
    ...over,
  };
}

function request(m: Mandate, over: Partial<MandateRequestOptions> = {}): Promise<MandateRequest> {
  return createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: RESPONSE_URI, ...over });
}

const emandateRequest = (m: Mandate, over: Partial<MandateRequestOptions> = {}) =>
  request(m, { transactionDataType: 'emandate', emandate: { scaVcts: [TEST_SCA_VCT] }, ...over });

/** Replaces the transaction data of a request, as a malicious or buggy platform would. */
function setTransactionData(req: MandateRequest, td: string): void {
  (req.params.transaction_data as string[])[0] = td;
  req.session.transactionData = td;
}

function payloadOf(req: MandateRequest): EmandatePayload {
  return decodeCanonical((req.params.transaction_data as string[])[0])!.payload as EmandatePayload;
}

async function obtain(
  req: MandateRequest,
  opts: { wallet?: TestWallet; policy?: WalletRequestPolicy; response?: Partial<MandateResponseOptions> } = {},
) {
  const body = await (opts.wallet ?? wallet).respond(req.params, opts.policy);
  return handleMandateResponse(body, req.session, responseOptions(opts.response));
}

function invocation(chain: MandateChain, m: Mandate, value = 1000, action = 'payments.sepa') {
  return createInvocation(agent.privateKey, { chain,
    mandateId: m.id,
    action,
    counterparty: 'shop.example',
    amount: { value, currency: 'EUR' },
    aud: AUD,
  });
}

async function verify(root: RootAuthorization, m: Mandate, over: Partial<VerifyOptions> = {}, delegations: string[] = []) {
  const chain: MandateChain = { root, delegations };
  return verifyAuthorization(chain, await invocation(chain, m), verifyOptions(over));
}

describe('TS12 mapping', () => {
  it('maps limits, dates, payee and the mandate hash', () => {
    const m = mandate();
    const p = mandateToEmandate(m);
    expect(p.transaction_id).toBe(m.id);
    expect(p.reference_number).toBe(mandateHash(m));
    expect(parseDateTime(p.start_date)).toBe(m.nbf);
    expect(parseDateTime(p.end_date)).toBe(m.exp);
    expect(p.purpose).toBe(describeMandate(m));
    expect(p.purpose).toContain('payments.sepa');
    expect(p.purpose).toContain('150.00 EUR per operation');
    expect(p.purpose).toContain('Sub-delegation: up to 1 level.');
    expect(p.payment_payload).toMatchObject({
      payee: { name: 'shop.example', id: 'shop.example', website: 'https://shop.example' },
      currency: 'EUR',
      amount: 150,
      recurrence: { frequency: 'INDA', mit_options: { amount_variable: true, max_amount: 150, total_amount: 300 } },
    });
    expect(emandateViolations(p, m)).toEqual([]);
  });

  it('shows no payee when there are several counterparties, and keeps the limits in the purpose', () => {
    const m = mandate({ counterparties: ['shop.example', 'other.example'] });
    const p = mandateToEmandate(m);
    expect(p.payment_payload).toBeUndefined();
    expect(p.purpose).toContain('shop.example, other.example');
    expect(p.purpose).toContain('300.00 EUR in total');
  });

  it('names the legal person in the purpose', () => {
    expect(describeMandate(legalMandate())).toMatch(/^On behalf of legal person ITRM\.RM1234567 as managing_director\./);
  });

  it('refuses mandates it cannot show faithfully', () => {
    expect(() => mandateToEmandate(mandate({ id: 'x'.repeat(37) }))).toThrow(/transaction_id/);
    expect(() => mandateToEmandate(mandate({ purpose: 'p'.repeat(1001) }))).toThrow(/purpose/);
    // A payee that does not cover the counterparties would show less than the mandate allows.
    expect(() => mandateToEmandate(mandate(), { payee: { name: 'Other', id: 'other.example' } })).toThrow(/not cover/);
  });

  it('converts amounts exactly or not at all', () => {
    expect(toMinorUnits(89.5, 'EUR')).toBe(8950);
    expect(toMinorUnits(150, 'EUR')).toBe(15000);
    expect(toMinorUnits(0.29, 'EUR')).toBe(29);
    expect(toMinorUnits(0.1 + 0.2, 'EUR')).toBeUndefined();
    expect(toMinorUnits(1.005, 'EUR')).toBeUndefined();
    expect(toMinorUnits(-1, 'EUR')).toBeUndefined();
    expect(toMinorUnits(1e21, 'EUR')).toBeUndefined();
    expect(toMinorUnits(Number.NaN, 'EUR')).toBeUndefined();
    expect(toMinorUnits('150' as unknown, 'EUR')).toBeUndefined();
    expect(toMinorUnits(1500, 'JPY')).toBe(1500);
    expect(toMinorUnits(1.5, 'JPY')).toBeUndefined();
    expect(toMinorUnits(1.234, 'BHD')).toBe(1234);
    expect(toMajorUnits(8950, 'EUR')).toBe(89.5);
    expect(toMajorUnits(5, 'EUR')).toBe(0.05);
  });

  it('accepts only date-times with an offset', () => {
    expect(parseDateTime('2026-10-19T10:00:00Z')).toBe(Date.UTC(2026, 9, 19, 10) / 1000);
    expect(parseDateTime('2026-10-19T12:00:00+02:00')).toBe(Date.UTC(2026, 9, 19, 10) / 1000);
    expect(parseDateTime('2026-10-19')).toBeUndefined();
    expect(parseDateTime('2026-10-19T10:00:00')).toBeUndefined();
    expect(parseDateTime('2026-02-30T10:00:00Z')).toBeUndefined();
  });
});

describe('the mandate must not be broader than the e-mandate shown', () => {
  const m = () => mandate();
  const cases: Array<[string, (p: any) => void, RegExp]> = [
    ['per-operation amount', (p) => (p.payment_payload.recurrence.mit_options.max_amount = 100), /per operation/],
    ['total amount', (p) => (p.payment_payload.recurrence.mit_options.total_amount = 200), /total/],
    ['single fixed payment', (p) => delete p.payment_payload.recurrence, /total/],
    ['start date', (p) => (p.start_date = new Date(Date.now() + DAY * 1000).toISOString()), /starts before/],
    ['start date by a fraction of a second', (p) => (p.start_date = p.start_date.replace('Z', '.5Z')), /starts before/],
    ['end date', (p) => (p.end_date = new Date(Date.now() + DAY * 1000).toISOString()), /ends after/],
    ['recurrence start date', (p) => (p.payment_payload.recurrence.start_date = new Date(Date.now() + DAY * 1000).toISOString()), /starts before/],
    ['recurrence end date', (p) => (p.payment_payload.recurrence.end_date = new Date(Date.now() + DAY * 1000).toISOString()), /ends after/],
    ['payee', (p) => (p.payment_payload.payee = { name: 'Other', id: 'other.example' }), /not covered by the payee/],
    ['payee id that cannot be enforced', (p) => (p.payment_payload.payee = { name: 'Shop', id: 'IT60X0542811101000000123456' }), /payee.id/],
    ['currency', (p) => (p.payment_payload.currency = 'USD'), /EUR/],
    ['purpose', (p) => (p.purpose = 'Pay one invoice of 10 euro'), /purpose/],
    ['frequency', (p) => (p.payment_payload.recurrence.frequency = 'MNTH'), /INDA/],
    ['number of payments', (p) => (p.payment_payload.recurrence.number = 1), /not enforced/],
    ['execution date', (p) => (p.payment_payload.execution_date = '2026-12-01T00:00:00Z'), /not enforced/],
    ['minimum amount', (p) => (p.payment_payload.recurrence.mit_options.min_amount = 1), /not enforced/],
    ['SEPA creditor', (p) => (p.creditor_id = 'FR14ZZZ001122334455'), /not enforced/],
  ];
  for (const [name, mutate, message] of cases) {
    it(`detects a narrower ${name}`, () => {
      const mm = m();
      const p = structuredClone(mandateToEmandate(mm)) as any;
      mutate(p);
      const v = emandateViolations(p, mm);
      expect(v.some((x) => x.kind === 'display' && message.test(x.message))).toBe(true);
    });
  }

  it('detects a mandate without limits shown with amounts', () => {
    const limited = mandate();
    const p = mandateToEmandate(limited);
    const unlimited = { ...limited, limits: undefined };
    delete unlimited.limits;
    const v = emandateViolations({ ...p, purpose: describeMandate(unlimited), reference_number: mandateHash(unlimited) }, unlimited);
    expect(v.map((x) => x.message).join()).toMatch(/no spending limits/);
  });

  it('detects a mandate open to any counterparty shown with one payee', () => {
    const base = mandate();
    const any = { ...base };
    delete any.counterparties;
    const p = { ...mandateToEmandate(base), purpose: describeMandate(any), reference_number: mandateHash(any) };
    expect(emandateViolations(p, any).map((x) => x.message).join()).toMatch(/any counterparty/);
  });

  it('accepts a display wider than the mandate', () => {
    const mm = m();
    const p = structuredClone(mandateToEmandate(mm)) as any;
    p.payment_payload.recurrence.mit_options.max_amount = 500;
    p.payment_payload.recurrence.mit_options.total_amount = 1000;
    p.payment_payload.payee = { name: '*.example', id: '*.example' };
    p.start_date = '2020-01-01T00:00:00Z';
    delete p.end_date;
    expect(emandateViolations(p, mm)).toEqual([]);
  });

  it('reports binding problems separately from display problems', () => {
    const mm = m();
    const p = { ...mandateToEmandate(mm), reference_number: mandateHash(mandate()) };
    expect(emandateViolations(p, mm)).toEqual([expect.objectContaining({ kind: 'binding', field: 'reference_number' })]);
    const q = { ...mandateToEmandate(mm), transaction_id: 'another-id' };
    expect(emandateViolations(q, mm).some((x) => x.kind === 'binding' && x.field === 'transaction_id')).toBe(true);
    const r: any = { ...mandateToEmandate(mm) };
    delete r.reference_number;
    expect(emandateViolations(r, mm).some((x) => x.kind === 'binding')).toBe(true);
  });

  it('rejects amounts that cannot be converted exactly', () => {
    const mm = m();
    const p = structuredClone(mandateToEmandate(mm)) as any;
    p.payment_payload.recurrence.mit_options.max_amount = 150.001;
    expect(emandateViolations(p, mm).some((x) => x.kind === 'shape')).toBe(true);
    p.payment_payload.recurrence.mit_options.max_amount = 150;
    p.payment_payload.amount = -150;
    expect(emandateViolations(p, mm).some((x) => x.kind === 'shape')).toBe(true);
  });
});

describe('roots in both forms', () => {
  it('keeps the plenipo_mandate form unchanged', async () => {
    const m = mandate();
    const req = await request(m);
    expect((req.params.dcql_query as any).credentials).toHaveLength(1);
    const { root } = await obtain(req);
    expect(root.mandate).toBeUndefined();
    expect(root.presentations).toBeUndefined();
    const d = await verify(root, m);
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') {
      expect(d.principal).toEqual({ given_name: 'Mario', family_name: 'Rossi' });
      expect(d.root_binding).toBeUndefined();
    }
  });

  it('round-trips a TS12 e-mandate bound to an SCA attestation', async () => {
    const m = mandate();
    const req = await emandateRequest(m);
    const dcql = (req.params.dcql_query as any).credentials;
    expect(dcql.map((q: any) => q.id)).toEqual(['pid', 'sca']);
    const td = decodeCanonical((req.params.transaction_data as string[])[0])!;
    expect(td).toMatchObject({ type: EMANDATE_TX_DATA_TYPE, credential_ids: ['sca'], transaction_data_hashes_alg: ['sha-256'] });
    expect(JSON.stringify(td)).not.toContain('"agent"');

    const { root, verified } = await obtain(req);
    expect(root.mandate).toEqual(m);
    expect(Object.keys(root.presentations!)).toEqual(['sca']);
    expect(verified.binding).toMatchObject({ type: EMANDATE_TX_DATA_TYPE, credential: 'sca', sca_issuer: bank.iss, sca_holder_binding: 'cnf' });

    const d = await verify(root, m);
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') {
      expect(d.root_binding?.credential).toBe('sca');
      expect(d.root_binding?.authentication_code).toMatch(/^[0-9a-f-]{36}$/);
      expect(d.principal).toEqual({ given_name: 'Mario', family_name: 'Rossi' });
    }
  });

  it('round-trips a TS12 e-mandate bound to the PID, with a wallet configured for it', async () => {
    const w = await newWallet({ emandateOnPid: true, sca: false });
    const m = mandate();
    const req = await emandateRequest(m, { emandate: { credential: 'pid' } });
    expect((req.params.dcql_query as any).credentials).toHaveLength(1);
    const { root } = await obtain(req, { wallet: w });
    expect(root.presentations).toBeUndefined();
    const d = await verify(root, m);
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') expect(d.root_binding).toEqual({ type: EMANDATE_TX_DATA_TYPE, credential: 'pid' });
    // Without the emandate option the same root is refused: e-mandates are opt-in.
    expect(await verify(root, m, { emandate: undefined })).toMatchObject({ decision: 'DENY', code: 'ROOT_POLICY', at: 0 });
  });

  it('a TS12 wallet refuses an e-mandate bound to the PID', async () => {
    const req = await emandateRequest(mandate(), { emandate: { credential: 'pid' } });
    expect(await wallet.respond(req.params)).toMatchObject({ error: 'invalid_transaction_data' });
  });

  it('still rejects unknown transaction data types, in the wallet and in the verifier', async () => {
    const m = mandate();
    const req = await emandateRequest(m);
    const td = encodeEmandateTransactionData(mandateToEmandate(m), { type: 'urn:example:unknown:1' });
    setTransactionData(req, td);
    expect(await wallet.respond(req.params)).toMatchObject({ error: 'invalid_transaction_data' });
    // A wallet that signs it anyway does not get it past the verifier.
    const { root } = await obtain(await emandateRequest(m));
    const d = await verify({ ...root, transaction_data: td }, m);
    expect(d).toMatchObject({ decision: 'DENY', code: 'TX_DATA_MISMATCH' });
  });

  it('a payload that breaks the TS12 schema is refused by the wallet', async () => {
    const m = mandate();
    const req = await emandateRequest(m);
    setTransactionData(req, encodeEmandateTransactionData({ ...mandateToEmandate(m), extra: 1 } as any));
    expect(await wallet.respond(req.params)).toMatchObject({ error: 'invalid_transaction_data' });
  });

  it('allows delegation below an e-mandate root', async () => {
    const m = mandate();
    const { root } = await obtain(await emandateRequest(m));
    const sub = await generateAgentKey();
    const child = createMandate({
      agentJwk: sub.publicJwk,
      actions: ['payments.sepa'],
      counterparties: ['shop.example'],
      limits: { currency: 'EUR', per_operation: 5000, total: 10000 },
      nbf: m.nbf,
      exp: m.exp,
    });
    const jws = await delegateMandate({ parent: m, parentAgentKey: agent.privateKey, child });
    const chain = { root, delegations: [jws] };
    const inv = await createInvocation(sub.privateKey, { chain, mandateId: child.id, action: 'payments.sepa', counterparty: 'shop.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, verifyOptions());
    expect(d.decision).toBe('ALLOW');
  });
});

describe('e-mandate binding and display attacks', () => {
  it('rejects a reference_number that binds another mandate', async () => {
    const m = mandate();
    const req = await emandateRequest(m);
    setTransactionData(req, encodeEmandateTransactionData({ ...payloadOf(req), reference_number: mandateHash(mandate()) }));
    await expect(obtain(req)).rejects.toMatchObject({ code: 'TX_DATA_MISMATCH' });
  });

  it('rejects a root whose mandate was swapped after approval', async () => {
    const m = mandate();
    const { root } = await obtain(await emandateRequest(m));
    const wider = { ...m, limits: { currency: 'EUR', per_operation: 999999, total: 999999 } };
    const d = await verify({ ...root, mandate: wider }, wider);
    expect(d).toMatchObject({ decision: 'DENY', code: 'TX_DATA_MISMATCH' });
  });

  it('rejects an approved e-mandate that shows less than the mandate allows', async () => {
    const m = mandate();
    const req = await emandateRequest(m);
    const p = structuredClone(payloadOf(req)) as any;
    p.payment_payload.recurrence.mit_options.max_amount = 10;
    setTransactionData(req, encodeEmandateTransactionData(p));
    // The wallet shows and signs it: the person approved 10 euro per payment.
    await expect(obtain(req)).rejects.toMatchObject({ code: 'DISPLAY_MISMATCH' });
  });

  it('denies the same narrower display at verification time', async () => {
    const m = mandate();
    const req = await emandateRequest(m);
    const p = structuredClone(payloadOf(req)) as any;
    p.end_date = new Date((m.exp - DAY) * 1000).toISOString();
    setTransactionData(req, encodeEmandateTransactionData(p));
    const body = await wallet.respond(req.params);
    // Skip the response handler to check that verifyAuthorization enforces the rule on its own.
    const root = await rootFromBody(body, req);
    const d = await verify(root, m);
    expect(d).toMatchObject({ decision: 'DENY', code: 'DISPLAY_MISMATCH' });
  });

  it('rejects an SCA key binding that does not sign the transaction data', async () => {
    const req = await emandateRequest(mandate());
    const policy: WalletRequestPolicy = { tamperKeyBinding: (id, kb) => id === 'sca' && delete kb.transaction_data_hashes };
    await expect(obtain(req, { policy })).rejects.toMatchObject({ code: 'TX_DATA_MISMATCH' });
  });

  it('rejects a PID key binding over the e-mandate when it is bound to the SCA attestation', async () => {
    // The wallet signs with the PID only: the SCA presentation carries no hash.
    const req = await emandateRequest(mandate());
    const policy: WalletRequestPolicy = {
      tamperKeyBinding: (id, kb) => {
        if (id === 'pid') kb.transaction_data_hashes = (req.params.transaction_data as string[]).map((t) => sha(t));
        if (id === 'sca') delete kb.transaction_data_hashes;
      },
    };
    await expect(obtain(req, { policy })).rejects.toMatchObject({ code: 'TX_DATA_MISMATCH' });
  });

  it('requires the TS12 key binding claims of the SCA presentation', async () => {
    for (const tamper of [(kb: any) => delete kb.amr, (kb: any) => (kb.amr = [{ knowledge: 'pin' }, { knowledge: 'pattern' }]), (kb: any) => delete kb.jti]) {
      const req = await emandateRequest(mandate());
      await expect(obtain(req, { policy: { tamperKeyBinding: (id, kb) => id === 'sca' && tamper(kb) } })).rejects.toMatchObject({
        code: 'ATTESTATION_INVALID',
      });
    }
  });

  it('rejects an SCA key binding for another response mode', async () => {
    const req = await emandateRequest(mandate());
    const policy: WalletRequestPolicy = { tamperKeyBinding: (id, kb) => id === 'sca' && (kb.response_mode = 'direct_post') };
    await expect(obtain(req, { policy })).rejects.toThrow(/response mode/);
  });

  it('rejects an SCA presentation taken from another request', async () => {
    const m = mandate();
    const first = await obtain(await emandateRequest(m));
    const second = await obtain(await emandateRequest(m));
    const spliced = { ...second.root, presentations: { sca: first.root.presentations!.sca } };
    const d = await verify(spliced, m);
    expect(d).toMatchObject({ decision: 'DENY', code: 'ATTESTATION_INVALID' });
  });

  it('ties an SCA attestation on another key to the PID only by claims or by explicit opt-in', async () => {
    const w = await newWallet({ sca: false });
    const key = await w.generateHolderKey();
    w.storeCredential(await bank.issue(key, { given_name: 'Mario', family_name: 'Rossi' }, { disclosable: ['given_name', 'family_name'] }), {
      transactionDataTypes: bank.transactionDataTypes,
    });
    const m = mandate();
    await expect(obtain(await emandateRequest(m), { wallet: w })).rejects.toThrow(/another holder key/);

    const byClaims = { ...emandateTrust(), scaIdentityClaims: ['given_name', 'family_name'] };
    const req = await emandateRequest(m, { emandate: { scaVcts: [TEST_SCA_VCT], scaIdentityClaims: ['given_name', 'family_name'] } });
    const { root, verified } = await obtain(req, { wallet: w, response: { emandate: byClaims } });
    expect(verified.binding?.sca_holder_binding).toBe('claims');
    expect((await verify(root, m, { emandate: byClaims })).decision).toBe('ALLOW');

    const weak = { ...emandateTrust(), scaSameResponseBinding: true };
    const second = await obtain(await emandateRequest(m), { wallet: w, response: { emandate: weak } });
    expect(second.verified.binding?.sca_holder_binding).toBe('same_response');
  });

  it("does not let a platform pair one person's PID with another person's SCA approval", async () => {
    // Alice and Mallory both answer the same request (same nonce and audience), e.g. Alice believing it is a login.
    const alice = await newWallet({ sca: false });
    const aliceKey = await alice.generateHolderKey();
    alice.storeCredential(await bank.issue(aliceKey, { given_name: 'Mario', family_name: 'Rossi' }, { disclosable: ['given_name', 'family_name'] }), {
      transactionDataTypes: bank.transactionDataTypes,
    });
    const mallory = await createTestWallet();
    mallory.storePid(await provider.issuePid(mallory.holderJwk, { given_name: 'Mallory', family_name: 'Malvagi' }));
    const malloryKey = await mallory.generateHolderKey();
    mallory.storeCredential(await bank.issue(malloryKey, { given_name: 'Mallory', family_name: 'Malvagi' }, { disclosable: ['given_name', 'family_name'] }), {
      transactionDataTypes: bank.transactionDataTypes,
    });
    const m = mandate();
    const ids = ['given_name', 'family_name'];
    const req = await emandateRequest(m, { encryptResponse: false, emandate: { scaVcts: [TEST_SCA_VCT], scaIdentityClaims: ids } });
    const fromAlice = (await alice.respond(req.params)).vp_token as Record<string, string[]>;
    const fromMallory = (await mallory.respond(req.params)).vp_token as Record<string, string[]>;
    const spliced: RootAuthorization = {
      transaction_data: req.session.transactionData,
      presentation: fromAlice.pid[0],
      mandate: m,
      presentations: { sca: fromMallory.sca[0] },
    };
    expect(await verify(spliced, m)).toMatchObject({ decision: 'DENY', code: 'ATTESTATION_INVALID' });
    expect(await verify(spliced, m, { emandate: { ...emandateTrust(), scaIdentityClaims: ids } })).toMatchObject({
      decision: 'DENY',
      code: 'ATTESTATION_INVALID',
      reason: expect.stringMatching(/another person/),
    });
    // Identity claims that do not match are never overridden by the weak binding.
    expect(await verify(spliced, m, { emandate: { ...emandateTrust(), scaIdentityClaims: ids, scaSameResponseBinding: true } })).toMatchObject({
      decision: 'DENY',
    });
    // The documented weakness: with same-response binding alone the pair is accepted, and the decision says so.
    const weak = await verify(spliced, m, { emandate: { ...emandateTrust(), scaSameResponseBinding: true } });
    expect(weak.decision).toBe('ALLOW');
    if (weak.decision === 'ALLOW') expect(weak.root_binding?.sca_holder_binding).toBe('same_response');
  });

  it('rejects an SCA attestation from an untrusted bank', async () => {
    const rogue = await createTestScaIssuer('https://rogue-bank.test');
    const w = await newWallet({ sca: false });
    w.storeCredential(await rogue.issue(w.holderJwk, {}), { transactionDataTypes: rogue.transactionDataTypes });
    await expect(obtain(await emandateRequest(mandate()), { wallet: w })).rejects.toMatchObject({ code: 'ATTESTATION_UNTRUSTED' });
  });

  it('rejects a revoked SCA attestation, at approval and at verification', async () => {
    const w = await newWallet({ sca: false });
    w.storeCredential(await bank.issue(w.holderJwk, {}), { transactionDataTypes: bank.transactionDataTypes });
    const ref = bank.lastStatus!;
    const m = mandate();
    const { root } = await obtain(await emandateRequest(m), { wallet: w });
    bank.statusList!.revoke(ref);
    try {
      await expect(obtain(await emandateRequest(m), { wallet: w })).rejects.toMatchObject({ code: 'ATTESTATION_REVOKED' });
      expect(await verify(root, m)).toMatchObject({ decision: 'DENY', code: 'ATTESTATION_REVOKED' });
    } finally {
      bank.statusList!.reinstate(ref);
    }
  });

  it('needs SCA trust to accept e-mandates bound to an SCA attestation', async () => {
    const m = mandate();
    const req = await emandateRequest(m);
    await expect(obtain(req, { response: { emandate: {} } })).rejects.toMatchObject({ code: 'CONFIGURATION' });
    const { root } = await obtain(await emandateRequest(m));
    expect(await verify(root, m, { emandate: {} })).toMatchObject({ decision: 'DENY', code: 'CONFIGURATION' });
    // Experimental: a verifier that is not configured for e-mandates refuses them outright.
    expect(await verify(root, m, { emandate: undefined })).toMatchObject({ decision: 'DENY', code: 'ROOT_POLICY' });
  });

  it('applies the relying party policy on e-mandate roots', async () => {
    const m = mandate({ actions: ['payments.sepa', 'admin.users'] });
    const { root } = await obtain(await emandateRequest(m));
    const em = emandateTrust();
    expect(await verify(root, m, { emandate: { ...em, allowedActions: ['payments.*'] } })).toMatchObject({ decision: 'DENY', code: 'ROOT_POLICY' });
    expect((await verify(root, m, { emandate: { ...em, allowedActions: ['payments.*', 'admin.*'] } })).decision).toBe('ALLOW');
    expect(await verify(root, m, { emandate: { ...em, maxDelegationDepth: 0 } })).toMatchObject({ decision: 'DENY', code: 'ROOT_POLICY' });
    expect(await verify(root, m, { emandate: { ...em, refuse: true } })).toMatchObject({ decision: 'DENY', code: 'ROOT_POLICY' });
  });

  it('a wildcard action is not covered by a narrower allow-list', async () => {
    const m = mandate({ actions: ['*'] });
    const { root } = await obtain(await emandateRequest(m));
    expect(await verify(root, m, { emandate: { ...emandateTrust(), allowedActions: ['payments.*'] } })).toMatchObject({ code: 'ROOT_POLICY' });
  });

  it('can refuse PID-bound e-mandates', async () => {
    const w = await newWallet({ emandateOnPid: true, sca: false });
    const m = mandate();
    const { root } = await obtain(await emandateRequest(m, { emandate: { credential: 'pid' } }), { wallet: w });
    expect(await verify(root, m, { emandate: { ...emandateTrust(), allowPidBinding: false } })).toMatchObject({ code: 'ROOT_POLICY' });
  });

  it('with purposeCheck none, a purpose that hides actions passes only under the allow-list', async () => {
    const m = mandate({ actions: ['payments.*'] });
    const req = await emandateRequest(m);
    setTransactionData(req, encodeEmandateTransactionData({ ...payloadOf(req), purpose: 'Pay shop invoices' }));
    await expect(obtain(req)).rejects.toMatchObject({ code: 'DISPLAY_MISMATCH' });
    // purposeCheck 'none' is refused unless the service bounds actions and depth itself.
    const unbounded = await emandateRequest(m);
    setTransactionData(unbounded, encodeEmandateTransactionData({ ...payloadOf(unbounded), purpose: 'Pay shop invoices' }));
    await expect(obtain(unbounded, { response: { emandate: { ...emandateTrust(), purposeCheck: 'none' } } })).rejects.toMatchObject({ code: 'CONFIGURATION' });
    const relaxed = { ...emandateTrust(), purposeCheck: 'none' as const, maxDelegationDepth: 1 };
    const req2 = await emandateRequest(m);
    setTransactionData(req2, encodeEmandateTransactionData({ ...payloadOf(req2), purpose: 'Pay shop invoices' }));
    const { root } = await obtain(req2, { response: { emandate: { ...relaxed, allowedActions: ['payments.*'] } } });
    expect(await verify(root, m, { emandate: { ...relaxed, allowedActions: ['payments.sepa'] } })).toMatchObject({ code: 'ROOT_POLICY' });
    expect((await verify(root, m, { emandate: { ...relaxed, allowedActions: ['payments.*'] } })).decision).toBe('ALLOW');
  });

  it('applies the lifetime policy to e-mandate roots', async () => {
    const m = mandate({ ttlSeconds: 30 * DAY });
    const { root } = await obtain(await emandateRequest(m));
    expect(await verify(root, m, { policy: { maxLifetimeSeconds: 7 * DAY } })).toMatchObject({ code: 'LIFETIME_POLICY' });
  });

  it('rejects malformed roots', async () => {
    const m = mandate();
    const { root } = await obtain(await emandateRequest(m));
    const noMandate = { ...root };
    delete noMandate.mandate;
    expect(await verify(noMandate, m)).toMatchObject({ code: 'MALFORMED' });
    expect(await verify({ ...root, presentations: {} }, m)).toMatchObject({ code: 'ROOT_INVALID' });
    expect(await verify({ ...root, presentations: { ...root.presentations, other: 'x' } }, m)).toMatchObject({ code: 'MALFORMED' });
    expect(await verify({ ...root, presentations: { ...root.presentations, representation: root.presentations!.sca } }, m)).toMatchObject({
      code: 'MALFORMED',
    });
    // The plenipo form never takes a separate mandate.
    const plain = await obtain(await request(m));
    expect(await verify({ ...plain.root, mandate: m }, m)).toMatchObject({ code: 'MALFORMED' });
  });

  it('rejects a response without the SCA presentation', async () => {
    const req = await emandateRequest(mandate());
    const body = await wallet.respond({ ...req.params, response_mode: 'direct_post' });
    delete (body.vp_token as Record<string, unknown>).sca;
    req.session.responseMode = 'direct_post';
    await expect(handleMandateResponse(body, req.session, responseOptions())).rejects.toMatchObject({ code: 'MALFORMED' });
  });

  it('keeps state and replay checks', async () => {
    const req = await emandateRequest(mandate());
    const body = await wallet.respond(req.params);
    const opts = responseOptions();
    await handleMandateResponse(body, req.session, opts);
    await expect(handleMandateResponse(body, req.session, opts)).rejects.toMatchObject({ code: 'REPLAY', message: expect.stringMatching(/already been answered/) });
    const other = await emandateRequest(mandate());
    await expect(handleMandateResponse(body, other.session, responseOptions())).rejects.toThrow();
  });

  it('createMandateRequest needs the SCA types to bind to an SCA attestation', async () => {
    await expect(request(mandate(), { transactionDataType: 'emandate' })).rejects.toThrow(/scaVcts/);
  });
});

describe('legal persons and role mandates', () => {
  let director: TestWallet;
  beforeAll(async () => {
    director = await newWallet();
    director.storeCredential(await register.issueRepresentation(director.holderJwk, representationClaims()));
  });

  async function walletWith(claims: RepresentationClaims, opts: { issuer?: TestRegister; otherKey?: boolean; omitStatus?: boolean; exp?: number } = {}) {
    const w = await newWallet();
    const key = opts.otherKey ? await w.generateHolderKey() : w.holderJwk;
    w.storeCredential(await (opts.issuer ?? register).issueRepresentation(key, claims, { omitStatus: opts.omitStatus, exp: opts.exp }));
    return w;
  }

  it('verifies a mandate given on behalf of a legal person', async () => {
    const m = legalMandate();
    const req = await request(m, { disclose: ['given_name', 'family_name'] });
    expect((req.params.dcql_query as any).credentials.map((q: any) => q.id)).toEqual(['pid', 'representation']);
    const { root, verified } = await obtain(req, { wallet: director });
    expect(Object.keys(root.presentations!)).toEqual(['representation']);
    expect(verified.legalPrincipal?.euid).toBe(EUID);
    const d = await verify(root, m);
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') {
      expect(d.principal).toEqual({
        type: 'legal_person',
        euid: EUID,
        legal_name: 'Acme S.p.A.',
        role: { code: 'managing_director', name: 'Amministratore delegato', basis: 'legal_representation' },
        representative: { given_name: 'Mario', family_name: 'Rossi' },
      });
      expect(d.representation).toEqual({ register: register.iss, trusted_via: 'issuer', holder_binding: 'cnf' });
    }
  });

  it('combines a legal person with a TS12 e-mandate', async () => {
    const m = legalMandate();
    const req = await emandateRequest(m);
    expect(payloadOf(req).purpose).toContain(EUID);
    const { root } = await obtain(req, { wallet: director });
    expect(Object.keys(root.presentations!).sort()).toEqual(['representation', 'sca']);
    const d = await verify(root, m);
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') expect(d.root_binding?.credential).toBe('sca');
  });

  it('refuses same-response SCA binding for a legal person', async () => {
    const w = await newWallet({ sca: false });
    w.storeCredential(await register.issueRepresentation(w.holderJwk, representationClaims()));
    w.storeCredential(await bank.issue(await w.generateHolderKey(), {}), { transactionDataTypes: bank.transactionDataTypes });
    const weak = { ...emandateTrust(), scaSameResponseBinding: true };
    await expect(obtain(await emandateRequest(legalMandate()), { wallet: w, response: { emandate: weak } })).rejects.toThrow(/tied to the representative/);
  });

  it('rejects an attestation status list signed by someone else', async () => {
    const w = await walletWith(representationClaims());
    const ref = register.lastStatus!;
    const m = legalMandate();
    const { root } = await obtain(await request(m), { wallet: w });
    const forged: StatusFetcher = async (uri) => (uri === ref.status_list.uri ? rogueRegister.statusList!.token() : statusFetcher(uri));
    const d = await verify(root, m, { statusFetcher: forged });
    expect(d).toMatchObject({ decision: 'DENY', code: 'ATTESTATION_REVOKED' });
    if (d.decision === 'DENY') expect(d.reason).not.toMatch(/signature/);
  });

  it('never fetches an attestation status list outside the issuer origin', async () => {
    const w = await newWallet();
    const claims = { ...representationClaims(), status: { status_list: { uri: 'https://169.254.169.254/latest', idx: 1 } } };
    w.storeCredential(await register.issue(w.holderJwk, claims as unknown as Record<string, unknown>, { omitStatus: true }));
    const m = legalMandate();
    let fetched = 0;
    const counting: StatusFetcher = async (uri) => {
      fetched++;
      return statusFetcher(uri);
    };
    await expect(obtain(await request(m), { wallet: w, response: { statusFetcher: counting } })).rejects.toMatchObject({ code: 'ATTESTATION_REVOKED' });
    expect(fetched).toBe(0);
  });

  it('rejects an attestation from an untrusted register', async () => {
    const w = await walletWith(representationClaims(), { issuer: rogueRegister });
    await expect(obtain(await request(legalMandate()), { wallet: w })).rejects.toMatchObject({ code: 'ATTESTATION_UNTRUSTED' });
  });

  it('rejects a register attesting outside its scope', async () => {
    const m = legalMandate();
    const { root } = await obtain(await request(m), { wallet: director });
    const scoped = representationTrust({ euidScopes: { [register.iss]: ['DE*'] } });
    expect(await verify(root, m, { representation: scoped })).toMatchObject({ code: 'ATTESTATION_UNTRUSTED' });
    expect((await verify(root, m, { representation: representationTrust({ euidScopes: { [register.iss]: ['IT*'] } }) })).decision).toBe('ALLOW');
    expect(await verify(root, m, { representation: representationTrust({ euidScopes: { [register.iss]: ['ITRM.RM123456'] } }) })).toMatchObject({
      code: 'ATTESTATION_UNTRUSTED',
    });
  });

  it('denies once the attestation is revoked or suspended', async () => {
    const w = await walletWith(representationClaims());
    const ref = register.lastStatus!;
    const m = legalMandate();
    const { root } = await obtain(await request(m), { wallet: w });
    expect((await verify(root, m)).decision).toBe('ALLOW');
    register.statusList!.suspend(ref);
    expect(await verify(root, m)).toMatchObject({ decision: 'DENY', code: 'ATTESTATION_REVOKED', reason: expect.stringMatching(/suspended/) });
    register.statusList!.revoke(ref);
    expect(await verify(root, m)).toMatchObject({ decision: 'DENY', code: 'ATTESTATION_REVOKED', reason: expect.stringMatching(/revoked/) });
    await expect(obtain(await request(m), { wallet: w })).rejects.toMatchObject({ code: 'ATTESTATION_REVOKED' });
  });

  it('checks attestation status only after the invocation is verified', async () => {
    const m = legalMandate();
    const { root } = await obtain(await request(m), { wallet: director });
    let fetched = 0;
    const counting: StatusFetcher = async (uri) => {
      fetched++;
      return statusFetcher(uri);
    };
    const d = await verifyAuthorization({ root, delegations: [] }, 'not-a-jws', verifyOptions({ statusFetcher: counting }));
    expect(d.decision).toBe('DENY');
    expect(fetched).toBe(0);
  });

  it('requires the attestation to be revocable', async () => {
    const w = await walletWith(representationClaims(), { omitStatus: true });
    await expect(obtain(await request(legalMandate()), { wallet: w })).rejects.toThrow(/status list/);
  });

  it('rejects an ended or not yet started role', async () => {
    const ended = await walletWith(representationClaims({ role: { code: 'managing_director', basis: 'legal_representation', valid_until: nowSeconds() - 60 } }));
    await expect(obtain(await request(legalMandate()), { wallet: ended })).rejects.toThrow(/role has ended/);
    const future = await walletWith(representationClaims({ role: { code: 'managing_director', basis: 'legal_representation', valid_from: nowSeconds() + DAY } }));
    await expect(obtain(await request(legalMandate()), { wallet: future })).rejects.toThrow(/not valid yet/);
  });

  it('denies when the role has ended since the mandate was approved', async () => {
    const until = nowSeconds() + 3 * DAY;
    const w = await walletWith(representationClaims({ role: { code: 'managing_director', basis: 'legal_representation', valid_until: until } }));
    const m = legalMandate({ ttlSeconds: 2 * DAY });
    const { root } = await obtain(await request(m), { wallet: w });
    // Status lists are deferred here: the test's list tokens are not valid days from now.
    const opts = { trustedIssuers: [provider.trusted], representation: representationTrust(), attestationStatus: 'defer' as const };
    await expect(verifyRoot(root, { ...opts, now: until - 60 })).resolves.toBeDefined();
    await expect(verifyRoot(root, { ...opts, now: until })).rejects.toMatchObject({ code: 'ATTESTATION_INVALID', message: expect.stringMatching(/role has ended/) });
  });

  it('rejects an expired attestation', async () => {
    const w = await walletWith(representationClaims(), { exp: nowSeconds() + 60 });
    const m = legalMandate({ ttlSeconds: 30 });
    const { root } = await obtain(await request(m), { wallet: w });
    await expect(verifyRoot(root, { trustedIssuers: [provider.trusted], now: nowSeconds() + 3600, representation: representationTrust(), statusFetcher })).rejects.toMatchObject({
      code: 'ATTESTATION_INVALID',
    });
  });

  const exceeding: Array<[string, () => Mandate, RegExp]> = [
    ['an action', () => legalMandate({ actions: ['payments.sepa', 'admin.users'] }), /action admin.users/],
    ['a wildcard action', () => legalMandate({ actions: ['*'] }), /action \*/],
    ['the per-operation limit', () => legalMandate({ limits: { currency: 'EUR', per_operation: 200000, total: 300000 } }), /per-operation/],
    ['the total limit', () => legalMandate({ limits: { currency: 'EUR', per_operation: 1000, total: 600000 } }), /total limit/],
    ['an unlimited total', () => legalMandate({ limits: { currency: 'EUR', per_operation: 1000 } }), /total limit unlimited/],
    ['the currency', () => legalMandate({ limits: { currency: 'USD', per_operation: 1000, total: 1000 } }), /USD/],
    ['missing limits', () => legalMandate({ limits: undefined }), /has none/],
    ['the delegation depth', () => legalMandate({ maxDepth: 3 }), /delegation depth/],
  ];
  for (const [name, make, message] of exceeding) {
    it(`rejects a mandate exceeding ${name} of the role`, async () => {
      const m = make();
      await expect(obtain(await request(m), { wallet: director })).rejects.toMatchObject({
        code: 'ROLE_EXCEEDED',
        message: expect.stringMatching(message),
      });
    });
  }

  it('rejects a mandate that outlives the role', async () => {
    const w = await walletWith(representationClaims({ role: { code: 'managing_director', basis: 'legal_representation', valid_until: nowSeconds() + 5 * DAY } }));
    await expect(obtain(await request(legalMandate({ ttlSeconds: 10 * DAY })), { wallet: w })).rejects.toMatchObject({
      code: 'ROLE_EXCEEDED',
      message: expect.stringMatching(/outlives the role/),
    });
  });

  it('checks role counterparties', () => {
    const claims = representationClaims({ powers: { actions: ['payments.*'], counterparties: ['*.suppliers.example'] } });
    expect(rolePowerViolations(claims, legalMandate({ counterparties: ['a.suppliers.example'] }))).toEqual([]);
    expect(rolePowerViolations(claims, legalMandate({ counterparties: ['shop.example'] })).join()).toMatch(/shop.example/);
    const open = legalMandate();
    delete open.counterparties;
    expect(rolePowerViolations(claims, open).join()).toMatch(/restricted/);
  });

  it('rejects an attestation bound to another holder key unless identity claims are configured and match', async () => {
    const same = await walletWith(representationClaims(), { otherKey: true });
    const m = legalMandate();
    await expect(obtain(await request(m), { wallet: same })).rejects.toThrow(/another holder key/);
    const ids = representationTrust({ identityClaims: ['given_name', 'family_name'] });
    const req = await request(m, { representation: { identityClaims: ['given_name', 'family_name'] } });
    const { root } = await obtain(req, { wallet: same, response: { representation: ids } });
    const d = await verify(root, m, { representation: ids });
    expect(d.decision).toBe('ALLOW');
    if (d.decision === 'ALLOW') expect(d.representation?.holder_binding).toBe('claims');
  });

  it('rejects an attestation naming another person', async () => {
    const other = await walletWith(representationClaims({ representative: { given_name: 'Luigi', family_name: 'Bianchi' } }), { otherKey: true });
    const ids = representationTrust({ identityClaims: ['given_name', 'family_name'] });
    const req = await request(legalMandate(), { representation: { identityClaims: ['given_name', 'family_name'] } });
    await expect(obtain(req, { wallet: other, response: { representation: ids } })).rejects.toThrow(/another person/);
  });

  it('rejects identity matching on claims that were not disclosed', async () => {
    const w = await walletWith(representationClaims(), { otherKey: true });
    const ids = representationTrust({ identityClaims: ['birthdate'] });
    const req = await request(legalMandate(), { representation: { identityClaims: ['birthdate'] } });
    await expect(obtain(req, { wallet: w, response: { representation: ids } })).rejects.toThrow(/not disclosed/);
  });

  it('rejects a root without the representation presentation', async () => {
    const m = legalMandate();
    const { root } = await obtain(await request(m), { wallet: director });
    const bare = { ...root };
    delete bare.presentations;
    expect(await verify(bare, m)).toMatchObject({ decision: 'DENY', code: 'ATTESTATION_INVALID' });
    // A wallet without the attestation cannot answer.
    await expect(obtain(await request(m, { encryptResponse: false }), { wallet: await newWallet() })).rejects.toThrow(/access_denied/);
  });

  it('rejects a representation presentation taken from another request', async () => {
    const m = legalMandate();
    const a = await obtain(await request(m), { wallet: director });
    const b = await obtain(await request(m), { wallet: director });
    const spliced = { ...b.root, presentations: { representation: a.root.presentations!.representation } };
    expect(await verify(spliced, m)).toMatchObject({ decision: 'DENY', code: 'ATTESTATION_INVALID' });
  });

  it('rejects an attestation for another legal person or another role', async () => {
    await expect(obtain(await request(legalMandate({}, { euid: 'ITRM.RM7654321' })), { wallet: director })).rejects.toThrow(/another legal person/);
    await expect(obtain(await request(legalMandate({}, { role: 'procurator' })), { wallet: director })).rejects.toThrow(/another role/);
  });

  it('accepts only the configured role bases', async () => {
    const w = await walletWith(representationClaims({ role: { code: 'managing_director', basis: 'power_of_attorney' } }));
    const strict = representationTrust({ acceptedBases: ['legal_representation'] });
    await expect(obtain(await request(legalMandate()), { wallet: w, response: { representation: strict } })).rejects.toThrow(/basis/);
    await expect(obtain(await request(legalMandate()), { wallet: w })).resolves.toBeDefined();
  });

  it('rejects technical Business Wallet roles as a basis for representation', async () => {
    const w = await walletWith(representationClaims({ role: { code: 'wallet_operator', basis: 'ebw_authorisation' as any } }));
    await expect(obtain(await request(legalMandate({}, { role: undefined })), { wallet: w })).rejects.toThrow(/role.basis/);
  });

  it('accepts EUIDs with a validation character', () => {
    expect(legalMandate({}, { euid: 'ESRMC.5789255_X' }).principal?.euid).toBe('ESRMC.5789255_X');
    expect(() => legalMandate({}, { euid: 'ESRMC.5789255_XY' })).toThrow(/EUID/);
  });

  it('rejects malformed attestations and principals', async () => {
    const bad = await walletWith({ ...representationClaims(), powers: { actions: [] } } as any);
    await expect(obtain(await request(legalMandate()), { wallet: bad })).rejects.toMatchObject({ code: 'ATTESTATION_INVALID' });
    expect(() => legalMandate({}, { euid: 'not an euid' })).toThrow(/EUID/);
    // A principal with unknown members is refused before any attestation is looked at.
    const m = { ...mandate(), principal: { type: 'legal_person', euid: EUID, extra: 1 } } as unknown as Mandate;
    await expect(obtain(await request(m), { wallet: director })).rejects.toMatchObject({ code: 'MALFORMED', message: expect.stringMatching(/principal/) });
  });

  it('rejects a PID presented in place of the attestation', async () => {
    const m = legalMandate();
    const req = await request(m, { representation: { vcts: ['urn:eudi:pid:1'] } });
    await expect(obtain(req, { wallet: director })).rejects.toMatchObject({ code: 'ATTESTATION_UNTRUSTED' });
    const viaTrust = representationTrust({ trust: { trustedIssuers: [register.trusted, provider.trusted] } });
    await expect(obtain(await request(m, { representation: { vcts: ['urn:eudi:pid:1'] } }), { wallet: director, response: { representation: viaTrust } })).rejects.toThrow(
      /not an accepted/,
    );
  });

  it('needs representation trust to accept a legal person root', async () => {
    const m = legalMandate();
    const { root } = await obtain(await request(m), { wallet: director });
    expect(await verify(root, m, { representation: undefined })).toMatchObject({ code: 'CONFIGURATION' });
  });

  it('rejects an attestation presented without a legal person principal', async () => {
    const m = legalMandate();
    const { root } = await obtain(await request(m), { wallet: director });
    const plain = await obtain(await request(mandate()), { wallet: director });
    expect(await verify({ ...plain.root, presentations: root.presentations }, mandate())).toMatchObject({ code: 'MALFORMED' });
  });

  it('a delegation cannot set or change the principal', async () => {
    const m = legalMandate({ maxDepth: 1 });
    const { root } = await obtain(await request(m), { wallet: director });
    const sub = await generateAgentKey();
    const child = {
      ...createMandate({ agentJwk: sub.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'], limits: { currency: 'EUR', per_operation: 100, total: 100 }, nbf: m.nbf, exp: m.exp }),
      principal: { type: 'legal_person', euid: 'DEHRB.HRB999' },
    } as Mandate;
    const jws = await delegateMandate({ parent: m, parentAgentKey: agent.privateKey, child });
    const chain = { root, delegations: [jws] };
    const inv = await createInvocation(sub.privateKey, { chain, mandateId: child.id, action: 'payments.sepa', counterparty: 'shop.example', amount: { value: 10, currency: 'EUR' }, aud: AUD });
    const d = await verifyAuthorization(chain, inv, verifyOptions());
    expect(d).toMatchObject({ decision: 'DENY', code: 'ATTENUATION_VIOLATION' });
  });
});

function sha(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('base64url');
}

/** Builds the root from a wallet body without the response handler (unencrypted, for direct verification). */
async function rootFromBody(body: Record<string, unknown>, req: MandateRequest): Promise<RootAuthorization> {
  const { plaintext } = await compactDecrypt(body.response as string, req.session.decryptionKey!);
  const payload = JSON.parse(new TextDecoder().decode(plaintext));
  const vp = payload.vp_token as Record<string, string[]>;
  const presentations = Object.fromEntries(Object.entries(vp).filter(([k]) => k !== 'pid').map(([k, v]) => [k, v[0]]));
  return {
    transaction_data: req.session.transactionData,
    presentation: vp.pid[0],
    ...(req.session.mandate ? { mandate: req.session.mandate } : {}),
    ...(Object.keys(presentations).length ? { presentations } : {}),
  };
}
