/**
 * Regression tests for the security review of the root area (findings R1 to R10). Each test started as the
 * reviewer's proof of concept and now asserts the safe behaviour.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import {
  createInvocation,
  createMandate,
  createMandateRequest,
  generateAgentKey,
  handleMandateResponse,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  mandateHash,
  nowSeconds,
  validateMandate,
  verifyAuthorization,
  type AgentKey,
  type Mandate,
  type MandateRequest,
  type StatusFetcher,
} from '../src/index.js';
import {
  createLegalMandate,
  currencyMinorDigits,
  decodeCanonical,
  emandateViolations,
  encodeEmandateTransactionData,
  mandateToEmandate,
  toMajorUnits,
} from '../src/experimental.js';
import { asMandateChain, authorizationHeaders, encodeChainHeader } from '../src/http/transport.js';
import { createGateway } from '../src/http/gateway.js';
import { fromBase64url } from '../src/encoding.js';
import { disclosedProtectedClaims } from '../src/presentation.js';
import {
  createTestCertificateAuthority,
  createTestPidProvider,
  createTestRegister,
  createTestScaIssuer,
  createTestWallet,
  TEST_SCA_VCT,
  type TestAttestationIssuer,
  type TestPidProvider,
  type TestRegister,
  type TestWallet,
} from '../src/testing.js';
import { PID_VCT } from '../src/types.js';
import { importJWK } from 'jose';
import { StatusListPublisher, verifyRoot } from '../src/index.js';

const AUD = 'https://pay.example';
const CLIENT_ID = 'x509_san_dns:agents.example';
const RESPONSE_URI = 'https://agents.example/response';
const EUID = 'ITRM.RM1234567';
const DAY = 24 * 3600;

/** An issuer that does not follow SD-JWT VC section 3.2.2: it makes protected claims disclosable. */
class LaxIssuer extends SDJwtVcInstance {
  validateDisclosureFrame(): void {}
}

let agent: AgentKey;
let provider: TestPidProvider;
let register: TestRegister;
let bank: TestAttestationIssuer & { transactionDataTypes: string[] };
let statusFetcher: StatusFetcher;

beforeAll(async () => {
  agent = await generateAgentKey();
  provider = await createTestPidProvider('https://pid.test');
  register = await createTestRegister('https://register.test');
  bank = await createTestScaIssuer('https://bank.test', { statusList: true });
  statusFetcher = async (uri) => {
    for (const i of [register, bank]) if (uri.startsWith(`${i.iss}/`)) return i.statusFetcher(uri);
    throw new Error('unknown status list');
  };
});

async function walletWithPid(): Promise<TestWallet> {
  const w = await createTestWallet();
  w.storePid(await provider.issuePid(w.holderJwk, { given_name: 'Mario', family_name: 'Rossi' }));
  return w;
}

function responseOptions(extra: Record<string, unknown> = {}) {
  return {
    trustedIssuers: [provider.trusted],
    now: nowSeconds(),
    sessions: new InMemoryNonceStore(),
    statusFetcher,
    representation: { trust: { trustedIssuers: [register.trusted] } },
    emandate: { scaTrust: { trustedIssuers: [bank.trusted] }, scaVcts: [TEST_SCA_VCT] },
    ...extra,
  };
}

const request = (m: Mandate, extra: Record<string, unknown> = {}) => createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: RESPONSE_URI, ...extra });
const emandateRequest = (m: Mandate, extra: Record<string, unknown> = {}) =>
  request(m, { transactionDataType: 'emandate', emandate: { scaVcts: [TEST_SCA_VCT] }, ...extra });

describe('R1: role restrictions cannot be withheld', () => {
  // A procurator limited to 1,000.00 EUR per operation, 5,000.00 EUR in total, one supplier, no
  // sub-delegation, ending in 2 days.
  const roleClaims = () => ({
    legal_person_id: EUID,
    legal_person_name: 'Acme S.p.A.',
    representative: { given_name: 'Mario', family_name: 'Rossi' },
    role: { code: 'procurator', basis: 'power_of_attorney', valid_until: nowSeconds() + 2 * DAY },
    powers: {
      actions: ['payments.*'],
      counterparties: ['supplier.example'],
      limits: { currency: 'EUR', per_operation: 100000, total: 500000 },
      max_delegation_depth: 0,
    },
  });
  const wideMandate = () =>
    createLegalMandate({
      agentJwk: agent.publicJwk,
      actions: ['payments.sepa'],
      limits: { currency: 'EUR', per_operation: 10_000_000, total: 100_000_000 },
      ttlSeconds: 60 * DAY,
      maxDepth: 3,
      principal: { type: 'legal_person', euid: EUID, role: 'procurator' },
    });

  for (const disclosable of [
    ['powers.limits', 'powers.counterparties', 'powers.max_delegation_depth', 'role.valid_until'],
    ['powers.limits'],
    ['role.valid_until'],
    ['powers'],
    ['role'],
  ]) {
    it(`refuses an attestation with selectively disclosable ${disclosable.join(', ')}`, async () => {
      const w = await walletWithPid();
      w.storeCredential(await register.issue(w.holderJwk, roleClaims(), { disclosable: ['legal_person_name', ...disclosable] }));
      const req = await request(wideMandate());
      await expect(handleMandateResponse(await w.respond(req.params), req.session, responseOptions())).rejects.toMatchObject({
        code: 'ATTESTATION_INVALID',
        message: expect.stringMatching(/plain text/),
      });
    });
  }

  it('an ended role hidden behind a disclosure no longer authorises', async () => {
    const w = await walletWithPid();
    const claims = roleClaims();
    claims.role.valid_until = nowSeconds() - DAY;
    w.storeCredential(await register.issue(w.holderJwk, claims, { disclosable: ['role.valid_until'] }));
    const m = createLegalMandate({
      agentJwk: agent.publicJwk,
      actions: ['payments.sepa'],
      counterparties: ['supplier.example'],
      limits: { currency: 'EUR', per_operation: 1000, total: 5000 },
      principal: { type: 'legal_person', euid: EUID, role: 'procurator' },
    });
    const req = await request(m);
    await expect(handleMandateResponse(await w.respond(req.params), req.session, responseOptions())).rejects.toMatchObject({ code: 'ATTESTATION_INVALID' });
  });

  it('with role and powers in plain text the same mandate is refused as exceeding the role', async () => {
    const w = await walletWithPid();
    w.storeCredential(await register.issue(w.holderJwk, roleClaims(), { disclosable: ['legal_person_name', 'representative.given_name'] }));
    const req = await request(wideMandate());
    await expect(handleMandateResponse(await w.respond(req.params), req.session, responseOptions())).rejects.toMatchObject({ code: 'ROLE_EXCEEDED' });
  });
});

describe('R2: the payee shown follows the enforced counterparty', () => {
  const m = () =>
    createMandate({
      agentJwk: agent.publicJwk,
      actions: ['payments.sepa'],
      counterparties: ['attacker.example'],
      limits: { currency: 'EUR', per_operation: 150000, total: 150000 },
    });
  const landlord = { name: 'Rent - Your landlord', id: 'attacker.example', website: 'https://landlord.example', logo: 'https://landlord.example/logo.png' };

  it('the platform cannot build a request showing another name, website or logo', async () => {
    await expect(emandateRequest(m(), { emandate: { scaVcts: [TEST_SCA_VCT], payee: landlord } })).rejects.toThrow(/payee/);
    await expect(emandateRequest(m(), { emandate: { scaVcts: [TEST_SCA_VCT], payee: { name: 'attacker.example', id: 'attacker.example', website: 'https://landlord.example' } } })).rejects.toThrow(/website/);
  });

  it('a request crafted by hand and approved in the wallet is refused', async () => {
    const w = await walletWithPid();
    w.storeCredential(await bank.issue(w.holderJwk, {}), { transactionDataTypes: bank.transactionDataTypes });
    const mm = m();
    const req: MandateRequest = await emandateRequest(mm);
    const p = structuredClone(decodeCanonical((req.params.transaction_data as string[])[0])!.payload) as any;
    p.payment_payload.payee = landlord;
    const td = encodeEmandateTransactionData(p);
    (req.params.transaction_data as string[])[0] = td;
    req.session.transactionData = td;
    await expect(handleMandateResponse(await w.respond(req.params), req.session, responseOptions())).rejects.toMatchObject({ code: 'DISPLAY_MISMATCH' });
  });

  it('checks name, website and logo one by one', () => {
    const mm = m();
    const base = mandateToEmandate(mm);
    expect(base.payment_payload!.payee).toEqual({ name: 'attacker.example', id: 'attacker.example', website: 'https://attacker.example' });
    const withPayee = (payee: Record<string, unknown>) => ({ ...base, payment_payload: { ...base.payment_payload!, payee } }) as any;
    const msgs = (payee: Record<string, unknown>, opts = {}) => emandateViolations(withPayee(payee), mm, opts).map((v) => v.field);
    expect(msgs({ name: 'Landlord', id: 'attacker.example' })).toContain('payment_payload.payee.name');
    expect(msgs({ name: 'attacker.example', id: 'attacker.example', website: 'https://landlord.example' })).toContain('payment_payload.payee.website');
    expect(msgs({ name: 'attacker.example', id: 'attacker.example', logo: 'https://x.example/l.png' })).toContain('payment_payload.payee.logo');
    expect(msgs({ name: 'attacker.example', id: 'attacker.example', logo: 'https://x.example/l.png' }, { allowedPayeeLogos: ['https://x.example/l.png'] })).toEqual([]);
    // A wildcard payee cannot claim a website.
    const wild = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['a.shops.example'], limits: { currency: 'EUR', total: 100 } });
    const wb = mandateToEmandate(wild, { payee: { name: '*.shops.example', id: '*.shops.example' } });
    const fields = emandateViolations({ ...wb, payment_payload: { ...wb.payment_payload!, payee: { name: '*.shops.example', id: '*.shops.example', website: 'https://*.shops.example' } } }, wild).map((v) => v.field);
    expect(fields).toContain('payment_payload.payee.website');
  });
});

describe('R3: purposeCheck none binds limits and counterparties to structured fields', () => {
  it('a free-text purpose cannot stand for an unlimited mandate to any counterparty', () => {
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], maxDepth: 0 });
    const shown = { transaction_id: m.id, reference_number: mandateHash(m), purpose: 'Pay up to 10.00 EUR, once, to shop.example' };
    expect(emandateViolations(shown, m, { purposeCheck: 'none' }).some((v) => v.kind === 'display')).toBe(true);
  });

  it('a bounded mandate shown with payment details passes, without them it does not', () => {
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'], limits: { currency: 'EUR', per_operation: 1000, total: 1000 } });
    const shown = { ...mandateToEmandate(m), purpose: 'Shop invoices' };
    expect(emandateViolations(shown, m, { purposeCheck: 'none' })).toEqual([]);
    const { payment_payload: _, ...bare } = shown;
    expect(emandateViolations(bare, m, { purposeCheck: 'none' }).map((v) => v.field)).toContain('payment_payload');
  });

  it('the verifier refuses purposeCheck none without an action allow-list and a depth limit', async () => {
    const w = await walletWithPid();
    w.storeCredential(await bank.issue(w.holderJwk, {}), { transactionDataTypes: bank.transactionDataTypes });
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'], limits: { currency: 'EUR', total: 1000 } });
    const req = await emandateRequest(m);
    const em = { scaTrust: { trustedIssuers: [bank.trusted] }, scaVcts: [TEST_SCA_VCT], purposeCheck: 'none' as const };
    await expect(handleMandateResponse(await w.respond(req.params), req.session, responseOptions({ emandate: { ...em, allowedActions: ['payments.*'] } }))).rejects.toMatchObject({
      code: 'CONFIGURATION',
    });
    const req2 = await emandateRequest(m);
    await expect(
      handleMandateResponse(await w.respond(req2.params), req2.session, responseOptions({ emandate: { ...em, allowedActions: ['payments.*'], maxDelegationDepth: 0 } })),
    ).resolves.toBeDefined();
  });
});

describe('R4: protected claims cannot be selectively disclosed', () => {
  async function laxIssue(iss: string, payload: Record<string, unknown>, sd: string[]) {
    const keys = await ES256.generateKeyPair();
    const lax = new LaxIssuer({ signer: await ES256.getSigner(keys.privateKey), signAlg: 'ES256', hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt });
    return { token: await lax.issue({ iss, ...payload } as any, { _sd: sd } as any), trusted: { iss, jwk: keys.publicKey as any } };
  }

  it('an SCA attestation whose withheld status was disclosable is refused, without any fetch', async () => {
    const w = await walletWithPid();
    const iat = nowSeconds();
    const sca = await laxIssue(
      'https://lax-bank.test',
      { iat, exp: iat + DAY, vct: TEST_SCA_VCT, cnf: { jwk: w.holderJwk }, status: { status_list: { uri: 'https://lax-bank.test/status/1', idx: 7 } } },
      ['status'],
    );
    w.storeCredential(sca.token, { transactionDataTypes: ['urn:eudi:sca:emandate:1'] });
    let fetched = 0;
    const counting: StatusFetcher = async () => {
      fetched++;
      throw new Error('revoked list would be served here');
    };
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'], limits: { currency: 'EUR', per_operation: 15000, total: 30000 } });
    const req = await emandateRequest(m);
    await expect(
      handleMandateResponse(await w.respond(req.params), req.session, responseOptions({ statusFetcher: counting, emandate: { scaTrust: { trustedIssuers: [sca.trusted] }, scaVcts: [TEST_SCA_VCT] } })),
    ).rejects.toMatchObject({ code: 'ATTESTATION_INVALID', message: expect.stringMatching(/no status/) });
    expect(fetched).toBe(0);
  });

  it('an SCA attestation that discloses a protected claim is refused', async () => {
    const w = await walletWithPid();
    const iat = nowSeconds();
    const sca = await laxIssue('https://lax-bank.test', { iat, exp: iat + DAY, vct: TEST_SCA_VCT, cnf: { jwk: w.holderJwk } }, ['exp']);
    w.storeCredential(sca.token, { transactionDataTypes: ['urn:eudi:sca:emandate:1'] });
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'], limits: { currency: 'EUR', total: 1000 } });
    const req = await emandateRequest(m);
    (req.params.dcql_query as any).credentials[1].claims = [{ path: ['exp'] }];
    await expect(
      handleMandateResponse(await w.respond(req.params), req.session, responseOptions({ emandate: { scaTrust: { trustedIssuers: [sca.trusted] }, scaVcts: [TEST_SCA_VCT], requireScaStatus: false } })),
    ).rejects.toMatchObject({ code: 'ATTESTATION_INVALID', message: expect.stringMatching(/exp/) });
  });

  it('a PID whose exp is disclosable is refused whether it is withheld or disclosed', async () => {
    const iat = nowSeconds() - 400 * DAY;
    for (const disclose of [['given_name', 'family_name'], ['given_name', 'family_name', 'exp']]) {
      const w = await createTestWallet();
      const pid = await laxIssue('https://lax-pid.test', { iat, exp: iat + DAY, vct: PID_VCT, cnf: { jwk: w.holderJwk }, given_name: 'Mario', family_name: 'Rossi' }, [
        'given_name',
        'family_name',
        'exp',
      ]);
      w.storePid(pid.token);
      const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'] });
      const req = await request(m, { disclose });
      await expect(handleMandateResponse(await w.respond(req.params), req.session, responseOptions({ trustedIssuers: [pid.trusted] }))).rejects.toMatchObject({
        code: 'ROOT_INVALID',
      });
    }
  });

  it('lists protected disclosures at any depth', () => {
    const d = (arr: unknown[]) => Buffer.from(JSON.stringify(arr)).toString('base64url');
    const pres = ['jwt', d(['s', 'given_name', 'Mario']), d(['s', 'status', {}]), d(['s', 'x']), ''].join('~');
    expect(disclosedProtectedClaims(pres)).toEqual(['status']);
  });
});

describe('R5: SCA and register certificates are checked for revocation', () => {
  it('a revoked PSP certificate is refused, a valid one accepted, also at verification time', async () => {
    const ca = await createTestCertificateAuthority('PSP CA');
    const psp = await createTestScaIssuer('https://psp.test', { x5c: true, ca, statusList: true });
    const w = await walletWithPid();
    w.storeCredential(await psp.issue(w.holderJwk, {}), { transactionDataTypes: psp.transactionDataTypes });
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'], limits: { currency: 'EUR', per_operation: 100, total: 100 } });
    const pspFetcher: StatusFetcher = (uri) => psp.statusFetcher(uri);
    const em = (crl: Uint8Array) => ({
      scaTrust: { trustAnchors: [ca.anchorPem], certificateRevocation: { policy: 'hard-fail' as const, crls: [crl], methods: ['crl' as const] } },
      scaVcts: [TEST_SCA_VCT],
    });
    const good = await ca.createCrl({ revoked: [] });
    const req = await emandateRequest(m);
    const { root } = await handleMandateResponse(await w.respond(req.params), req.session, responseOptions({ statusFetcher: pspFetcher, emandate: em(good) }));

    // The leaf certificate of the PSP is the first x5c entry of the attestation; revoke its serial number.
    const header = JSON.parse(fromBase64url(root.presentations!.sca.split('.')[0]));
    const { X509Certificate } = await import('node:crypto');
    const serial = new X509Certificate(Buffer.from(header.x5c[0], 'base64')).serialNumber.toLowerCase();
    const revoked = await ca.createCrl({ revoked: [serial] });
    const req2 = await emandateRequest(m);
    await expect(handleMandateResponse(await w.respond(req2.params), req2.session, responseOptions({ statusFetcher: pspFetcher, emandate: em(revoked) }))).rejects.toMatchObject({
      code: 'ATTESTATION_UNTRUSTED',
    });

    const inv = await createInvocation(agent.privateKey, { chain: { root, delegations: [] }, mandateId: m.id, action: 'payments.sepa', counterparty: 'shop.example', amount: { value: 10, currency: 'EUR' }, aud: AUD });
    const base = { trustedIssuers: [provider.trusted], audience: AUD, ledger: new InMemorySpendingLedger(), statusFetcher: pspFetcher };
    expect((await verifyAuthorization({ root, delegations: [] }, inv, { ...base, nonces: new InMemoryNonceStore(), emandate: em(good) })).decision).toBe('ALLOW');
    expect(await verifyAuthorization({ root, delegations: [] }, inv, { ...base, nonces: new InMemoryNonceStore(), emandate: em(revoked) })).toMatchObject({
      decision: 'DENY',
      code: 'ATTESTATION_UNTRUSTED',
    });
  });

  it('a revoked register certificate is refused', async () => {
    const ca = await createTestCertificateAuthority('Register CA');
    const reg = await createTestRegister('https://x5c-register.test', { x5c: true, ca });
    const w = await walletWithPid();
    w.storeCredential(
      await reg.issueRepresentation(w.holderJwk, {
        legal_person_id: EUID,
        role: { code: 'director', basis: 'legal_representation' },
        powers: { actions: ['payments.*'] },
      }),
    );
    const m = createLegalMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], ttlSeconds: 3600, principal: { type: 'legal_person', euid: EUID } });
    const req = await request(m);
    const header = JSON.parse(fromBase64url((await reg.issue(w.holderJwk, {})).split('.')[0]));
    const { X509Certificate } = await import('node:crypto');
    const serial = new X509Certificate(Buffer.from(header.x5c[0], 'base64')).serialNumber.toLowerCase();
    const trust = async (revoked: string[]) => ({
      trust: { trustAnchors: [ca.anchorPem], certificateRevocation: { policy: 'hard-fail' as const, crls: [await ca.createCrl({ revoked })], methods: ['crl' as const] } },
    });
    const regFetcher = (u: string) => reg.statusFetcher(u);
    await expect(handleMandateResponse(await w.respond(req.params), req.session, responseOptions({ statusFetcher: regFetcher, representation: await trust([]) }))).resolves.toBeDefined();
    const representation = await trust([serial]);
    const req2 = await request(m);
    await expect(handleMandateResponse(await w.respond(req2.params), req2.session, responseOptions({ statusFetcher: regFetcher, representation }))).rejects.toMatchObject({
      code: 'ATTESTATION_UNTRUSTED',
    });
  });
});

describe('R6: the HTTP transport carries e-mandate and legal person roots', () => {
  it('accepts the optional members and stays strict otherwise', () => {
    const root = { transaction_data: 'eyJ0eXBlIjoieCJ9', presentation: 'a~b', mandate: { id: 'x' }, presentations: { sca: 'c~d', representation: 'e~f' } };
    const decoded = JSON.parse(fromBase64url(encodeChainHeader({ root: root as any, delegations: [] })));
    expect(asMandateChain(decoded)).toEqual({ root, delegations: [] });
    const bad = [
      { ...root, extra: 1 },
      { ...root, mandate: 'x' },
      { ...root, mandate: [] },
      { ...root, presentations: { other: 'x' } },
      { ...root, presentations: { sca: 1 } },
      { ...root, presentations: { sca: '' } },
      { ...root, presentations: {} },
      { ...root, presentations: { sca: 'x'.repeat(64 * 1024 + 1) } },
      { ...root, presentations: ['x'] },
    ];
    for (const r of bad) expect(asMandateChain({ root: r, delegations: [] })).toBeUndefined();
  });

  it('a gateway verifies an e-mandate root sent in the headers', async () => {
    const w = await walletWithPid();
    w.storeCredential(await bank.issue(w.holderJwk, {}), { transactionDataTypes: bank.transactionDataTypes });
    const API = 'https://api.bank.example';
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.transfer'], counterparties: ['shop.example'], limits: { currency: 'EUR', per_operation: 5000, total: 5000 } });
    const req = await emandateRequest(m);
    const { root } = await handleMandateResponse(await w.respond(req.params), req.session, responseOptions());
    const gw = createGateway({
      routes: [
        {
          method: 'POST',
          path: '/payments',
          action: 'payments.transfer',
          counterparty: (r) => (r.json() as { creditor: string }).creditor,
          amount: (r) => ({ value: (r.json() as { amount: number }).amount, currency: 'EUR' }),
        },
      ],
      verify: {
        audience: API,
        nonces: new InMemoryNonceStore(),
        ledger: new InMemorySpendingLedger(),
        trustedIssuers: [provider.trusted],
        statusFetcher,
        emandate: { scaTrust: { trustedIssuers: [bank.trusted] }, scaVcts: [TEST_SCA_VCT] },
      },
      downstream: () => new Response(null, { status: 204 }),
    });
    const body = { creditor: 'shop.example', amount: 1200 };
    const inv = await createInvocation(agent.privateKey, {
      chain: { root, delegations: [] },
      mandateId: m.id,
      action: 'payments.transfer',
      counterparty: 'shop.example',
      amount: { value: 1200, currency: 'EUR' },
      aud: API,
      args: { method: 'POST', path: '/payments', query: {}, media_type: 'application/json', body },
    });
    const res = await gw.handle(
      new Request(`${API}/payments`, {
        method: 'POST',
        headers: { ...authorizationHeaders({ root, delegations: [] }, inv), 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }),
    );
    expect(res.status).toBe(204);
  });
});

describe('R7: identity claims are requested from the PID', () => {
  it('merges representation and SCA identity claims into the PID query', async () => {
    const legal = createLegalMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], principal: { type: 'legal_person', euid: EUID } });
    const r1 = await request(legal, { representation: { identityClaims: ['birthdate'] } });
    expect((r1.params.dcql_query as any).credentials[0].claims.map((c: any) => c.path[0])).toEqual(['given_name', 'family_name', 'birthdate']);
    const plain = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'], limits: { currency: 'EUR', total: 100 } });
    const r2 = await emandateRequest(plain, { emandate: { scaVcts: [TEST_SCA_VCT], scaIdentityClaims: ['personal_administrative_number', 'given_name'] } });
    expect((r2.params.dcql_query as any).credentials[0].claims.map((c: any) => c.path[0])).toEqual(['given_name', 'family_name', 'personal_administrative_number']);
  });

  it('claim binding works with a PID query built by Plenipo alone', async () => {
    const w = await walletWithPid();
    const otherKey = await w.generateHolderKey();
    w.storeCredential(
      await register.issueRepresentation(otherKey, {
        legal_person_id: EUID,
        representative: { given_name: 'Mario', family_name: 'Rossi' },
        role: { code: 'director', basis: 'legal_representation' },
        powers: { actions: ['payments.*'] },
      }),
    );
    const m = createLegalMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], ttlSeconds: 3600, principal: { type: 'legal_person', euid: EUID } });
    const ids = ['given_name', 'family_name'];
    const req = await request(m, { disclose: ['given_name'], representation: { identityClaims: ids } });
    const { verified } = await handleMandateResponse(
      await w.respond(req.params),
      req.session,
      responseOptions({ representation: { trust: { trustedIssuers: [register.trusted] }, identityClaims: ids } }),
    );
    expect(verified.representation?.holder_binding).toBe('claims');
  });
});

describe('R8: limits are ISO 4217 minor units', () => {
  it('exposes the exponent used for the display', () => {
    expect(currencyMinorDigits('EUR')).toBe(2);
    expect(currencyMinorDigits('KWD')).toBe(3);
    expect(currencyMinorDigits('JPY')).toBe(0);
    expect(currencyMinorDigits('toString')).toBe(2);
    expect(toMajorUnits(15000, 'KWD')).toBe(15);
    expect(toMajorUnits(15000, 'EUR')).toBe(150);
  });
});

describe('R9: no fetch before the response is bound to the request', () => {
  it('a response with another nonce causes no PID status fetch', async () => {
    const p = await createTestPidProvider('https://pid-status.test', { statusList: true });
    const w = await createTestWallet();
    w.storePid(await p.issuePid(w.holderJwk, { given_name: 'Mario', family_name: 'Rossi' }));
    let fetched = 0;
    const counting: StatusFetcher = async (uri) => {
      fetched++;
      return p.statusFetcher(uri);
    };
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'] });
    const req = await request(m);
    const body = await w.respond(req.params, { tamperKeyBinding: (_id, kb) => (kb.nonce = 'another-nonce') });
    await expect(handleMandateResponse(body, req.session, responseOptions({ trustedIssuers: [p.trusted], statusFetcher: counting }))).rejects.toThrow(/nonce/);
    expect(fetched).toBe(0);
    const ok = await request(m);
    await handleMandateResponse(await w.respond(ok.params), ok.session, responseOptions({ trustedIssuers: [p.trusted], statusFetcher: counting }));
    expect(fetched).toBe(1);
  });
});

describe('R10: the purpose shown is plain, bounded text', () => {
  const base = () => createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'] });
  for (const [name, purpose] of [
    ['too long', 'p'.repeat(501)],
    ['a line break', 'Pay the shop\nLimits: none'],
    ['a bidi override', 'Pay ‮elpmaxe.kcatta'],
    ['a zero-width character', 'Pay​shop'],
    ['a NUL', 'Pay\u0000shop'],
  ]) {
    it(`refuses a purpose with ${name}`, () => {
      expect(validateMandate({ ...base(), purpose }).join()).toMatch(/purpose/);
      expect(() => createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], purpose })).toThrow(/purpose/);
    });
  }

  it('accepts ordinary text, accents and emoji without joiners', () => {
    expect(validateMandate({ ...base(), purpose: 'Pagare le fatture di città 🚆 entro ottobre' })).toEqual([]);
    expect(validateMandate({ ...base(), purpose: 'p'.repeat(500) })).toEqual([]);
  });
});

describe('Second review P2-2: a PID status the holder can withhold', () => {
  async function laxPidSetup() {
    const keys = await ES256.generateKeyPair();
    const iss = 'https://pid.lax.test';
    const signingKey = await importJWK(keys.privateKey as any, 'ES256');
    const publisher = new StatusListPublisher({ uri: `${iss}/status/1`, signingKey: signingKey as any, iss });
    const status = publisher.allocate();
    publisher.revoke(status);
    const counter = { fetched: 0 };
    const statusFetcher = async (uri: string) => {
      counter.fetched++;
      expect(uri).toBe(publisher.uri);
      return publisher.token();
    };
    const lax = new LaxIssuer({ signer: await ES256.getSigner(keys.privateKey), signAlg: 'ES256', hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt });
    const run = async (sd: string[], extra: Record<string, unknown> = {}, withStatus = true) => {
      const w = await createTestWallet();
      const iat = nowSeconds();
      w.storePid(
        await lax.issue(
          { iss, iat, exp: iat + 30 * DAY, vct: PID_VCT, cnf: { jwk: w.holderJwk }, ...(withStatus ? { status } : {}), given_name: 'Mario', family_name: 'Rossi' } as any,
          { _sd: sd } as any,
        ),
      );
      const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'] });
      const chain = { root: await w.approveMandate(m), delegations: [] };
      const inv = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.sepa', counterparty: 'shop.example', aud: AUD });
      return verifyAuthorization(chain, inv, {
        audience: AUD,
        nonces: new InMemoryNonceStore(),
        trustedIssuers: [{ iss, jwk: keys.publicKey as any }],
        statusFetcher,
        ...extra,
      });
    };
    return { run, counter, iss, keys };
  }

  it('a revoked PID whose status is disclosable and withheld is refused, without any fetch', async () => {
    const { run, counter } = await laxPidSetup();
    const plain = await run(['given_name', 'family_name']);
    expect(plain).toMatchObject({ decision: 'DENY', code: 'PID_REVOKED' });
    expect(counter.fetched).toBe(1);
    const hidden = await run(['given_name', 'family_name', 'status']);
    expect(hidden).toMatchObject({ decision: 'DENY', code: 'ROOT_INVALID', reason: expect.stringMatching(/no status list entry/) });
    expect(counter.fetched).toBe(1);
  });

  it('PIDs without status are accepted only from providers configured as such', async () => {
    const { run, iss, keys } = await laxPidSetup();
    expect(await run(['given_name', 'family_name'], {}, false)).toMatchObject({ decision: 'DENY', code: 'ROOT_INVALID' });
    const declared = { trustedIssuers: [{ iss, jwk: keys.publicKey as any, withoutStatusList: true }] };
    expect((await run(['given_name', 'family_name'], declared, false)).decision).toBe('ALLOW');
    expect((await run(['given_name', 'family_name'], { requirePidStatus: false }, false)).decision).toBe('ALLOW');
    // Another provider's opt-out does not apply.
    const other = { trustedIssuers: [{ iss, jwk: keys.publicKey as any }, { iss: 'https://other.test', jwk: keys.publicKey as any, withoutStatusList: true }] };
    expect(await run(['given_name', 'family_name'], other, false)).toMatchObject({ decision: 'DENY', code: 'ROOT_INVALID' });
  });

  it('the opt-out for x5c-trusted providers names the provider', async () => {
    const ca = await createTestCertificateAuthority('PID CA');
    const p = await createTestPidProvider('https://pid-x5c.test', { x5c: true, ca });
    const w = await createTestWallet();
    w.storePid(await p.issuePid(w.holderJwk, { given_name: 'Mario', family_name: 'Rossi' }));
    const root = await w.approveMandate(createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'] }));
    const base = { now: nowSeconds(), trustAnchors: [ca.anchorPem] };
    await expect(verifyRoot(root, base)).rejects.toMatchObject({ code: 'ROOT_INVALID' });
    await expect(verifyRoot(root, { ...base, pidProvidersWithoutStatus: ['https://elsewhere.test'] })).rejects.toMatchObject({ code: 'ROOT_INVALID' });
    await expect(verifyRoot(root, { ...base, pidProvidersWithoutStatus: [p.iss] })).resolves.toBeDefined();
  });

  it('the test PID provider declares the opt-out only when it has no status list', async () => {
    expect(provider.trusted.withoutStatusList).toBe(true);
    const withList = await createTestPidProvider('https://pid-with-list.test', { statusList: true });
    expect(withList.trusted.withoutStatusList).toBeUndefined();
  });

  it('an attestation whose exp is disclosable and withheld is refused', async () => {
    const w = await walletWithPid();
    const keys = await ES256.generateKeyPair();
    const lax = new LaxIssuer({ signer: await ES256.getSigner(keys.privateKey), signAlg: 'ES256', hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt });
    const iat = nowSeconds();
    const iss = 'https://lax-sca.test';
    w.storeCredential(
      await lax.issue({ iss, iat, exp: iat + DAY, vct: TEST_SCA_VCT, cnf: { jwk: w.holderJwk }, status: { status_list: { uri: `${iss}/status/1`, idx: 1 } } } as any, { _sd: ['exp'] } as any),
      { transactionDataTypes: ['urn:eudi:sca:emandate:1'] },
    );
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'], counterparties: ['shop.example'], limits: { currency: 'EUR', total: 1000 } });
    const req = await emandateRequest(m);
    await expect(
      handleMandateResponse(await w.respond(req.params), req.session, responseOptions({ emandate: { scaTrust: { trustedIssuers: [{ iss, jwk: keys.publicKey as any }] }, scaVcts: [TEST_SCA_VCT] } })),
    ).rejects.toMatchObject({ code: 'ATTESTATION_INVALID', message: expect.stringMatching(/no exp/) });
  });
});

describe('Second review P2-8: line separators and spacing in the purpose', () => {
  const base = () => createMandate({ agentJwk: agent.publicJwk, actions: ['payments.sepa'] });
  it('refuses U+2028 and U+2029, which wallets render as line breaks', () => {
    const fake = 'Train tickets.\u2029\u2029Mandate for an AI agent. Actions: travel.book. Counterparties: rail.example. Limits: 10.00 EUR in total.';
    expect(() => createMandate({ agentJwk: agent.publicJwk, actions: ['x.y'], purpose: fake })).toThrow(/purpose/);
    expect(() => createMandate({ agentJwk: agent.publicJwk, actions: ['x.y'], purpose: fake.replace('\u2029\u2029', '\u2028\u2028') })).toThrow(/purpose/);
  });

  for (const [name, purpose] of [
    ['leading space', ' Pay the shop'],
    ['trailing space', 'Pay the shop '],
    ['two spaces', 'Pay the  shop'],
    ['a tab', 'Pay\tthe shop'],
    ['two no-break spaces', 'Pay\u00A0\u00A0shop'],
  ]) {
    it(`refuses a purpose with ${name}`, () => {
      expect(validateMandate({ ...base(), purpose }).join()).toMatch(/purpose/);
    });
  }

  it('accepts single spaces between words', () => {
    expect(validateMandate({ ...base(), purpose: 'Pay the shop invoices, up to 30 euro' })).toEqual([]);
  });
});
