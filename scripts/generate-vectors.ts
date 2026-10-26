/**
 * Generates the interoperability test vectors in test-vectors/. Run with `npm run vectors`.
 *
 * Every vector is a chain, an invocation and the verifier inputs that decide it, with the decision a
 * conforming verifier must reach. Signatures are ECDSA and therefore not reproducible byte for byte:
 * regenerating replaces every token, and the committed file is the reference.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { decodeJwt, SignJWT } from 'jose';
import {
  createInvocation,
  createMandate,
  delegateMandate,
  generateAgentKey,
  mandateHash,
  type Amount,
  type Mandate,
  type MandateChain,
} from '../src/index.js';
import { createTestPidProvider, createTestWallet } from '../src/testing.js';

const AUD = 'https://bank.example';

interface Vector {
  id: string;
  description: string;
  chain: MandateChain;
  invocation: string;
  verifier: { audience: string; now: number; expected?: { action?: string; counterparty?: string | null; amount?: Amount | null } };
  expect: { decision: 'ALLOW' | 'DENY'; code?: string; at?: number };
}

async function main() {
  const provider = await createTestPidProvider();
  const wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Maria', family_name: 'Rossi' }));
  const agent = await generateAgentKey();
  const sub = await generateAgentKey();
  const stranger = await generateAgentKey();

  const bills = createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.transfer', 'accounts.read'],
    counterparties: ['acquaviva.example', 'lumen-energia.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
    ttlSeconds: 30 * 86400,
    maxDepth: 1,
    purpose: 'Pay the household bills',
  });
  const root = await wallet.approveMandate(bills);
  const single: MandateChain = { root, delegations: [] };

  const readOnly: Mandate = createMandate({
    agentJwk: sub.publicJwk,
    actions: ['accounts.read'],
    counterparties: ['acquaviva.example', 'lumen-energia.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
    exp: bills.exp,
  });
  const delegated: MandateChain = {
    root,
    delegations: [await delegateMandate({ parent: bills, parentAgentKey: agent.privateKey, child: readOnly })],
  };
  // A delegation signed by a key that is not the parent agent's.
  const forged: MandateChain = {
    root,
    delegations: [
      await new SignJWT({ mandate: readOnly, parent_id: bills.id, parent_hash: mandateHash(bills), iat: Math.floor(Date.now() / 1000) })
        .setProtectedHeader({ alg: 'ES256', typ: 'plenipo-delegation+jwt' })
        .sign(stranger.privateKey),
    ],
  };

  const vectors: Vector[] = [];
  const add = async (
    id: string,
    description: string,
    chain: MandateChain,
    key: CryptoKey,
    mandateId: string,
    call: { action: string; counterparty?: string; amount?: Amount; aud?: string },
    expect: Vector['expect'],
    verifier: Partial<Vector['verifier']> = {},
  ) => {
    const invocation = await createInvocation(key, { chain, mandateId, aud: call.aud ?? AUD, action: call.action, counterparty: call.counterparty, amount: call.amount });
    const iat = decodeJwt(invocation).iat as number;
    vectors.push({ id, description, chain, invocation, verifier: { audience: AUD, now: iat + 1, ...verifier }, expect });
  };
  const eur = (value: number): Amount => ({ value, currency: 'EUR' });
  const pay = (counterparty: string, value: number) => ({ action: 'payments.transfer', counterparty, amount: eur(value) });

  await add('allow-payment', 'A payment to a listed payee within the per-operation limit.', single, agent.privateKey, bills.id, pay('acquaviva.example', 8950), { decision: 'ALLOW' });
  await add('deny-counterparty', 'A payee the mandate does not list.', single, agent.privateKey, bills.id, pay('example.org', 1000), { decision: 'DENY', code: 'COUNTERPARTY_NOT_PERMITTED', at: 0 });
  await add('deny-per-operation', 'An amount above the per-operation limit.', single, agent.privateKey, bills.id, pay('lumen-energia.example', 15001), { decision: 'DENY', code: 'LIMIT_PER_OPERATION', at: 0 });
  await add('deny-currency', 'An amount in a currency other than the limits currency.', single, agent.privateKey, bills.id, { action: 'payments.transfer', counterparty: 'acquaviva.example', amount: { value: 1000, currency: 'USD' } }, { decision: 'DENY', code: 'CURRENCY_MISMATCH', at: 0 });
  await add('deny-action', 'An action the mandate does not cover.', single, agent.privateKey, bills.id, { action: 'cards.block', counterparty: 'acquaviva.example' }, { decision: 'DENY', code: 'ACTION_NOT_PERMITTED', at: 0 });
  await add('deny-audience', 'An invocation addressed to another relying party.', single, agent.privateKey, bills.id, { ...pay('acquaviva.example', 1000), aud: 'https://other.example' }, { decision: 'DENY', code: 'AUDIENCE_MISMATCH' });
  await add('deny-wrong-signer', 'An invocation signed by a key that is not the leaf agent key.', single, stranger.privateKey, bills.id, pay('acquaviva.example', 1000), { decision: 'DENY', code: 'INVOCATION_SIGNATURE_INVALID' });
  await add('allow-read-no-money', 'A balance read the relying party declares as moving no money and having no counterparty.', single, agent.privateKey, bills.id, { action: 'accounts.read' }, { decision: 'ALLOW' }, { expected: { action: 'accounts.read', counterparty: null, amount: null } });
  await add('allow-delegated-read', 'A sub-agent with a read-only delegation reads the balance.', delegated, sub.privateKey, readOnly.id, { action: 'accounts.read', counterparty: 'acquaviva.example', amount: eur(0) }, { decision: 'ALLOW' });
  await add('deny-delegated-payment', 'The read-only sub-agent tries to pay.', delegated, sub.privateKey, readOnly.id, pay('acquaviva.example', 1000), { decision: 'DENY', code: 'ACTION_NOT_PERMITTED', at: 1 });
  await add('deny-forged-delegation', 'A delegation not signed by the parent agent.', forged, sub.privateKey, readOnly.id, { action: 'accounts.read', counterparty: 'acquaviva.example', amount: eur(0) }, { decision: 'DENY', code: 'DELEGATION_SIGNATURE_INVALID', at: 1 });
  const late = await createInvocation(agent.privateKey, { chain: single, mandateId: bills.id, aud: AUD, ...pay('acquaviva.example', 1000) });
  vectors.push({
    id: 'deny-expired',
    description: 'The verifier clock is past the mandate expiry.',
    chain: single,
    invocation: late,
    verifier: { audience: AUD, now: bills.exp + 1 },
    expect: { decision: 'DENY', code: 'EXPIRED', at: 0 },
  });

  // Invocation members (0.5): a verifier must refuse members it does not know, a key without arguments, and a
  // key it cannot keep, since a retry would otherwise run again.
  const signed = async (payload: Record<string, unknown>) =>
    new SignJWT(payload).setProtectedHeader({ alg: 'ES256', typ: 'plenipo-invocation+jwt' }).sign(agent.privateKey);
  const base = await createInvocation(agent.privateKey, { chain: single, mandateId: bills.id, aud: AUD, ...pay('acquaviva.example', 1000), args: { payee: 'acquaviva.example' } });
  const claims = decodeJwt(base) as Record<string, unknown>;
  const hand = (id: string, description: string, invocation: string, expect: Vector['expect']) =>
    vectors.push({ id, description, chain: single, invocation, verifier: { audience: AUD, now: (claims.iat as number) + 1 }, expect });
  hand('deny-unknown-member', 'An invocation with a member the profile does not define.', await signed({ ...claims, nonce: 'vector-unknown-member', priority: 'high' }), {
    decision: 'DENY',
    code: 'MALFORMED',
  });
  hand('deny-idem-without-args', 'An idempotency key without an argument hash.', await signed({ ...claims, args_hash: undefined, nonce: 'vector-idem-no-args', idem: '0123456789abcdef0123456789abcdef' }), {
    decision: 'DENY',
    code: 'MALFORMED',
  });
  hand('deny-idem-without-store', 'An idempotency key sent to a verifier that keeps no idempotency keys.', await signed({ ...claims, nonce: 'vector-idem-no-store', idem: '0123456789abcdef0123456789abcdef' }), {
    decision: 'DENY',
    code: 'CONFIGURATION',
  });

  const out = {
    profile: 'plenipo-0.2',
    generated: new Date().toISOString().slice(0, 10),
    notes:
      'Verify each vector with the trusted issuer below, a fresh nonce store, a fresh spending ledger, no idempotency store and no revocation, at verifier.now. ' +
      'Each listed PID provider issues PIDs without a status list entry. Where expect.code is absent only the decision is normative.',
    trustedIssuers: [provider.trusted],
    vectors,
  };
  mkdirSync(new URL('../test-vectors/', import.meta.url), { recursive: true });
  writeFileSync(new URL('../test-vectors/plenipo-0.2.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
  console.log(`wrote ${vectors.length} vectors`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
