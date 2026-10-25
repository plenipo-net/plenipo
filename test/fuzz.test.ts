/**
 * Property-based tests on the code that reads untrusted input. Each property runs a few hundred random
 * cases; on failure fast-check prints the smallest input that breaks it and a seed to replay it.
 * The properties: parsers either return a value or throw an Error (never crash otherwise, never hang),
 * and verification never returns ALLOW for input that was not produced by the signing functions.
 */
import fc from 'fast-check';
import { describe, expect, it, beforeAll } from 'vitest';
import {
  canonicalize,
  createInvocation,
  createMandate,
  decodeMandateTransactionData,
  decodeStatusList,
  ecdsaDerToJose,
  encodeChainHeader,
  generateAgentKey,
  hasDuplicateJsonKeys,
  InMemoryNonceStore,
  loadTrustedList,
  parseAuthorizationHeaders,
  validateMandate,
  verifyAuthorization,
  type MandateChain,
} from '../src/index.js';
import { parseDelegation } from '../src/experimental.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider } from '../src/testing.js';

const RUNS = { numRuns: 300 };
const AUD = 'https://bank.example';

/** Asserts that `f` returns or throws an Error, and nothing else. */
async function returnsOrThrowsError(f: () => unknown): Promise<void> {
  try {
    await f();
  } catch (e) {
    expect(e).toBeInstanceOf(Error);
  }
}

const json = fc.jsonValue({ maxDepth: 4 });
const tokenish = fc.oneof(
  fc.string({ maxLength: 300 }),
  fc.base64String({ maxLength: 300 }),
  fc.tuple(fc.base64String(), fc.base64String(), fc.base64String()).map((p) => p.join('.').replace(/=/g, '')),
  json.map((v) => Buffer.from(JSON.stringify(v)).toString('base64url')),
);

describe('DER signatures', () => {
  it('decodes any well-formed DER (r, s) back to the same integers', () => {
    const scalar = fc.uint8Array({ minLength: 1, maxLength: 32 });
    const derInt = (b: Uint8Array) => {
      let v = Buffer.from(b);
      while (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) v = v.subarray(1);
      if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0]), v]);
      return Buffer.concat([Buffer.from([0x02, v.length]), v]);
    };
    fc.assert(
      fc.property(scalar, scalar, (r, s) => {
        const body = Buffer.concat([derInt(r), derInt(s)]);
        const der = Buffer.concat([Buffer.from([0x30, body.length]), body]);
        const jose = ecdsaDerToJose(der, 'ES256');
        expect(jose.length).toBe(64);
        expect(BigInt('0x' + Buffer.from(jose.subarray(0, 32)).toString('hex'))).toBe(BigInt('0x' + (Buffer.from(r).toString('hex') || '0')));
        expect(BigInt('0x' + Buffer.from(jose.subarray(32)).toString('hex'))).toBe(BigInt('0x' + (Buffer.from(s).toString('hex') || '0')));
      }),
      RUNS,
    );
  });

  it('either decodes or throws on arbitrary bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 80 }), (bytes) => {
        try {
          expect(ecdsaDerToJose(bytes, 'ES256').length).toBe(64);
        } catch (e) {
          expect((e as Error).message).toMatch(/^invalid DER ECDSA signature/);
        }
      }),
      RUNS,
    );
  });
});

describe('parsers of untrusted input', () => {
  it('mandate transaction data', () => {
    fc.assert(fc.asyncProperty(tokenish, (s) => returnsOrThrowsError(() => decodeMandateTransactionData(s))), RUNS);
  });

  it('accepts canonical base64url of canonical JSON only', () => {
    fc.assert(
      fc.property(json, (v) => {
        const canonical = Buffer.from(canonicalize(v)).toString('base64url');
        const loose = Buffer.from(JSON.stringify(v, null, 1)).toString('base64url');
        if (loose !== canonical) expect(() => decodeMandateTransactionData(loose)).toThrow();
      }),
      RUNS,
    );
  });

  it('delegations', () => {
    fc.assert(fc.asyncProperty(fc.oneof(tokenish, tokenish.map((t) => `${t}~${t}~`)), (s) => returnsOrThrowsError(() => parseDelegation(s))), RUNS);
  });

  it('authorization headers never throw', () => {
    fc.assert(
      fc.property(tokenish, tokenish, (chain, inv) => {
        const headers = new Headers();
        try {
          headers.set('plenipo-chain', chain);
          headers.set('plenipo-invocation', inv);
        } catch {
          return; // not a valid header value; the HTTP layer refuses it before Plenipo sees it
        }
        const r = parseAuthorizationHeaders(headers);
        expect(typeof r.ok).toBe('boolean');
      }),
      RUNS,
    );
  });

  it('status lists', () => {
    fc.assert(fc.asyncProperty(json, (v) => returnsOrThrowsError(() => decodeStatusList(v))), RUNS);
  });

  it('trusted lists', () => {
    fc.assert(fc.asyncProperty(fc.oneof(tokenish, json.map((v) => JSON.stringify(v))), (s) => returnsOrThrowsError(() => loadTrustedList(s))), { numRuns: 100 });
  });

  it('mandate validation reports errors instead of throwing', () => {
    fc.assert(
      fc.property(json, (v) => {
        expect(Array.isArray(validateMandate(v as never))).toBe(true);
      }),
      RUNS,
    );
  });

  it('duplicate key detection stops at the end of an unterminated string', () => {
    // Found by the property below: the scan used to loop forever on `"abc` or `{"a\\"`.
    expect(() => hasDuplicateJsonKeys('"abc')).toThrow(/unterminated/);
    expect(() => hasDuplicateJsonKeys('{"a\\"')).toThrow(/unterminated/);
  });

  it('duplicate key detection', () => {
    fc.assert(fc.asyncProperty(fc.oneof(fc.string(), json.map((v) => JSON.stringify(v))), (s) => returnsOrThrowsError(() => hasDuplicateJsonKeys(s))), RUNS);
  });
});

describe('verification of tampered input', () => {
  let provider: TestPidProvider;
  let chain: MandateChain;
  let invocation: string;

  beforeAll(async () => {
    provider = await createTestPidProvider();
    const wallet = await createTestWallet();
    wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Maria', family_name: 'Rossi' }));
    const agent = await generateAgentKey();
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.transfer'], counterparties: ['acquaviva.example'], limits: { currency: 'EUR', per_operation: 10000 } });
    chain = { root: await wallet.approveMandate(m), delegations: [] };
    invocation = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.transfer', counterparty: 'acquaviva.example', amount: { value: 100, currency: 'EUR' }, aud: AUD });
  });

  const verify = (c: unknown, inv: unknown) =>
    verifyAuthorization(c as MandateChain, inv as string, { trustedIssuers: [provider.trusted], audience: AUD, nonces: new InMemoryNonceStore() });

  it('the untampered chain is allowed', async () => {
    expect((await verify(chain, invocation)).decision).toBe('ALLOW');
  });

  it('never allows a chain or invocation with one character changed', async () => {
    const encoded = encodeChainHeader(chain);
    await fc.assert(
      fc.asyncProperty(fc.nat(), fc.nat(), fc.constantFrom('chain', 'invocation', 'presentation', 'transaction_data'), fc.string({ minLength: 1, maxLength: 1 }), async (i, j, target, ch) => {
        const flip = (s: string, k: number) => {
          const pos = k % s.length;
          const c = ch === s[pos] ? (ch === 'A' ? 'B' : 'A') : ch;
          return s.slice(0, pos) + c + s.slice(pos + 1);
        };
        let c: unknown = chain;
        let inv = invocation;
        if (target === 'invocation') inv = flip(invocation, i);
        else if (target === 'presentation') c = { ...chain, root: { ...chain.root, presentation: flip(chain.root.presentation, j) } };
        else if (target === 'transaction_data') c = { ...chain, root: { ...chain.root, transaction_data: flip(chain.root.transaction_data, j) } };
        else {
          try {
            c = JSON.parse(Buffer.from(flip(encoded, j), 'base64url').toString('utf8'));
          } catch {
            return;
          }
        }
        if (c === chain && inv === invocation) return;
        const d = await verify(c, inv);
        // A change that decodes to the same bytes (base64url padding bits, for instance) may still verify.
        if (d.decision === 'ALLOW') {
          const same =
            JSON.stringify(c) === JSON.stringify(chain) ||
            (target === 'invocation' && Buffer.from(inv.split('.')[2] ?? '', 'base64url').equals(Buffer.from(invocation.split('.')[2], 'base64url')) && inv.split('.').slice(0, 2).join('.') === invocation.split('.').slice(0, 2).join('.'));
          expect(same).toBe(true);
        }
      }),
      { numRuns: 200 },
    );
  });

  it('never throws on arbitrary chains and invocations', async () => {
    await fc.assert(
      fc.asyncProperty(fc.oneof(json, fc.record({ root: json, delegations: fc.array(tokenish, { maxLength: 3 }) })), fc.oneof(tokenish, json), async (c, inv) => {
        const d = await verify(c, inv);
        expect(d.decision).toBe('DENY');
      }),
      { numRuns: 200 },
    );
  });
});
