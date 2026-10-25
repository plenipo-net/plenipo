import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { InMemoryNonceStore, InMemorySpendingLedger, verifyAuthorization, type MandateChain, type TrustedIssuer } from '../src/index.js';

interface VectorFile {
  profile: string;
  trustedIssuers: TrustedIssuer[];
  vectors: {
    id: string;
    description: string;
    chain: MandateChain;
    invocation: string;
    verifier: { audience: string; now: number; expected?: Record<string, unknown> };
    expect: { decision: 'ALLOW' | 'DENY'; code?: string; at?: number };
  }[];
}

const file = JSON.parse(readFileSync(new URL('../test-vectors/plenipo-0.1.json', import.meta.url), 'utf8')) as VectorFile;

describe(`test vectors (${file.profile})`, () => {
  it('has vectors for both outcomes', () => {
    expect(file.vectors.some((v) => v.expect.decision === 'ALLOW')).toBe(true);
    expect(file.vectors.some((v) => v.expect.decision === 'DENY')).toBe(true);
    expect(new Set(file.vectors.map((v) => v.id)).size).toBe(file.vectors.length);
  });

  for (const v of file.vectors) {
    it(`${v.id}: ${v.description}`, async () => {
      const d = await verifyAuthorization(v.chain, v.invocation, {
        trustedIssuers: file.trustedIssuers,
        audience: v.verifier.audience,
        now: v.verifier.now,
        nonces: new InMemoryNonceStore(),
        ledger: new InMemorySpendingLedger(),
        ...(v.verifier.expected ? { expected: v.verifier.expected } : {}),
      });
      expect(d.decision).toBe(v.expect.decision);
      if (v.expect.code) expect(d).toMatchObject({ code: v.expect.code });
      if (v.expect.at !== undefined) expect(d).toMatchObject({ at: v.expect.at });
    });
  }
});
