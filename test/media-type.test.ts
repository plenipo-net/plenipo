/**
 * jsonMediaType: the JSON media types the gateways accept, and the charset parameter read without a regex
 * (CodeQL js/polynomial-redos on the former pattern).
 */
import { describe, expect, it } from 'vitest';
import { jsonMediaType } from '../src/index.js';

describe('jsonMediaType', () => {
  it('accepts JSON types with no charset or utf-8, quoted or not', () => {
    for (const ct of ['application/json', 'Application/JSON', 'application/problem+json', 'application/json; charset=utf-8', 'application/json;charset=UTF-8', 'application/json; charset = "utf-8"', 'application/json; charset="utf-8', 'application/json; charset=utf-8"']) {
      expect(jsonMediaType(ct), ct).not.toBeNull();
    }
  });

  it('refuses other types, other charsets, other parameters and stray quotes', () => {
    for (const ct of [null, '', 'text/plain', 'application/jsonx', 'application/json; charset=latin1', 'application/json; boundary=x', 'application/json; charset', 'application/json; charset=ut"f-8', 'application/json; charsetx=utf-8']) {
      expect(jsonMediaType(ct), String(ct)).toBeNull();
    }
  });

  it('takes linear time on a long header', () => {
    const started = Date.now();
    for (const p of [`charset=${'"'.repeat(1)}${'a'.repeat(100_000)}"x`, `charset${' '.repeat(100_000)}x`, `charset=${' '.repeat(100_000)}`]) jsonMediaType(`application/json; ${p}`);
    expect(Date.now() - started).toBeLessThan(200);
  });
});
