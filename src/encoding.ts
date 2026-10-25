import { createHash } from 'node:crypto';
import canonicalizeImport from 'canonicalize';

const canonicalizeFn = canonicalizeImport as unknown as (input: unknown) => string | undefined;

/** RFC 8785 canonical JSON. */
export function canonicalize(value: unknown): string {
  const out = canonicalizeFn(value);
  if (out === undefined) throw new TypeError('value cannot be canonicalized');
  return out;
}

export function base64url(input: string | Uint8Array): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
  return buf.toString('base64url');
}

export function fromBase64url(input: string): string {
  return Buffer.from(input, 'base64url').toString('utf8');
}

/** SHA-256 of a UTF-8 string, base64url-encoded without padding. */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('base64url');
}

/** Hash that binds a delegation to its parent mandate. */
export function mandateHash(mandate: unknown): string {
  return sha256(canonicalize(mandate));
}
