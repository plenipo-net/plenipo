/**
 * Raw request targets. The adapters must check the path a router will route on, not a normalised copy:
 * the WHATWG URL parser turns `\` into `/` and resolves `.`, `..` and `%2e` segments, while Node accepts
 * the raw target and Express routes on it. `/accounts/123\..\456/payments` would be checked as account 456
 * and executed as account "123\..\456". So a target is accepted only when parsing it changes nothing.
 */

export class TargetError extends Error {}

// Printable ASCII without space; anything else (controls, non-ASCII, DEL) is refused raw.
const SAFE_CHARS = /^[\x21-\x7e]*$/;
// Encoded slash, backslash, controls and DEL: routers decode these differently in parameters.
const ENCODED_DANGEROUS = /%(2f|5c|[01][0-9a-f]|7f)/i;

/** Problems of a raw path (no query): a reason, or undefined when the path is unambiguous. */
export function pathProblem(path: string): string | undefined {
  if (!path.startsWith('/')) return 'the path must start with /';
  if (path.startsWith('//')) return 'the path must not start with //';
  if (!SAFE_CHARS.test(path)) return 'the path contains a control, space or non-ASCII character';
  if (path.includes('\\')) return 'the path contains a backslash';
  if (path.includes('#')) return 'the path contains a fragment';
  if (ENCODED_DANGEROUS.test(path)) return 'the path contains an encoded slash, backslash or control character';
  for (const seg of path.split('/')) {
    const d = seg.toLowerCase().replace(/%2e/g, '.');
    if (d === '.' || d === '..') return 'the path contains a dot segment';
  }
  return undefined;
}

/**
 * Builds the URL the gateway checks from a raw origin-form request target, and refuses the target when the
 * URL would differ from it: what is authorised must be byte for byte what the router routes.
 */
export function urlFromRawTarget(target: string | undefined, origin: string): URL {
  const t = target ?? '/';
  const q = t.indexOf('?');
  const path = q < 0 ? t : t.slice(0, q);
  const query = q < 0 ? '' : t.slice(q);
  const problem = pathProblem(path);
  if (problem) throw new TargetError(problem);
  if (!SAFE_CHARS.test(query) || query.includes('#')) throw new TargetError('the query contains a control, space, fragment or non-ASCII character');
  const url = new URL(path + query, origin);
  if (url.pathname !== path || (url.search !== query && !(query === '?' && url.search === ''))) {
    throw new TargetError('the request target is not in normal form');
  }
  return url;
}
