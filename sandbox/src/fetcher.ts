/**
 * Status lists are identified by https URLs, and the library fetches them over https only. In the
 * sandbox the services listen on plain http on 127.0.0.1, so this fetcher maps each known https
 * origin to the local address of the service that publishes it. It keeps the guarantees the library
 * asks of a custom fetcher: no redirects, a 5 second timeout, at most 1 MB, and nothing outside the map.
 */
import { defaultStatusFetcher, type StatusFetcher } from 'plenipo';
import { boundedFetch } from './http.js';

export function mappedStatusFetcher(
  /** https origin → local base URL. Read on every fetch, so routes can be added as services start. */
  map: Record<string, string>,
  opts: { allowPublicHttps?: boolean; onFetch?: (uri: string) => void } = {},
): StatusFetcher {
  return async (uri) => {
    const u = new URL(uri);
    if (u.protocol !== 'https:') throw new Error('status lists are fetched over https only');
    opts.onFetch?.(uri);
    const route = Object.entries(map).find(([origin]) => new URL(origin).origin === u.origin);
    const local = route?.[1].replace(/\/$/, '');
    if (!local) {
      if (opts.allowPublicHttps) return defaultStatusFetcher(uri);
      throw new Error(`no route to ${u.origin} in the sandbox`);
    }
    const res = await boundedFetch(`${local}${u.pathname}${u.search}`, { headers: { accept: 'application/statuslist+jwt' } });
    if (res.status !== 200) throw new Error(`status list returned HTTP ${res.status}`);
    return res.text.trim();
  };
}
