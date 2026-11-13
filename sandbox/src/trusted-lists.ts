/**
 * PID providers taken from ETSI TS 119 602 lists of trusted entities (LoTE), such as the list of test PID
 * providers that the EUDI Wallet reference implementation publishes. A PID from the EU test issuer, held in
 * the reference wallet, is then accepted by the platform and the bank like the sandbox's own PIDs.
 *
 *   PLENIPO_PID_TRUSTED_LISTS          list URLs (https) or files, comma separated
 *   PLENIPO_PID_TRUSTED_LIST_SIGNERS   PEM files of the certificates allowed to sign them, comma separated
 *   PLENIPO_PID_LIST_STATUS_ORIGINS    optional: https origins whose PID status lists are accepted when
 *                                      signed under a listed PID provider or revocation service
 *
 * The lists are read at start and again every PLENIPO_PID_TRUSTED_LIST_REFRESH_HOURS (default 12). A list
 * that cannot be fetched or verified is reported and skipped: the sandbox still starts, trusting its own
 * PID provider, and keeps the anchors of the last good reading.
 */
import { readFileSync } from 'node:fs';
import { fetchTrustedList, loadTrustedList, LOTE_SERVICE_TYPE, LOTE_TYPE, trustConfigFromLists, type TrustConfig, type TrustedList } from 'plenipo';

export interface PidListSettings {
  sources: string[];
  signerPems: string[];
  statusOrigins: string[];
  refreshSeconds: number;
}

const split = (v: string | undefined) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);

export function pidListSettingsFromEnv(env: NodeJS.ProcessEnv = process.env): PidListSettings | undefined {
  const sources = split(env.PLENIPO_PID_TRUSTED_LISTS);
  if (sources.length === 0) return undefined;
  const signers = split(env.PLENIPO_PID_TRUSTED_LIST_SIGNERS);
  if (signers.length === 0) throw new Error('PLENIPO_PID_TRUSTED_LISTS needs PLENIPO_PID_TRUSTED_LIST_SIGNERS: the certificates that sign the lists');
  const statusOrigins = split(env.PLENIPO_PID_LIST_STATUS_ORIGINS);
  for (const o of statusOrigins) {
    let u: URL | undefined;
    try {
      u = new URL(o);
    } catch {
      u = undefined;
    }
    if (!u || u.protocol !== 'https:' || u.origin !== o.replace(/\/$/, '')) throw new Error(`PLENIPO_PID_LIST_STATUS_ORIGINS: ${o} is not an https origin`);
  }
  const hours = Number(env.PLENIPO_PID_TRUSTED_LIST_REFRESH_HOURS ?? 12);
  if (!Number.isFinite(hours) || hours <= 0) throw new Error('PLENIPO_PID_TRUSTED_LIST_REFRESH_HOURS must be a positive number');
  return {
    sources,
    signerPems: signers.map((f) => readFileSync(f, 'utf8')),
    statusOrigins: statusOrigins.map((o) => o.replace(/\/$/, '')),
    refreshSeconds: Math.round(hours * 3600),
  };
}

export interface PidListReading {
  /** CA certificates of the listed PID issuance services, as PEM. */
  issuanceAnchors: string[];
  /** CA certificates of the listed PID revocation services, as PEM (they sign status lists). */
  revocationAnchors: string[];
  lists: Array<{ source: string; sequence?: number; nextUpdate?: string; entities?: number; error?: string }>;
}

async function readSource(source: string): Promise<Uint8Array | string> {
  if (source.startsWith('https://')) return fetchTrustedList(source);
  if (/^[a-z][a-z0-9+.-]*:/i.test(source)) throw new Error('lists are read over https or from a file');
  return readFileSync(source, 'utf8');
}

/** Reads and verifies every list; a failing list is reported in `lists` and contributes nothing. */
export async function readPidLists(settings: PidListSettings): Promise<PidListReading> {
  const good: TrustedList[] = [];
  const lists: PidListReading['lists'] = [];
  for (const source of settings.sources) {
    try {
      const list = await loadTrustedList(await readSource(source), {
        signerCertificates: settings.signerPems,
        expectedType: LOTE_TYPE.pidProviders,
        // The EU profiles allow six months between issue and NextUpdate; a day of slack for rounding.
        maxValiditySeconds: 184 * 24 * 3600,
      });
      good.push(list);
      lists.push({
        source,
        sequence: list.sequenceNumber,
        nextUpdate: new Date(list.nextUpdate * 1000).toISOString(),
        entities: list.entities.length,
      });
    } catch (e) {
      lists.push({ source, error: (e as Error).message });
    }
  }
  const anchorsOf = (type: string) => (good.length ? (trustConfigFromLists(good, { serviceTypes: [type] }).trustAnchors ?? []) : []);
  return { issuanceAnchors: anchorsOf(LOTE_SERVICE_TYPE.pidIssuance), revocationAnchors: anchorsOf(LOTE_SERVICE_TYPE.pidRevocation), lists };
}

export interface PidListTrust {
  /** The status trust to pass as `pidStatusTrust`, when status origins are configured. */
  statusTrust?: TrustConfig;
  /** What the last reading found, for logs and the admin view. */
  last(): PidListReading | undefined;
  refresh(): Promise<PidListReading>;
  close(): void;
}

/**
 * Keeps `anchors` (the array the platform and the bank read on every verification) equal to the base
 * anchors plus the listed PID providers. The array is changed in place, so a refresh needs no restart.
 * With status origins, a status trust is built the same way: the sandbox's own PID origin and anchors,
 * plus the listed providers and revocation services for the listed origins.
 */
export async function startPidListTrust(
  settings: PidListSettings,
  anchors: string[],
  own: { statusOrigin: string; anchors: string[] },
  log: (s: string) => void = (s) => console.log(s),
): Promise<PidListTrust> {
  const base = anchors.length;
  const statusTrust: TrustConfig | undefined = settings.statusOrigins.length
    ? { trustAnchors: [...own.anchors], statusOrigins: [own.statusOrigin, ...settings.statusOrigins] }
    : undefined;
  const statusBase = own.anchors.length;
  let last: PidListReading | undefined;

  async function refresh(): Promise<PidListReading> {
    const r = await readPidLists(settings);
    for (const l of r.lists) {
      log(l.error ? `[trusted lists] ${l.source}: ${l.error}` : `[trusted lists] ${l.source}: sequence ${l.sequence}, ${l.entities} entities, next update ${l.nextUpdate}`);
    }
    const ok = r.lists.some((l) => !l.error);
    // Keep the last good anchors when every list failed this time (a network outage is not a revocation).
    if (ok || !last) {
      anchors.splice(base, anchors.length - base, ...r.issuanceAnchors);
      if (statusTrust?.trustAnchors) {
        statusTrust.trustAnchors.splice(statusBase, statusTrust.trustAnchors.length - statusBase, ...r.issuanceAnchors, ...r.revocationAnchors);
      }
      last = r;
    }
    log(`[trusted lists] trusting ${anchors.length - base} listed PID provider CA certificates`);
    return r;
  }

  await refresh();
  const timer = setInterval(() => void refresh().catch((e) => log(`[trusted lists] refresh failed: ${(e as Error).message}`)), settings.refreshSeconds * 1000);
  timer.unref();
  return { statusTrust, last: () => last, refresh, close: () => clearInterval(timer) };
}
