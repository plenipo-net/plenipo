/**
 * Boots the five services in dependency order and wires their configuration. The launcher passes trust
 * material (the PID trust anchor, the platform's status list key, the RP CA) as configuration, the way a
 * deployment would; at runtime the services talk to each other over HTTP only.
 */
import { readFileSync } from 'node:fs';
import type { TrustConfig, TrustedIssuer } from 'plenipo';
import { PERSONS } from './catalog.js';
import { DEFAULT_IDENTITIES, DEFAULT_PORTS, type Identities, type SandboxOptions, type ServiceName } from './config.js';
import { mappedStatusFetcher } from './fetcher.js';
import { startBank, type BankService } from './services/bank.js';
import { startDashboard, type DashboardService } from './services/dashboard.js';
import { startPidProvider, type PidProviderService } from './services/pid-provider.js';
import { loadRequestSigner, startPlatform, type PlatformService } from './services/platform.js';
import { createStores, storeOptionsFromEnv, type SandboxStores } from './services/stores.js';
import { startWallet, type WalletService } from './services/wallet.js';

export interface Sandbox {
  urls: Record<ServiceName, string>;
  /** URLs to show to a browser (public URLs when configured). */
  publicUrls: Record<ServiceName, string>;
  identities: Identities;
  pid: PidProviderService;
  wallet: WalletService;
  platform: PlatformService;
  bank: BankService;
  dashboard: DashboardService;
  statusCacheSeconds: number;
  adminToken?: string;
  stores: SandboxStores;
  close(): Promise<void>;
}

/** Extra PID providers trusted by key, e.g. a walt.id issuer for level 2: a JSON file of [{ iss, jwk }]. */
function extraPidIssuers(): TrustedIssuer[] | undefined {
  const file = process.env.PLENIPO_EXTRA_PID_ISSUERS_FILE;
  if (!file) return undefined;
  const list = JSON.parse(readFileSync(file, 'utf8')) as TrustedIssuer[];
  if (!Array.isArray(list) || !list.every((t) => typeof t.iss === 'string' && typeof t.jwk === 'object')) {
    throw new Error(`${file} must contain an array of { iss, jwk }`);
  }
  return list;
}

/**
 * Who may sign PID status lists hosted on another origin than the PID `iss`, e.g. the EU test issuer:
 * a JSON file { "trustAnchors": ["ca.pem", ...], "statusOrigins": ["https://..."] } (paths relative to cwd).
 */
function pidStatusTrust(): TrustConfig | undefined {
  const file = process.env.PLENIPO_PID_STATUS_TRUST_FILE;
  if (!file) return undefined;
  const raw = JSON.parse(readFileSync(file, 'utf8')) as { trustAnchors?: string[]; statusOrigins?: string[] };
  if (!Array.isArray(raw.statusOrigins) || raw.statusOrigins.some((o) => !o.startsWith('https://'))) {
    throw new Error(`${file}: statusOrigins must be a list of https origins`);
  }
  return { trustAnchors: (raw.trustAnchors ?? []).map((f) => readFileSync(f, 'utf8')), statusOrigins: raw.statusOrigins };
}

/** Extra PID trust anchors (PEM files, comma separated), e.g. the CA of a walt.id or EU test issuer. */
function extraAnchors(): string[] {
  const files = process.env.PLENIPO_EXTRA_PID_ANCHORS;
  return files ? files.split(',').filter(Boolean).map((f) => readFileSync(f.trim(), 'utf8')) : [];
}

export async function startSandbox(options: SandboxOptions = {}): Promise<Sandbox> {
  const host = options.host ?? '127.0.0.1';
  const port = (n: ServiceName) => options.ports?.[n] ?? DEFAULT_PORTS[n];
  const identities: Identities = { ...DEFAULT_IDENTITIES, ...options.identities };
  const statusCacheSeconds = options.statusCacheSeconds ?? 2;
  const started: Array<{ close(): Promise<void> }> = [];
  // Stores first: with Postgres or Redis a wrong URL should stop the start, before any port is taken.
  const stores: SandboxStores = await createStores({ ...storeOptionsFromEnv(), ...options.stores });
  started.push(stores);
  const housekeeping = setInterval(() => void stores.housekeeping().catch((e) => console.error('[stores] housekeeping failed:', (e as Error).message)), 60_000);
  housekeeping.unref();
  started.push({ close: async () => clearInterval(housekeeping) });
  const log = options.verbose ? (s: string) => console.log(s) : () => {};

  try {
    const pid = await startPidProvider({ host, port: port('pid'), iss: identities.pidIssuer, adminToken: options.adminToken });
    started.push(pid);
    log(`pid provider on ${pid.url}`);

    // The platform's status origin is known before it starts; its local address only after.
    const routes: Record<string, string> = { [new URL(identities.pidIssuer).origin]: pid.url };
    const statusFetcher = mappedStatusFetcher(routes, { allowPublicHttps: process.env.SANDBOX_ALLOW_PUBLIC_STATUS === '1' });
    const pidAnchors = [pid.anchorPem, ...extraAnchors()];
    const pidIssuers = extraPidIssuers();
    const pidStatus = pidStatusTrust();

    let requestSigner;
    if (process.env.PLATFORM_RP_KEY && process.env.PLATFORM_RP_CHAIN) {
      requestSigner = await loadRequestSigner(process.env.PLATFORM_RP_KEY, process.env.PLATFORM_RP_CHAIN);
    }
    // The wallet's link is known only once it listens; the platform reads it lazily through this object.
    const walletRef: { url?: string } = {};
    const platform = await startPlatform({
      host,
      port: port('platform'),
      publicUrl: options.publicUrls?.platform,
      origin: identities.platformOrigin,
      pidTrustAnchors: pidAnchors,
      pidTrustedIssuers: pidIssuers,
      pidStatusTrust: pidStatus,
      statusFetcher,
      requestSigner,
      bankHost: identities.bankHost,
      stores: stores.platform,
      get walletUrl() {
        return walletRef.url;
      },
    });
    started.push(platform);
    routes[new URL(identities.platformOrigin).origin] = platform.url;
    log(`platform on ${platform.url}`);

    const bank = await startBank({
      host,
      port: port('bank'),
      bankHost: identities.bankHost,
      pidTrustAnchors: pidAnchors,
      pidTrustedIssuers: pidIssuers,
      pidStatusTrust: pidStatus,
      platformStatusSigners: [platform.statusSigner],
      acceptedPlatforms: [platform.clientId],
      statusFetcher,
      statusCacheSeconds,
      stores: stores.bank,
      sweepSeconds: options.sweepSeconds,
      adminToken: options.adminToken,
    });
    started.push(bank);
    log(`bank on ${bank.url}`);

    const wallet = await startWallet({
      host,
      port: port('wallet'),
      pidUrl: pid.url,
      pidAdminToken: options.adminToken,
      persons: PERSONS,
      rpTrustAnchors: platform.rpAnchorPem ? [platform.rpAnchorPem] : process.env.WALLET_RP_ANCHORS ? [readFileSync(process.env.WALLET_RP_ANCHORS, 'utf8')] : [],
      strictClientId: options.strictClientId,
      bankHost: identities.bankHost,
    });
    started.push(wallet);
    walletRef.url = options.publicUrls?.wallet ?? wallet.url;
    log(`wallet on ${wallet.url}`);

    const publicUrls: Record<ServiceName, string> = {
      pid: options.publicUrls?.pid ?? pid.url,
      wallet: walletRef.url,
      platform: platform.publicUrl,
      bank: options.publicUrls?.bank ?? bank.url,
      dashboard: '',
    };
    const dashboard = await startDashboard({
      host,
      port: port('dashboard'),
      sources: { pid: pid.url, wallet: wallet.url, platform: platform.url, bank: bank.url },
      links: {
        wallet: { label: 'Wallet', url: publicUrls.wallet },
        platform: { label: 'Agent platform', url: publicUrls.platform },
        bank: { label: 'Bank', url: publicUrls.bank },
        pid: { label: 'PID provider', url: publicUrls.pid },
      },
    });
    started.push(dashboard);
    publicUrls.dashboard = options.publicUrls?.dashboard ?? dashboard.url;

    return {
      urls: { pid: pid.url, wallet: wallet.url, platform: platform.url, bank: bank.url, dashboard: dashboard.url },
      publicUrls,
      identities,
      pid,
      wallet,
      platform,
      bank,
      dashboard,
      statusCacheSeconds,
      adminToken: options.adminToken,
      stores,
      close: async () => {
        for (const s of started.reverse()) await s.close();
      },
    };
  } catch (e) {
    for (const s of started.reverse()) await s.close().catch(() => {});
    throw e;
  }
}
