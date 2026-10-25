/**
 * Sandbox configuration. Level 1 runs everything on 127.0.0.1 with test identities under
 * `*.sandbox.plenipo.test`; level 2 sets the PLENIPO_* variables to real public names (see level2/).
 */
export type ServiceName = 'dashboard' | 'pid' | 'wallet' | 'platform' | 'bank' | 'agent';

export interface Identities {
  /** `iss` of the PIDs, and origin of the PID status list. Must be https: verifiers fetch status over https only. */
  pidIssuer: string;
  /** Origin that signs and serves the mandate status list; its DNS name is the OpenID4VP client_id. */
  platformOrigin: string;
  /** The bank's host name: the counterparty of read-only and card operations, and the root of its audiences. */
  bankHost: string;
}

export interface SandboxOptions {
  host?: string;
  /** Port per service; 0 picks a free port. */
  ports?: Partial<Record<ServiceName, number>>;
  identities?: Partial<Identities>;
  /** Externally reachable base URL per service, when it differs from the bind address (public host). */
  publicUrls?: Partial<Record<ServiceName, string>>;
  /** How long the bank caches a verified status list: the revocation latency it accepts. */
  statusCacheSeconds?: number;
  /** When set, admin endpoints (PID issuance and revocation, the bank clock) require this bearer token. */
  adminToken?: string;
  /** Require the wallet's response_uri host to equal the client_id DNS name, as OpenID4VP does. */
  strictClientId?: boolean;
  /** Print service logs. */
  verbose?: boolean;
  /** Overrides of the store choice read from the environment (SANDBOX_STORES, PLENIPO_PG_URL, PLENIPO_REDIS_URL). */
  stores?: import('./services/stores.js').StoreOptions;
  /** How often the bank sweeps a shared ledger, in seconds. */
  sweepSeconds?: number;
  /** Public sandbox: how often drained accounts get their opening balance back. */
  refillSeconds?: number;
  /** `mandate`: the bank opens a fresh account per root mandate (public sandbox). Default `person`. */
  accountScope?: 'person' | 'mandate';
  /** The hosted MCP gateway for remote agents (port `agent`). Off unless set. */
  agentGateway?: AgentGatewaySettings;
}

export interface AgentGatewaySettings {
  /** Secret path segment: the endpoint is /mcp/<token>. Without it the endpoint is /mcp. */
  token?: string;
  /** Page where a person watches a session live; the demo code is appended as ?code=. */
  watchUrl?: string;
  maxSessions?: number;
  /** Close a session after this long without requests, in seconds. */
  idleSeconds?: number;
  /** New sessions one client address may open per hour. */
  sessionsPerHour?: number;
  /** Requests one client address may send per minute. */
  requestsPerMinute?: number;
  /** Header carrying the client address set by the proxy in front, e.g. fly-client-ip. */
  clientIpHeader?: string;
  /** Let visitors run the scripted scenarios through the gateway (GET /scenarios, POST /scenarios/<id>/run). */
  publicScenarios?: boolean;
}

export const DEFAULT_IDENTITIES: Identities = {
  pidIssuer: 'https://pid.sandbox.plenipo.test',
  platformOrigin: 'https://platform.sandbox.plenipo.test',
  bankHost: 'bank.sandbox.plenipo.test',
};

export const DEFAULT_PORTS: Record<ServiceName, number> = {
  dashboard: 4400,
  pid: 4401,
  wallet: 4402,
  platform: 4403,
  bank: 4404,
  agent: 4405,
};

function envPort(name: ServiceName, base: number | undefined): number | undefined {
  const specific = process.env[`SANDBOX_PORT_${name.toUpperCase()}`];
  if (specific !== undefined) return Number(specific);
  if (base !== undefined) return base + Object.keys(DEFAULT_PORTS).indexOf(name);
  return undefined;
}

/** Reads the options from the environment, for the launcher and the containers. */
export function optionsFromEnv(env = process.env): SandboxOptions {
  const base = env.SANDBOX_PORT_BASE ? Number(env.SANDBOX_PORT_BASE) : undefined;
  const ports: Partial<Record<ServiceName, number>> = {};
  const publicUrls: Partial<Record<ServiceName, string>> = {};
  for (const name of Object.keys(DEFAULT_PORTS) as ServiceName[]) {
    const p = envPort(name, base);
    if (p !== undefined) ports[name] = p;
    const pub = env[`SANDBOX_PUBLIC_URL_${name.toUpperCase()}`];
    if (pub) publicUrls[name] = pub.replace(/\/$/, '');
  }
  const identities: Partial<Identities> = {};
  if (env.PLENIPO_PID_ISSUER) identities.pidIssuer = env.PLENIPO_PID_ISSUER;
  if (env.PLENIPO_PLATFORM_ORIGIN) identities.platformOrigin = env.PLENIPO_PLATFORM_ORIGIN;
  if (env.PLENIPO_BANK_HOST) identities.bankHost = env.PLENIPO_BANK_HOST;
  return {
    host: env.SANDBOX_HOST ?? '127.0.0.1',
    ports,
    publicUrls,
    identities,
    statusCacheSeconds: env.SANDBOX_STATUS_CACHE_SECONDS ? Number(env.SANDBOX_STATUS_CACHE_SECONDS) : undefined,
    adminToken: env.SANDBOX_ADMIN_TOKEN || undefined,
    strictClientId: env.SANDBOX_STRICT_CLIENT_ID === '1',
    verbose: env.SANDBOX_VERBOSE === '1',
    refillSeconds: env.SANDBOX_REFILL_SECONDS ? Number(env.SANDBOX_REFILL_SECONDS) : undefined,
    accountScope: env.SANDBOX_ACCOUNT_SCOPE === 'mandate' ? 'mandate' : undefined,
    agentGateway:
      env.SANDBOX_AGENT_GATEWAY === '1'
        ? {
            token: env.SANDBOX_MCP_TOKEN || undefined,
            watchUrl: env.SANDBOX_WATCH_URL || undefined,
            maxSessions: env.SANDBOX_MAX_SESSIONS ? Number(env.SANDBOX_MAX_SESSIONS) : undefined,
            idleSeconds: env.SANDBOX_SESSION_IDLE_SECONDS ? Number(env.SANDBOX_SESSION_IDLE_SECONDS) : undefined,
            clientIpHeader: env.SANDBOX_CLIENT_IP_HEADER || undefined,
            publicScenarios: env.SANDBOX_PUBLIC_SCENARIOS === '1',
          }
        : undefined,
  };
}

export function bankAudiences(bankHost: string): { mcp: string; rest: string } {
  return { mcp: `mcp://${bankHost}`, rest: `https://${bankHost}/psd2` };
}
