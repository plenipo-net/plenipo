/**
 * Agent platform: where a person's AI agents live. It asks the person's wallet to approve mandates
 * over OpenID4VP, keeps the agents' keys, signs their invocations, creates sub-delegations, and
 * publishes the status list through which the person revokes or suspends a mandate.
 *
 * The platform is not trusted by the bank: it signs whatever its agents ask, and every limit is
 * enforced by the bank's verifier. That is the point of the demo.
 */
import { randomUUID } from 'node:crypto';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { exportJWK, generateKeyPair, importPKCS8, type CryptoKey, type JWK } from 'jose';
import QRCode from 'qrcode';
import {
  authorizationRequestUrl,
  createInvocation,
  createMandate,
  createMandateRequest,
  delegateMandate,
  generateAgentKey,
  handleMandateResponse,
  InMemoryNonceStore,
  nowSeconds,
  RootError,
  sha256,
  StatusListPublisher,
  type AgentKey,
  type Amount,
  type Mandate,
  type MandateChain,
  type MandateRequestSession,
  type StatusFetcher,
  type MandateSessionStore,
  type NonceStore,
  type StatusReference,
  type TrustConfig,
  type TrustedIssuer,
} from 'plenipo';
import { createTestCertificateAuthority } from 'plenipo/testing';
import { counterpartyLabel, formatEuro, formatTime, PRESETS, scopeLine, type MandateSpec } from '../catalog.js';
import { EventLog, eventsHandler } from '../events.js';
import { escapeHtml, HttpError, listen, readFields, redirect, Router, sendHtml, sendJson, sendText, type Request, type RunningServer } from '../http.js';
import { autoRefresh, page } from '../ui/layout.js';

export interface PlatformOptions {
  host: string;
  port: number;
  /** Base URL wallets use to reach request_uri and response_uri. */
  publicUrl?: string;
  /** https origin that signs and serves the mandate status list; its host is the client_id DNS name. */
  origin: string;
  /** CA certificates of the PID providers this platform accepts. */
  pidTrustAnchors: string[];
  /** Extra PID providers trusted by explicit key (level 2, e.g. a walt.id issuer). */
  pidTrustedIssuers?: TrustedIssuer[];
  /** Who may sign PID status lists served from another origin than the PID `iss` (e.g. the EU test issuer). */
  pidStatusTrust?: TrustConfig;
  statusFetcher: StatusFetcher;
  /** URL of the sandbox wallet, to offer a one-click link next to the QR code. */
  walletUrl?: string;
  /** Request object signer for x509_san_dns; generated under a test CA when absent. */
  requestSigner?: { key: CryptoKey; x5c: string[] };
  /** Status list token `ttl` hint, in seconds. */
  statusTtlSeconds?: number;
  /** Ask for the response encrypted to the platform (direct_post.jwt). Default true. */
  encryptResponse?: boolean;
  /** The bank's host name, used by the mandate templates. */
  bankHost: string;
  stores?: PlatformStores;
}

export interface MandateRecord {
  id: string;
  mandate: Mandate;
  chain: MandateChain;
  agentId: string;
  parentId?: string;
  depth: number;
  status?: StatusReference;
  state: 'active' | 'revoked' | 'suspended';
  principal: Record<string, unknown>;
  createdAt: string;
}

interface RequestRecord {
  id: string;
  agentId: string;
  mandate: Mandate;
  emandate: boolean;
  requestObject: string;
  params: Record<string, unknown>;
  state: 'pending' | 'active' | 'refused' | 'failed';
  error?: string;
  createdAt: string;
}

interface AgentRecord {
  id: string;
  name: string;
  publicJwk: JWK;
  /** Absent for agents that hold their own key ("bring your own key"): the platform cannot sign for them. */
  key?: AgentKey;
}

/** Where the platform keeps OpenID4VP sessions: in memory by default, or a shared store (see stores.ts). */
export interface PlatformStores {
  /** Request sessions between createMandateRequest and the wallet's POST. */
  requestSessions: MandateSessionStore;
  /** Single use of a wallet response; must not be the invocation nonce store. */
  responseSessions: NonceStore;
}

/** In-memory MandateSessionStore for one process. */
export class InMemoryMandateSessionStore implements MandateSessionStore {
  private readonly map = new Map<string, { session: MandateRequestSession; until: number }>();
  readonly retentionSeconds = 900;
  async put(id: string, session: MandateRequestSession, ttlSeconds = this.retentionSeconds): Promise<void> {
    this.map.set(id, { session, until: Date.now() + ttlSeconds * 1000 });
  }
  async get(id: string): Promise<MandateRequestSession | undefined> {
    const e = this.map.get(id);
    if (!e || e.until < Date.now()) return undefined;
    return e.session;
  }
  async delete(id: string): Promise<void> {
    this.map.delete(id);
  }
}

/** A public EC P-256 JWK, as an agent that holds its own key sends it. Private members are refused. */
export function parseAgentJwk(x: unknown): JWK {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) throw new HttpError(400, 'agent_jwk must be a JWK object');
  const j = x as Record<string, unknown>;
  if ('d' in j) throw new HttpError(400, 'agent_jwk must be a public key: never send the private key');
  const b64 = /^[A-Za-z0-9_-]{43}$/;
  if (j.kty !== 'EC' || j.crv !== 'P-256' || typeof j.x !== 'string' || typeof j.y !== 'string' || !b64.test(j.x) || !b64.test(j.y)) {
    throw new HttpError(400, 'agent_jwk must be an EC P-256 public key');
  }
  return { kty: 'EC', crv: 'P-256', x: j.x, y: j.y };
}

export interface PlatformService extends RunningServer {
  clientId: string;
  publicUrl: string;
  /** Public key that signs the mandate status list: the bank configures it in mandateStatusTrust. */
  statusSigner: TrustedIssuer;
  /** Trust anchor for request objects: the wallet configures it as a trusted relying party CA. */
  rpAnchorPem?: string;
  events: EventLog;
}

/** Loads a request object signer from PEM files (level 2: a certificate whose DNS SAN is the public host). */
export async function loadRequestSigner(keyPath: string, chainPath: string): Promise<{ key: CryptoKey; x5c: string[] }> {
  const key = await importPKCS8(readFileSync(keyPath, 'utf8'), 'ES256');
  const pems = readFileSync(chainPath, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  if (pems.length === 0) throw new Error(`no certificate in ${chainPath}`);
  const x5c = pems.map((p) => Buffer.from(new X509Certificate(p).raw).toString('base64'));
  return { key, x5c };
}

const ACTION_RE = /^(\*|[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?)$/;
const HOST_RE = /^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+$/;

/** Validates a scope coming from an API caller; the library validates the mandate again on creation. */
export function parseSpec(body: Record<string, unknown>): MandateSpec {
  const arr = (v: unknown, re: RegExp, name: string): string[] | undefined => {
    if (v === undefined) return undefined;
    if (!Array.isArray(v) || v.length === 0 || v.length > 20 || !v.every((x) => typeof x === 'string' && re.test(x))) {
      throw new HttpError(400, `invalid ${name}`);
    }
    return v as string[];
  };
  const int = (v: unknown, name: string): number | undefined => {
    if (v === undefined) return undefined;
    if (!Number.isSafeInteger(v) || (v as number) < 0) throw new HttpError(400, `invalid ${name}`);
    return v as number;
  };
  const actions = arr(body.actions, ACTION_RE, 'actions');
  if (!actions) throw new HttpError(400, 'actions required');
  let limits: MandateSpec['limits'];
  if (body.limits !== undefined) {
    const l = body.limits as Record<string, unknown>;
    if (typeof l !== 'object' || l === null || typeof l.currency !== 'string' || !/^[A-Z]{3}$/.test(l.currency)) {
      throw new HttpError(400, 'invalid limits');
    }
    limits = { currency: l.currency, per_operation: int(l.per_operation, 'per_operation'), total: int(l.total, 'total') };
    if (limits.per_operation === undefined) delete limits.per_operation;
    if (limits.total === undefined) delete limits.total;
  }
  const purpose = body.purpose === undefined ? undefined : String(body.purpose).slice(0, 300);
  return {
    actions,
    counterparties: arr(body.counterparties, HOST_RE, 'counterparties'),
    limits,
    ttlSeconds: int(body.ttl_seconds, 'ttl_seconds'),
    maxDepth: int(body.max_depth, 'max_depth'),
    purpose,
  };
}

function parseAmount(v: unknown): Amount | undefined {
  if (v === undefined) return undefined;
  const a = v as Record<string, unknown>;
  if (typeof a !== 'object' || a === null || typeof a.currency !== 'string' || typeof a.value !== 'number') {
    throw new HttpError(400, 'invalid amount');
  }
  return { value: a.value, currency: a.currency };
}

export async function startPlatform(opts: PlatformOptions): Promise<PlatformService> {
  const events = new EventLog('platform');
  const clientDns = new URL(opts.origin).hostname;
  const clientId = `x509_san_dns:${clientDns}`;

  let signer = opts.requestSigner;
  let rpAnchorPem: string | undefined;
  if (!signer) {
    const rpCa = await createTestCertificateAuthority('Sandbox Relying Party CA');
    // clientAuth EKU: walt.id checks the client-auth usage of x509_san_dns request object certificates.
    const leaf = await rpCa.issueLeaf(opts.origin, { eku: { usages: ['1.3.6.1.5.5.7.3.2'] } });
    signer = { key: leaf.privateKey as unknown as CryptoKey, x5c: leaf.x5c };
    rpAnchorPem = rpCa.anchorPem;
  }

  const statusKeys = await generateKeyPair('ES256', { extractable: true });
  const statusJwk = await exportJWK(statusKeys.publicKey);
  const statusSigner: TrustedIssuer = { iss: opts.origin, jwk: { kty: statusJwk.kty, crv: statusJwk.crv, x: statusJwk.x, y: statusJwk.y } as JWK };
  const publisher = new StatusListPublisher({
    uri: `${opts.origin}/status/mandates`,
    signingKey: statusKeys.privateKey,
    iss: opts.origin,
    ttlSeconds: opts.statusTtlSeconds ?? 30,
    lifetimeSeconds: 3600,
  });

  const agents = new Map<string, AgentRecord>();
  const mandates = new Map<string, MandateRecord>();
  const requests = new Map<string, RequestRecord>();
  // A store of its own for OpenID4VP sessions: the state is visible to anyone who sees the request.
  const stores: PlatformStores = opts.stores ?? { requestSessions: new InMemoryMandateSessionStore(), responseSessions: new InMemoryNonceStore() };
  const router = new Router();
  const running = await listen(router, opts.host, opts.port);
  const publicUrl = (opts.publicUrl ?? running.url).replace(/\/$/, '');

  async function newAgent(name: string, ownJwk?: JWK): Promise<AgentRecord> {
    const id = `agent-${randomUUID().slice(0, 8)}`;
    const label = name.slice(0, 60) || 'Agent';
    let a: AgentRecord;
    if (ownJwk) a = { id, name: label, publicJwk: ownJwk };
    else {
      const key = await generateAgentKey();
      a = { id, name: label, publicJwk: key.publicJwk, key };
    }
    agents.set(a.id, a);
    return a;
  }

  async function createRequest(
    agentName: string,
    spec: MandateSpec,
    o: { agentJwk?: JWK; emandate?: boolean; disclose?: string[] } = {},
  ): Promise<RequestRecord> {
    const agent = await newAgent(agentName, o.agentJwk);
    const status = publisher.allocate();
    const mandate = createMandate({
      agentJwk: agent.publicJwk,
      actions: spec.actions,
      counterparties: spec.counterparties,
      limits: spec.limits,
      ttlSeconds: spec.ttlSeconds ?? 7 * 24 * 3600,
      maxDepth: spec.maxDepth,
      purpose: spec.purpose,
      status,
    });
    const id = randomUUID();
    const req = await createMandateRequest({
      mandate,
      clientId,
      responseUri: `${publicUrl}/response/${id}`,
      disclose: o.disclose ?? ['given_name', 'family_name', 'birthdate'],
      encryptResponse: opts.encryptResponse ?? true,
      signer,
      // TS12 e-mandate, bound to the PID: the wallet shows a TS12 summary whose reference_number binds the
      // mandate by hash and whose purpose spells it out. TS12 itself binds e-mandates to an SCA attestation.
      ...(o.emandate ? { transactionDataType: 'emandate' as const, emandate: { credential: 'pid' as const } } : {}),
    });
    await stores.requestSessions.put(id, req.session);
    const record: RequestRecord = {
      id,
      agentId: agent.id,
      mandate,
      emandate: Boolean(o.emandate),
      requestObject: req.requestObject!,
      params: req.params,
      state: 'pending',
      createdAt: new Date().toISOString(),
    };
    requests.set(id, record);
    statusRefs.set(mandate.id, status);
    events.append('mandate_requested', {
      request_id: id,
      mandate_id: mandate.id,
      agent: agent.name,
      scope: scopeLine(mandate),
      purpose: mandate.purpose,
    });
    return record;
  }
  const statusRefs = new Map<string, StatusReference>();

  function requestLinks(r: RequestRecord) {
    const requestUri = `${publicUrl}/request/${r.id}`;
    const authorizationUrl = authorizationRequestUrl(clientId, requestUri);
    const walletLink = opts.walletUrl
      ? `${opts.walletUrl}/authorize?${new URLSearchParams({ client_id: clientId, request_uri: requestUri })}`
      : undefined;
    return { request_uri: requestUri, authorization_url: authorizationUrl, wallet_url: walletLink };
  }

  function requestView(r: RequestRecord) {
    return { request_id: r.id, state: r.state, mandate_id: r.mandate.id, agent_id: r.agentId, error: r.error, ...requestLinks(r) };
  }

  function mandateView(m: MandateRecord) {
    return {
      id: m.id,
      state: effectiveState(m),
      own_state: m.state,
      depth: m.depth,
      parent_id: m.parentId,
      agent: agents.get(m.agentId)?.name,
      agent_id: m.agentId,
      principal: m.principal,
      mandate: m.mandate,
      created_at: m.createdAt,
    };
  }

  /** A mandate is only as valid as every mandate above it. */
  function effectiveState(m: MandateRecord): MandateRecord['state'] {
    let cur: MandateRecord | undefined = m;
    while (cur) {
      if (cur.state !== 'active') return cur.state;
      cur = cur.parentId ? mandates.get(cur.parentId) : undefined;
    }
    return 'active';
  }

  async function handleResponse(r: RequestRecord, body: Record<string, unknown>): Promise<void> {
    // An approved request is final: a second response (the link opened twice, a second device) is
    // answered with 409 and changes nothing, so it can never undo the approval.
    if (r.state === 'active') {
      events.append('response_ignored', { request_id: r.id, mandate_id: r.mandate.id, reason: 'request_already_used' });
      throw new HttpError(409, 'request_already_used');
    }
    if (typeof body.error === 'string' && body.response === undefined) {
      // An error response is not authenticated: anyone who saw the request could post one. It marks the
      // request as refused but does not consume the session, so a genuine approval still counts.
      const s = await stores.requestSessions.get(r.id);
      if (!s || body.state !== s.state) throw new HttpError(400, 'invalid_request');
      r.state = 'refused';
      r.error = /^[a-z_]{1,40}$/.test(body.error) ? body.error : 'unknown_error';
      events.append('mandate_refused', { request_id: r.id, mandate_id: r.mandate.id, error: r.error });
      return;
    }
    const payload: Record<string, unknown> = { ...body };
    if (typeof payload.vp_token === 'string') {
      try {
        payload.vp_token = JSON.parse(payload.vp_token);
      } catch {
        throw new HttpError(400, 'invalid_request');
      }
    }
    try {
      const session = await stores.requestSessions.get(r.id);
      if (!session) throw new RootError('ROOT_INVALID', 'the request session has expired');
      const { root, verified } = await handleMandateResponse(payload, session, {
        now: nowSeconds(),
        trustAnchors: opts.pidTrustAnchors,
        trustedIssuers: opts.pidTrustedIssuers,
        pidStatusTrust: opts.pidStatusTrust,
        statusFetcher: opts.statusFetcher,
        sessions: stores.responseSessions,
        // TS12 e-mandate roots are experimental and opt-in; the sandbox accepts them bound to the PID.
        emandate: { allowPidBinding: true },
      });
      r.state = 'active';
      const record: MandateRecord = {
        id: r.mandate.id,
        mandate: r.mandate,
        chain: { root, delegations: [] },
        agentId: r.agentId,
        depth: 0,
        status: statusRefs.get(r.mandate.id),
        state: 'active',
        principal: verified.principal,
        createdAt: new Date().toISOString(),
      };
      mandates.set(record.id, record);
      events.append('mandate_approved', {
        request_id: r.id,
        mandate_id: record.id,
        depth: 0,
        agent: agents.get(r.agentId)?.name,
        person: `${verified.principal.given_name ?? ''} ${verified.principal.family_name ?? ''}`.trim(),
        pid_issuer: verified.pidIssuer,
        scope: scopeLine(r.mandate),
        mandate: r.mandate,
        tx_hash: sha256(root.transaction_data),
      });
    } catch (e) {
      if (e instanceof RootError) {
        // Two responses racing: the one that lost must not mark an approved request as failed.
        if (r.state === 'active' || e.code === 'REPLAY') {
          events.append('response_ignored', { request_id: r.id, mandate_id: r.mandate.id, reason: 'request_already_used' });
          throw new HttpError(409, 'request_already_used');
        }
        r.state = 'failed';
        r.error = e.code;
        events.append('mandate_rejected', { request_id: r.id, mandate_id: r.mandate.id, code: e.code, reason: e.message });
        throw new HttpError(400, 'invalid_request');
      }
      throw e;
    }
  }

  async function delegate(parent: MandateRecord, agentName: string, spec: MandateSpec, ownJwk?: JWK): Promise<MandateRecord> {
    if (effectiveState(parent) !== 'active') throw new HttpError(409, 'parent mandate is not active');
    const parentAgent = agents.get(parent.agentId)!;
    if (!parentAgent.key) throw new HttpError(409, 'the parent agent holds its own key: it signs its delegations itself (delegateMandate)');
    const sub = await newAgent(agentName, ownJwk);
    const now = nowSeconds();
    const nbf = Math.max(now, parent.mandate.nbf);
    const exp = Math.min(nbf + (spec.ttlSeconds ?? 24 * 3600), parent.mandate.exp);
    const status = publisher.allocate();
    let child: Mandate;
    let jws: string;
    try {
      child = createMandate({
        agentJwk: sub.publicJwk,
        actions: spec.actions,
        counterparties: spec.counterparties,
        limits: spec.limits,
        nbf,
        exp,
        maxDepth: spec.maxDepth,
        purpose: spec.purpose,
        status,
      });
      jws = await delegateMandate({ parent: parent.mandate, parentAgentKey: parentAgent.key.privateKey, child });
    } catch (e) {
      // The library refuses to sign a child that widens its parent; report why to the operator.
      events.append('delegation_refused', { parent_id: parent.id, agent: sub.name, reason: (e as Error).message });
      throw new HttpError(400, (e as Error).message);
    }
    const record: MandateRecord = {
      id: child.id,
      mandate: child,
      chain: { root: parent.chain.root, delegations: [...parent.chain.delegations, jws] },
      agentId: sub.id,
      parentId: parent.id,
      depth: parent.depth + 1,
      status,
      state: 'active',
      principal: parent.principal,
      createdAt: new Date().toISOString(),
    };
    mandates.set(record.id, record);
    events.append('mandate_delegated', {
      mandate_id: record.id,
      parent_id: parent.id,
      depth: record.depth,
      agent: sub.name,
      parent_agent: parentAgent.name,
      person: `${parent.principal.given_name ?? ''} ${parent.principal.family_name ?? ''}`.trim(),
      scope: scopeLine(child),
      mandate: child,
    });
    return record;
  }

  function setState(m: MandateRecord, action: 'revoke' | 'suspend' | 'reinstate'): void {
    if (!m.status) throw new HttpError(409, 'mandate has no status entry');
    if (m.state === 'revoked' && action !== 'revoke') throw new HttpError(409, 'a revoked mandate cannot be changed');
    publisher[action](m.status);
    m.state = action === 'revoke' ? 'revoked' : action === 'suspend' ? 'suspended' : 'active';
    events.append(action === 'revoke' ? 'mandate_revoked' : action === 'suspend' ? 'mandate_suspended' : 'mandate_reinstated', {
      mandate_id: m.id,
      depth: m.depth,
      agent: agents.get(m.agentId)?.name,
      children: [...mandates.values()].filter((c) => c.parentId === m.id).map((c) => c.id),
    });
  }

  function getMandate(req: Request): MandateRecord {
    const m = mandates.get(req.params.id);
    if (!m) throw new HttpError(404, 'unknown mandate');
    return m;
  }

  // ---- OpenID4VP endpoints: the only ones a phone wallet needs to reach ----
  router.get('/request/:id', (req, res) => {
    const r = requests.get(req.params.id);
    if (!r) throw new HttpError(404, 'unknown request');
    // Once approved, the request object is no longer served: a wallet that fetches it again says so.
    if (r.state === 'active') {
      events.append('request_refetched', { request_id: r.id, mandate_id: r.mandate.id });
      throw new HttpError(410, 'request_already_used');
    }
    events.append('request_fetched', { request_id: r.id });
    sendText(res, 200, r.requestObject, 'application/oauth-authz-req+jwt');
  });
  router.post('/response/:id', async (req, res) => {
    const r = requests.get(req.params.id);
    if (!r) throw new HttpError(404, 'unknown request');
    const body = await readFields(req, 512 * 1024);
    await handleResponse(r, body);
    sendJson(res, 200, {});
  });
  router.get('/status/mandates', async (_req, res) => sendText(res, 200, await publisher.token(), 'application/statuslist+jwt'));
  router.get('/events', (req, res) => sendJson(res, 200, eventsHandler(events)(req)));

  // ---- Platform API, used by agents and by the "my mandates" page ----
  router.get('/api/info', (_req, res) =>
    sendJson(res, 200, { client_id: clientId, status_list: publisher.uri, status_signer: statusSigner, presets: PRESETS.map((p) => p.id) }),
  );
  router.post('/api/requests', async (req, res) => {
    const body = await readFields(req);
    let spec: MandateSpec;
    if (typeof body.preset === 'string') {
      const p = PRESETS.find((x) => x.id === body.preset);
      if (!p) throw new HttpError(400, 'unknown preset');
      spec = p.spec();
      if (body.ttl_seconds !== undefined) {
        if (!Number.isSafeInteger(body.ttl_seconds) || (body.ttl_seconds as number) <= 0) throw new HttpError(400, 'invalid ttl_seconds');
        spec.ttlSeconds = body.ttl_seconds as number;
      }
    } else spec = parseSpec(body);
    let r: RequestRecord;
    try {
      if (body.transaction_data_type !== undefined && body.transaction_data_type !== 'plenipo_mandate' && body.transaction_data_type !== 'emandate') {
        throw new HttpError(400, 'transaction_data_type must be plenipo_mandate or emandate');
      }
      r = await createRequest(String(body.agent_name ?? 'Assistant'), spec, {
        agentJwk: body.agent_jwk === undefined ? undefined : parseAgentJwk(body.agent_jwk),
        emandate: body.transaction_data_type === 'emandate',
      });
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(400, (e as Error).message);
    }
    sendJson(res, 201, requestView(r));
  });
  router.get('/api/requests/:id', (req, res) => {
    const r = requests.get(req.params.id);
    if (!r) throw new HttpError(404, 'unknown request');
    sendJson(res, 200, requestView(r));
  });
  router.get('/api/mandates', (_req, res) => sendJson(res, 200, [...mandates.values()].map(mandateView)));
  router.get('/api/mandates/:id', (req, res) => sendJson(res, 200, { ...mandateView(getMandate(req)), chain: getMandate(req).chain }));
  for (const action of ['revoke', 'suspend', 'reinstate'] as const) {
    router.post(`/api/mandates/:id/${action}`, (req, res) => {
      const m = getMandate(req);
      setState(m, action);
      sendJson(res, 200, mandateView(m));
    });
    router.post(`/mandates/:id/${action}`, (req, res) => {
      setState(getMandate(req), action);
      redirect(res, '/');
    });
  }
  router.post('/api/mandates/:id/delegate', async (req, res) => {
    const body = await readFields(req);
    const m = await delegate(
      getMandate(req),
      String(body.agent_name ?? 'Sub-agent'),
      parseSpec(body),
      body.agent_jwk === undefined ? undefined : parseAgentJwk(body.agent_jwk),
    );
    sendJson(res, 201, mandateView(m));
  });
  router.post('/api/mandates/:id/invocations', async (req, res) => {
    const m = getMandate(req);
    const body = await readFields(req, 64 * 1024);
    if (typeof body.action !== 'string' || typeof body.aud !== 'string') throw new HttpError(400, 'action and aud required');
    if (body.counterparty !== undefined && typeof body.counterparty !== 'string') throw new HttpError(400, 'invalid counterparty');
    if (body.nonce !== undefined && typeof body.nonce !== 'string') throw new HttpError(400, 'invalid nonce');
    const agent = agents.get(m.agentId)!;
    if (!agent.key) throw new HttpError(409, 'this agent holds its own key: it signs its invocations itself');
    const invocation = await createInvocation(agent.key.privateKey, {
      mandateId: m.id,
      action: body.action,
      counterparty: body.counterparty as string | undefined,
      amount: parseAmount(body.amount),
      aud: body.aud,
      nonce: body.nonce as string | undefined,
      args: body.args,
      // The invocation is bound to the exact chain presented with it (chain_hash).
      chain: m.chain,
    });
    sendJson(res, 200, { mandate_id: m.id, chain: m.chain, invocation });
  });

  // ---- Web pages ----
  router.get('/', (_req, res) => sendHtml(res, homePage()));
  router.post('/requests/new', async (req, res) => {
    const body = await readFields(req);
    const p = PRESETS.find((x) => x.id === body.preset) ?? PRESETS[0];
    const r = await createRequest(String(body.agent_name || 'Bill assistant'), p.spec(), { emandate: body.emandate === 'on' });
    redirect(res, `/requests/${r.id}`);
  });
  router.get('/requests/:id', async (req, res) => {
    const r = requests.get(req.params.id);
    if (!r) throw new HttpError(404, 'unknown request');
    const links = requestLinks(r);
    const qr = await QRCode.toString(links.authorization_url, { type: 'svg', margin: 1, width: 240 });
    const state =
      r.state === 'pending'
        ? '<span class="badge b-warn">waiting for the wallet</span>'
        : r.state === 'active'
          ? '<span class="badge b-allow">approved</span>'
          : `<span class="badge b-deny">${escapeHtml(r.state)}${r.error ? ': ' + escapeHtml(r.error) : ''}</span>`;
    sendHtml(
      res,
      page({
        title: 'Agent Platform',
        service: 'platform',
        subtitle: 'Mandate request',
        nav: [['My mandates', '/']],
        head: r.state === 'pending' ? '<meta http-equiv="refresh" content="2">' : '',
        body: `<div class="grid cols-2"><div class="card"><h2>Approve in your wallet ${state}</h2>
<p>Scan with an EUDI wallet, or open the sandbox wallet.</p><div style="background:#fff;display:inline-block;padding:8px;border-radius:8px">${qr}</div>
<p class="row">${links.wallet_url ? `<a class="btn primary" href="${escapeHtml(links.wallet_url)}" target="_blank">Open in the sandbox wallet</a>` : ''}</p>
<label>request_uri</label><code>${escapeHtml(links.request_uri)}</code><label>client_id</label><code>${escapeHtml(clientId)}</code></div>
<div class="card"><h2>What the agent asks for</h2>${mandateDl(r.mandate)}</div></div>`,
      }),
    );
  });

  function mandateDl(m: Mandate): string {
    const bankHost = opts.bankHost;
    return `<dl class="kv"><dt>Purpose</dt><dd>${escapeHtml(m.purpose ?? '')}</dd>
<dt>Actions</dt><dd>${m.actions.map((a) => `<code>${escapeHtml(a)}</code>`).join(' ')}</dd>
<dt>Counterparties</dt><dd>${(m.counterparties ?? ['any']).map((c) => `${escapeHtml(counterpartyLabel(c, bankHost))} <span class="muted mono">${escapeHtml(c)}</span>`).join('<br>')}</dd>
<dt>Limits</dt><dd>${m.limits ? `${m.limits.per_operation !== undefined ? formatEuro(m.limits.per_operation) + ' per payment' : ''}${m.limits.total !== undefined ? ', ' + formatEuro(m.limits.total) + ' in total' : ''}` : 'none'}</dd>
<dt>Valid</dt><dd>${formatTime(m.nbf)} → ${formatTime(m.exp)}</dd>
<dt>Sub-delegation</dt><dd>${m.delegation?.max_depth ? `up to ${m.delegation.max_depth} level(s)` : 'not allowed'}</dd></dl>`;
  }

  function homePage(): string {
    const list = [...mandates.values()];
    const roots = list.filter((m) => !m.parentId);
    const render = (m: MandateRecord, open: boolean): string => {
      const st = effectiveState(m);
      const cls = st === 'active' ? 'b-allow' : st === 'suspended' ? 'b-warn' : 'b-deny';
      const own = m.state !== st ? ` <span class="muted">(via parent)</span>` : '';
      const kids = list.filter((c) => c.parentId === m.id).map((c) => render(c, open)).join('');
      const actions: Array<'suspend' | 'reinstate' | 'revoke'> = m.state === 'active' ? ['suspend', 'revoke'] : m.state === 'suspended' ? ['reinstate', 'revoke'] : [];
      const buttons = actions
        .map((a) => `<form method="post" action="/mandates/${encodeURIComponent(m.id)}/${a}"><button class="small${a === 'revoke' ? ' danger' : ''}">${a}</button></form>`)
        .join('');
      return `<div class="card" style="margin:${m.depth ? '10px 0 0 22px' : '0 0 14px'};${st === 'active' ? '' : 'opacity:.75'}">
<div class="row"><strong>${escapeHtml(agents.get(m.agentId)?.name)}</strong><span class="badge ${cls}">${st}</span>${own}
<span class="muted">for ${escapeHtml(`${m.principal.given_name ?? ''} ${m.principal.family_name ?? ''}`)}</span><span class="mono muted">${escapeHtml(m.id.slice(0, 8))}</span>
<span style="margin-left:auto" class="row">${buttons}</span></div>
<div class="muted" style="font-size:13.5px;margin-top:4px">${m.depth ? `sub-delegation, depth ${m.depth} · ` : ''}${escapeHtml(scopeLine(m.mandate))}</div>
<details${open ? ' open' : ''} style="margin-top:6px"><summary class="muted" style="font-size:13px">Details</summary><div style="margin-top:8px">${mandateDl(m.mandate)}</div></details>${kids}</div>`;
    };
    const pending = [...requests.values()]
      .filter((r) => r.state !== 'active')
      .slice(-8)
      .reverse()
      .map((r) => `<li><a href="/requests/${r.id}">${escapeHtml(agents.get(r.agentId)?.name)}</a> <span class="badge ${r.state === 'pending' ? 'b-warn' : 'b-deny'}">${r.state}</span> <span class="muted">${escapeHtml(r.error ?? '')}</span></li>`)
      .join('');
    return page({
      title: 'Agent Platform',
      service: 'platform',
      subtitle: 'My mandates: what my agents may do, and the switch to stop them',
      nav: [['Status list', '/status/mandates'], ['API', '/api/mandates']],
      head: autoRefresh(5),
      body: `<div class="grid" style="grid-template-columns:2fr 1fr">
<div>${roots.reverse().map((m, i) => render(m, i === 0)).join('') || '<div class="card muted">No mandates yet. Create a request on the right, then approve it in the wallet.</div>'}</div>
<div><div class="card"><h2>New mandate request</h2><form method="post" action="/requests/new">
<label>Agent name</label><input name="agent_name" value="Bill assistant">
<label>Template</label><select name="preset">${PRESETS.map((p) => `<option value="${p.id}">${escapeHtml(p.label)}</option>`).join('')}</select>
<label style="display:flex;gap:8px;align-items:center;margin-top:10px"><input type="checkbox" name="emandate" style="width:auto"> As a TS12 e-mandate (<code>urn:eudi:sca:emandate:1</code>, bound to the PID)</label>
<p><button class="primary">Create request</button></p></form></div>
<div class="card" style="margin-top:16px"><h2>Recent requests</h2><ul class="plain">${pending || '<li class="muted">none</li>'}</ul></div></div></div>`,
    });
  }

  return { ...running, clientId, publicUrl, statusSigner, rpAnchorPem, events };
}
