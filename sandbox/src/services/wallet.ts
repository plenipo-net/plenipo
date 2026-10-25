/**
 * Sandbox wallet: the test wallet from plenipo/testing behind a web consent screen. It behaves like an
 * EUDI wallet on the points that matter for mandates: it fetches the request object, checks that it is
 * signed by a certificate naming the client_id, refuses transaction data types it does not know, shows
 * the person exactly what the agent will be allowed to do, and on approval posts the OpenID4VP response.
 */
import { randomUUID } from 'node:crypto';
import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import {
  decodeMandateTransactionData,
  sha256,
  TX_DATA_TYPE,
  EMANDATE_TX_DATA_TYPE,
  validateMandate,
  verifyX5c,
  nowSeconds,
  type Mandate,
} from 'plenipo';
import { createTestWallet, type TestWallet } from 'plenipo/testing';
import { ACTION_LABELS, counterpartyLabel, formatEuro, formatTime, type Person } from '../catalog.js';
import { EventLog, eventsHandler } from '../events.js';
import {
  boundedFetch,
  escapeHtml,
  HttpError,
  listen,
  readFields,
  redirect,
  Router,
  sendHtml,
  sendJson,
  type RunningServer,
} from '../http.js';
import { autoRefresh, page } from '../ui/layout.js';

export interface WalletOptions {
  host: string;
  port: number;
  /** Where the PID provider issues PIDs (sandbox shortcut for OpenID4VCI). */
  pidUrl: string;
  pidAdminToken?: string;
  persons: Person[];
  /** CA certificates of the relying parties (agent platforms) this wallet accepts requests from. */
  rpTrustAnchors: string[];
  /** Require response_uri to be https on the client_id host, as OpenID4VP requires for x509_san_dns. */
  strictClientId?: boolean;
  bankHost: string;
}

interface Holder {
  person: Person;
  wallet: TestWallet;
  pidId: string;
  statusIdx: number;
}

interface PendingRequest {
  id: string;
  clientId: string;
  clientName: string;
  certificateSubject: string;
  requestUri: string;
  requestObject: string;
  responseUri: string;
  /** `plenipo`: the whole mandate is shown and signed. `emandate`: a TS12 e-mandate summary is shown and signed. */
  kind: 'plenipo' | 'emandate';
  /** The mandate, for plenipo_mandate requests. */
  mandate?: Mandate;
  /** The TS12 payload, for e-mandate requests: all the wallet sees of the mandate, which it binds by hash. */
  emandate?: Record<string, any>;
  /** Purpose and reference shown in lists. */
  title: string;
  reference: string;
  mandateProblems: string[];
  txHash: string;
  disclose: string[];
  warnings: string[];
  personHint?: string;
  state: 'pending' | 'approved' | 'refused' | 'error';
  person?: string;
  outcome?: string;
  receivedAt: string;
}

export interface WalletService extends RunningServer {
  events: EventLog;
  /** Accepts a request as if the person had scanned its QR code. */
  intake(clientId: string, requestUri: string, personHint?: string): Promise<PendingRequest>;
  decide(id: string, decision: 'approve' | 'refuse', personId: string): Promise<PendingRequest>;
}

const MAX_REQUEST_OBJECT = 256 * 1024;

export async function startWallet(opts: WalletOptions): Promise<WalletService> {
  const events = new EventLog('wallet');
  const holders = new Map<string, Holder>();
  for (const person of opts.persons) {
    // Accepts TS12 e-mandates bound to the PID too (the platform offers them as an option).
    const wallet = await createTestWallet({ emandateOnPid: true });
    const res = await boundedFetch(`${opts.pidUrl}/issue`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(opts.pidAdminToken ? { authorization: `Bearer ${opts.pidAdminToken}` } : {}) },
      body: JSON.stringify({
        person_id: person.id,
        holder_jwk: wallet.holderJwk,
        claims: { given_name: person.given_name, family_name: person.family_name, birthdate: person.birthdate, nationality: person.nationality },
      }),
    });
    if (res.status !== 200) throw new Error(`PID issuance for ${person.id} failed with HTTP ${res.status}`);
    const issued = JSON.parse(res.text) as { pid: string; pid_id: string; status: { status_list: { idx: number } } };
    wallet.storePid(issued.pid);
    holders.set(person.id, { person, wallet, pidId: issued.pid_id, statusIdx: issued.status.status_list.idx });
    events.append('pid_stored', { person: `${person.given_name} ${person.family_name}`, pid_id: issued.pid_id });
  }

  const requests = new Map<string, PendingRequest>();

  async function intake(clientId: string, requestUri: string, personHint?: string): Promise<PendingRequest> {
    if (typeof clientId !== 'string' || !clientId.startsWith('x509_san_dns:')) {
      throw new HttpError(400, 'this wallet accepts x509_san_dns client identifiers only');
    }
    const dns = clientId.slice('x509_san_dns:'.length);
    if (!/^([a-z0-9-]+\.)*[a-z0-9-]+$/.test(dns)) throw new HttpError(400, 'invalid client_id');
    // The same link opened twice shows the request already received: a pending one is decided once,
    // an approved one is shown as approved. A refused or failed one may be fetched again.
    for (const prev of requests.values()) {
      if (prev.clientId === clientId && prev.requestUri === requestUri && (prev.state === 'pending' || prev.state === 'approved')) {
        events.append('request_reopened', { request_id: prev.id, client_id: clientId, state: prev.state });
        return prev;
      }
    }
    let fetched;
    try {
      fetched = await boundedFetch(requestUri, { headers: { accept: 'application/oauth-authz-req+jwt' } }, { maxBytes: MAX_REQUEST_OBJECT });
    } catch {
      throw new HttpError(502, 'the request_uri could not be fetched');
    }
    if (fetched.status === 410) throw new HttpError(410, 'this request has already been approved: there is nothing left to do');
    if (fetched.status !== 200) throw new HttpError(502, `the request_uri returned HTTP ${fetched.status}`);
    const jwt = fetched.text.trim();

    // The request object must be signed by a certificate that chains to a trusted RP CA and names the client.
    let header: Record<string, unknown>;
    try {
      header = decodeProtectedHeader(jwt) as Record<string, unknown>;
    } catch {
      throw new HttpError(400, 'the request object is not a JWT');
    }
    if (header.alg !== 'ES256' || header.typ !== 'oauth-authz-req+jwt') throw new HttpError(400, 'unexpected request object header');
    let key;
    try {
      key = verifyX5c(header.x5c, opts.rpTrustAnchors, nowSeconds(), `https://${dns}`);
    } catch (e) {
      throw new HttpError(400, `the requester's certificate is not trusted: ${(e as Error).message}`);
    }
    let payload: Record<string, any>;
    try {
      ({ payload } = await jwtVerify(jwt, await importJWK(key.jwk, 'ES256'), { typ: 'oauth-authz-req+jwt', algorithms: ['ES256'] }));
    } catch {
      throw new HttpError(400, 'the request object signature does not verify');
    }
    if (payload.client_id !== clientId) throw new HttpError(400, 'client_id does not match the signed request');
    if (payload.response_type !== 'vp_token' || !['direct_post', 'direct_post.jwt'].includes(payload.response_mode)) {
      throw new HttpError(400, 'unsupported response type or mode');
    }
    let responseUri: URL;
    try {
      responseUri = new URL(String(payload.response_uri));
    } catch {
      throw new HttpError(400, 'invalid response_uri');
    }
    const warnings: string[] = [];
    if (responseUri.hostname !== dns || responseUri.protocol !== 'https:') {
      if (opts.strictClientId) throw new HttpError(400, 'response_uri is not on the client_id host');
      warnings.push(`Development mode: the response goes to ${responseUri.origin}, not to https://${dns}. A production wallet refuses this.`);
    }
    const tx = payload.transaction_data;
    if (!Array.isArray(tx) || tx.length !== 1 || typeof tx[0] !== 'string') {
      throw new HttpError(400, 'expected exactly one transaction_data entry');
    }
    let decoded;
    try {
      decoded = decodeMandateTransactionData(tx[0]);
    } catch {
      throw new HttpError(400, 'invalid_transaction_data');
    }
    // As OpenID4VP requires, an unknown transaction data type is refused, never signed blindly.
    const emandate = decoded.type === EMANDATE_TX_DATA_TYPE ? ((decoded as Record<string, any>).payload as Record<string, any> | undefined) : undefined;
    if (!(decoded.type === TX_DATA_TYPE && decoded.mandate) && !(emandate && typeof emandate === 'object')) {
      throw new HttpError(400, 'invalid_transaction_data: unsupported type');
    }
    const claims = payload.dcql_query?.credentials?.[0]?.claims;
    const disclose = Array.isArray(claims) ? claims.map((c: { path?: unknown[] }) => String(c?.path?.[0] ?? '')).filter(Boolean) : [];

    const r: PendingRequest = {
      id: randomUUID(),
      clientId,
      clientName: dns,
      certificateSubject: key.subject ?? '',
      requestUri,
      requestObject: jwt,
      responseUri: responseUri.toString(),
      kind: emandate ? 'emandate' : 'plenipo',
      ...(emandate ? { emandate } : { mandate: decoded.mandate }),
      title: String((emandate ? emandate.purpose : decoded.mandate!.purpose) ?? 'No purpose given'),
      reference: String(emandate ? (emandate.reference_number ?? emandate.transaction_id) : decoded.mandate!.id),
      mandateProblems: emandate ? (typeof emandate.transaction_id === 'string' ? [] : ['the e-mandate has no transaction_id']) : validateMandate(decoded.mandate),
      txHash: sha256(tx[0]),
      disclose,
      warnings,
      personHint: personHint && holders.has(personHint) ? personHint : undefined,
      state: 'pending',
      receivedAt: new Date().toISOString(),
    };
    requests.set(r.id, r);
    events.append('request_received', { request_id: r.id, client_id: clientId, mandate_id: r.mandate?.id, kind: r.kind, purpose: r.title });
    return r;
  }

  async function decide(id: string, decision: 'approve' | 'refuse', personId: string): Promise<PendingRequest> {
    const r = requests.get(id);
    if (!r) throw new HttpError(404, 'unknown request');
    if (r.state !== 'pending') throw new HttpError(409, 'this request has already been answered');
    const holder = holders.get(personId);
    if (!holder) throw new HttpError(400, 'unknown person');
    if (decision === 'approve' && r.mandateProblems.length) throw new HttpError(400, 'this mandate is malformed and cannot be approved');
    const body = await holder.wallet.respond(r.requestObject, { approve: () => decision === 'approve', approveTransaction: () => decision === 'approve' });
    const form = new URLSearchParams();
    for (const [k, v] of Object.entries(body)) form.set(k, typeof v === 'string' ? v : JSON.stringify(v));
    r.person = personId;
    let status = 0;
    try {
      const res = await boundedFetch(r.responseUri, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
      });
      status = res.status;
    } catch {
      status = 0;
    }
    const name = `${holder.person.given_name} ${holder.person.family_name}`;
    if (status === 200) {
      r.state = decision === 'approve' ? 'approved' : 'refused';
      r.outcome = decision === 'approve' ? 'The platform accepted your approval.' : 'You refused. The platform has been told.';
    } else if (status === 409) {
      // Answered from elsewhere (another device, or an earlier copy of this request): the earlier answer stands.
      r.state = 'error';
      r.outcome = 'This request had already been answered. Nothing changed: the earlier answer stands.';
    } else {
      r.state = 'error';
      r.outcome = status ? `The platform answered HTTP ${status}.` : 'The platform could not be reached.';
    }
    events.append(decision === 'approve' ? 'consent_approved' : 'consent_refused', {
      request_id: r.id,
      mandate_id: r.mandate?.id,
      kind: r.kind,
      person: name,
      response_status: status,
    });
    return r;
  }

  const router = new Router();
  router.get('/events', (req, res) => sendJson(res, 200, eventsHandler(events)(req)));
  router.get('/api/persons', (_req, res) =>
    sendJson(res, 200, [...holders.values()].map((h) => ({ id: h.person.id, name: `${h.person.given_name} ${h.person.family_name}`, pid_id: h.pidId }))),
  );
  router.post('/api/requests', async (req, res) => {
    const body = await readFields(req);
    const { clientId, requestUri } = parseTarget(body);
    const r = await intake(clientId, requestUri, typeof body.person === 'string' ? body.person : undefined);
    sendJson(res, 201, view(r));
  });
  router.get('/api/requests/:id', (req, res) => {
    const r = requests.get(req.params.id);
    if (!r) throw new HttpError(404, 'unknown request');
    sendJson(res, 200, view(r));
  });
  router.post('/api/requests/:id/decision', async (req, res) => {
    const body = await readFields(req);
    const decision = body.decision === 'approve' ? 'approve' : body.decision === 'refuse' ? 'refuse' : undefined;
    if (!decision) throw new HttpError(400, 'decision must be approve or refuse');
    const r = await decide(req.params.id, decision, String(body.person ?? ''));
    sendJson(res, 200, view(r));
  });

  // Same-device flow: the platform links here with the OpenID4VP parameters.
  router.get('/authorize', async (req, res) => {
    const { clientId, requestUri } = parseTarget(Object.fromEntries(req.query));
    try {
      const r = await intake(clientId, requestUri, req.query.get('person') ?? undefined);
      redirect(res, `/requests/${r.id}`);
    } catch (e) {
      if (!(e instanceof HttpError)) throw e;
      sendHtml(res, page({ title: 'Wallet', service: 'wallet', body: `<div class="card err">Request refused: ${escapeHtml(e.message)}</div>`, nav: [['Home', '/']] }), e.status);
    }
  });
  router.get('/requests/:id', (req, res) => {
    const r = requests.get(req.params.id);
    if (!r) throw new HttpError(404, 'unknown request');
    sendHtml(res, consentPage(r));
  });
  router.post('/requests/:id/approve', async (req, res) => {
    const body = await readFields(req);
    await decide(req.params.id, 'approve', String(body.person ?? ''));
    redirect(res, `/requests/${encodeURIComponent(req.params.id)}`);
  });
  router.post('/requests/:id/refuse', async (req, res) => {
    const body = await readFields(req);
    await decide(req.params.id, 'refuse', String(body.person ?? ''));
    redirect(res, `/requests/${encodeURIComponent(req.params.id)}`);
  });
  router.get('/', (_req, res) => sendHtml(res, homePage()));

  function view(r: PendingRequest) {
    return {
      id: r.id,
      state: r.state,
      client_id: r.clientId,
      kind: r.kind,
      mandate: r.mandate,
      emandate: r.emandate,
      tx_hash: r.txHash,
      disclose: r.disclose,
      warnings: r.warnings,
      person: r.person,
      outcome: r.outcome,
    };
  }

  function homePage(): string {
    const persons = [...holders.values()]
      .map(
        (h) => `<div class="card"><h2>${escapeHtml(h.person.given_name)} ${escapeHtml(h.person.family_name)}</h2>
<dl class="kv"><dt>Credential</dt><dd>Person Identification Data <span class="muted">(urn:eudi:pid:1)</span></dd>
<dt>Born</dt><dd>${escapeHtml(h.person.birthdate)}</dd><dt>PID</dt><dd class="mono">${escapeHtml(h.pidId)}</dd></dl></div>`,
      )
      .join('');
    const list = [...requests.values()]
      .reverse()
      .slice(0, 12)
      .map(
        (r) =>
          `<tr><td><a href="/requests/${r.id}">${escapeHtml(r.title)}</a></td><td class="mono">${escapeHtml(r.clientName)}</td><td>${stateBadge(r.state)}</td></tr>`,
      )
      .join('');
    return page({
      title: 'EUDI Wallet (sandbox)',
      service: 'wallet',
      subtitle: 'Two people, one PID each. Requests from agent platforms land here for consent.',
      head: autoRefresh(5),
      body: `<div class="grid cols-2">${persons}</div>
<div class="card" style="margin-top:16px"><h2>Requests</h2><table><tr><th>Purpose</th><th>From</th><th>State</th></tr>${list || '<tr><td colspan=3 class="muted">No requests yet.</td></tr>'}</table></div>
<div class="card" style="margin-top:16px"><h2>Open a request link</h2><form method="get" action="/authorize">
<label>openid4vp:// link (as in the QR code)</label><input name="url" placeholder="openid4vp://?client_id=...&amp;request_uri=..."><p><button>Open</button></p></form></div>`,
    });
  }

  /** What the person is asked to approve: the whole Plenipo mandate. */
  function mandateSection(m: Mandate): string {
    const actions = m.actions
      .map((a) => `<li>${escapeHtml(ACTION_LABELS[a] ?? a)} <span class="muted mono">${escapeHtml(a)}</span></li>`)
      .join('');
    const cps = m.counterparties
      ? m.counterparties.map((c) => `<li>${escapeHtml(counterpartyLabel(c, opts.bankHost))} <span class="muted mono">${escapeHtml(c)}</span></li>`).join('')
      : '<li><strong>Any payee</strong></li>';
    const limits = m.limits
      ? `<li>${m.limits.per_operation !== undefined ? `At most <strong>${formatEuro(m.limits.per_operation)}</strong> per payment` : 'No per-payment limit'}</li>
<li>${m.limits.total !== undefined ? `At most <strong>${formatEuro(m.limits.total)}</strong> in total` : 'No total limit'}</li>`
      : '<li><strong>No spending limits</strong></li>';
    const days = Math.round((m.exp - m.nbf) / 3600 / 24);
    return `<h3>An AI agent asks for a mandate</h3><p style="font-size:17px;margin:4px 0 0">${escapeHtml(m.purpose ?? 'No purpose given')}</p>
<h3>It will be able to</h3><ul>${actions}</ul>
<h3>Payments only to</h3><ul>${cps}</ul>
<h3>Spending limits</h3><ul>${limits}</ul>
<h3>Valid</h3><p style="margin:0">From ${formatTime(m.nbf)} to <strong>${formatTime(m.exp)}</strong> (${days} days)</p>
<h3>Hand-over to other agents</h3><p style="margin:0">${m.delegation?.max_depth ? `Allowed, ${m.delegation.max_depth} level(s), and only with narrower powers` : 'Not allowed'}</p>
<h3>You can stop it</h3><p style="margin:0">${m.status ? 'Yes: revoke or suspend it at any time from the agent platform. Banks check its status before every operation.' : 'No status entry: it can only expire.'}</p>`;
  }

  /** What the person is asked to approve: a TS12 e-mandate, as a TS12 wallet renders it. */
  function emandateSection(p: Record<string, any>): string {
    const pay = p.payment_payload as Record<string, any> | undefined;
    const dt = (v: unknown) => (typeof v === 'string' ? escapeHtml(v.replace('T', ' ').slice(0, 16)) : 'not set');
    return `<h3>E-mandate (EUDI TS12, urn:eudi:sca:emandate:1)</h3><p style="font-size:16px;margin:4px 0 0;white-space:pre-line">${escapeHtml(p.purpose ?? 'No mandate text')}</p>
${pay ? `<h3>Payment</h3><p style="margin:0">To <strong>${escapeHtml(pay.payee?.name)}</strong>, ${escapeHtml(pay.currency)} ${escapeHtml(pay.amount)}${pay.recurrence?.mit_options?.total_amount !== undefined ? `, at most ${escapeHtml(pay.recurrence.mit_options.total_amount)} in total` : ''}</p>` : ''}
<h3>Valid</h3><p style="margin:0">From ${dt(p.start_date)} to <strong>${dt(p.end_date)}</strong></p>
<h3>Reference</h3><p style="margin:0" class="mono">${escapeHtml(p.reference_number ?? p.transaction_id)}</p>
<p class="muted" style="font-size:13px">The reference is the SHA-256 of the full mandate the bank will enforce; the bank checks that the text above describes exactly that mandate.</p>`;
  }

  function consentPage(r: PendingRequest): string {
    const decided = r.state !== 'pending';
    const personChoices = [...holders.values()]
      .map((h, i) => {
        const checked = r.person ? r.person === h.person.id : r.personHint ? r.personHint === h.person.id : i === 0;
        return `<label style="display:flex;gap:8px;align-items:center;color:var(--ink);font-size:15px"><input type="radio" name="person" value="${h.person.id}" style="width:auto"${checked ? ' checked' : ''}${decided ? ' disabled' : ''}> ${escapeHtml(h.person.given_name)} ${escapeHtml(h.person.family_name)}</label>`;
      })
      .join('');
    const outcome = decided
      ? `<div class="${r.state === 'approved' ? 'ok' : r.state === 'refused' ? 'notice' : 'err'}">${escapeHtml(r.outcome ?? r.state)}</div>`
      : '';
    return page({
      title: 'EUDI Wallet (sandbox)',
      service: 'wallet',
      subtitle: 'Authorise an AI agent',
      nav: [['Home', '/']],
      body: `<div style="max-width:640px;margin:0 auto">
${r.warnings.map((w) => `<div class="notice" style="margin-bottom:12px">${escapeHtml(w)}</div>`).join('')}
<div class="card"><div class="muted" style="font-size:13px">Request from</div>
<div style="font-size:18px;font-weight:650">${escapeHtml(r.clientName)}</div>
<div class="muted" style="font-size:13px">Verified certificate: ${escapeHtml(r.certificateSubject)}</div>
${r.mandate ? mandateSection(r.mandate) : emandateSection(r.emandate ?? {})}
<h3>Shared with the platform</h3><p style="margin:0">${r.disclose.map((d) => `<code>${escapeHtml(d)}</code>`).join(' ') || 'nothing'} from your PID</p>
${r.mandateProblems.length ? `<div class="err" style="margin-top:12px">This mandate is malformed: ${escapeHtml(r.mandateProblems.join('; '))}</div>` : ''}
<details style="margin-top:14px"><summary class="muted">Technical details</summary><dl class="kv" style="margin-top:8px">
<dt>Reference</dt><dd class="mono">${escapeHtml(r.reference)}</dd><dt>You sign</dt><dd class="mono">SHA-256 ${escapeHtml(r.txHash)}</dd>
<dt>Response to</dt><dd class="mono">${escapeHtml(r.responseUri)}</dd></dl></details></div>
<form method="post" class="card" style="margin-top:14px"><h2>Who are you?</h2>${personChoices}
<div class="row" style="margin-top:14px">${
        decided
          ? outcome
          : `<button class="primary" formaction="/requests/${r.id}/approve">Approve with my PID</button><button class="danger" formaction="/requests/${r.id}/refuse">Refuse</button>`
      }</div></form></div>`,
    });
  }


  const running = await listen(router, opts.host, opts.port);
  return { ...running, events, intake, decide };
}

/** Accepts either an openid4vp:// URL or separate client_id and request_uri. */
function parseTarget(body: Record<string, unknown>): { clientId: string; requestUri: string } {
  if (typeof body.url === 'string' && body.url) {
    let u: URL;
    try {
      u = new URL(body.url);
    } catch {
      throw new HttpError(400, 'invalid link');
    }
    return { clientId: u.searchParams.get('client_id') ?? '', requestUri: u.searchParams.get('request_uri') ?? '' };
  }
  if (typeof body.client_id !== 'string' || typeof body.request_uri !== 'string') throw new HttpError(400, 'client_id and request_uri required');
  return { clientId: body.client_id, requestUri: body.request_uri };
}

function stateBadge(s: string): string {
  const cls = s === 'approved' ? 'b-allow' : s === 'pending' ? 'b-warn' : 'b-deny';
  return `<span class="badge ${cls}">${escapeHtml(s)}</span>`;
}
