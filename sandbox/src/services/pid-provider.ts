/**
 * PID provider: a test certificate authority (standing in for the CA on an EU trusted list), a PID
 * issuer certified by it, and the PID status list published over HTTP.
 *
 * Issuance is a plain POST here. A real provider issues over OpenID4VCI after identifying the person;
 * that leg is out of scope for the sandbox, so the endpoint is admin-only when an admin token is set.
 */
import { createTestCertificateAuthority, createTestPidProvider, type PidClaims } from 'plenipo/testing';
import { decodeJwt, type JWK } from 'jose';
import type { StatusReference } from 'plenipo';
import { EventLog, eventsHandler } from '../events.js';
import { checkAdmin, escapeHtml, HttpError, listen, readFields, redirect, Router, sendHtml, sendJson, sendText, type Handler, type RunningServer } from '../http.js';
import { page } from '../ui/layout.js';

export interface PidProviderOptions {
  host: string;
  port: number;
  /** PID `iss`; the status list is served under it. */
  iss: string;
  adminToken?: string;
}

interface IssuedPid {
  id: string;
  personId: string;
  name: string;
  status: StatusReference;
  state: 'valid' | 'revoked' | 'suspended';
  issuedAt: string;
}

export interface PidProviderService extends RunningServer {
  iss: string;
  anchorPem: string;
  events: EventLog;
}

function isJwk(x: unknown): x is JWK {
  if (typeof x !== 'object' || x === null) return false;
  const j = x as Record<string, unknown>;
  return j.kty === 'EC' && j.crv === 'P-256' && typeof j.x === 'string' && typeof j.y === 'string' && j.d === undefined;
}

const CLAIM_RE = /^[A-Za-z0-9 '\-.àèéìòùÀÈÉÌÒÙ]{1,64}$/;

export async function startPidProvider(opts: PidProviderOptions): Promise<PidProviderService> {
  const ca = await createTestCertificateAuthority('Sandbox PID Trust Anchor');
  const provider = await createTestPidProvider(opts.iss, { x5c: true, statusList: true, ca });
  const statusList = provider.statusList!;
  const statusPath = new URL(`${opts.iss}/status/1`).pathname;
  const events = new EventLog('pid');
  const issued = new Map<string, IssuedPid>();

  const router = new Router();
  router.get('/events', (req, res) => sendJson(res, 200, eventsHandler(events)(req)));
  router.get('/trust-anchor.pem', (_req, res) => sendText(res, 200, ca.anchorPem, 'application/x-pem-file'));
  router.get(statusPath, async (_req, res) => sendText(res, 200, await statusList.token(), 'application/statuslist+jwt'));
  router.get('/api/pids', (_req, res) => sendJson(res, 200, [...issued.values()]));

  router.post('/issue', async (req, res) => {
    checkAdmin(req, opts.adminToken);
    const body = await readFields(req, 16 * 1024);
    const holder = body.holder_jwk;
    const claims = body.claims as Record<string, unknown> | undefined;
    const personId = String(body.person_id ?? '');
    if (!isJwk(holder)) throw new HttpError(400, 'holder_jwk must be a public EC P-256 JWK');
    if (!claims || typeof claims !== 'object') throw new HttpError(400, 'claims required');
    for (const k of ['given_name', 'family_name', 'birthdate', 'nationality']) {
      if (claims[k] !== undefined && (typeof claims[k] !== 'string' || !CLAIM_RE.test(claims[k] as string))) {
        throw new HttpError(400, `invalid claim ${k}`);
      }
    }
    if (typeof claims.given_name !== 'string' || typeof claims.family_name !== 'string') throw new HttpError(400, 'names required');
    if (!/^[a-z0-9-]{1,32}$/.test(personId)) throw new HttpError(400, 'invalid person_id');
    const pidClaims: PidClaims = {
      given_name: claims.given_name,
      family_name: claims.family_name,
      ...(claims.birthdate ? { birthdate: String(claims.birthdate) } : {}),
      ...(claims.nationality ? { nationality: String(claims.nationality) } : {}),
    };
    const pid = await provider.issuePid(holder, pidClaims);
    // Read the status reference from the PID itself (the claim is not selectively disclosable), not from
    // `lastStatus`, which a concurrent issuance could overwrite between the call and the read.
    const status = decodeJwt(pid.split('~')[0]).status as StatusReference | undefined;
    if (!status) throw new Error('the PID has no status reference');
    const record: IssuedPid = {
      id: `${personId}-${status.status_list.idx}`,
      personId,
      name: `${pidClaims.given_name} ${pidClaims.family_name}`,
      status,
      state: 'valid',
      issuedAt: new Date().toISOString(),
    };
    issued.set(record.id, record);
    events.append('pid_issued', { pid_id: record.id, person: record.name, status_idx: status.status_list.idx });
    sendJson(res, 200, { pid, pid_id: record.id, status });
  });

  const change = (action: 'revoke' | 'suspend' | 'reinstate'): Handler => async (req, res) => {
    checkAdmin(req, opts.adminToken);
    const record = issued.get(req.params.id);
    if (!record) throw new HttpError(404, 'unknown pid');
    statusList[action](record.status);
    record.state = action === 'revoke' ? 'revoked' : action === 'suspend' ? 'suspended' : 'valid';
    events.append(`pid_${action === 'reinstate' ? 'reinstated' : action === 'revoke' ? 'revoked' : 'suspended'}`, {
      pid_id: record.id,
      person: record.name,
    });
    if (String(req.headers.accept ?? '').includes('text/html')) return redirect(res, '/');
    sendJson(res, 200, record);
  };
  router.post('/admin/pids/:id/revoke', change('revoke'));
  router.post('/admin/pids/:id/suspend', change('suspend'));
  router.post('/admin/pids/:id/reinstate', change('reinstate'));

  router.get('/', (_req, res) => {
    const rows = [...issued.values()]
      .map(
        (p) => `<tr><td>${escapeHtml(p.name)}</td><td class="mono">${escapeHtml(p.id)}</td><td>${badge(p.state)}</td>
<td class="row">${(['revoke', 'suspend', 'reinstate'] as const)
          .map((a) => `<form method="post" action="/admin/pids/${encodeURIComponent(p.id)}/${a}"><button class="small${a === 'revoke' ? ' danger' : ''}">${a}</button></form>`)
          .join('')}</td></tr>`,
      )
      .join('');
    sendHtml(
      res,
      page({
        title: 'PID Provider',
        service: 'pid',
        subtitle: 'Issues Person Identification Data and publishes its status list',
        body: `<div class="grid cols-2">
<div class="card"><h2>Identity</h2><dl class="kv"><dt>Issuer (iss)</dt><dd class="mono">${escapeHtml(opts.iss)}</dd>
<dt>Status list</dt><dd class="mono">${escapeHtml(opts.iss)}/status/1</dd><dt>Trust anchor</dt><dd><a href="/trust-anchor.pem">trust-anchor.pem</a></dd></dl>
<p class="muted">Test keys generated at start-up. In production the anchor comes from the EU trusted list of PID providers.</p></div>
<div class="card"><h2>Issued PIDs</h2><table><tr><th>Person</th><th>PID</th><th>Status</th><th></th></tr>${rows || '<tr><td colspan=4 class="muted">none yet</td></tr>'}</table></div></div>`,
        nav: [['Status list', `${statusPath}`]],
      }),
    );
  });

  const running = await listen(router, opts.host, opts.port);
  return { ...running, iss: opts.iss, anchorPem: ca.anchorPem, events };
}

function badge(state: string): string {
  const cls = state === 'valid' ? 'b-allow' : state === 'suspended' ? 'b-warn' : 'b-deny';
  return `<span class="badge ${cls}">${escapeHtml(state)}</span>`;
}
