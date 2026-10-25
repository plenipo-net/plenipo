/**
 * Bank: simulated accounts and a payee register, exposed two ways to AI agents:
 *  - a PSD2-like REST API (balance, payments, card block), and
 *  - an MCP server with the tools get_balance, list_payees, transfer and block_card.
 * Both are protected by Plenipo: every call carries the mandate chain and a signed invocation, and the
 * bank verifies them (PID trust, attenuation, limits, status lists, replay) before touching an account.
 * Every decision is appended to the bank's event log.
 */
import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import {
  InMemoryNonceStore,
  InMemorySpendingLedger,
  mandateHash,
  nowSeconds,
  type ReservationInfo,
  peekInvocation,
  StatusListCache,
  verifyAuthorization,
  type Amount,
  type Decision,
  type Mandate,
  type MandateChain,
  type StatusFetcher,
  type TrustConfig,
  type TrustedIssuer,
  type VerifyOptions,
} from 'plenipo';
import { guardTool } from 'plenipo/mcp';
import { BINDING_META_KEY, bindCall, type BoundCall, type ToolBinding } from '../binding.js';
import { BILLS, formatEuro, OPENING_BALANCES, PAYEES, PERSONS, type Person } from '../catalog.js';
import { bankAudiences } from '../config.js';
import { EventLog, eventsHandler } from '../events.js';
import {
  checkAdmin,
  escapeHtml,
  HttpError,
  listen,
  readBody,
  readFields,
  Router,
  sendHtml,
  sendJson,
  type Request,
  type RunningServer,
} from '../http.js';
import { page } from '../ui/layout.js';
import type { BankStores } from './stores.js';

export interface BankOptions {
  host: string;
  port: number;
  bankHost: string;
  pidTrustAnchors: string[];
  pidTrustedIssuers?: TrustedIssuer[];
  pidStatusTrust?: TrustConfig;
  /** Who signs the mandate status lists, per agent platform. */
  platformStatusSigners: TrustedIssuer[];
  /** OpenID4VP client_ids of the agent platforms whose mandates this bank accepts. */
  acceptedPlatforms?: string[];
  statusFetcher: StatusFetcher;
  /** Seconds a verified status list is reused: the revocation latency the bank accepts. */
  statusCacheSeconds: number;
  stores?: BankStores;
  /** How often the shared ledger's sweep runs, in seconds. Default 10. */
  sweepSeconds?: number;
  adminToken?: string;
  /** Public sandbox: this often, accounts below half their opening balance get it back and their bills reopen. */
  refillSeconds?: number;
  /**
   * `person` (default): one account per person, shared by every mandate. `mandate`: one account per person and
   * root mandate, opened with the opening balance and every bill unpaid, so that visitors of a public sandbox
   * never find each other's payments. Delegated mandates use their root's account.
   */
  accountScope?: 'person' | 'mandate';
}

/** At most this many per-mandate accounts are kept; the least recently used goes first. */
const MAX_MANDATE_ACCOUNTS = 5000;

interface Account {
  person: Person;
  iban: string;
  balance: number;
  card: { last4: string; blocked: boolean };
  transactions: Array<{ at: string; payee: string; amount: number; reference: string }>;
  paid: Set<string>;
}

export interface BankService extends RunningServer {
  events: EventLog;
  /** Runs the shared ledger's sweep now (it also runs on a timer). */
  sweep(): Promise<void>;
  audiences: { mcp: string; rest: string };
  clock: { offset: number };
}

type ToolResult = {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
  structuredContent?: Record<string, unknown>;
  _meta?: Record<string, unknown>;
};

const PAYEE_IDS = new Set(PAYEES.map((p) => p.id));

function ok(data: Record<string, unknown>, text: string): ToolResult {
  return { content: [{ type: 'text', text }], structuredContent: data };
}
// Every failure here is detected before the bank moves money, so the guard may release the reservation.
function fail(error: string, text: string): ToolResult {
  return { isError: true, content: [{ type: 'text', text }], structuredContent: { error }, _meta: { 'plenipo/outcome': 'not-executed' } };
}

export async function startBank(opts: BankOptions): Promise<BankService> {
  const events = new EventLog('bank');
  const stores: BankStores = opts.stores ?? { kind: 'memory', ledger: new InMemorySpendingLedger(), nonces: new InMemoryNonceStore() };
  // Admin switch: the next transfer debits the account and then throws, like a core banking call that times
  // out after the money left. The guard then leaves the reservation pending (unknown outcome).
  let failNextTransfer = false;
  const statusCache = new StatusListCache(opts.statusCacheSeconds);
  const audiences = bankAudiences(opts.bankHost);
  const clock = { offset: 0 };

  const accounts = new Map<string, Account>();
  PERSONS.forEach((p, i) => {
    accounts.set(p.id, {
      person: p,
      iban: `IT${60 + i}X0300203280${String(400100 + i * 77).padStart(12, '0')}`,
      balance: OPENING_BALANCES[p.id] ?? 100000,
      card: { last4: String(4021 + i * 1111).slice(-4), blocked: false },
      transactions: [],
      paid: new Set(),
    });
  });

  /** The bank binds a mandate to an account through the PID claims the wallet disclosed. */
  function accountOf(principal: Record<string, unknown>): Account | undefined {
    return [...accounts.values()].find(
      (a) =>
        a.person.given_name === principal.given_name &&
        a.person.family_name === principal.family_name &&
        a.person.birthdate === principal.birthdate,
    );
  }

  const mandateAccounts = new Map<string, Account & { root: string }>();
  /** The account an allowed call acts on: the person's, or with `accountScope: 'mandate'` its root mandate's. */
  function accountFor(d: { principal: Record<string, unknown>; path: Array<{ mandate_id: string }> }): Account | undefined {
    const base = accountOf(d.principal);
    if (!base || opts.accountScope !== 'mandate') return base;
    const root = d.path[0]?.mandate_id;
    if (!root) return base;
    const key = `${base.person.id}:${root}`;
    let acct = mandateAccounts.get(key);
    if (acct) {
      mandateAccounts.delete(key);
    } else {
      acct = { ...base, root, balance: OPENING_BALANCES[base.person.id] ?? 100000, card: { ...base.card, blocked: false }, transactions: [], paid: new Set() };
      if (mandateAccounts.size >= MAX_MANDATE_ACCOUNTS) mandateAccounts.delete(mandateAccounts.keys().next().value!);
    }
    mandateAccounts.set(key, acct);
    return acct;
  }
  /** The accounts to show on the bank page: the people's, or the most recent per-mandate ones. */
  function shownAccounts(): Array<Account & { root?: string }> {
    return opts.accountScope === 'mandate' ? [...mandateAccounts.values()].reverse().slice(0, 6) : [...accounts.values()];
  }

  /** The bank's clock, in seconds: the system clock, moved by the admin offset to show expiry. */
  const now = () => nowSeconds() + clock.offset;

  function verifyOptions(audience: string): Omit<VerifyOptions, 'expected' | 'now'> {
    return {
      trustAnchors: opts.pidTrustAnchors,
      trustedIssuers: opts.pidTrustedIssuers,
      pidStatusTrust: opts.pidStatusTrust,
      mandateStatusTrust: { trustedIssuers: opts.platformStatusSigners },
      acceptedRootAudiences: opts.acceptedPlatforms,
      statusFetcher: opts.statusFetcher,
      statusCache,
      audience,
      nonces: stores.nonces,
      ledger: stores.ledger,
      requiredPrincipalClaims: ['given_name', 'family_name', 'birthdate'],
      // TS12 e-mandate roots are experimental and opt-in; the sandbox accepts them bound to the PID.
      emandate: { allowPidBinding: true },
    };
  }

  async function usage(mandates: Mandate[], currency: string) {
    return Promise.all(
      mandates.map(async (m, depth) => ({
        mandate_id: m.id,
        depth,
        per_operation: m.limits?.per_operation,
        total: m.limits?.total,
        spent: await stores.ledger.spent(mandateHash(m), currency),
      })),
    );
  }

  function recordDecision(channel: 'mcp' | 'rest', tool: string, d: Decision, call: BoundCall, invocation?: string) {
    let claimed: string | undefined;
    try {
      claimed = invocation ? peekInvocation(invocation).mandate : undefined;
    } catch {
      claimed = undefined;
    }
    const base = {
      channel,
      tool,
      action: call.action,
      counterparty: call.counterparty,
      amount: call.amount,
      mandate_path: d.path.map((p) => p.mandate_id),
      leaf_mandate: d.decision === 'ALLOW' ? d.invocation.mandate : claimed,
    };
    if (d.decision === 'ALLOW') {
      events.append('decision', {
        ...base,
        decision: 'ALLOW',
        person: `${d.principal.given_name ?? ''} ${d.principal.family_name ?? ''}`.trim(),
        depth: d.path.length - 1,
        pid_issuer: d.pid_issuer,
        // Read-only and card calls declare no amount: nothing is reserved against the limits.
        reservation: Boolean(d.reservation),
      });
    } else {
      events.append('decision', { ...base, decision: 'DENY', code: d.code, reason: d.reason, at: d.at, detail: d.detail });
    }
  }

  // ---- The operations, shared by MCP and REST. They run only after an ALLOW. ----
  function getBalance(acct: Account): ToolResult {
    return ok(
      { iban: acct.iban, balance_cents: acct.balance, currency: 'EUR', card_blocked: acct.card.blocked },
      `Balance of ${acct.iban}: ${formatEuro(acct.balance)}`,
    );
  }

  function listPayees(acct: Account, category?: string): ToolResult {
    const payees = PAYEES.filter((p) => !category || p.category === category).map((p) => {
      const bills = (BILLS[acct.person.id] ?? []).filter((b) => b.payee === p.id && !acct.paid.has(`${b.payee}:${b.period}`));
      return {
        payee: p.id,
        name: p.name,
        category: p.category,
        open_bills: bills.map((b) => ({ amount_cents: b.amount_cents, period: b.period, due: b.due, ...(b.note ? { note: b.note } : {}) })),
      };
    });
    const lines = payees.map(
      (p) =>
        `${p.payee} (${p.name}, ${p.category}): ${p.open_bills.length ? 'open bills ' + p.open_bills.map((b) => `${formatEuro(b.amount_cents)} for ${b.period}, due ${b.due}${b.note ? `. Note on the bill: "${b.note}"` : ''}`).join('; ') : 'no open bill'}`,
    );
    // Said in words, so an agent never reads a missing bill as a paid one.
    const open = payees.flatMap((p) => p.open_bills);
    const who = `${acct.person.given_name} ${acct.person.family_name}`;
    const summary = open.length
      ? `Open bills for ${who}: ${open.length}, total ${formatEuro(open.reduce((t, b) => t + b.amount_cents, 0))}.`
      : `No open bills for ${who}${category ? ` in ${category}` : ''}. This says nothing about who paid them or when: the account's payments are not listed here.`;
    return ok({ payees, open_bills_count: open.length }, [summary, ...lines].join('\n'));
  }

  function transfer(acct: Account, a: { payee: string; amount_cents: number; reference: string }, mandateId?: string): ToolResult {
    if (failNextTransfer && PAYEE_IDS.has(a.payee) && a.amount_cents <= acct.balance) {
      failNextTransfer = false;
      acct.balance -= a.amount_cents;
      acct.transactions.unshift({ at: new Date().toISOString(), payee: a.payee, amount: a.amount_cents, reference: a.reference });
      events.append('payment_unknown_outcome', {
        mandate_id: mandateId,
        person: `${acct.person.given_name} ${acct.person.family_name}`,
        payee: a.payee,
        amount: { value: a.amount_cents, currency: 'EUR' },
      });
      throw new Error('core banking did not answer in time: the payment may or may not have been executed');
    }
    if (!PAYEE_IDS.has(a.payee)) return fail('unknown_payee', `${a.payee} is not in the payee register`);
    if (a.amount_cents > acct.balance) return fail('insufficient_funds', 'Insufficient funds');
    acct.balance -= a.amount_cents;
    acct.transactions.unshift({ at: new Date().toISOString(), payee: a.payee, amount: a.amount_cents, reference: a.reference });
    const bill = (BILLS[acct.person.id] ?? []).find((b) => b.payee === a.payee && b.amount_cents === a.amount_cents && !acct.paid.has(`${b.payee}:${b.period}`));
    if (bill) acct.paid.add(`${bill.payee}:${bill.period}`);
    const id = `TRX-${randomUUID().slice(0, 8).toUpperCase()}`;
    events.append('payment_executed', {
      mandate_id: mandateId,
      person: `${acct.person.given_name} ${acct.person.family_name}`,
      payee: a.payee,
      amount: { value: a.amount_cents, currency: 'EUR' },
      reference: a.reference,
      balance_after: acct.balance,
      transaction_id: id,
    });
    return ok(
      { transaction_id: id, payee: a.payee, amount_cents: a.amount_cents, balance_after_cents: acct.balance, bill_settled: bill ? bill.period : null },
      `Paid ${formatEuro(a.amount_cents)} to ${a.payee} (${a.reference}). Transaction ${id}. New balance ${formatEuro(acct.balance)}.`,
    );
  }

  function blockCard(acct: Account, reason?: string, mandateId?: string): ToolResult {
    acct.card.blocked = true;
    events.append('card_blocked', { mandate_id: mandateId, person: `${acct.person.given_name} ${acct.person.family_name}`, reason });
    return ok({ card: `**** ${acct.card.last4}`, blocked: true }, `Card **** ${acct.card.last4} blocked.`);
  }

  // ---- MCP ----
  // Reads and card blocking have no counterparty and move no money: `null` tells the verifier so, and
  // payee restrictions and spending limits then do not apply to them (nothing is reserved).
  const bindings: Record<string, ToolBinding> = {
    get_balance: { action: 'account.read', audience: audiences.mcp, counterparty: null, amount: null },
    list_payees: { action: 'account.read', audience: audiences.mcp, counterparty: null, amount: null },
    transfer: { action: 'payments.transfer', audience: audiences.mcp, counterparty: { arg: 'payee' }, amount: { arg: 'amount_cents', currency: 'EUR' } },
    block_card: { action: 'card.block', audience: audiences.mcp, counterparty: null, amount: null },
  };

  /** The guard's extractors for a binding: a function reading the argument, or null when the tool has none. */
  function extractors(binding: ToolBinding) {
    return {
      counterparty: binding.counterparty ? (a: unknown) => bindCall(binding, a as Record<string, unknown>).counterparty ?? undefined : null,
      amount: binding.amount ? (a: unknown) => bindCall(binding, a as Record<string, unknown>).amount ?? undefined : null,
    };
  }

  function buildMcpServer(): McpServer {
    const server = new McpServer({ name: opts.bankHost, version: '1.0.0' });
    const pendingInvocation = { value: undefined as string | undefined };

    function register<S extends z.ZodRawShape>(
      name: keyof typeof bindings,
      description: string,
      shape: S,
      run: (acct: Account, args: z.infer<z.ZodObject<S>>, mandateId: string) => ToolResult,
    ) {
      const binding = bindings[name];
      const guarded = guardTool<z.infer<z.ZodObject<S>>>(
        // The guard hands the verified decision to the handler: the principal identifies the account.
        async (args, _extra, d) => {
          const acct = accountFor(d);
          if (!acct) return fail('no_account', 'This bank holds no account for the person who granted the mandate.');
          const result = run(acct, args, d.invocation.mandate);
          // Recorded before the guard settles the reservation: `spent` includes this call as pending.
          events.append('ledger', {
            tool: name,
            outcome: result.isError ? 'not_executed' : 'executed',
            reservation: Boolean(d.reservation),
            usage: await usage(d.mandates, 'EUR'),
          });
          return result;
        },
        {
          ...verifyOptions(binding.audience),
          now,
          action: binding.action,
          ...extractors(binding),
          onDecision: (d, a) => recordDecision('mcp', name, d, bindCall(binding, a as Record<string, unknown>), pendingInvocation.value),
        },
      );
      server.registerTool(
        name,
        { description, inputSchema: shape, _meta: { [BINDING_META_KEY]: binding } },
        (async (args: z.infer<z.ZodObject<S>>, extra: { _meta?: Record<string, unknown> }) => {
          const meta = extra?._meta?.['plenipo/authorization'] as { invocation?: unknown } | undefined;
          pendingInvocation.value = typeof meta?.invocation === 'string' ? meta.invocation : undefined;
          return guarded(args, extra as never);
        }) as never,
      );
    }

    register('get_balance', 'Read the balance of the account of the person who granted the mandate.', {}, (acct) => getBalance(acct));
    register(
      'list_payees',
      'List the payees in the bank register, with the open bills of the person who granted the mandate. Amounts are in euro cents.',
      { category: z.enum(['utilities', 'telco', 'travel', 'shopping']).optional() },
      (acct, a) => listPayees(acct, a.category),
    );
    register(
      'transfer',
      'Pay a payee from the register. `payee` is the payee id (its domain, e.g. acquaviva.example), `amount_cents` the amount in euro cents.',
      { payee: z.string().min(1).max(100), amount_cents: z.number().int().positive().max(10_000_000), reference: z.string().min(1).max(140) },
      (acct, a, m) => transfer(acct, a, m),
    );
    register('block_card', "Block the person's payment card.", { reason: z.string().max(140).optional() }, (acct, a, m) => blockCard(acct, a.reason, m));
    return server;
  }

  const router = new Router();
  router.mount('/mcp', async (req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'content-type': 'application/json', allow: 'POST' });
      res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed: this server is stateless' }, id: null }));
      return;
    }
    let body: unknown;
    try {
      body = JSON.parse(await readBody(req, 1024 * 1024));
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(400, 'invalid_json');
    }
    // Stateless: a fresh server and transport per request, so nothing leaks between callers.
    const server = buildMcpServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req.raw, res, body);
  });

  // ---- PSD2-like REST ----
  function readAuth(req: Request): { chain: MandateChain; invocation: string } {
    const chainHeader = req.headers['plenipo-chain'];
    const invocation = req.headers['plenipo-invocation'];
    if (typeof chainHeader !== 'string' || typeof invocation !== 'string') throw new HttpError(401, 'Plenipo-Chain and Plenipo-Invocation headers required');
    try {
      return { chain: fromBase64urlJson(chainHeader) as MandateChain, invocation };
    } catch {
      throw new HttpError(400, 'Plenipo-Chain must be base64url JSON');
    }
  }

  async function restCall(
    req: Request,
    res: Parameters<Parameters<Router['post']>[1]>[1],
    tool: keyof typeof bindings,
    args: Record<string, unknown>,
    run: (acct: Account, mandateId: string) => ToolResult,
  ) {
    const { chain, invocation } = readAuth(req);
    const call = bindCall(bindings[tool], args);
    if (call.counterparty === undefined || call.amount === undefined) throw new HttpError(400, 'invalid request');
    const d = await verifyAuthorization(chain, invocation, {
      ...verifyOptions(audiences.rest),
      now: now(),
      expected: { action: call.action, counterparty: call.counterparty, amount: call.amount, args },
    });
    recordDecision('rest', tool, d, call, invocation);
    if (d.decision === 'DENY') return sendJson(res, 403, { decision: 'DENY', code: d.code, reason: d.reason });
    const acct = accountFor(d);
    // As in guardTool: a throw is an unknown outcome, so the reservation stays pending for the sweep.
    const result = acct ? run(acct, d.invocation.mandate) : fail('no_account', 'no account for this person');
    if (d.reservation) {
      if (result.isError) await stores.ledger.release(d.reservation);
      else await stores.ledger.commit(d.reservation);
    }
    events.append('ledger', { tool, outcome: result.isError ? 'not_executed' : 'executed', reservation: Boolean(d.reservation), usage: await usage(d.mandates, 'EUR') });
    sendJson(res, result.isError ? 422 : 200, { decision: 'ALLOW', ...(result.structuredContent ?? {}) });
  }

  router.get('/psd2/v1/accounts/balance', (req, res) => restCall(req, res, 'get_balance', {}, (acct) => getBalance(acct)));
  router.post('/psd2/v1/payments', async (req, res) => {
    const body = await readFields(req, 16 * 1024);
    const parsed = z.object({ payee: z.string().min(1).max(100), amount_cents: z.number().int().positive().max(10_000_000), reference: z.string().min(1).max(140) }).strict().safeParse(body);
    if (!parsed.success) throw new HttpError(400, 'invalid payment');
    return restCall(req, res, 'transfer', parsed.data, (acct, m) => transfer(acct, parsed.data, m));
  });
  router.post('/psd2/v1/cards/block', async (req, res) => {
    const body = await readFields(req, 16 * 1024);
    const parsed = z.object({ reason: z.string().max(140).optional() }).strict().safeParse(body);
    if (!parsed.success) throw new HttpError(400, 'invalid request');
    return restCall(req, res, 'block_card', parsed.data, (acct, m) => blockCard(acct, parsed.data.reason, m));
  });

  // ---- Admin and pages ----
  router.get('/events', (req, res) => sendJson(res, 200, eventsHandler(events)(req)));
  router.get('/api/accounts', (_req, res) => sendJson(res, 200, shownAccounts().map(accountView)));
  router.get('/admin/clock', (_req, res) => sendJson(res, 200, { offset_seconds: clock.offset, now: nowSeconds() + clock.offset }));
  router.post('/admin/clock', async (req, res) => {
    checkAdmin(req, opts.adminToken);
    const body = await readFields(req);
    const offset = Number(body.offset_seconds);
    if (!Number.isSafeInteger(offset) || Math.abs(offset) > 400 * 24 * 3600) throw new HttpError(400, 'invalid offset_seconds');
    clock.offset = offset;
    events.append('clock_changed', { offset_seconds: offset });
    sendJson(res, 200, { offset_seconds: offset });
  });
  router.get('/', (_req, res) => sendHtml(res, homePage()));

  function accountView(a: Account & { root?: string }) {
    return {
      person: `${a.person.given_name} ${a.person.family_name}`,
      ...(a.root ? { mandate: a.root } : {}),
      iban: a.iban,
      balance_cents: a.balance,
      card_blocked: a.card.blocked,
      transactions: a.transactions.slice(0, 20),
    };
  }

  function homePage(): string {
    const accts = shownAccounts()
      .map(
        (a) => `<div class="card"><h2>${escapeHtml(a.person.given_name)} ${escapeHtml(a.person.family_name)}${a.root ? ` <span class="pill">mandate ${escapeHtml(a.root.slice(0, 8))}</span>` : ''}</h2>
<dl class="kv"><dt>IBAN</dt><dd class="mono">${escapeHtml(a.iban)}</dd><dt>Balance</dt><dd style="font-size:20px;font-weight:650">${formatEuro(a.balance)}</dd>
<dt>Card</dt><dd>**** ${a.card.last4} ${a.card.blocked ? '<span class="badge b-deny">blocked</span>' : '<span class="badge b-allow">active</span>'}</dd></dl>
<h3>Recent payments</h3><table>${a.transactions.slice(0, 6).map((t) => `<tr><td class="mono">${escapeHtml(t.at.slice(11, 19))}</td><td>${escapeHtml(t.payee)}</td><td>${formatEuro(t.amount)}</td></tr>`).join('') || '<tr><td class="muted">none</td></tr>'}</table></div>`,
      )
      .join('');
    const decisions = events
      .all()
      .filter((e) => e.type === 'decision')
      .slice(-12)
      .reverse()
      .map(
        (e) => `<tr><td class="mono">${escapeHtml(e.ts.slice(11, 19))}</td><td>${e.decision === 'ALLOW' ? '<span class="badge b-allow">ALLOW</span>' : `<span class="badge b-deny">DENY</span><div class="mono" style="font-size:11.5px">${escapeHtml(e.code)}</div>`}</td>
<td><strong>${escapeHtml(e.tool)}</strong> <span class="muted">${escapeHtml(e.channel)}</span><div class="muted" style="font-size:13px">${escapeHtml(e.counterparty ?? '')} ${e.amount && (e.amount as Amount).value ? formatEuro((e.amount as Amount).value) : ''}</div></td></tr>`,
      )
      .join('');
    return page({
      title: 'Banca Sandbox',
      service: 'bank',
      subtitle: `Accounts, payee register, PSD2-like API and MCP server at /mcp · ${opts.bankHost}`,
      head: '<meta http-equiv="refresh" content="3">',
      nav: [['Accounts API', '/api/accounts'], ['Events', '/events']],
      body: `${opts.accountScope === 'mandate' ? '<p class="notice">Public sandbox: every mandate gets its own copy of the account, with the opening balance and every bill unpaid. The latest ones are shown.</p>' : ''}<div class="grid cols-2">${accts || '<div class="card muted">No mandate has used the bank yet.</div>'}</div>
<div class="grid cols-2" style="margin-top:16px"><div class="card"><h2>Payee register</h2><table>${PAYEES.map((p) => `<tr><td class="mono">${escapeHtml(p.id)}</td><td>${escapeHtml(p.name)}</td><td class="muted">${p.category}</td></tr>`).join('')}</table></div>
<div class="card"><h2>Latest decisions</h2><table>${decisions || '<tr><td class="muted">none yet</td></tr>'}</table>${clock.offset ? `<p class="notice">Bank clock moved forward by ${clock.offset} s</p>` : ''}</div></div>`,
    });
  }

  // ---- Reservations whose outcome is unknown (shared ledgers only) ----
  let lastUnresolved = '';
  async function sweep(): Promise<void> {
    if (!stores.reservations) return;
    const swept = await stores.reservations.sweep();
    const unresolved = await stores.reservations.unresolved();
    const fingerprint = unresolved.map((r) => r.id).join(',');
    if (swept > 0 || fingerprint !== lastUnresolved) {
      lastUnresolved = fingerprint;
      events.append('reservations', { swept, unresolved: unresolved.map(reservationView) });
    }
  }
  let sweeping = false;
  const sweepTimer = setInterval(() => {
    if (sweeping) return;
    sweeping = true;
    sweep()
      .catch((e) => console.error('[bank] ledger sweep failed:', (e as Error).message))
      .finally(() => (sweeping = false));
  }, (opts.sweepSeconds ?? 10) * 1000);
  sweepTimer.unref();

  // Play money for a public sandbox that many people use between nightly restarts.
  const refillTimer = opts.refillSeconds
    ? setInterval(() => {
        for (const acct of accounts.values()) {
          const opening = OPENING_BALANCES[acct.person.id] ?? 100000;
          if (acct.balance >= opening / 2) continue;
          acct.balance = opening;
          acct.paid.clear();
          events.append('account_refilled', { person: `${acct.person.given_name} ${acct.person.family_name}`, balance_after: opening });
        }
      }, opts.refillSeconds * 1000)
    : undefined;
  refillTimer?.unref();

  router.get('/api/reservations', async (_req, res) => {
    const unresolved = stores.reservations ? await stores.reservations.unresolved() : [];
    sendJson(res, 200, { stores: stores.kind, sweeps: Boolean(stores.reservations), unresolved: unresolved.map(reservationView) });
  });
  router.post('/admin/reservations/sweep', async (req, res) => {
    checkAdmin(req, opts.adminToken);
    await sweep();
    sendJson(res, 200, { ok: true });
  });
  router.post('/admin/reservations/:id/reconcile', async (req, res) => {
    checkAdmin(req, opts.adminToken);
    if (!stores.reservations) throw new HttpError(409, 'the in-memory ledger has no reconciliation');
    const body = await readFields(req);
    if (body.outcome !== 'executed' && body.outcome !== 'not_executed') throw new HttpError(400, 'outcome must be executed or not_executed');
    const state = await stores.reservations.reconcile(req.params.id, body.outcome);
    events.append('reservation_reconciled', { reservation: req.params.id, outcome: body.outcome, state });
    await sweep();
    sendJson(res, 200, { state });
  });
  router.post('/admin/fail-next-transfer', (req, res) => {
    checkAdmin(req, opts.adminToken);
    failNextTransfer = true;
    events.append('note', { text: 'The next transfer will time out after the money left (unknown outcome)' });
    sendJson(res, 200, { armed: true });
  });

  const running = await listen(router, opts.host, opts.port);
  return {
    ...running,
    events,
    audiences,
    clock,
    sweep,
    close: async () => {
      clearInterval(sweepTimer);
      if (refillTimer) clearInterval(refillTimer);
      await running.close();
    },
  };
}

function reservationView(r: ReservationInfo) {
  return { id: r.id, state: r.state, amount: { value: r.amount, currency: r.currency }, created_at: r.createdAt.toISOString(), expires_at: r.expiresAt.toISOString(), mandate_keys: r.keys.length };
}

function fromBase64urlJson(s: string): unknown {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new Error('not base64url');
  return JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
}
