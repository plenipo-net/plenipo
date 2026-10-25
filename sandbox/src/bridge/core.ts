/**
 * The Plenipo agent bridge, without any transport: what an MCP client such as Claude Desktop needs to act
 * at the bank under a mandate.
 *
 * - The agent key is generated here and never leaves: the platform only receives its public key ("bring
 *   your own key") and the bridge signs every invocation itself.
 * - A mandate is requested from the agent platform; the person approves it in their wallet; the bridge
 *   then keeps the approved chain.
 * - The bank's MCP tools are mirrored: each call is signed for exactly its arguments and the chain, sent
 *   with the Plenipo `_meta`, and the bank's answer (or DENY) is returned verbatim.
 *
 * State goes through a `BridgeStateStore`: a file for the stdio bridge, a per-session store for a hosted
 * variant. Nothing here writes anywhere else.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { chainHash, createInvocation, peekInvocation, type Mandate, type MandateChain } from 'plenipo';
import { META_KEY } from 'plenipo/mcp';
import { BINDING_META_KEY, bindCall, invocationFields, isToolBinding, type ToolBinding } from '../binding.js';

export interface BridgeState {
  agent?: { privateJwk: JWK; publicJwk: JWK };
  /** The request waiting for the person's approval. */
  pending?: { requestId: string; mandateId: string; walletUrl?: string; authorizationUrl: string; createdAt: string };
  /** The approved mandate and its chain. */
  mandate?: { id: string; chain: MandateChain; mandate: Mandate; approvedAt: string };
  last?: LastDecision;
}

export interface LastDecision {
  at: string;
  tool: string;
  args: Record<string, unknown>;
  invocation?: { action: string; counterparty?: string; amount?: { value: number; currency: string }; aud: string; nonce: string; chain_hash?: string };
  decision: 'ALLOW' | 'DENY' | 'ERROR' | 'NOT_SENT';
  code?: string;
  text: string;
}

/** Where the bridge keeps its state; one per user session. */
export interface BridgeStateStore {
  load(): Promise<BridgeState>;
  save(state: BridgeState): Promise<void>;
}

export class MemoryStateStore implements BridgeStateStore {
  private state: BridgeState = {};
  async load() {
    return structuredClone(this.state);
  }
  async save(s: BridgeState) {
    this.state = structuredClone(s);
  }
}

export interface BridgeConfig {
  platformUrl: string;
  /** The platform as a person's browser or phone reaches it, when it differs from platformUrl. */
  publicPlatformUrl?: string;
  bankUrl: string;
  /** Optional: narrative events for the sandbox dashboard. */
  dashboardUrl?: string;
  /** Bearer token for posting to the dashboard, when it requires one. */
  dashboardToken?: string;
  store: BridgeStateStore;
  /** Where to log; must not be stdout for the stdio bridge. */
  log?: (line: string) => void;
  /** Fields added to every dashboard event, e.g. the demo code of a hosted session. */
  noteFields?: Record<string, unknown>;
  /** A line appended to the request_mandate answer, e.g. where to watch the session live. */
  demoHint?: string;
}

export interface ToolText {
  text: string;
  isError?: boolean;
  data?: Record<string, unknown>;
}

export interface MirroredTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  binding: ToolBinding;
}

export interface MandateRequestInput {
  payees: string[];
  per_payment_eur: number;
  total_eur: number;
  days: number;
  purpose: string;
  actions?: string[];
  emandate?: boolean;
}

const HOST_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;
const ACTION_RE = /^[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?$/;

/** Plain-language reading of the deny codes the bank returns. */
export const DENY_EXPLANATIONS: Record<string, string> = {
  LIMIT_PER_OPERATION: 'the amount is above the per-payment limit the person approved',
  LIMIT_TOTAL: 'this payment would take the spending under the mandate above its approved total',
  COUNTERPARTY_NOT_PERMITTED: 'the payee is not one of the payees the person approved',
  ACTION_NOT_PERMITTED: 'the mandate does not allow this kind of operation',
  REVOKED: 'the person (or the platform) revoked or suspended the mandate',
  EXPIRED: 'the mandate has expired',
  NOT_YET_VALID: 'the mandate is not valid yet',
  REPLAY: 'this exact signed call was already used once',
  PID_REVOKED: "the person's identity credential (PID) was revoked by its issuer",
  TX_DATA_MISMATCH: 'the mandate presented is not the one the person approved in the wallet',
  INVOCATION_MISMATCH: 'what was signed does not match the call the bank received',
  INVOCATION_STALE: 'the signed call is too old or from the future (clock problem)',
  STATUS_UNAVAILABLE: 'the bank could not check whether the mandate is still valid; trying again later may work',
  MALFORMED: 'the call or its authorization could not be read',
};

const euroToCents = (v: number) => Math.round(v * 100);

export class BridgeCore {
  private bank?: Client;
  private tools?: MirroredTool[];
  private readonly log: (line: string) => void;

  constructor(readonly config: BridgeConfig) {
    this.log = config.log ?? (() => {});
  }

  private async http<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.config.platformUrl}${path}`, {
      method,
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    const text = await res.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      json = { error: text.slice(0, 200) };
    }
    if (!res.ok) throw new Error(`the agent platform answered HTTP ${res.status}: ${(json as { error?: string }).error ?? ''}`);
    return json as T;
  }

  /** Posts a narrative event to the dashboard, if one is configured. Never throws. */
  async note(type: string, data: Record<string, unknown>): Promise<void> {
    if (!this.config.dashboardUrl) return;
    try {
      await fetch(`${this.config.dashboardUrl}/api/agent-events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(this.config.dashboardToken ? { authorization: `Bearer ${this.config.dashboardToken}` } : {}) },
        body: JSON.stringify({ type, ...data, ...this.config.noteFields }),
        signal: AbortSignal.timeout(2000),
      });
    } catch {
      /* the dashboard is optional */
    }
  }

  /** The agent key, created on first use. The private key stays in the state store. */
  private async agent(state: BridgeState): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
    if (state.agent) return state.agent;
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const privateJwk = await exportJWK(privateKey);
    state.agent = { privateJwk, publicJwk: { kty: 'EC', crv: 'P-256', x: privateJwk.x, y: privateJwk.y } };
    await this.config.store.save(state);
    this.log('generated a new agent key');
    return state.agent;
  }

  async requestMandate(input: MandateRequestInput): Promise<ToolText> {
    const payees = input.payees ?? [];
    if (!Array.isArray(payees) || payees.length === 0 || payees.length > 20 || !payees.every((p) => typeof p === 'string' && HOST_RE.test(p))) {
      return { isError: true, text: 'payees must be 1 to 20 payee ids (their domain names, e.g. acquaviva.example); call list_payees after approval to see the register' };
    }
    const actions = input.actions ?? ['payments.transfer', 'account.read'];
    if (!Array.isArray(actions) || actions.length === 0 || !actions.every((a) => typeof a === 'string' && ACTION_RE.test(a))) {
      return { isError: true, text: 'actions must be dotted names such as payments.transfer or account.read' };
    }
    for (const [k, v, max] of [
      ['per_payment_eur', input.per_payment_eur, 100_000],
      ['total_eur', input.total_eur, 1_000_000],
      ['days', input.days, 90],
    ] as const) {
      if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0 || v > max) return { isError: true, text: `${k} must be a positive number up to ${max}` };
    }
    if (input.per_payment_eur > input.total_eur) return { isError: true, text: 'per_payment_eur cannot exceed total_eur' };
    if (typeof input.purpose !== 'string' || input.purpose.trim().length < 5) return { isError: true, text: 'purpose must say, in words the person will read, what the mandate is for' };

    const state = await this.config.store.load();
    const agent = await this.agent(state);
    const req = await this.http<{ request_id: string; mandate_id: string; request_uri: string; authorization_url: string; wallet_url?: string }>('POST', '/api/requests', {
      agent_name: 'Claude (MCP bridge)',
      agent_jwk: agent.publicJwk,
      actions,
      counterparties: payees,
      limits: { currency: 'EUR', per_operation: euroToCents(input.per_payment_eur), total: euroToCents(input.total_eur) },
      ttl_seconds: Math.round(input.days * 24 * 3600),
      purpose: input.purpose.trim().slice(0, 300),
      ...(input.emandate ? { transaction_data_type: 'emandate' } : {}),
    });
    state.pending = { requestId: req.request_id, mandateId: req.mandate_id, walletUrl: req.wallet_url, authorizationUrl: req.authorization_url, createdAt: new Date().toISOString() };
    await this.config.store.save(state);
    await this.note('note', { text: `Claude asked for a mandate: ${input.purpose}`, request_id: req.request_id, mandate_id: req.mandate_id });
    const link = req.wallet_url ?? req.authorization_url;
    return {
      text:
        `Mandate requested. The person must now approve it in their wallet. Ask them to open this link (it shows exactly what you will be allowed to do) and approve:\n\n${link}\n\n` +
        `A phone wallet can scan the QR code at ${this.config.publicPlatformUrl ?? this.config.platformUrl}/requests/${req.request_id}. ` +
        'After they approve, call mandate_status. Do not try to pay before the mandate is active.' +
        (this.config.demoHint ? `\n\n${this.config.demoHint}` : ''),
      data: {
        request_id: req.request_id,
        mandate_id: req.mandate_id,
        wallet_url: req.wallet_url,
        authorization_url: req.authorization_url,
        request_uri: req.request_uri,
        client_id: new URL(req.authorization_url).searchParams.get('client_id'),
      },
    };
  }

  async mandateStatus(): Promise<ToolText> {
    const state = await this.config.store.load();
    if (state.pending) {
      const r = await this.http<{ state: string; mandate_id: string; error?: string }>('GET', `/api/requests/${encodeURIComponent(state.pending.requestId)}`);
      if (r.state === 'pending') {
        return { text: `Still waiting for the person to approve in the wallet: ${state.pending.walletUrl ?? state.pending.authorizationUrl}`, data: { state: 'pending' } };
      }
      // A platform that recorded the approval keeps the mandate even if a later response to the same
      // request was rejected: look for it before giving up, so a second answer never loses a valid approval.
      type MandateView = { id: string; state?: string; mandate: Mandate; chain: MandateChain };
      const m =
        r.state === 'active'
          ? await this.http<MandateView>('GET', `/api/mandates/${encodeURIComponent(r.mandate_id)}`)
          : await this.http<MandateView>('GET', `/api/mandates/${encodeURIComponent(state.pending.mandateId)}`).catch(() => undefined);
      if (!m || (r.state !== 'active' && m.state !== 'active')) {
        delete state.pending;
        await this.config.store.save(state);
        return { isError: true, text: `The mandate request ended as ${r.state}${r.error ? ` (${r.error})` : ''}. No mandate: you cannot act at the bank.`, data: { state: r.state } };
      }
      // The bridge signs under this mandate only if it names the bridge's own key.
      if (m.mandate.agent.jwk.x !== state.agent?.publicJwk.x || m.mandate.agent.jwk.y !== state.agent?.publicJwk.y) {
        return { isError: true, text: 'The approved mandate names another agent key than this bridge holds: refusing to use it.' };
      }
      state.mandate = { id: m.id, chain: m.chain, mandate: m.mandate, approvedAt: new Date().toISOString() };
      delete state.pending;
      await this.config.store.save(state);
      await this.note('note', { text: 'The person approved the mandate; Claude can act at the bank', mandate_id: m.id });
    }
    if (!state.mandate) return { isError: true, text: 'No mandate yet. Call request_mandate first.', data: { state: 'none' } };
    const info = await this.http<{ state: string; principal: Record<string, unknown> }>('GET', `/api/mandates/${encodeURIComponent(state.mandate.id)}`).catch(() => undefined);
    const m = state.mandate.mandate;
    const lim = m.limits;
    const who = info ? `${info.principal.given_name ?? ''} ${info.principal.family_name ?? ''}`.trim() : 'the person';
    return {
      text:
        `Mandate ${info?.state ?? 'state unknown'}, granted by ${who}.\n` +
        `Purpose: ${m.purpose ?? '-'}\nActions: ${m.actions.join(', ')}\nPayees: ${(m.counterparties ?? ['any']).join(', ')}\n` +
        (lim ? `Limits: ${lim.per_operation !== undefined ? `${(lim.per_operation / 100).toFixed(2)} ${lim.currency} per payment` : 'no per-payment limit'}, ${lim.total !== undefined ? `${(lim.total / 100).toFixed(2)} ${lim.currency} in total` : 'no total'}\n` : '') +
        `Valid until ${new Date(m.exp * 1000).toISOString()}. Amounts in the bank tools are in euro cents.`,
      data: { state: info?.state, mandate_id: m.id, principal: who, mandate: m },
    };
  }

  async revokeMandate(): Promise<ToolText> {
    const state = await this.config.store.load();
    const id = state.mandate?.id ?? state.pending?.mandateId;
    if (!state.mandate) return { isError: true, text: 'There is no approved mandate to revoke.' };
    await this.http('POST', `/api/mandates/${encodeURIComponent(id!)}/revoke`, {});
    await this.note('note', { text: 'Claude revoked its own mandate', mandate_id: id });
    return { text: `Mandate ${id} revoked at the platform. The bank will refuse further calls under it as soon as its status cache refreshes (a few seconds).` };
  }

  async explainLastDecision(): Promise<ToolText> {
    const { last } = await this.config.store.load();
    if (!last) return { text: 'No bank call has been made through this bridge yet.' };
    const inv = last.invocation;
    const lines = [
      `${last.decision}${last.code ? ` ${last.code}` : ''} for ${last.tool} at ${last.at}.`,
      last.code && DENY_EXPLANATIONS[last.code] ? `Why: ${DENY_EXPLANATIONS[last.code]}.` : '',
      inv
        ? `Signed invocation: action ${inv.action}${inv.counterparty ? `, payee ${inv.counterparty}` : ', no payee'}${inv.amount ? `, amount ${(inv.amount.value / 100).toFixed(2)} ${inv.amount.currency}` : ', no amount'}, audience ${inv.aud}, nonce ${inv.nonce}, chain hash ${inv.chain_hash ?? '-'}.`
        : 'Nothing was signed.',
      `Arguments: ${JSON.stringify(last.args)}`,
      `Bank answer: ${last.text}`,
    ];
    return { text: lines.filter(Boolean).join('\n'), data: last as unknown as Record<string, unknown> };
  }

  // ---- The bank's tools ----

  private async bankClient(): Promise<Client> {
    if (this.bank) return this.bank;
    const client = new Client({ name: 'plenipo-bridge', version: '0.1.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${this.config.bankUrl}/mcp`)));
    this.bank = client;
    return client;
  }

  /** The bank's tools with their Plenipo binding. Cached once listed; an unreachable bank gives none. */
  async bankTools(): Promise<MirroredTool[]> {
    if (this.tools) return this.tools;
    try {
      const { tools } = await (await this.bankClient()).listTools();
      this.tools = tools.flatMap((t) => {
        const binding = t._meta?.[BINDING_META_KEY];
        return isToolBinding(binding) ? [{ name: t.name, description: t.description, inputSchema: t.inputSchema as Record<string, unknown>, binding }] : [];
      });
      return this.tools;
    } catch (e) {
      this.log(`the bank at ${this.config.bankUrl} is not reachable: ${(e as Error).message}`);
      this.bank = undefined;
      return [];
    }
  }

  /** Signs the call under the mandate, for exactly these arguments and the chain, and forwards it to the bank. */
  async callBankTool(name: string, rawArgs: Record<string, unknown>): Promise<ToolText> {
    const tool = (await this.bankTools()).find((t) => t.name === name);
    if (!tool) return { isError: true, text: `The bank has no tool ${name}, or the bank is not reachable.` };
    const state = await this.config.store.load();
    const record = async (last: Omit<LastDecision, 'at' | 'tool'>) => {
      const s = await this.config.store.load();
      s.last = { at: new Date().toISOString(), tool: name, ...last };
      await this.config.store.save(s);
    };
    if (!state.mandate || !state.agent) {
      const text = state.pending
        ? 'The mandate is not approved yet. Ask the person to approve it in the wallet, then call mandate_status.'
        : 'No mandate yet. Call request_mandate, have the person approve it, then call mandate_status.';
      await record({ args: rawArgs ?? {}, decision: 'NOT_SENT', text });
      return { isError: true, text };
    }
    // The bank validates and strips arguments it does not declare; the signature covers exactly what it sees.
    const props = Object.keys((tool.inputSchema.properties as Record<string, unknown>) ?? {});
    const args = Object.fromEntries(Object.entries(rawArgs ?? {}).filter(([k, v]) => props.includes(k) && v !== undefined));
    const chain = state.mandate.chain;
    const key = await importJWK(state.agent.privateJwk, 'ES256');
    const invocation = await createInvocation(key as CryptoKey, {
      mandateId: state.mandate.id,
      ...invocationFields(bindCall(tool.binding, args)),
      aud: tool.binding.audience,
      args,
      chain,
    });
    const inv = peekInvocation(invocation);
    const summary = { action: inv.action, counterparty: inv.counterparty, amount: inv.amount, aud: inv.aud, nonce: inv.nonce, chain_hash: inv.chain_hash ?? chainHash(chain) };
    await this.note('tool_call', { tool: name, args, mandate_id: state.mandate.id });
    let text: string;
    let isError: boolean;
    let data: Record<string, unknown> | undefined;
    try {
      const res = await (await this.bankClient()).callTool({ name, arguments: args, _meta: { [META_KEY]: { chain, invocation } } });
      text = ((res.content as Array<{ type: string; text?: string }>) ?? []).map((c) => c.text ?? '').join('\n');
      isError = Boolean(res.isError);
      data = res.structuredContent as Record<string, unknown> | undefined;
    } catch (e) {
      this.bank = undefined;
      text = `The bank could not be reached: ${(e as Error).message}. The outcome is unknown; check the balance before retrying.`;
      await record({ args, invocation: summary, decision: 'ERROR', text });
      return { isError: true, text };
    }
    const deny = (data?.plenipo as { decision?: string; code?: string } | undefined)?.decision === 'DENY' ? (data!.plenipo as { code: string }).code : undefined;
    await record({ args, invocation: summary, decision: deny ? 'DENY' : isError ? 'ERROR' : 'ALLOW', code: deny ?? (isError ? String(data?.error ?? '') || undefined : undefined), text });
    this.log(`${name}: ${deny ? `DENY ${deny}` : isError ? 'error' : 'ALLOW'}`);
    await this.note('tool_result', {
      tool: name,
      mandate_id: state.mandate.id,
      decision: deny ? 'DENY' : isError ? 'ERROR' : 'ALLOW',
      ...(deny ? { code: deny, why: DENY_EXPLANATIONS[deny] } : {}),
      text: text.slice(0, 300),
    });
    return { text, isError, data };
  }

  async close(): Promise<void> {
    await this.bank?.close().catch(() => {});
    this.bank = undefined;
  }
}
