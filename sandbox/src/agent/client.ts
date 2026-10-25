/**
 * What an agent runtime needs to work in the sandbox: ask the platform for a mandate, have the person
 * approve it, and call the bank's MCP tools (or REST API) with a signed invocation attached.
 * Used by the scripted scenarios and by the LLM agent.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Amount, Mandate, MandateChain } from 'plenipo';
import { META_KEY } from 'plenipo/mcp';
import { BINDING_META_KEY, bindCall, invocationFields, isToolBinding, type ToolBinding } from '../binding.js';
import type { MandateSpec } from '../catalog.js';

export interface SandboxEndpoints {
  platform: string;
  wallet: string;
  bank: string;
  dashboard?: string;
}

export interface CallOutcome {
  decision: 'ALLOW' | 'DENY';
  /** Deny code, or the bank's error code when the call was allowed but the operation failed. */
  code?: string;
  text: string;
  isError: boolean;
  data?: Record<string, unknown>;
}

export interface SignedCall {
  name: string;
  args: Record<string, unknown>;
  meta: { chain: MandateChain; invocation: string };
}

export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  binding: ToolBinding;
}

async function json<T>(res: Response): Promise<T> {
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${(body as { error?: string }).error ?? text.slice(0, 200)}`);
  return body as T;
}

export class SandboxAgentClient {
  private mcp?: Client;
  private tools?: ToolInfo[];

  constructor(readonly endpoints: SandboxEndpoints) {}

  private async post<T>(url: string, body: unknown): Promise<T> {
    return json<T>(await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15_000) }));
  }
  private async get<T>(url: string): Promise<T> {
    return json<T>(await fetch(url, { signal: AbortSignal.timeout(15_000) }));
  }

  /** Posts a narrative event to the dashboard; never fails the caller. */
  async note(type: string, data: Record<string, unknown>): Promise<void> {
    if (!this.endpoints.dashboard) return;
    try {
      await fetch(`${this.endpoints.dashboard}/api/agent-events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type, ...data }),
        signal: AbortSignal.timeout(3000),
      });
    } catch {
      /* the dashboard is optional */
    }
  }

  /** Creates a mandate request at the platform. */
  async requestMandate(input: { agentName: string; preset?: string; spec?: MandateSpec; ttlSeconds?: number; emandate?: boolean; agentJwk?: unknown }) {
    const extra = {
      ...(input.emandate ? { transaction_data_type: 'emandate' } : {}),
      ...(input.agentJwk ? { agent_jwk: input.agentJwk } : {}),
    };
    const body = input.preset
      ? { agent_name: input.agentName, preset: input.preset, ...(input.ttlSeconds ? { ttl_seconds: input.ttlSeconds } : {}), ...extra }
      : {
          agent_name: input.agentName,
          actions: input.spec!.actions,
          counterparties: input.spec!.counterparties,
          limits: input.spec!.limits,
          ttl_seconds: input.ttlSeconds ?? input.spec!.ttlSeconds,
          max_depth: input.spec!.maxDepth,
          purpose: input.spec!.purpose,
          ...extra,
        };
    return this.post<{ request_id: string; mandate_id: string; request_uri: string; authorization_url: string; wallet_url?: string; state: string }>(
      `${this.endpoints.platform}/api/requests`,
      body,
    );
  }

  /** Plays the person: the wallet fetches the request and the person approves or refuses it. */
  async walletDecide(requestUri: string, clientId: string, person: string, decision: 'approve' | 'refuse') {
    const r = await this.walletOpen(requestUri, clientId, person);
    return this.walletDecideById(r.id, person, decision);
  }

  /** The person opens a request link (or scans its QR code) in the wallet. */
  async walletOpen(requestUri: string, clientId: string, person: string) {
    return this.post<{ id: string; state: string }>(`${this.endpoints.wallet}/api/requests`, { client_id: clientId, request_uri: requestUri, person });
  }

  /** The person answers a request already open in the wallet. */
  async walletDecideById(id: string, person: string, decision: 'approve' | 'refuse') {
    return this.post<{ state: string; outcome: string }>(`${this.endpoints.wallet}/api/requests/${id}/decision`, { decision, person });
  }

  async requestState(requestId: string) {
    return this.get<{ state: string; mandate_id: string; error?: string }>(`${this.endpoints.platform}/api/requests/${requestId}`);
  }

  /** Waits until the person has answered in the wallet. */
  async waitForApproval(requestId: string, timeoutMs = 600_000, onTick?: () => void): Promise<{ state: string; mandate_id: string; error?: string }> {
    const until = Date.now() + timeoutMs;
    for (;;) {
      const s = await this.requestState(requestId);
      if (s.state !== 'pending') return s;
      if (Date.now() > until) throw new Error('timed out waiting for the wallet');
      onTick?.();
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  /** Requests a mandate and has the person approve it in the sandbox wallet, end to end over HTTP. */
  async obtainMandate(input: { agentName: string; person: string; preset?: string; spec?: MandateSpec; ttlSeconds?: number; emandate?: boolean }): Promise<string> {
    const req = await this.requestMandate(input);
    const clientId = new URL(req.authorization_url).searchParams.get('client_id')!;
    await this.walletDecide(req.request_uri, clientId, input.person, 'approve');
    const s = await this.waitForApproval(req.request_id, 10_000);
    if (s.state !== 'active') throw new Error(`mandate not approved: ${s.state} ${s.error ?? ''}`);
    return s.mandate_id;
  }

  async delegate(parentId: string, agentName: string, spec: MandateSpec): Promise<string> {
    const r = await this.post<{ id: string }>(`${this.endpoints.platform}/api/mandates/${parentId}/delegate`, {
      agent_name: agentName,
      actions: spec.actions,
      counterparties: spec.counterparties,
      limits: spec.limits,
      ttl_seconds: spec.ttlSeconds,
      max_depth: spec.maxDepth,
      purpose: spec.purpose,
    });
    return r.id;
  }

  async setMandateState(id: string, action: 'revoke' | 'suspend' | 'reinstate') {
    return this.post(`${this.endpoints.platform}/api/mandates/${id}/${action}`, {});
  }

  async mandate(id: string): Promise<{ mandate: Mandate; state: string; principal: Record<string, unknown> }> {
    return this.get(`${this.endpoints.platform}/api/mandates/${id}`);
  }

  /** Asks the platform, which holds the agent's key, to sign an invocation. */
  async sign(mandateId: string, call: { action: string; counterparty?: string; amount?: Amount; aud: string; args: unknown }) {
    return this.post<{ chain: MandateChain; invocation: string }>(`${this.endpoints.platform}/api/mandates/${mandateId}/invocations`, call);
  }

  // ---- MCP ----
  async connect(): Promise<void> {
    if (this.mcp) return;
    const client = new Client({ name: 'plenipo-sandbox-agent', version: '0.1.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${this.endpoints.bank}/mcp`)));
    this.mcp = client;
  }

  async listTools(): Promise<ToolInfo[]> {
    if (this.tools) return this.tools;
    await this.connect();
    const { tools } = await this.mcp!.listTools();
    this.tools = tools.flatMap((t) => {
      const binding = t._meta?.[BINDING_META_KEY];
      return isToolBinding(binding) ? [{ name: t.name, description: t.description, inputSchema: t.inputSchema as Record<string, unknown>, binding }] : [];
    });
    return this.tools;
  }

  /**
   * Keeps only the arguments the tool declares: the server validates and strips the rest, and the
   * invocation is bound to the hash of exactly the arguments the server will see.
   */
  normaliseArgs(tool: ToolInfo, args: Record<string, unknown>): Record<string, unknown> {
    const props = Object.keys((tool.inputSchema.properties as Record<string, unknown>) ?? {});
    return Object.fromEntries(Object.entries(args ?? {}).filter(([k, v]) => props.includes(k) && v !== undefined));
  }

  /** Builds a signed call without sending it, so a scenario can send it twice (replay). */
  async prepareCall(mandateId: string, name: string, rawArgs: Record<string, unknown>): Promise<SignedCall> {
    const tool = (await this.listTools()).find((t) => t.name === name);
    if (!tool) throw new Error(`the bank has no tool ${name}`);
    const args = this.normaliseArgs(tool, rawArgs);
    const signed = await this.sign(mandateId, { ...invocationFields(bindCall(tool.binding, args)), aud: tool.binding.audience, args });
    return { name, args, meta: signed };
  }

  async send(call: SignedCall): Promise<CallOutcome> {
    await this.connect();
    const res = await this.mcp!.callTool({ name: call.name, arguments: call.args, _meta: { [META_KEY]: call.meta } });
    const text = ((res.content as Array<{ type: string; text?: string }>) ?? []).map((c) => c.text ?? '').join('\n');
    const sc = (res.structuredContent ?? {}) as Record<string, unknown>;
    const plenipo = sc.plenipo as { decision: 'DENY'; code: string } | undefined;
    if (plenipo?.decision === 'DENY') return { decision: 'DENY', code: plenipo.code, text, isError: true };
    return { decision: 'ALLOW', code: res.isError ? String(sc.error ?? 'error') : undefined, text, isError: Boolean(res.isError), data: sc };
  }

  async callTool(mandateId: string, name: string, args: Record<string, unknown>): Promise<CallOutcome> {
    return this.send(await this.prepareCall(mandateId, name, args));
  }

  // ---- PSD2-like REST ----
  async restBalance(mandateId: string, aud: string) {
    const signed = await this.sign(mandateId, { action: 'account.read', aud, args: {} });
    const res = await fetch(`${this.endpoints.bank}/psd2/v1/accounts/balance`, { headers: this.restHeaders(signed) });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  }

  async restPay(mandateId: string, aud: string, body: { payee: string; amount_cents: number; reference: string }) {
    const signed = await this.sign(mandateId, { action: 'payments.transfer', counterparty: body.payee, amount: { value: body.amount_cents, currency: 'EUR' }, aud, args: body });
    const res = await fetch(`${this.endpoints.bank}/psd2/v1/payments`, {
      method: 'POST',
      headers: { ...this.restHeaders(signed), 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  }

  private restHeaders(signed: { chain: MandateChain; invocation: string }): Record<string, string> {
    return { 'plenipo-chain': Buffer.from(JSON.stringify(signed.chain)).toString('base64url'), 'plenipo-invocation': signed.invocation };
  }

  async close(): Promise<void> {
    await this.mcp?.close();
    this.mcp = undefined;
    this.tools = undefined;
  }
}
