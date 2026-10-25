/**
 * End-to-end: boots the five services on free ports on 127.0.0.1 and runs every scripted scenario over
 * HTTP, then the LLM agent loop with a scripted stand-in for the model, then a few attacks on the
 * sandbox's own HTTP surface. No external network access.
 */
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import type Anthropic from '@anthropic-ai/sdk';
import { generateKeyPair, SignJWT } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestCertificateAuthority } from 'plenipo/testing';
import { SandboxAgentClient } from '../src/agent/client.js';
import { runLlmAgent, type CreateMessage } from '../src/agent/llm.js';
import { mappedStatusFetcher } from '../src/fetcher.js';
import { startSandbox, type Sandbox } from '../src/sandbox.js';
import { formatResult, runScenario, SCENARIOS, type ScenarioEnv } from '../src/scenarios.js';

let sb: Sandbox;
let env: ScenarioEnv;

beforeAll(async () => {
  sb = await startSandbox({ ports: { dashboard: 0, pid: 0, wallet: 0, platform: 0, bank: 0 }, statusCacheSeconds: 1 });
  env = {
    client: new SandboxAgentClient({ platform: sb.urls.platform, wallet: sb.urls.wallet, bank: sb.urls.bank, dashboard: sb.urls.dashboard }),
    bankHost: sb.identities.bankHost,
    audiences: sb.bank.audiences,
    urls: sb.urls,
    statusCacheSeconds: sb.statusCacheSeconds,
  };
});

afterAll(async () => {
  await env?.client.close();
  await sb?.close();
});

describe('scripted scenarios', () => {
  for (const s of SCENARIOS) {
    it(s.title, async () => {
      const r = await runScenario(s, env);
      if (!r.pass) console.log(formatResult(r, false));
      expect(r.pass).toBe(true);
    });
  }
});

describe('dashboard', () => {
  it('has merged the events of every service', async () => {
    await new Promise((r) => setTimeout(r, 900));
    const events = (await (await fetch(`${sb.urls.dashboard}/api/events`)).json()) as Array<{ source: string; type: string; decision?: string }>;
    const sources = new Set(events.map((e) => e.source));
    for (const s of ['pid', 'wallet', 'platform', 'bank', 'agent']) expect(sources).toContain(s);
    expect(events.some((e) => e.type === 'decision' && e.decision === 'ALLOW')).toBe(true);
    expect(events.some((e) => e.type === 'decision' && e.decision === 'DENY')).toBe(true);
    const page = await (await fetch(sb.urls.dashboard)).text();
    expect(page).toContain('Plenipo Sandbox');
    expect(page).not.toMatch(/<script[^>]+src=|<link[^>]+href="http/);
  });
});

/** A stand-in for the Messages API that plays a fixed conversation, to test the loop offline. */
function scriptedModel(turns: Array<Anthropic.ContentBlock[]>): { create: CreateMessage; seen: Anthropic.MessageCreateParamsNonStreaming[] } {
  const seen: Anthropic.MessageCreateParamsNonStreaming[] = [];
  let i = 0;
  return {
    seen,
    create: async (params) => {
      seen.push(structuredClone(params));
      const content = turns[i++] ?? [{ type: 'text', text: 'done', citations: null }];
      return {
        id: `msg_${i}`,
        type: 'message',
        role: 'assistant',
        model: params.model,
        content,
        stop_reason: content.some((b) => b.type === 'tool_use') ? 'tool_use' : 'end_turn',
        stop_sequence: null,
        usage: { input_tokens: 1, output_tokens: 1 },
      } as unknown as Anthropic.Message;
    },
  };
}
const toolUse = (id: string, name: string, input: Record<string, unknown>) => ({ type: 'tool_use', id, name, input }) as unknown as Anthropic.ContentBlock;
const text = (t: string) => ({ type: 'text', text: t, citations: null }) as unknown as Anthropic.ContentBlock;

describe('LLM agent loop', () => {
  it('turns tool_use blocks into signed MCP calls and returns the bank answers, DENY included', async () => {
    const mandateId = await env.client.obtainMandate({ agentName: 'Claude bill assistant', person: 'luca', preset: 'utilities' });
    const model = scriptedModel([
      [text('Let me look at the payees.'), toolUse('t1', 'list_payees', { category: 'utilities', extra: 'ignored by the server' })],
      [toolUse('t2', 'transfer', { payee: 'lumen-energia.example', amount_cents: 6210, reference: 'Lumen 2026-09' }), toolUse('t3', 'transfer', { payee: 'rotaia.example', amount_cents: 3000, reference: 'not allowed' })],
      [text('Paid Lumen; the train ticket was refused by the bank.')],
    ]);
    const r = await runLlmAgent({ client: env.client, mandateId, task: 'Pay my bills', model: 'test-model', createMessage: model.create });
    expect(r.calls.map((c) => `${c.tool}:${c.outcome.decision}${c.outcome.code ? ':' + c.outcome.code : ''}`)).toEqual([
      'list_payees:ALLOW',
      'transfer:ALLOW',
      'transfer:DENY:COUNTERPARTY_NOT_PERMITTED',
    ]);
    expect(r.finalText).toContain('Paid Lumen');
    // The model saw the tools with their schemas, the mandate in the system prompt, and the DENY as an error result.
    expect(model.seen[0].tools?.map((t) => (t as Anthropic.Tool).name).sort()).toEqual(['block_card', 'get_balance', 'list_payees', 'transfer']);
    expect(String(model.seen[0].system)).toContain('Luca Bianchi');
    const lastUser = model.seen[2].messages.at(-1)!;
    const results = lastUser.content as Anthropic.ToolResultBlockParam[];
    expect(results[1].is_error).toBe(true);
    expect(String(results[1].content)).toContain('COUNTERPARTY_NOT_PERMITTED');
  });
});

describe('the sandbox surface', () => {
  it('the bank denies an MCP call without authorization and a REST call without headers', async () => {
    const tools = await env.client.listTools();
    expect(tools.length).toBe(4);
    const res = await fetch(`${sb.urls.bank}/psd2/v1/accounts/balance`);
    expect(res.status).toBe(401);
    const mcp = await fetch(`${sb.urls.bank}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_balance', arguments: {} } }),
    });
    const body = await mcp.text();
    expect(body).toContain('DENY MALFORMED');
  });

  it('the wallet refuses a request object signed under an untrusted CA', async () => {
    const rogueCa = await createTestCertificateAuthority('Rogue CA');
    const leaf = await rogueCa.issueLeaf(sb.identities.platformOrigin);
    const host = new URL(sb.identities.platformOrigin).hostname;
    const jwt = await new SignJWT({ client_id: `x509_san_dns:${host}`, response_type: 'vp_token', response_mode: 'direct_post', response_uri: 'http://127.0.0.1:9/x', transaction_data: [] })
      .setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: leaf.x5c })
      .sign(leaf.privateKey);
    const server = createServer((_req, res) => res.end(jwt));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    try {
      const res = await fetch(`${sb.urls.wallet}/api/requests`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_id: `x509_san_dns:${host}`, request_uri: `http://127.0.0.1:${port}/r` }),
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toMatch(/not trusted/);
    } finally {
      server.close();
    }
  });

  it('the wallet refuses an unsigned request object', async () => {
    const { privateKey } = await generateKeyPair('ES256');
    const jwt = await new SignJWT({ client_id: 'x509_san_dns:platform.sandbox.plenipo.test' }).setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt' }).sign(privateKey);
    const server = createServer((_req, res) => res.end(jwt));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    try {
      const res = await fetch(`${sb.urls.wallet}/api/requests`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_id: 'x509_san_dns:platform.sandbox.plenipo.test', request_uri: `http://127.0.0.1:${port}/r` }),
      });
      expect(res.status).toBe(400);
    } finally {
      server.close();
    }
  });

  // Plays the wallet by hand, so the same response can be posted twice.
  async function handRespond(agentName: string) {
    const req = await env.client.requestMandate({ agentName, preset: 'utilities' });
    const jwt = await (await fetch(req.request_uri)).text();
    const { createTestWallet } = await import('plenipo/testing');
    const w = await createTestWallet();
    const pidRes = await fetch(`${sb.urls.pid}/issue`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ person_id: 'eve', holder_jwk: w.holderJwk, claims: { given_name: 'Eve', family_name: 'Test', birthdate: '1990-01-01' } }),
    });
    w.storePid(((await pidRes.json()) as { pid: string }).pid);
    const body = await w.respond(jwt);
    const post = () =>
      fetch(req.request_uri.replace('/request/', '/response/'), {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(body as Record<string, string>).toString(),
      });
    return { req, post };
  }

  it('the platform does not accept the same wallet response twice, and keeps the approval', async () => {
    const { req, post } = await handRespond('Replay target');
    expect((await post()).status).toBe(200);
    expect((await post()).status).toBe(409);
    expect(await env.client.requestState(req.request_id)).toMatchObject({ state: 'active' });
    expect((await fetch(req.request_uri)).status).toBe(410);
  });

  it('two responses racing: one approves, the other is refused without undoing it', async () => {
    const { req, post } = await handRespond('Race target');
    const statuses = (await Promise.all([post(), post()])).map((r) => r.status).sort();
    expect(statuses).toEqual([200, 409]);
    const s = await env.client.requestState(req.request_id);
    expect(s).toMatchObject({ state: 'active' });
    expect(s.error).toBeUndefined();
  });

  it('bodies above the limit are refused', async () => {
    const res = await fetch(`${sb.urls.platform}/api/requests`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(300 * 1024) });
    expect(res.status).toBe(413);
  });

  it('the status fetcher only reaches mapped https origins', async () => {
    const f = mappedStatusFetcher({ 'https://pid.sandbox.plenipo.test': sb.urls.pid });
    await expect(f('http://pid.sandbox.plenipo.test/status/1')).rejects.toThrow(/https only/);
    await expect(f('https://169.254.169.254/latest')).rejects.toThrow(/no route/);
    expect(await f('https://pid.sandbox.plenipo.test/status/1')).toMatch(/^ey/);
  });
});
