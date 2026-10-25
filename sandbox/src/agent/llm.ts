/**
 * An LLM agent: Claude receives a task in natural language and the bank's MCP tools, and decides what to
 * call. Every tool call goes through the sandbox client, which has the platform sign a Plenipo invocation
 * for exactly that call and attaches it in the MCP request `_meta`. The model never sees a key, and
 * whatever it decides, the bank enforces the mandate.
 */
import type Anthropic from '@anthropic-ai/sdk';
import { formatEuro, scopeLine } from '../catalog.js';
import type { CallOutcome, SandboxAgentClient } from './client.js';

/** Default model; override with PLENIPO_AGENT_MODEL. */
export const DEFAULT_MODEL = 'claude-sonnet-5-5';

export type CreateMessage = (params: Anthropic.MessageCreateParamsNonStreaming) => Promise<Anthropic.Message>;

export interface LlmAgentOptions {
  client: SandboxAgentClient;
  mandateId: string;
  task: string;
  model: string;
  createMessage: CreateMessage;
  maxTurns?: number;
  log?: (line: string) => void;
}

export interface LlmAgentResult {
  finalText: string;
  calls: Array<{ tool: string; args: Record<string, unknown>; outcome: CallOutcome }>;
  turns: number;
}

function systemPrompt(principal: string, scope: string, purpose: string | undefined, exp: number, limits?: { per_operation?: number; total?: number }): string {
  return [
    `You are a payments assistant acting for ${principal}. You operate the bank account of ${principal} through the bank's tools.`,
    `${principal} gave you a mandate from their EU Digital Identity Wallet. Its purpose: "${purpose ?? 'not stated'}".`,
    `Scope: ${scope}. ${limits?.per_operation !== undefined ? `At most ${formatEuro(limits.per_operation)} per payment. ` : ''}${limits?.total !== undefined ? `At most ${formatEuro(limits.total)} in total. ` : ''}It expires at ${new Date(exp * 1000).toISOString()}.`,
    'Amounts are in euro cents in every tool. Pay only what the task asks for, using the payee ids returned by list_payees.',
    'Every call is checked by the bank against the mandate. If a tool answers "plenipo: DENY", the bank refused it: do not try to get around the refusal (no splitting payments, no other payees, no retries). Report it.',
    'When you are done, reply with a short summary for the person: what you paid, to whom, how much, and anything you could not do and why.',
  ].join('\n');
}

export async function runLlmAgent(opts: LlmAgentOptions): Promise<LlmAgentResult> {
  const log = opts.log ?? (() => {});
  const { client } = opts;
  const info = await client.mandate(opts.mandateId);
  const principal = `${info.principal.given_name ?? ''} ${info.principal.family_name ?? ''}`.trim() || 'the person';
  const tools = await client.listTools();
  const anthropicTools: Anthropic.Tool[] = tools.map((t) => {
    const { $schema: _ignored, ...schema } = t.inputSchema as Record<string, unknown>;
    return { name: t.name, description: t.description, input_schema: { ...(schema as object), type: 'object' } as Anthropic.Tool.InputSchema };
  });
  const system = systemPrompt(principal, scopeLine(info.mandate), info.mandate.purpose, info.mandate.exp, info.mandate.limits);
  const messages: Anthropic.MessageParam[] = [{ role: 'user', content: opts.task }];
  const calls: LlmAgentResult['calls'] = [];
  const maxTurns = opts.maxTurns ?? 12;
  let finalText = '';

  for (let turn = 1; turn <= maxTurns; turn++) {
    const response = await opts.createMessage({ model: opts.model, max_tokens: 4096, system, tools: anthropicTools, messages });
    // The whole assistant turn goes back into the history, including any thinking blocks.
    messages.push({ role: 'assistant', content: response.content as Anthropic.ContentBlockParam[] });
    const text = response.content
      .filter((b): b is Anthropic.TextBlock => b.type === 'text')
      .map((b) => b.text)
      .join('\n')
      .trim();
    if (text) {
      log(`assistant: ${text}`);
      await client.note('llm_text', { text: text.slice(0, 600) });
    }
    const uses = response.content.filter((b): b is Anthropic.ToolUseBlock => b.type === 'tool_use');
    if (response.stop_reason !== 'tool_use' || uses.length === 0) {
      finalText = text;
      return { finalText, calls, turns: turn };
    }
    const results: Anthropic.ToolResultBlockParam[] = [];
    for (const use of uses) {
      const args = (use.input ?? {}) as Record<string, unknown>;
      log(`tool call: ${use.name} ${JSON.stringify(args)}`);
      await client.note('tool_call', { tool: use.name, args });
      let outcome: CallOutcome;
      try {
        outcome = await client.callTool(opts.mandateId, use.name, args);
      } catch (e) {
        outcome = { decision: 'DENY', code: 'CLIENT_ERROR', text: `The call could not be made: ${(e as Error).message}`, isError: true };
      }
      calls.push({ tool: use.name, args, outcome });
      log(`  -> ${outcome.decision}${outcome.code ? ' ' + outcome.code : ''}: ${outcome.text.split('\n')[0]}`);
      results.push({ type: 'tool_result', tool_use_id: use.id, content: outcome.text || outcome.decision, is_error: outcome.isError });
    }
    messages.push({ role: 'user', content: results });
  }
  return { finalText: finalText || `Stopped after ${maxTurns} turns.`, calls, turns: maxTurns };
}
