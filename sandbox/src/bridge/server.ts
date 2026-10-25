/**
 * The bridge as an MCP server: its own tools (request_mandate, mandate_status, revoke_mandate,
 * explain_last_decision) plus a mirror of the bank's tools, served by the low-level SDK server so the
 * bank's JSON schemas pass through unchanged. Transport-agnostic: connect it to stdio, or later to a
 * Streamable HTTP transport with one BridgeCore per session.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { BridgeCore, ToolText } from './core.js';

const OWN_TOOLS = [
  {
    name: 'request_mandate',
    description:
      'Ask the person for a mandate to act at their bank. Returns a link the person must open to approve it in their EU Digital Identity Wallet; ' +
      'then call mandate_status. Payees are domain names from the bank payee register (e.g. lumen-energia.example, acquaviva.example, telenord.example). ' +
      'Ask only for what the task needs: the bank enforces exactly these limits.',
    inputSchema: {
      type: 'object',
      properties: {
        payees: { type: 'array', items: { type: 'string' }, description: 'Payee ids (domains) the agent may pay' },
        per_payment_eur: { type: 'number', description: 'Maximum amount of one payment, in euro' },
        total_eur: { type: 'number', description: 'Maximum total of all payments, in euro' },
        days: { type: 'number', description: 'How long the mandate lasts, in days (at most 90)' },
        purpose: {
          type: 'string',
          description: 'What the mandate is for, in words the person will read in the wallet: write it in the language you are using with the person',
        },
        actions: {
          type: 'array',
          items: { type: 'string' },
          description: 'Default ["payments.transfer", "account.read"]. Add "card.block" only if the task needs it.',
        },
        emandate: { type: 'boolean', description: 'Ask for it as an EUDI TS12 e-mandate (urn:eudi:sca:emandate:1). Default false.' },
      },
      required: ['payees', 'per_payment_eur', 'total_eur', 'days', 'purpose'],
    },
  },
  {
    name: 'mandate_status',
    description:
      'Whether the person approved the mandate, and what it allows (payees, limits, expiry). Call it after request_mandate. ' +
      'On the public sandbox, a new connection can continue an earlier journey by passing its demo_code.',
    inputSchema: {
      type: 'object',
      properties: { demo_code: { type: 'string', description: 'Optional: the six-character demo code of a journey started in an earlier connection' } },
    },
  },
  {
    name: 'revoke_mandate',
    description: 'Revoke the current mandate at the agent platform. The bank refuses every later call under it.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'explain_last_decision',
    description: 'Explain the last bank call: what was signed (action, payee, amount, nonce, chain hash) and why the bank allowed or denied it.',
    inputSchema: { type: 'object', properties: {} },
  },
] as const;

const BANK_NOTE =
  ' [Via the Plenipo bridge: signed under the mandate the person approved; the bank checks payee, limits, expiry and revocation and may answer "plenipo: DENY <code>". Amounts are in euro cents.]';

function result(t: ToolText) {
  return {
    content: [{ type: 'text' as const, text: t.text }],
    ...(t.isError ? { isError: true } : {}),
    ...(t.data ? { structuredContent: t.data } : {}),
  };
}

export const BRIDGE_INSTRUCTIONS =
  'Tools to act at the person\'s bank under a Plenipo mandate. First request_mandate and have the person approve it in their wallet, ' +
  'then mandate_status, then the bank tools. Never try to work around a DENY: report it to the person. ' +
  'Never say that something was paid unless a transfer under this mandate returned ALLOW; a bill missing from list_payees says nothing about who paid it.';

export function createBridgeServer(core: BridgeCore, opts: { instructions?: string; onToolCall?: (name: string) => void } = {}): Server {
  const server = new Server(
    { name: 'plenipo-bank', version: '0.1.0' },
    {
      capabilities: { tools: { listChanged: true } },
      instructions: opts.instructions ?? BRIDGE_INSTRUCTIONS,
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const bank = await core.bankTools();
    return {
      tools: [
        ...OWN_TOOLS.map((t) => ({ ...t, inputSchema: { ...t.inputSchema } })),
        ...bank.map((t) => ({ name: t.name, description: `${t.description ?? ''}${BANK_NOTE}`, inputSchema: t.inputSchema as { type: 'object' } })),
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    opts.onToolCall?.(req.params.name);
    try {
      switch (req.params.name) {
        case 'request_mandate':
          return result(await core.requestMandate(args as never));
        case 'mandate_status':
          return result(await core.mandateStatus(args as { demo_code?: string }));
        case 'revoke_mandate':
          return result(await core.revokeMandate());
        case 'explain_last_decision':
          return result(await core.explainLastDecision());
        default:
          return result(await core.callBankTool(req.params.name, args));
      }
    } catch (e) {
      return result({ isError: true, text: (e as Error).message });
    }
  });
  // When the bank was not reachable at start, its tools appear later: tell the client to list again.
  server.oninitialized = () => {
    void (async () => {
      if ((await core.bankTools()).length) return;
      const timer = setInterval(async () => {
        if (!(await core.bankTools()).length) return;
        clearInterval(timer);
        await server.sendToolListChanged().catch(() => {});
      }, 5000);
      timer.unref();
      server.onclose = () => clearInterval(timer);
    })();
  };
  return server;
}
