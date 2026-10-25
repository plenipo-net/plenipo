/**
 * End-to-end demo: a person approves a mandate in their wallet over OpenID4VP, an agent delegates a
 * narrower mandate to a sub-agent, and a rail operator's MCP server checks every booking, including the
 * status of the PID and of the mandate.
 *
 *   npm run demo
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import { exportJWK, generateKeyPair } from 'jose';
import {
  createInvocation,
  createMandate,
  createMandateRequest,
  delegateMandate,
  generateAgentKey,
  handleMandateResponse,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  nowSeconds,
  StatusListPublisher,
  type MandateChain,
  type StatusFetcher,
} from '../src/index.js';
import { guardTool, META_KEY } from '../src/mcp.js';
import { createTestPidProvider, createTestWallet } from '../src/testing.js';

const RAIL = 'mcp://rail.example';
const log = (s = '') => console.log(s);

// 1. A PID provider with an X.509 certificate under a trust anchor and a status list issues a PID to the
//    person's wallet (test keys, never use outside development).
const pidProvider = await createTestPidProvider('https://pid.example.eu', { x5c: true, statusList: true });
const wallet = await createTestWallet();
wallet.storePid(await pidProvider.issuePid(wallet.holderJwk, { given_name: 'Mario', family_name: 'Rossi', birthdate: '1980-01-01' }));

// 2. The agent platform publishes a status list for the mandates it creates.
const PLATFORM = 'https://agents.example';
const platformKeys = await generateKeyPair('ES256', { extractable: true });
const mandateStatus = new StatusListPublisher({ uri: `${PLATFORM}/status/mandates`, signingKey: platformKeys.privateKey, iss: PLATFORM });
const platformTrust = { trustedIssuers: [{ iss: PLATFORM, jwk: await exportJWK(platformKeys.publicKey) }] };
// Stands in for HTTPS: the rail operator fetches both status lists.
const statusFetcher: StatusFetcher = async (uri) =>
  uri === mandateStatus.uri ? mandateStatus.token() : pidProvider.statusFetcher(uri);

// 3. The travel assistant asks for a mandate, and the person approves it in the wallet over OpenID4VP.
const assistant = await generateAgentKey();
const mandateRef = mandateStatus.allocate();
const mandate = createMandate({
  agentJwk: assistant.publicJwk,
  actions: ['travel.*'],
  counterparties: ['*.rail.example'],
  limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
  ttlSeconds: 7 * 24 * 3600,
  maxDepth: 1,
  purpose: 'Trains for the Milan trip, up to 150 euro each, 300 in total',
  status: mandateRef,
});
const request = await createMandateRequest({
  mandate,
  clientId: 'x509_san_dns:agents.example',
  responseUri: `${PLATFORM}/openid4vp/response`,
  disclose: ['given_name', 'family_name'],
});
log('Platform sent an OpenID4VP request: PID by DCQL, mandate as transaction data, encrypted response');
const walletBody = await wallet.respond(request.params);
const { root } = await handleMandateResponse(walletBody, request.session, {
  now: nowSeconds(),
  trustAnchors: [pidProvider.anchorPem!],
  statusFetcher,
  sessions: new InMemoryNonceStore(),
});
log('Wallet approved the mandate: travel.*, *.rail.example, 150 euro per booking, 300 total, 7 days');

// 4. The assistant hands the booking to a sub-agent with a narrower mandate.
const bookingBot = await generateAgentKey();
const subMandate = createMandate({
  agentJwk: bookingBot.publicJwk,
  actions: ['travel.book'],
  counterparties: ['www.rail.example'],
  limits: { currency: 'EUR', per_operation: 10000, total: 20000 },
  nbf: mandate.nbf,
  ttlSeconds: 2 * 24 * 3600,
});
const delegation = await delegateMandate({ parent: mandate, parentAgentKey: assistant.privateKey, child: subMandate });
const chain: MandateChain = { root, delegations: [delegation] };
log('Assistant delegated to the booking bot: travel.book, www.rail.example, 100 euro per booking, 200 total, 2 days');

// 5. The rail operator exposes a booking tool, guarded by Plenipo.
const ledger = new InMemorySpendingLedger();
const server = new McpServer({ name: 'rail.example', version: '1.0.0' });
const bookTrain = guardTool<{ route: string; price_cents: number }>(
  async ({ route, price_cents }) => ({
    content: [{ type: 'text', text: `Booked ${route} for ${(price_cents / 100).toFixed(2)} euro` }],
  }),
  {
    action: 'travel.book',
    trustAnchors: [pidProvider.anchorPem!],
    mandateStatusTrust: platformTrust,
    statusFetcher,
    audience: RAIL,
    ledger,
    nonces: new InMemoryNonceStore(),
    counterparty: () => 'www.rail.example',
    amount: (a) => ({ value: a.price_cents, currency: 'EUR' }),
    onDecision: (d) => {
      if (d.decision === 'ALLOW') {
        const who = `${d.principal.given_name} ${d.principal.family_name}`;
        log(`  rail.example: ALLOW, acting for ${who}, chain depth ${d.path.length - 1}`);
      } else {
        log(`  rail.example: DENY ${d.code}, ${d.reason}`);
      }
    },
  },
);
server.registerTool(
  'book_train',
  { description: 'Book a train ticket', inputSchema: { route: z.string(), price_cents: z.number().int() } },
  bookTrain as any,
);

const [clientT, serverT] = InMemoryTransport.createLinkedPair();
await server.connect(serverT);
const client = new Client({ name: 'booking-bot', version: '1.0.0' });
await client.connect(clientT);

async function book(route: string, price_cents: number) {
  log(`\nBooking bot: ${route}, ${(price_cents / 100).toFixed(2)} euro`);
  const args = { route, price_cents };
  const invocation = await createInvocation(bookingBot.privateKey, { chain,
    mandateId: subMandate.id,
    action: 'travel.book',
    counterparty: 'www.rail.example',
    amount: { value: price_cents, currency: 'EUR' },
    aud: RAIL,
    args,
  });
  const res = await client.callTool({ name: 'book_train', arguments: args, _meta: { [META_KEY]: { chain, invocation } } });
  const text = (res.content as Array<{ text: string }>)[0]?.text;
  log(`  result: ${text}`);
}

await book('Roma-Milano 18 Oct', 8900);
await book('Milano-Roma 20 Oct, first class', 12000);
await book('Milano-Roma 20 Oct', 8900);
await book('Roma-Napoli 21 Oct', 5000);

log('\nThe person revokes the mandate; the platform flips its entry in the status list.');
mandateStatus.revoke(mandateRef);
await book('Roma-Firenze 22 Oct', 3000);

await client.close();
