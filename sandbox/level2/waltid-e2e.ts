/**
 * End to end with a real wallet: walt.id Wallet API 2 holds Maria's PID and approves a Plenipo mandate
 * over OpenID4VP; then the agent pays a bill at the sandbox bank under that mandate.
 *
 * Prerequisites (level2/README.md): the sandbox running with the RP certificate from make-rp-cert.ts and
 * SANDBOX_HOST=0.0.0.0 SANDBOX_PUBLIC_URL_PLATFORM=http://host.docker.internal:4403; walt.id Wallet API 2
 * running with level2/waltid/config on http://localhost:7006.
 *
 *   npx tsx level2/waltid-e2e.ts
 */
import { exportJWK, generateKeyPair } from 'jose';
import { SandboxAgentClient } from '../src/agent/client.js';
import { DEFAULT_PORTS } from '../src/config.js';

const WALTID = (process.env.WALTID_URL ?? 'http://localhost:7006').replace(/\/$/, '');
const local = (n: keyof typeof DEFAULT_PORTS) => `http://127.0.0.1:${process.env[`SANDBOX_PORT_${n.toUpperCase()}`] ?? DEFAULT_PORTS[n]}`;
const admin: Record<string, string> = process.env.SANDBOX_ADMIN_TOKEN ? { authorization: `Bearer ${process.env.SANDBOX_ADMIN_TOKEN}` } : {};

async function call(method: string, url: string, body?: unknown, headers: Record<string, string> = {}): Promise<any> {
  const res = await fetch(url, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${url} -> HTTP ${res.status}: ${text.slice(0, 500)}`);
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
const step = (s: string) => console.log(`\n== ${s}`);

step('1. Create a walt.id wallet and import a P-256 holder key');
const { walletId } = await call('POST', `${WALTID}/wallet`, {});
const holder = await generateKeyPair('ES256', { extractable: true });
const privateJwk = await exportJWK(holder.privateKey);
const publicJwk = { kty: 'EC', crv: 'P-256', x: privateJwk.x, y: privateJwk.y };
const { keyId } = await call('POST', `${WALTID}/wallet/${walletId}/keys/import`, { key: { type: 'jwk', jwk: privateJwk } });
console.log(`wallet ${walletId}, key ${keyId}`);

step('2. The sandbox PID provider issues a PID bound to that key, and the wallet imports it');
// Sandbox shortcut for OpenID4VCI: the PID provider issues to the holder key directly.
const issued = await call('POST', `${local('pid')}/issue`, {
  person_id: 'maria-waltid',
  holder_jwk: publicJwk,
  claims: { given_name: 'Maria', family_name: 'Rossi', birthdate: '1984-03-12', nationality: 'IT' },
}, admin);
const stored = await call('POST', `${WALTID}/wallet/${walletId}/credentials/import`, { rawCredential: issued.pid, label: 'PID Maria Rossi (sandbox)' });
console.log(`PID ${issued.pid_id} stored as ${stored.id ?? JSON.stringify(stored).slice(0, 80)}`);

step('3. The agent platform asks for a mandate');
const client = new SandboxAgentClient({ platform: local('platform'), wallet: local('wallet'), bank: local('bank'), dashboard: local('dashboard') });
const req = await client.requestMandate({ agentName: 'Bill assistant (walt.id)', preset: 'utilities' });
console.log(`request_uri ${req.request_uri}\n${req.authorization_url}`);

step('4. walt.id resolves the request and shows the transaction data (preview)');
const preview = await call('POST', `${WALLET_PATH()}/credentials/present/preview`, { requestUrl: req.authorization_url, keyId });
console.log(JSON.stringify({ valid: preview.valid, clientId: preview.clientId, error: preview.error, transactionData: preview.transactionData }, null, 2));
if (!preview.valid) throw new Error('walt.id rejected the request; see the error above');

step('5. The person approves: walt.id presents the PID with the mandate hash in the KB-JWT');
const presented = await call('POST', `${WALLET_PATH()}/credentials/present`, { requestUrl: req.authorization_url, keyId });
console.log(JSON.stringify(presented).slice(0, 400));
const state = await client.waitForApproval(req.request_id, 15_000);
console.log(`platform: ${state.state}${state.error ? ' ' + state.error : ''}`);
if (state.state !== 'active') throw new Error('the platform did not accept the walt.id response');

step('6. The agent pays the Lumen bill at the bank under the walt.id-approved mandate');
const paid = await client.callTool(state.mandate_id, 'transfer', { payee: 'lumen-energia.example', amount_cents: 8430, reference: 'Lumen 2026-09 (walt.id)' });
console.log(`${paid.decision}${paid.code ? ' ' + paid.code : ''}: ${paid.text}`);
const denied = await client.callTool(state.mandate_id, 'transfer', { payee: 'lumen-energia.example', amount_cents: 18000, reference: 'too much' });
console.log(`${denied.decision}${denied.code ? ' ' + denied.code : ''}: ${denied.text}`);
await client.close();
console.log(paid.decision === 'ALLOW' && denied.code === 'LIMIT_PER_OPERATION' ? '\nPASS: walt.id end to end' : '\nFAIL');

function WALLET_PATH() {
  return `${WALTID}/wallet/${walletId}`;
}
