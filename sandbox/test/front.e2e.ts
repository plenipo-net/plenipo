/**
 * The front door of a hosted sandbox: dispatch by host name, the optional demo login, and the paths a
 * wallet, a remote MCP client and a showcase page reach without it.
 */
import { request } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { hostRoutes, openPaths, startFront, type RunningFront } from '../src/front.js';
import { startSandbox, type Sandbox } from '../src/sandbox.js';

const DOMAIN = 'sandbox.plenipo.test';
const LOGIN = 'demo:s3cret';
let sb: Sandbox;
let front: RunningFront;

function get(host: string, path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) {
  const u = new URL(front.url);
  return new Promise<{ status: number; headers: Record<string, unknown>; body: string }>((resolve, reject) => {
    const r = request({ hostname: u.hostname, port: u.port, path, method: init.method ?? 'GET', headers: { host, ...init.headers } }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    r.on('error', reject);
    r.end(init.body);
  });
}
const auth = { authorization: `Basic ${Buffer.from(LOGIN).toString('base64')}` };

beforeAll(async () => {
  sb = await startSandbox({ ports: { dashboard: 0, pid: 0, wallet: 0, platform: 0, bank: 0, agent: 0 }, agentGateway: { token: 'front-test-token' } });
  front = await startFront({ host: '127.0.0.1', port: 0, routes: hostRoutes(DOMAIN, sb.urls), basicAuth: LOGIN, open: openPaths(DOMAIN), clientIpHeader: 'fly-client-ip' });
});

afterAll(async () => {
  await front?.close();
  await sb?.close();
});

describe('front door', () => {
  it('dispatches by host name behind the demo login', async () => {
    expect((await get(DOMAIN, '/')).status).toBe(401);
    expect((await get(DOMAIN, '/')).headers['www-authenticate']).toMatch(/Basic/);
    const dash = await get(DOMAIN, '/', { headers: auth });
    expect(dash.status).toBe(200);
    expect(dash.body).toContain('Plenipo Sandbox');
    const wallet = await get(`wallet.${DOMAIN}:443`, '/', { headers: auth });
    expect(wallet.status).toBe(200);
    expect(wallet.body).not.toContain('Plenipo Sandbox · live');
    expect((await get('elsewhere.example', '/', { headers: auth })).status).toBe(404);
  });

  it('leaves open what a wallet, a remote MCP client and a showcase page must reach', async () => {
    expect((await get(`platform.${DOMAIN}`, '/status/mandates')).status).toBe(200);
    expect((await get(`pid.${DOMAIN}`, '/trust-anchor.pem')).status).toBe(200);
    const feed = await get(DOMAIN, '/api/demo/ABCDEF');
    expect(feed.status).toBe(200);
    expect(feed.headers['access-control-allow-origin']).toBe('*');
    expect((await get(DOMAIN, '/api/events')).status).toBe(401);
    expect((await get(`bank.${DOMAIN}`, '/')).status).toBe(401);
    const init = await get(`mcp.${DOMAIN}`, '/mcp/front-test-token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } }),
    });
    expect(init.status).toBe(200);
    expect(init.headers['mcp-session-id']).toBeTruthy();
    expect(init.body).toMatch(/public Plenipo sandbox/);
  });

  it('answers the health check on any host', async () => {
    const h = await get('fly-internal', '/healthz');
    expect(h.status).toBe(200);
  });
});
