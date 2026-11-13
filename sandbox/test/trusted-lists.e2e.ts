/**
 * PID providers from trusted lists (ETSI TS 119 602 LoTE) and the material a wallet build needs to trust
 * the platform: the relying party CA at /rp-ca.pem and the links the EUDI reference apps open.
 */
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LOTE_SERVICE_TYPE, LOTE_TYPE } from 'plenipo';
import { buildTestLoTE, createTestCertificateAuthority, createTestListOperator, type TestListOperator } from 'plenipo/testing';
import { SandboxAgentClient } from '../src/agent/client.js';
import { startSandbox, type Sandbox } from '../src/sandbox.js';
import { pidListSettingsFromEnv, readPidLists, startPidListTrust } from '../src/trusted-lists.js';

const dir = mkdtempSync(join(tmpdir(), 'plenipo-lists-'));
let op: TestListOperator;
let listCa: Awaited<ReturnType<typeof createTestCertificateAuthority>>;
let revCa: Awaited<ReturnType<typeof createTestCertificateAuthority>>;
const PRESET = 'utilities';
const fp = (pem: string) => new X509Certificate(pem).fingerprint256;

async function writeList(name: string, cas: string[], extra: Partial<Parameters<typeof buildTestLoTE>[0]> = {}, signer = op) {
  const doc = buildTestLoTE({
    type: LOTE_TYPE.pidProviders,
    entities: [
      {
        name: 'Test PID Provider',
        services: [
          { type: LOTE_SERVICE_TYPE.pidIssuance, certificates: cas },
          { type: LOTE_SERVICE_TYPE.pidRevocation, certificates: [revCa.certificateB64] },
        ],
      },
    ],
    ...extra,
  });
  const file = join(dir, name);
  writeFileSync(file, await signer.sign(doc));
  return file;
}

beforeAll(async () => {
  op = await createTestListOperator('EUDI Test Operator');
  listCa = await createTestCertificateAuthority('Listed PID CA');
  revCa = await createTestCertificateAuthority('Listed revocation CA');
  writeFileSync(join(dir, 'signer.pem'), op.certificatePem);
});

describe('reading PID provider lists', () => {
  it('takes the issuance and revocation CAs of a list signed by a pinned signer', async () => {
    const file = await writeList('ok.jwt', [listCa.certificateB64]);
    const r = await readPidLists({ sources: [file], signerPems: [op.certificatePem], statusOrigins: [], refreshSeconds: 3600 });
    expect(r.lists[0]).toMatchObject({ source: file, sequence: 1, entities: 1 });
    expect(r.issuanceAnchors.map(fp)).toEqual([fp(listCa.anchorPem)]);
    expect(r.revocationAnchors.map(fp)).toEqual([fp(revCa.anchorPem)]);
  });

  it('reports and skips a list signed by someone else, or of another type', async () => {
    const other = await createTestListOperator('Someone Else');
    const forged = await writeList('forged.jwt', [listCa.certificateB64], {}, other);
    const wallets = await writeList('wallets.jwt', [listCa.certificateB64], { type: LOTE_TYPE.walletProviders });
    const r = await readPidLists({ sources: [forged, wallets], signerPems: [op.certificatePem], statusOrigins: [], refreshSeconds: 3600 });
    expect(r.issuanceAnchors).toEqual([]);
    expect(r.lists[0].error).toMatch(/not an expected list signer/);
    expect(r.lists[1].error).toMatch(/is of type/);
  });

  it('refuses list URLs that are not https and settings without a signer', () => {
    expect(() => pidListSettingsFromEnv({ PLENIPO_PID_TRUSTED_LISTS: 'x.jwt' })).toThrow(/SIGNERS/);
    expect(() =>
      pidListSettingsFromEnv({ PLENIPO_PID_TRUSTED_LISTS: 'x.jwt', PLENIPO_PID_TRUSTED_LIST_SIGNERS: join(dir, 'signer.pem'), PLENIPO_PID_LIST_STATUS_ORIGINS: 'http://status.example' }),
    ).toThrow(/https origin/);
    return expect(readPidLists({ sources: ['http://list.example/pid.jwt'], signerPems: [op.certificatePem], statusOrigins: [], refreshSeconds: 1 })).resolves.toMatchObject({
      lists: [{ error: expect.stringMatching(/https or from a file/) }],
    });
  });

  it('updates the shared anchors in place and keeps the last good reading when every list fails', async () => {
    const file = join(dir, 'rotating.jwt');
    writeFileSync(file, await op.sign(buildTestLoTE({ entities: [{ name: 'A', services: [{ type: LOTE_SERVICE_TYPE.pidIssuance, certificates: [listCa.certificateB64] }] }] })));
    const anchors = ['BASE'];
    const own = await createTestCertificateAuthority('Own PID CA');
    const t = await startPidListTrust(
      { sources: [file], signerPems: [op.certificatePem], statusOrigins: ['https://status.example'], refreshSeconds: 3600 },
      anchors,
      { statusOrigin: 'https://pid.example', anchors: [own.anchorPem] },
      () => {},
    );
    expect(anchors[0]).toBe('BASE');
    expect(anchors.slice(1).map(fp)).toEqual([fp(listCa.anchorPem)]);
    expect(t.statusTrust?.statusOrigins).toEqual(['https://pid.example', 'https://status.example']);
    expect(t.statusTrust?.trustAnchors?.map(fp)).toEqual([fp(own.anchorPem), fp(listCa.anchorPem)]);

    writeFileSync(file, 'not a list');
    await t.refresh();
    expect(anchors.slice(1).map(fp)).toEqual([fp(listCa.anchorPem)]);

    const next = await createTestCertificateAuthority('Next PID CA');
    writeFileSync(file, await op.sign(buildTestLoTE({ sequenceNumber: 2, entities: [{ name: 'A', services: [{ type: LOTE_SERVICE_TYPE.pidIssuance, certificates: [next.certificateB64] }] }] })));
    await t.refresh();
    expect(anchors.map((a) => (a === 'BASE' ? a : fp(a)))).toEqual(['BASE', fp(next.anchorPem)]);
    t.close();
  });
});

describe('a sandbox with listed PID providers and a fixed relying party certificate', () => {
  let sb: Sandbox;
  let rpCaPem: string;
  const keys = ['PLENIPO_PID_TRUSTED_LISTS', 'PLENIPO_PID_TRUSTED_LIST_SIGNERS', 'PLATFORM_RP_KEY', 'PLATFORM_RP_CHAIN', 'WALLET_RP_ANCHORS'];

  beforeAll(async () => {
    const list = await writeList('sandbox.jwt', [listCa.certificateB64]);
    const rpCa = await createTestCertificateAuthority('Fixed RP CA');
    const leaf = await rpCa.issueLeaf('https://platform.sandbox.plenipo.test', { eku: { usages: ['1.3.6.1.5.5.7.3.2'] } });
    const pem = (b64: string) => `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;
    rpCaPem = rpCa.anchorPem;
    process.env.PLENIPO_PID_TRUSTED_LISTS = list;
    process.env.PLENIPO_PID_TRUSTED_LIST_SIGNERS = join(dir, 'signer.pem');
    // Inline PEM, as a Fly secret holds it; the key with escaped newlines, as some secret stores give it.
    process.env.PLATFORM_RP_KEY = (createPrivateKey({ key: leaf.privateJwk as never, format: 'jwk' }).export({ type: 'pkcs8', format: 'pem' }) as string).replace(/\n/g, '\\n');
    process.env.PLATFORM_RP_CHAIN = leaf.x5c.map(pem).join('');
    process.env.WALLET_RP_ANCHORS = rpCa.anchorPem;
    sb = await startSandbox({ ports: { dashboard: 0, pid: 0, wallet: 0, platform: 0, bank: 0 }, statusCacheSeconds: 1 });
  });

  afterAll(async () => {
    for (const k of keys) delete process.env[k];
    await sb?.close();
  });

  it('trusts the listed PID provider next to its own', () => {
    expect(sb.pidLists?.last()?.issuanceAnchors.map(fp)).toEqual([fp(listCa.anchorPem)]);
  });

  it('publishes the relying party CA it was given, and names it in /api/info', async () => {
    const res = await fetch(`${sb.urls.platform}/rp-ca.pem`);
    expect(res.status).toBe(200);
    expect(fp(await res.text())).toBe(fp(rpCaPem));
    const info = (await (await fetch(`${sb.urls.platform}/api/info`)).json()) as { rp_ca?: string };
    expect(info.rp_ca).toMatch(/\/rp-ca\.pem$/);
  });

  it('offers the openid4vp link and the EUDI app link, and the wallet accepts the fixed certificate', async () => {
    const client = new SandboxAgentClient({ platform: sb.urls.platform, wallet: sb.urls.wallet, bank: sb.urls.bank, dashboard: sb.urls.dashboard });
    try {
      const r = (await client.requestMandate({ agentName: 'List test', preset: PRESET })) as { request_uri: string; authorization_url: string; eudi_wallet_url?: string; request_id: string };
      expect(r.authorization_url.startsWith('openid4vp://?')).toBe(true);
      const eudi = new URL(r.eudi_wallet_url!);
      expect(eudi.protocol).toBe('eudi-openid4vp:');
      expect(eudi.host).toBe('authorize');
      expect(eudi.searchParams.get('request_uri')).toBe(r.request_uri);
      const page = await (await fetch(`${sb.urls.platform}/requests/${r.request_id}`)).text();
      expect(page).toContain('href="/rp-ca.pem"');
      await client.walletDecide(r.request_uri, eudi.searchParams.get('client_id')!, 'maria', 'approve');
      expect((await client.waitForApproval(r.request_id, 10_000)).state).toBe('active');
    } finally {
      await client.close();
    }
  });
});

describe('a request certificate kept on disk', () => {
  it('is created once, reused, and replaced when it names another host', async () => {
    const { storedRpMaterial } = await import('../src/rp-store.js');
    const { statSync } = await import('node:fs');
    const rpDir = join(dir, 'rp');
    const first = await storedRpMaterial(rpDir, 'https://platform.sandbox.plenipo.test');
    expect(first.created).toBe(true);
    expect(statSync(join(rpDir, 'rp-key.pem')).mode & 0o777).toBe(0o600);
    const leaf = new X509Certificate(first.chainPem);
    expect(leaf.checkHost('platform.sandbox.plenipo.test')).toBeTruthy();
    expect(leaf.verify(new X509Certificate(first.caPem).publicKey)).toBe(true);
    // The leaf lives about as long as its CA (five years), so the CA in wallet builds does not change.
    expect(new Date(leaf.validTo).getTime() - Date.now()).toBeGreaterThan(4 * 365 * 24 * 3600_000);
    const again = await storedRpMaterial(rpDir, 'https://platform.sandbox.plenipo.test');
    expect(again.created).toBe(false);
    expect(fp(again.caPem)).toBe(fp(first.caPem));
    const other = await storedRpMaterial(rpDir, 'https://platform.other.test');
    expect(other.created).toBe(true);
    expect(fp(other.caPem)).not.toBe(fp(first.caPem));
  });
});
