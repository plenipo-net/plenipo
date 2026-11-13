/**
 * A request object certificate kept on disk, so it survives restarts without being handed in as a secret:
 * on the first start the sandbox creates a CA and a leaf for the platform host in SANDBOX_RP_DIR and reuses
 * them afterwards. Wallet builds that should open the platform's requests trust the CA, published at
 * /rp-ca.pem. Test material: the CA is a throwaway test CA, not for production.
 */
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createTestCertificateAuthority } from 'plenipo/testing';

export interface StoredRpMaterial {
  keyPem: string;
  chainPem: string;
  caPem: string;
  created: boolean;
}

const pem = (b64: string) => `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;

/** Reads the material from `dir`, or creates it for `origin` (the platform's https origin). */
export async function storedRpMaterial(dir: string, origin: string): Promise<StoredRpMaterial> {
  const files = { key: join(dir, 'rp-key.pem'), chain: join(dir, 'rp-chain.pem'), ca: join(dir, 'rp-ca.pem') };
  const host = new URL(origin).hostname;
  if (existsSync(files.key) && existsSync(files.chain) && existsSync(files.ca)) {
    const m = { keyPem: readFileSync(files.key, 'utf8'), chainPem: readFileSync(files.chain, 'utf8'), caPem: readFileSync(files.ca, 'utf8') };
    const leaf = new X509Certificate(m.chainPem);
    // A certificate for another host, or one about to expire, is replaced rather than served.
    if (leaf.checkHost(host) && new Date(leaf.validTo).getTime() - Date.now() > 30 * 24 * 3600_000) return { ...m, created: false };
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const ca = await createTestCertificateAuthority('Plenipo Sandbox Relying Party CA');
  const caNotAfter = new Date(new X509Certificate(ca.anchorPem).validTo);
  // clientAuth EKU: walt.id checks it on x509_san_dns certificates. The leaf lives as long as its CA.
  const leaf = await ca.issueLeaf(origin, {
    eku: { usages: ['1.3.6.1.5.5.7.3.2'] },
    notAfter: new Date(caNotAfter.getTime() - 24 * 3600_000),
  });
  const keyPem = createPrivateKey({ key: leaf.privateJwk as never, format: 'jwk' }).export({ type: 'pkcs8', format: 'pem' }) as string;
  const chainPem = leaf.x5c.map(pem).join('');
  writeFileSync(files.key, keyPem, { mode: 0o600 });
  chmodSync(files.key, 0o600);
  writeFileSync(files.chain, chainPem);
  writeFileSync(files.ca, ca.anchorPem);
  return { keyPem, chainPem, caPem: ca.anchorPem, created: true };
}
