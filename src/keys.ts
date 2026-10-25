import { exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';

export interface AgentKey {
  publicJwk: JWK;
  privateKey: CryptoKey;
}

/** Generates an ES256 key pair for an agent. The private key never leaves the agent. */
export async function generateAgentKey(): Promise<AgentKey> {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  return { publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }, privateKey };
}
