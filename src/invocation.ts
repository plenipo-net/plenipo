import { randomUUID } from 'node:crypto';
import { signCompactJwt, type SigningKey } from './signer.js';
import { canonicalize, sha256 } from './encoding.js';
import { INVOCATION_TYP, type Amount, type InvocationPayload, type MandateChain } from './types.js';
import { nowSeconds } from './mandate.js';

export interface InvocationInput {
  /** Id of the leaf mandate the agent acts under. */
  mandateId: string;
  action: string;
  counterparty?: string;
  amount?: Amount;
  /** Identifier of the relying party (its URL or MCP server name). */
  aud: string;
  /** Nonce issued by the relying party; a random one is used when absent. */
  nonce?: string;
  /** Tool or API arguments to bind to the invocation. */
  args?: unknown;
  /**
   * The chain the agent presents with this invocation. Its hash goes in `chain_hash`, so the invocation
   * cannot be replayed with another chain that happens to end in a mandate with the same id.
   */
  chain: MandateChain;
}

export function argsHash(args: unknown): string {
  return sha256(canonicalize(args ?? {}));
}

/**
 * SHA-256 over the RFC 8785 JSON of everything the chain carries: the root transaction data and
 * presentation (and the TS12 mandate and further presentations when present), then every delegation in
 * order. Members a chain does not have are left out, so encodings that differ only by an absent member agree.
 */
export function chainHash(chain: MandateChain): string {
  const r = chain.root;
  const root: Record<string, unknown> = { transaction_data: r.transaction_data, presentation: r.presentation };
  if (r.mandate !== undefined) root.mandate = r.mandate;
  if (r.presentations !== undefined) root.presentations = r.presentations;
  return sha256(canonicalize({ typ: 'plenipo-chain', root, delegations: chain.delegations }));
}

/** The agent signs what it is about to do, with the key named in its mandate. */
export async function createInvocation(agentKey: SigningKey, input: InvocationInput): Promise<string> {
  if (!input.chain || typeof input.chain !== 'object') throw new Error('createInvocation needs the chain it is presented with');
  const payload: InvocationPayload = {
    mandate: input.mandateId,
    action: input.action,
    ...(input.counterparty ? { counterparty: input.counterparty } : {}),
    ...(input.amount ? { amount: input.amount } : {}),
    aud: input.aud,
    nonce: input.nonce ?? randomUUID(),
    iat: nowSeconds(),
    ...(input.args !== undefined ? { args_hash: argsHash(input.args) } : {}),
    chain_hash: chainHash(input.chain),
  };
  return signCompactJwt(payload as unknown as Record<string, unknown>, { alg: 'ES256', typ: INVOCATION_TYP }, agentKey);
}
