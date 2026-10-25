import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest } from '@sd-jwt/crypto-nodejs';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import type { JWK } from 'jose';
import { canonicalize, fromBase64url, sha256 } from './encoding.js';
import { bindToPidHolder, checkRepresentation, legalPrincipalProblems, RepresentationError, REPRESENTATION_QUERY_ID, type RepresentationVerifyOptions } from './legal.js';
import { disclosedProtectedClaims, PresentationError, verifyAttestationPresentation } from './presentation.js';
import { anyActionCovers, validateMandate } from './scope.js';
import { checkStatus, StatusUnavailableError, httpsOrigin, isStatusReference, type StatusFetcher, type StatusListCache, type StatusReference } from './status.js';
import { checkChainRevocation, resolveSigningKey, TrustError, type TrustConfig } from './trust.js';
import type { CertificateRevocationOptions } from './x509-revocation.js';
import { emandateEnvelopeProblems, emandateViolations, type EmandateCheckOptions } from './ts12.js';
import {
  EMANDATE_TX_DATA_TYPE,
  PID_VCT,
  REPRESENTATION_VCT,
  TX_DATA_TYPE,
  type LegalPersonPrincipal,
  type Mandate,
  type RepresentationInfo,
  type RootAuthorization,
  type RootBinding,
} from './types.js';

/** DCQL query id of the SCA attestation a TS12 e-mandate is bound to. */
export const SCA_QUERY_ID = 'sca';

export class RootError extends Error {
  constructor(
    readonly code:
      | 'ROOT_INVALID'
      | 'PID_ISSUER_UNTRUSTED'
      | 'PID_REVOKED'
      | 'TX_DATA_MISMATCH'
      | 'MALFORMED'
      | 'CONFIGURATION'
      | 'DISPLAY_MISMATCH'
      | 'ROOT_POLICY'
      | 'ATTESTATION_UNTRUSTED'
      | 'ATTESTATION_INVALID'
      | 'ATTESTATION_REVOKED'
      | 'ROLE_EXCEEDED'
      | 'STATUS_UNAVAILABLE'
      | 'REPLAY',
    message: string,
    /** Internal detail for logs; never send it to the caller. */
    readonly detail?: string,
  ) {
    super(message);
  }
}

export interface RootResult {
  mandate: Mandate;
  principal: Record<string, unknown>;
  pidIssuer: string;
  pidExp?: number;
  approvedAt: number;
  /** Key binding JWT claims, for callers that check the original wallet request (nonce, aud). */
  keyBinding: { nonce: string; aud: unknown; iat: number };
  /** How the PID provider was trusted. */
  trustedVia: 'issuer' | 'x5c';
  /** The PID status reference, when the PID has one and its check was deferred. */
  pidStatus?: StatusReference;
  /**
   * The validated certificate path of the PID provider (base64 DER, leaf first, ending with the anchor),
   * when trusted via x5c. Lets a caller check revocation later, after cheaper checks.
   */
  pidCertificateChain?: string[];
  /** Present when the mandate is given on behalf of a legal person. `principal` stays the PID claims. */
  legalPrincipal?: LegalPersonPrincipal;
  representation?: RepresentationInfo;
  /** Present for TS12 e-mandate roots. */
  binding?: RootBinding;
  /** `response_mode` from the SCA key binding JWT, for the caller that knows the original request. */
  scaResponseMode?: string;
  /** Attestation status lists whose check was deferred (`attestationStatus: 'defer'`). */
  deferredStatus?: DeferredStatus[];
  /** The PID holder key (`cnf.jwk`) that signed the key binding JWT. */
  holderJwk?: JWK;
  /** Attestation issuer certificate paths whose revocation check was deferred (`attestationStatus: 'defer'`). */
  deferredCertificates?: DeferredCertificateCheck[];
}

/** A revocation check of an SCA or register certificate path, to run with `checkAttestationCertificates`. */
export interface DeferredCertificateCheck {
  label: string;
  /** Validated path, leaf first, ending with the anchor. */
  chain: string[];
  /** The `certificateRevocation` of the trust that accepted the attestation. */
  revocation: CertificateRevocationOptions;
}

/** A status list check of a non-PID attestation, to run with `checkAttestationStatus`. */
export interface DeferredStatus {
  label: string;
  ref: StatusReference;
  /** The attestation issuer: the status list must be signed for this identity. */
  issuer: string;
  trust: TrustConfig;
}

export interface EmandateVerifyOptions extends EmandateCheckOptions {
  /** Refuse TS12 e-mandate roots altogether. Default false. */
  refuse?: boolean;
  /** Transaction data types accepted as e-mandates. Default [`urn:eudi:sca:emandate:1`]. */
  types?: string[];
  /** Who issues SCA attestations (the payer's PSP). Required to accept e-mandates bound to an SCA attestation. */
  scaTrust?: TrustConfig;
  /** Accepted SCA attestation vct values. Required with `scaTrust`: TS12 defines no single SCA type. */
  scaVcts?: string[];
  /**
   * Accept e-mandates bound to the PID key instead of an SCA attestation. TS12 wallets only accept the type
   * for SCA attestations, so this serves wallets configured otherwise and tests. Default true.
   */
  allowPidBinding?: boolean;
  /**
   * Action patterns an e-mandate root may grant: every mandate action must be covered by one. Required
   * with `purposeCheck: 'none'`, since actions are then bound by hash but not shown.
   */
  allowedActions?: string[];
  /** Maximum delegation depth an e-mandate root may allow. Required with `purposeCheck: 'none'`. */
  maxDelegationDepth?: number;
  /**
   * Require the SCA attestation to carry a status list entry, so a revoked attestation cannot pass by
   * omitting it. Default true.
   */
  requireScaStatus?: boolean;
  /**
   * How the SCA attestation is tied to the PID holder. With TS12 only the SCA key binding JWT signs the
   * e-mandate; the PID only shares its nonce and audience, which the requesting platform chooses. The SCA
   * attestation is accepted when it has the PID holder key, or when these claims (e.g. a personal number
   * the bank puts in its attestation) equal the PID's.
   */
  scaIdentityClaims?: string[];
  /**
   * Also accept an SCA attestation tied to the PID only by being in the same response. Weak: a platform can
   * combine one person's PID with another person's SCA approval (docs/root.md). Default false.
   */
  scaSameResponseBinding?: boolean;
}

export interface RootOptions extends TrustConfig {
  now: number;
  acceptedVcts?: string[];
  skewSeconds?: number;
  /**
   * What to do when the PID carries a status list reference. `check` (default) fetches and verifies the
   * list and denies a revoked or suspended PID. `defer` returns the reference in the result, for the
   * caller to check with `checkPidStatus` after cheaper checks. `skip` is for offline tests only.
   */
  pidStatus?: 'check' | 'defer' | 'skip';
  /**
   * Require the PID to carry a status list entry. Default true: a PID without one is refused with
   * ROOT_INVALID, because a provider that (against SD-JWT VC) made `status` selectively disclosable lets the
   * holder of a revoked PID withhold it, and a withheld status cannot be told from an absent one. Set false
   * only when no configured PID provider uses status lists; prefer the per-provider opt-outs
   * (`TrustedIssuer.withoutStatusList`, `pidProvidersWithoutStatus`). Ignored with `pidStatus: 'skip'`.
   */
  requirePidStatus?: boolean;
  /**
   * PID provider identifiers (`iss`) trusted through x5c whose PIDs carry no status list entry (short-lived
   * PIDs). Their PIDs are accepted without status; any other provider's are not.
   */
  pidProvidersWithoutStatus?: string[];
  /**
   * Who may sign the PID status list, when that is not the PID provider itself. By default the token
   * must be signed by the PID provider key (or a certificate naming the PID `iss`) and served from the
   * origin of the PID `iss`. With this option the signer must be named for the status list origin, and
   * the origin must be in `statusOrigins` (or among `trustedIssuers`).
   */
  pidStatusTrust?: TrustConfig;
  statusFetcher?: StatusFetcher;
  statusCache?: StatusListCache;
  /** How TS12 e-mandate roots are accepted. */
  emandate?: EmandateVerifyOptions;
  /** How representation attestations are accepted; required for mandates on behalf of a legal person. */
  representation?: RepresentationVerifyOptions;
  /**
   * SCA and representation attestation status lists: `check` (default) now, or `defer` to `deferredStatus`
   * for the caller to check with `checkAttestationStatus` after cheaper checks. Never skipped.
   */
  attestationStatus?: 'check' | 'defer';
}

const TECHNICAL_CLAIMS = new Set(['iss', 'iat', 'nbf', 'exp', 'vct', 'vct#integrity', 'cnf', 'status', 'sub', '_sd_alg']);

/** Strictly decodes the transaction data: unpadded base64url of canonical JSON (RFC 8785). */
export function decodeMandateTransactionData(td: string): { type?: string; credential_ids?: unknown; mandate?: Mandate } {
  if (typeof td !== 'string' || !/^[A-Za-z0-9_-]+$/.test(td)) {
    throw new RootError('MALFORMED', 'transaction_data is not strict base64url');
  }
  try {
    const json = fromBase64url(td);
    const parsed = JSON.parse(json);
    if (canonicalize(parsed) !== json) throw new Error('not canonical');
    return parsed;
  } catch {
    throw new RootError('MALFORMED', 'transaction_data must be canonical JSON (RFC 8785) in base64url');
  }
}

/**
 * Verifies the root of a chain: a PID SD-JWT VC from a trusted provider, not revoked, presented with a key
 * binding JWT whose transaction_data_hashes contains the hash of the encoded mandate.
 */
export async function verifyRoot(root: RootAuthorization, opts: RootOptions): Promise<RootResult> {
  if (typeof root?.transaction_data !== 'string' || typeof root?.presentation !== 'string') {
    throw new RootError('MALFORMED', 'root needs transaction_data and presentation strings');
  }
  if (!opts.trustedIssuers?.length && !opts.trustAnchors?.length) {
    throw new RootError('CONFIGURATION', 'configure trustedIssuers or trustAnchors');
  }

  const extra = root.presentations;
  if (extra !== undefined) {
    if (typeof extra !== 'object' || extra === null || Array.isArray(extra)) throw new RootError('MALFORMED', 'root presentations must be an object');
    for (const [k, v] of Object.entries(extra)) {
      if (k !== SCA_QUERY_ID && k !== REPRESENTATION_QUERY_ID) throw new RootError('MALFORMED', 'root has an unexpected presentation');
      if (typeof v !== 'string') throw new RootError('MALFORMED', 'root presentations must be strings');
    }
  }

  const td = decodeMandateTransactionData(root.transaction_data);
  const form = selectForm(td, root, opts);
  const mandate = form.mandate;
  const boundTo = form.boundTo;

  // Which further presentations the root must carry, exactly.
  const expected = new Set<string>();
  if (boundTo === SCA_QUERY_ID) {
    if (!opts.emandate?.scaTrust || !opts.emandate.scaVcts?.length) {
      throw new RootError('CONFIGURATION', 'configure emandate.scaTrust and emandate.scaVcts to accept e-mandates bound to an SCA attestation');
    }
    expected.add(SCA_QUERY_ID);
  }
  if (mandate.principal !== undefined) {
    const problems = legalPrincipalProblems(mandate.principal);
    if (problems.length) throw new RootError('MALFORMED', `root mandate: ${problems.join('; ')}`);
    if (!opts.representation?.trust) {
      throw new RootError('CONFIGURATION', 'configure representation to accept mandates on behalf of a legal person');
    }
    expected.add(REPRESENTATION_QUERY_ID);
  }
  for (const k of Object.keys(extra ?? {})) {
    if (!expected.has(k)) throw new RootError('MALFORMED', `the root carries a ${k} presentation it does not need`);
  }
  for (const k of expected) {
    if (typeof extra?.[k] !== 'string') {
      throw new RootError(k === SCA_QUERY_ID ? 'ROOT_INVALID' : 'ATTESTATION_INVALID', `the root has no ${k} presentation`);
    }
  }

  const issuerJwt = root.presentation.split('~')[0];
  let header: Record<string, unknown>;
  let iss: string | undefined;
  try {
    header = decodeProtectedHeader(issuerJwt) as Record<string, unknown>;
    iss = decodeJwt(issuerJwt).iss;
  } catch {
    throw new RootError('MALFORMED', 'presentation is not an SD-JWT');
  }
  if (typeof iss !== 'string' || iss.length === 0) throw new RootError('MALFORMED', 'the PID has no iss');
  let key;
  try {
    // Revocation needs the network, so it waits until the presentation and its binding have verified.
    key = resolveSigningKey(header, iss, { ...opts, certificateRevocation: undefined }, opts.now);
  } catch (e) {
    if (e instanceof TrustError) throw new RootError('PID_ISSUER_UNTRUSTED', 'PID provider not trusted', e.message);
    throw e;
  }

  // The library verifies the key binding JWT only when given its nonce. The nonce belonged to the
  // original wallet request, so it is read from the presentation itself: what matters here is the
  // signature by the PID holder key and the sd_hash, which the library then checks.
  const kbSegment = root.presentation.split('~').pop();
  let kbNonce: unknown;
  try {
    kbNonce = kbSegment ? decodeJwt(kbSegment).nonce : undefined;
  } catch {
    kbNonce = undefined;
  }
  if (typeof kbNonce !== 'string' || kbNonce.length === 0) {
    throw new RootError('ROOT_INVALID', 'presentation has no key binding JWT');
  }

  const sdjwt = new SDJwtVcInstance({
    hasher: digest,
    hashAlg: 'sha-256',
    verifier: await ES256.getVerifier(key.jwk),
    kbVerifier: async (data: string, sig: string, payload: Record<string, any>) => {
      const jwk = payload?.cnf?.jwk;
      if (!jwk) return false;
      return (await ES256.getVerifier(jwk))(data, sig);
    },
  });

  let verified: Awaited<ReturnType<typeof sdjwt.verify>>;
  try {
    verified = await sdjwt.verify(root.presentation, {
      keyBindingNonce: kbNonce,
      currentDate: opts.now,
      skewSeconds: opts.skewSeconds ?? 60,
      allowedIssuerAlgorithms: ['ES256'],
      allowedKeyBindingAlgorithms: ['ES256'],
      // Status is checked below with the same trust configuration as the PID itself.
      disableStatusVerification: true,
    });
  } catch (e) {
    throw new RootError('ROOT_INVALID', 'PID presentation does not verify', (e as Error).message);
  }

  const payload = verified.payload as Record<string, unknown>;
  // A PID provider that made exp or status disclosable lets the holder withhold them: refuse such PIDs.
  let protectedDisclosed: string[];
  try {
    protectedDisclosed = disclosedProtectedClaims(root.presentation);
  } catch {
    throw new RootError('MALFORMED', 'presentation has an unreadable disclosure');
  }
  if (protectedDisclosed.length) {
    throw new RootError('ROOT_INVALID', `the PID makes ${protectedDisclosed.join(', ')} selectively disclosable, which SD-JWT VC forbids`);
  }
  // Protected claims are read only from the issuer-signed plain text, never from disclosures (refused above):
  // a withheld digest and an absent claim look the same, so what is relied on must be in clear.
  const signed = decodeJwt(issuerJwt) as Record<string, unknown>;
  // Without exp a PID would never expire and a mandate could outlive it: SD-JWT VC PIDs carry one.
  if (typeof signed.exp !== 'number') throw new RootError('ROOT_INVALID', 'the PID has no exp');
  const accepted = opts.acceptedVcts ?? [PID_VCT];
  if (!accepted.includes(String(payload.vct))) {
    throw new RootError('ROOT_INVALID', `credential type ${String(payload.vct)} is not an accepted PID type`);
  }
  if (!verified.kb) throw new RootError('ROOT_INVALID', 'presentation has no key binding JWT');

  let pidStatus: StatusReference | undefined;
  const statusMode = opts.pidStatus ?? 'check';
  if (statusMode !== 'skip') {
    if (signed.status !== undefined) {
      if (!isStatusReference(signed.status)) throw new RootError('ROOT_INVALID', 'PID status reference is malformed');
      pidStatus = signed.status;
    } else if ((opts.requirePidStatus ?? true) && !providerWithoutStatus(iss, key.via, opts)) {
      throw new RootError('ROOT_INVALID', 'the PID has no status list entry, so its revocation cannot be checked');
    }
  }
  const kb = verified.kb.payload as Record<string, unknown>;
  if (boundTo === 'pid') requireTransactionDataHash(kb, root.transaction_data);

  const revocation = opts.certificateRevocation;
  if (revocation && revocation.policy !== 'off' && key.chain) {
    try {
      await checkChainRevocation(key.chain, revocation, opts.now);
    } catch (e) {
      if (e instanceof TrustError) throw new RootError('PID_ISSUER_UNTRUSTED', 'PID provider not trusted', e.message);
      throw e;
    }
  }

  const principal: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(payload)) if (!TECHNICAL_CLAIMS.has(k)) principal[k] = v;

  const deferred: DeferredStatus[] = [];
  const deferredCerts: DeferredCertificateCheck[] = [];
  const certCheck = (label: string, trust: TrustConfig, chain: string[] | undefined) => {
    const r = trust.certificateRevocation;
    if (chain && r && r.policy !== 'off') deferredCerts.push({ label, chain, revocation: r });
  };
  const present = (label: string, presentation: string, trust: TrustConfig, acceptedVcts: string[], untrusted: RootError['code']) =>
    verifyAttestationPresentation(presentation, {
      label,
      trust,
      acceptedVcts,
      nonce: kbNonce as string,
      aud: kb.aud,
      now: opts.now,
      skewSeconds: opts.skewSeconds,
    }).catch((e) => {
      if (e instanceof PresentationError) throw new RootError(e.kind === 'untrusted' ? untrusted : 'ATTESTATION_INVALID', e.message, e.detail);
      throw e;
    });

  let binding: RootBinding | undefined;
  let scaResponseMode: string | undefined;
  if (form.kind === 'emandate') {
    binding = { type: String(td.type), credential: boundTo };
    if (boundTo === SCA_QUERY_ID) {
      const em = opts.emandate!;
      const sca = await present('SCA attestation', extra![SCA_QUERY_ID], em.scaTrust!, em.scaVcts!, 'ATTESTATION_UNTRUSTED');
      requireTransactionDataHash(sca.kb, root.transaction_data);
      const ts12 = ts12KeyBindingProblem(sca.kb);
      if (ts12) throw new RootError('ATTESTATION_INVALID', `SCA key binding: ${ts12}`);
      const pidHolder = (payload.cnf as { jwk?: JWK } | undefined)?.jwk;
      if (!pidHolder) throw new RootError('ROOT_INVALID', 'the PID has no holder key');
      try {
        binding.sca_holder_binding = await bindToPidHolder(
          { holderJwk: sca.holderJwk, claims: sca.payload },
          { holderJwk: pidHolder, claims: principal },
          em.scaIdentityClaims ?? [],
        );
      } catch (e) {
        // A positive mismatch of identity claims is never overridden by same-response binding.
        const mismatch = (em.scaIdentityClaims?.length ?? 0) > 0;
        if (mismatch || !em.scaSameResponseBinding) throw new RootError('ATTESTATION_INVALID', `SCA attestation: ${(e as Error).message}`);
        // On behalf of a legal person, the approver must provably be the representative.
        if (mandate.principal !== undefined) {
          throw new RootError('ATTESTATION_INVALID', 'a mandate for a legal person needs the SCA attestation tied to the representative by key or claims');
        }
        binding.sca_holder_binding = 'same_response';
      }
      if (!sca.status && (em.requireScaStatus ?? true)) {
        throw new RootError('ATTESTATION_INVALID', 'the SCA attestation has no status list entry and cannot be revoked');
      }
      certCheck('SCA attestation issuer', em.scaTrust!, sca.certificateChain);
      binding.sca_issuer = sca.iss;
      binding.authentication_code = sca.kb.jti as string;
      scaResponseMode = sca.kb.response_mode as string;
      if (sca.status) deferred.push({ label: 'SCA attestation', ref: sca.status, issuer: sca.iss, trust: em.scaTrust! });
    }
  }

  let legal: { principal: LegalPersonPrincipal; info: RepresentationInfo } | undefined;
  if (mandate.principal !== undefined) {
    const ro = opts.representation!;
    const att = await present(
      'representation attestation',
      extra![REPRESENTATION_QUERY_ID],
      ro.trust,
      ro.acceptedVcts ?? [REPRESENTATION_VCT],
      'ATTESTATION_UNTRUSTED',
    );
    try {
      const pidHolder = (payload.cnf as { jwk?: JWK } | undefined)?.jwk;
      if (!pidHolder) throw new RepresentationError('ATTESTATION_INVALID', 'the PID has no holder key');
      const r = await checkRepresentation(
        att,
        { mandate, pidHolderJwk: pidHolder, pidClaims: principal, now: opts.now, skewSeconds: opts.skewSeconds ?? 60 },
        ro,
      );
      legal = { principal: r.principal, info: r.info };
      certCheck('representation attestation issuer', ro.trust, att.certificateChain);
      if (r.status) deferred.push({ label: 'representation attestation', ref: r.status, issuer: att.iss, trust: ro.trust });
    } catch (e) {
      if (e instanceof RepresentationError) throw new RootError(e.code, e.message);
      throw e;
    }
  }

  const result: RootResult = {
    mandate,
    principal,
    pidIssuer: String(iss),
    pidExp: signed.exp as number,
    approvedAt: Number(kb.iat),
    keyBinding: { nonce: kbNonce, aud: kb.aud, iat: Number(kb.iat) },
    trustedVia: key.via,
    ...(key.chain ? { pidCertificateChain: key.chain } : {}),
    ...((payload.cnf as { jwk?: JWK } | undefined)?.jwk ? { holderJwk: (payload.cnf as { jwk: JWK }).jwk } : {}),
  };
  if (legal) {
    result.legalPrincipal = legal.principal;
    result.representation = legal.info;
  }
  if (binding) result.binding = binding;
  if (scaResponseMode !== undefined) result.scaResponseMode = scaResponseMode;
  if (pidStatus) {
    if (statusMode === 'defer') result.pidStatus = pidStatus;
    else await checkPidStatus(pidStatus, iss, opts);
  }
  if (opts.attestationStatus === 'defer') {
    if (deferredCerts.length) result.deferredCertificates = deferredCerts;
    if (deferred.length) result.deferredStatus = deferred;
  } else {
    for (const c of deferredCerts) await checkAttestationCertificates(c, opts.now);
    for (const d of deferred) await checkAttestationStatus(d, opts);
  }
  return result;
}

interface RootForm {
  kind: 'plenipo' | 'emandate';
  mandate: Mandate;
  /** DCQL query id of the credential whose key binding must carry the transaction data hash. */
  boundTo: string;
}

/** Decides which form of root this is and checks what can be checked without cryptography. */
function selectForm(td: Record<string, unknown>, root: RootAuthorization, opts: RootOptions): RootForm {
  if (td.type === TX_DATA_TYPE && td.mandate) {
    if (root.mandate !== undefined) throw new RootError('MALFORMED', 'root.mandate is only used with e-mandate transaction data');
    return { kind: 'plenipo', mandate: td.mandate as Mandate, boundTo: 'pid' };
  }
  // TS12 e-mandate roots are experimental: accepted only by verifiers configured with `emandate`.
  const em = opts.emandate;
  const types = em?.types ?? [EMANDATE_TX_DATA_TYPE];
  if (typeof td.type !== 'string' || !types.includes(td.type)) {
    throw new RootError('TX_DATA_MISMATCH', `transaction_data type must be ${TX_DATA_TYPE}`);
  }
  if (!em) throw new RootError('ROOT_POLICY', 'this verifier does not accept e-mandate roots (set emandate to accept them)');
  if (em.refuse) throw new RootError('ROOT_POLICY', 'this service does not accept e-mandate roots');
  if (em.purposeCheck === 'none' && (!em.allowedActions || em.maxDelegationDepth === undefined)) {
    // Without the purpose text the person saw no actions and no depth: the service must bound them itself.
    throw new RootError('CONFIGURATION', "purposeCheck 'none' needs emandate.allowedActions and emandate.maxDelegationDepth");
  }
  const envelope = emandateEnvelopeProblems(td);
  if (envelope.length) throw new RootError('MALFORMED', `e-mandate transaction data: ${envelope.join('; ')}`);
  const mandate = root.mandate;
  // Shape only: the lifetime policy is the relying party's and is applied by the caller, as for any root.
  const shape = validateMandate(mandate, { maxLifetimeSeconds: Number.MAX_SAFE_INTEGER });
  if (shape.length) throw new RootError('MALFORMED', `root.mandate: ${shape.join('; ')}`);
  const m = mandate as Mandate;
  const boundTo = (td.credential_ids as string[])[0];
  if (boundTo !== 'pid' && boundTo !== SCA_QUERY_ID) throw new RootError('MALFORMED', 'the e-mandate must be bound to the pid or sca credential');
  if (boundTo === 'pid' && em.allowPidBinding === false) {
    throw new RootError('ROOT_POLICY', 'this service accepts e-mandates only when bound to an SCA attestation');
  }

  const violations = emandateViolations(td.payload, m, { purposeCheck: em.purposeCheck, describe: em.describe, allowedPayeeLogos: em.allowedPayeeLogos });
  for (const kind of ['shape', 'binding', 'display'] as const) {
    const found = violations.filter((v) => v.kind === kind);
    if (!found.length) continue;
    const code = kind === 'shape' ? 'MALFORMED' : kind === 'binding' ? 'TX_DATA_MISMATCH' : 'DISPLAY_MISMATCH';
    const what = kind === 'display' ? 'the mandate is broader than what the person was shown' : 'the e-mandate does not bind this mandate';
    throw new RootError(code, `${what}: ${found.map((v) => v.message).join('; ')}`);
  }
  if (em.allowedActions) {
    const outside = m.actions.filter((a) => !anyActionCovers(em.allowedActions!, a));
    if (outside.length) throw new RootError('ROOT_POLICY', `e-mandate roots may not grant ${outside.join(', ')}`);
  }
  if (em.maxDelegationDepth !== undefined && (m.delegation?.max_depth ?? 0) > em.maxDelegationDepth) {
    throw new RootError('ROOT_POLICY', `e-mandate roots may allow at most ${em.maxDelegationDepth} delegation levels`);
  }
  return { kind: 'emandate', mandate: m, boundTo };
}

function requireTransactionDataHash(kb: Record<string, unknown>, transactionData: string): void {
  const hashes = kb.transaction_data_hashes;
  const alg = kb.transaction_data_hashes_alg ?? 'sha-256';
  if (alg !== 'sha-256') throw new RootError('TX_DATA_MISMATCH', `unsupported transaction_data_hashes_alg ${String(alg)}`);
  if (!Array.isArray(hashes) || !hashes.includes(sha256(transactionData))) {
    throw new RootError('TX_DATA_MISMATCH', 'the wallet did not approve this mandate');
  }
}

const AMR_CATEGORIES = new Set(['knowledge', 'possession', 'inherence']);

/** TS12 section 3.6: the SCA key binding JWT carries jti, response_mode and amr with two factor categories. */
function ts12KeyBindingProblem(kb: Record<string, unknown>): string | undefined {
  if (typeof kb.jti !== 'string' || kb.jti.length < 16 || kb.jti.length > 256) return 'jti is missing';
  if (typeof kb.response_mode !== 'string' || kb.response_mode.length === 0) return 'response_mode is missing';
  const amr = kb.amr;
  if (!Array.isArray(amr) || amr.length > 10) return 'amr is missing';
  const categories = new Set<string>();
  for (const a of amr) {
    if (typeof a !== 'object' || a === null || Array.isArray(a)) return 'amr entries must be objects';
    const keys = Object.keys(a);
    if (keys.length !== 1 || !AMR_CATEGORIES.has(keys[0]) || typeof (a as Record<string, unknown>)[keys[0]] !== 'string') {
      return 'amr entries must name one authentication category';
    }
    categories.add(keys[0]);
  }
  if (categories.size < 2) return 'amr must show two different authentication categories';
  return undefined;
}

/**
 * Checks the revocation of an SCA or register certificate path, with the `certificateRevocation` of the
 * trust that accepted it. Throws RootError ATTESTATION_UNTRUSTED when revoked or not verifiable.
 */
export async function checkAttestationCertificates(c: DeferredCertificateCheck, now: number): Promise<void> {
  try {
    await checkChainRevocation(c.chain, c.revocation, now);
  } catch (e) {
    if (e instanceof TrustError) throw new RootError('ATTESTATION_UNTRUSTED', `${c.label} certificate is revoked or its status could not be verified`, e.message);
    throw e;
  }
}

/**
 * Checks the status of an SCA or representation attestation. The list must be signed for the attestation
 * issuer under the same trust that accepted the attestation, and served from that issuer's origin unless
 * the trust names `statusOrigins`. Throws RootError ATTESTATION_REVOKED unless the status is valid.
 */
export async function checkAttestationStatus(
  d: DeferredStatus,
  opts: { now: number; statusFetcher?: StatusFetcher; statusCache?: StatusListCache },
): Promise<void> {
  const allowedOrigins = d.trust.statusOrigins ?? [httpsOrigin(d.issuer)].filter((o): o is string => !!o);
  let status: number;
  try {
    status = await checkStatus(d.ref, {
      trust: d.trust,
      signer: d.issuer,
      allowedOrigins,
      fetcher: opts.statusFetcher,
      now: opts.now,
      cache: opts.statusCache,
    });
  } catch (e) {
    throw new RootError(e instanceof StatusUnavailableError ? 'STATUS_UNAVAILABLE' : 'ATTESTATION_REVOKED', `${d.label} status could not be verified`, (e as Error).message);
  }
  if (status !== 0) throw new RootError('ATTESTATION_REVOKED', `${d.label} is ${status === 2 ? 'suspended' : 'revoked'}`);
}

/** True when the PID provider `iss` is configured as issuing PIDs without status lists. */
function providerWithoutStatus(iss: string, via: 'issuer' | 'x5c', opts: RootOptions): boolean {
  if (via === 'issuer') return opts.trustedIssuers?.find((t) => t.iss === iss)?.withoutStatusList === true;
  return opts.pidProvidersWithoutStatus?.includes(iss) === true;
}

function statusOriginsOf(trust: TrustConfig): string[] {
  if (trust.statusOrigins) return trust.statusOrigins;
  return (trust.trustedIssuers ?? []).map((t) => httpsOrigin(t.iss)).filter((o): o is string => o !== undefined);
}

/** Checks the status of a PID issued by `pidIss`. Throws RootError PID_REVOKED unless it is valid. */
export async function checkPidStatus(ref: StatusReference, pidIss: string, opts: RootOptions): Promise<void> {
  const origin = httpsOrigin(ref.status_list.uri);
  const custom = opts.pidStatusTrust;
  const check = custom
    ? { trust: custom, signer: origin ?? '', allowedOrigins: statusOriginsOf(custom) }
    : { trust: opts as TrustConfig, signer: pidIss, allowedOrigins: [httpsOrigin(pidIss)].filter((o): o is string => !!o) };
  let status: number;
  try {
    status = await checkStatus(ref, { ...check, fetcher: opts.statusFetcher, now: opts.now, cache: opts.statusCache });
  } catch (e) {
    throw new RootError(e instanceof StatusUnavailableError ? 'STATUS_UNAVAILABLE' : 'PID_REVOKED', 'PID status could not be verified', (e as Error).message);
  }
  if (status !== 0) throw new RootError('PID_REVOKED', `PID status is ${status === 2 ? 'suspended' : 'revoked'}`);
}
