import type { JWK } from 'jose';

export const MANDATE_VERSION = '0.1';
export const TX_DATA_TYPE = 'plenipo_mandate';
export const DELEGATION_TYP = 'plenipo-delegation+jwt';
export const INVOCATION_TYP = 'plenipo-invocation+jwt';
export const PID_VCT = 'urn:eudi:pid:1';
/** TS12 e-mandate transaction data type (EUDI TS12 v1.0, section 4.3.4). */
export const EMANDATE_TX_DATA_TYPE = 'urn:eudi:sca:emandate:1';
/** Experimental representation attestation type defined by Plenipo (see docs/root.md). */
export const REPRESENTATION_VCT = 'urn:plenipo:representation:1';

/**
 * Spending limits. Amounts are integers in the ISO 4217 minor unit of `currency`: 1/100 for EUR, 1 for JPY,
 * 1/1000 for KWD (`currencyMinorDigits`). Not always cents.
 */
export interface Limits {
  /** ISO 4217 currency code. */
  currency: string;
  /** Maximum amount of a single invocation, in ISO 4217 minor units. */
  per_operation?: number;
  /** Maximum sum under this mandate and everything delegated from it, in ISO 4217 minor units. */
  total?: number;
}

export interface Mandate {
  v: typeof MANDATE_VERSION;
  id: string;
  agent: { jwk: JWK };
  /** Dotted action names; `x.*` covers everything below x, `*` covers everything. */
  actions: string[];
  /** Host names; `*.example.com` covers sub-domains and example.com. Absent means any. */
  counterparties?: string[];
  limits?: Limits;
  nbf: number;
  exp: number;
  delegation?: { max_depth: number };
  purpose?: string;
  /** IETF Token Status List entry, so the mandate can be revoked without a shared registry. */
  status?: { status_list: { uri: string; idx: number } };
  /**
   * Experimental: the mandate is given on behalf of a legal person. Only meaningful on a root mandate;
   * the root must then carry a representation attestation for this EUID (see docs/root.md).
   */
  principal?: LegalPrincipal;
}

/** The legal person a root mandate is given for, as approved by its representative. */
export interface LegalPrincipal {
  type: 'legal_person';
  /** European Unique Identifier of the legal person. */
  euid: string;
  /** Role code the representative acts in; when present the attestation must state exactly this role. */
  role?: string;
}

/** The transaction data object the wallet approves, before base64url encoding. */
export interface MandateTransactionData {
  type: typeof TX_DATA_TYPE;
  credential_ids: string[];
  mandate: Mandate;
}

export interface RootAuthorization {
  /** base64url-encoded MandateTransactionData, exactly as sent to the wallet. */
  transaction_data: string;
  /** PID SD-JWT VC presentation with a key binding JWT. */
  presentation: string;
  /**
   * The full mandate, for roots whose transaction data is a TS12 e-mandate: the e-mandate only shows a
   * summary and binds this object by hash through its `reference_number`.
   */
  mandate?: Mandate;
  /**
   * Further presentations from the same wallet response, by DCQL credential query id: `sca` (the SCA
   * attestation a TS12 e-mandate is bound to) and `representation` (the role attestation for a legal person).
   */
  presentations?: Record<string, string>;
}

export interface MandateChain {
  root: RootAuthorization;
  /** Compact JWS delegations, from the root agent down to the leaf agent. */
  delegations: string[];
}

export interface DelegationPayload {
  mandate: Mandate;
  parent_id: string;
  parent_hash: string;
  iat: number;
}

export interface Amount {
  value: number;
  currency: string;
}

export interface InvocationPayload {
  mandate: string;
  action: string;
  counterparty?: string;
  amount?: Amount;
  aud: string;
  nonce: string;
  iat: number;
  /** Optional hash binding the invocation to the tool arguments. */
  args_hash?: string;
  /** Hash of the mandate chain presented with the invocation (see `chainHash`). Required by the verifier. */
  chain_hash: string;
  /**
   * Idempotency key: the same value in every attempt of one intention, so that at most one attempt runs
   * (see `src/idempotency.ts`). Requires `args_hash`.
   */
  idem?: string;
}

export interface TrustedIssuer {
  iss: string;
  jwk: JWK;
  /**
   * For PID providers only: this provider issues PIDs without a status list entry (short-lived PIDs), so its
   * PIDs are accepted without one. Absent: a PID without status is refused (`requirePidStatus`).
   */
  withoutStatusList?: boolean;
}

export type DenyCode =
  | 'CONFIGURATION'
  | 'MALFORMED'
  | 'INVOCATION_MISMATCH'
  | 'ROOT_INVALID'
  | 'PID_ISSUER_UNTRUSTED'
  | 'PID_REVOKED'
  | 'TX_DATA_MISMATCH'
  | 'LIFETIME_POLICY'
  | 'DELEGATION_SIGNATURE_INVALID'
  | 'DELEGATION_PARENT_MISMATCH'
  | 'DELEGATION_NOT_ALLOWED'
  | 'ATTENUATION_VIOLATION'
  | 'NOT_YET_VALID'
  | 'EXPIRED'
  | 'REVOKED'
  | 'INVOCATION_SIGNATURE_INVALID'
  | 'INVOCATION_MANDATE_MISMATCH'
  | 'INVOCATION_STALE'
  | 'AUDIENCE_MISMATCH'
  | 'REPLAY'
  | 'ACTION_NOT_PERMITTED'
  | 'COUNTERPARTY_NOT_PERMITTED'
  | 'CURRENCY_MISMATCH'
  | 'LIMIT_PER_OPERATION'
  | 'LIMIT_TOTAL'
  | 'DISPLAY_MISMATCH'
  | 'ROOT_POLICY'
  | 'ATTESTATION_UNTRUSTED'
  | 'ATTESTATION_INVALID'
  | 'ATTESTATION_REVOKED'
  | 'ROLE_EXCEEDED'
  /** A status list or revocation source could not be fetched or verified. Still a denial; a retry may succeed. */
  | 'STATUS_UNAVAILABLE'
  /** The idempotency key was already used for a different request. */
  | 'IDEMPOTENCY_CONFLICT'
  /** An attempt with this idempotency key is still running; a retry later may get its result. */
  | 'IDEMPOTENCY_IN_PROGRESS'
  /** An attempt with this idempotency key ended with an unknown outcome; the service must reconcile it first. */
  | 'IDEMPOTENCY_UNRESOLVED'
  /** An attempt with this idempotency key already executed; the decision may carry its stored result. */
  | 'ALREADY_EXECUTED'
  /** An unexpected error (a store or registry that threw). Details only in `detail`. */
  | 'INTERNAL';

export interface PathEntry {
  depth: number;
  mandate_id: string;
  actions: string[];
  exp: number;
}

export type Decision =
  | {
      decision: 'ALLOW';
      principal: Record<string, unknown>;
      pid_issuer: string;
      /** How the PID provider was trusted: an explicit key, or an x5c chain to a trust anchor. */
      pid_trusted_via: 'issuer' | 'x5c';
      path: PathEntry[];
      /** The mandate chain, root first. */
      mandates: Mandate[];
      /** The verified invocation: what exactly was authorised. */
      invocation: InvocationPayload;
      /**
       * Present when the root is given on behalf of a legal person: how the representation attestation
       * was verified. `principal` then describes the legal person, the role and the representative.
       */
      representation?: RepresentationInfo;
      /** Present when the root is a TS12 e-mandate: which credential the wallet bound it to. */
      root_binding?: RootBinding;
      /**
       * Present when the amount was reserved against a total limit. The caller must commit it
       * after performing the action, or release it if the action does not happen.
       */
      reservation?: string;
      /**
       * Present when the invocation carries an idempotency key: the attempt that now holds it. The caller
       * must end it on the idempotency store with the outcome of the action (`finish`), as it settles the
       * reservation; an attempt never ended blocks the key until reconciled.
       */
      idempotency?: { key: string; attempt: string };
      /**
       * RFC 7638 SHA-256 thumbprint of the PID holder key (`cnf.jwk`). Distinguishes people with the same
       * name; a wallet that uses a fresh key per PID copy yields a different value per copy.
       */
      pid_holder_jkt?: string;
    }
  | {
      decision: 'DENY';
      code: DenyCode;
      reason: string;
      /** Index in the chain where the failure occurred, when it applies. */
      at?: number;
      /** Internal detail for logs (network errors, library messages). The MCP guard never returns it. */
      detail?: string;
      path: PathEntry[];
      /** With `ALREADY_EXECUTED`: what the service stored when the first attempt ran, if it kept anything. */
      replay?: { result?: string };
    };

/** Principal of a Decision whose root mandate was given on behalf of a legal person. */
export interface LegalPersonPrincipal {
  type: 'legal_person';
  euid: string;
  /** Present when the wallet disclosed it. */
  legal_name?: string;
  role: { code: string; name?: string; basis: 'legal_representation' | 'power_of_attorney' };
  /** PID claims of the natural person who approved the mandate. */
  representative: Record<string, unknown>;
}

export interface RepresentationInfo {
  /** Issuer of the representation attestation (business register or the legal person's Business Wallet). */
  register: string;
  trusted_via: 'issuer' | 'x5c';
  /** How the attestation was tied to the person: same holder key as the PID, or matching identity claims. */
  holder_binding: 'cnf' | 'claims';
}

export interface RootBinding {
  /** Transaction data type, e.g. urn:eudi:sca:emandate:1. */
  type: string;
  /** DCQL query id of the credential whose key binding JWT signed the transaction data: `pid` or `sca`. */
  credential: string;
  /** Issuer of the SCA attestation, when bound to one. */
  sca_issuer?: string;
  /** How the SCA attestation was tied to the PID holder: same key, matching claims, or only the same response. */
  sca_holder_binding?: 'cnf' | 'claims' | 'same_response';
  /** TS12 authentication code (key binding `jti`), when bound to an SCA attestation. */
  authentication_code?: string;
}
