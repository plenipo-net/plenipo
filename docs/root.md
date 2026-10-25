# Root authorisation: TS12 e-mandates and legal persons

Status: experimental, shipped in v0.3. Both features change what a relying party accepts as the root of
a mandate chain, so both are opt-in on the verifier side, and both fail closed. Their helpers are exported
from `plenipo/experimental` and may change in any minor release, because TS12 is still a draft and the
representation attestation is a Plenipo-defined format.

This document covers:

1. the alignment of the root with the TS12 e-mandate transaction data type, so that certified EUDI
   wallets (and IT-Wallet) can render the approval;
2. mandates given on behalf of a legal person, approved by a natural person who presents a
   representation attestation next to the PID.

## 1. TS12 e-mandates

### Why

OpenID4VP requires a wallet to reject transaction data of a type it does not support. Certified EUDI
wallets will support the closed catalogue of EUDI TS12 ("Electronic payments SCA implementation with
wallet", v1.0 of 2025-12-05, editorial v1.0.1 of 2026-01-30), not `plenipo_mandate`. TS12 defines four
types; the one closest to a mandate for an agent is `urn:eudi:sca:emandate:1`, and TS12 says it "may get
amended in a future version of this specification to also cover usages in the context of agentic
commerce".

### What TS12 actually requires (and what it means for Plenipo)

From TS12 sections 3, 4.2, 4.3 and the published JSON schemas:

- The transaction data object is `{ type, credential_ids, transaction_data_hashes_alg, payload }`; the
  e-mandate payload has `transaction_id` (required, 1 to 36 characters), `date_time`, `start_date`,
  `end_date` (RFC 3339 date-times), `reference_number` (up to 50), `creditor_id` (up to 50), `purpose` (up
  to 1000, required when there is no `payment_payload`) and `payment_payload` (an
  `urn:eudi:sca:payment:1` object: `transaction_id`, `payee {name, id, logo, website}`, `currency`,
  `amount` in major units, `recurrence {start_date, end_date, number, frequency, mit_options {max_amount,
  total_amount, ...}}`, ...). The schema has `additionalProperties: false`: no extra fields are allowed.
- **TS12 transaction data is bound to an SCA attestation, not to the PID.** The wallet processes it only for
  an attestation whose type metadata has category `urn:eu:europa:ec:eudi:sua:sca` and lists the
  transaction data type in `transaction_data_types` (sections 3 and 3.2; ARF topic, SUA_07). The
  attestation is issued by the payer's PSP; TS12 does not define its vct, and no SCA Attestation Rulebook
  exists yet. A TS12 wallet asked to bind an e-mandate to the PID refuses the request.
- The key binding JWT of the SCA presentation signs `transaction_data_hashes` and carries `jti` (the PSD2
  authentication code), `response_mode` and `amr` with at least two authentication categories (section 3.6).
- The `type` value is the key in the attestation's `transaction_data_types`; `urn:eudi:sca:emandate:1` is the
  schema of the built-in type. Plenipo uses the URN as type by default and makes it configurable.

### Design

`createMandateRequest({ transactionDataType: 'emandate', emandate: { scaVcts } })` puts one transaction data
object of type `urn:eudi:sca:emandate:1` in the request, bound to an SCA attestation requested with a
second DCQL query (`sca`), next to the PID query (`pid`). The full Plenipo mandate no longer travels in the
transaction data: it is kept in the request session and returned in `RootAuthorization.mandate`.

| Plenipo mandate | E-mandate field | Shown to the person |
| --- | --- | --- |
| `id` | `transaction_id`, `payment_payload.transaction_id` | yes (logged by the wallet) |
| SHA-256 of the canonical mandate (`mandateHash`) | `reference_number` | yes, as an opaque string |
| `nbf`, `exp` | `start_date`, `end_date`, and `recurrence.start_date`, `recurrence.end_date` | yes |
| `limits.per_operation` | `payment_payload.amount` and `mit_options.max_amount` (major units) | yes |
| `limits.total` | `mit_options.total_amount` | yes |
| `limits.currency` | `payment_payload.currency` | yes |
| single `counterparties` entry | `payment_payload.payee` (`id` = host pattern, `name` = the same host, `website` = `https://<host>`) | yes |
| `actions`, `counterparties`, `limits`, validity, `delegation.max_depth`, `purpose`, legal `principal` | `purpose` text (`describeMandate`) | yes, in words |
| `agent.jwk`, `status`, `v` | none | **bound by hash, not displayed** |

`payment_payload` is emitted only when the mandate has limits and a single payee can be shown (exactly one
counterparty, or an explicit `emandate.payee` that covers all of them). Otherwise the limits appear only in
the purpose text. The payee shows nothing that is not enforced: `name` is the host pattern itself,
`website` (optional) is `https://` plus the concrete host, and `logo` is accepted only from the relying
party's `allowedPayeeLogos`, since a name or logo of the platform's choosing ("Your landlord") would tell the
person something other than where the money can go. `recurrence.frequency` is `INDA` (several times a day), the least restrictive code,
because Plenipo does not limit how often an agent acts; `amount_variable: true` and `amount_estimated:
true` say the shown amount is a ceiling.

The default purpose text is deterministic English, for example:

```
Mandate for an AI agent. Actions: payments.sepa. Counterparties: shop.example. Limits: 150.00 EUR per
operation, 300.00 EUR in total. Valid from 2026-10-19T10:00:00Z to 2026-10-26T10:00:00Z. Sub-delegation:
up to 1 level. Purpose: Pay the shop invoices
```

A platform can pass its own `describe` function (for another language); the verifier must use the same.
The mandate `purpose` embedded in the text is limited by `validateMandate` to 500 characters, without
control, format or line/paragraph separator characters (Unicode Cc, Cf, Zl, Zp: line breaks, U+2028/U+2029,
bidi overrides, zero-width characters), without leading or trailing whitespace and without runs of two or
more whitespace characters. Such purposes are refused, not normalised, because the mandate is signed and
hashed exactly as given: a purpose cannot fake further lines of the description, push text out of view or
reorder what the person reads.

### Verification

`verifyRoot` (and so `verifyAuthorization` and `handleMandateResponse`) accepts both forms. For an e-mandate:

1. The transaction data is strict base64url of canonical JSON, the envelope has only the four TS12 members,
   one credential id (`pid` or `sca`) and `sha-256`.
2. `root.mandate` is a well-formed mandate. `transaction_id` equals its id and `reference_number` equals its
   hash, otherwise `TX_DATA_MISMATCH`.
3. **The mandate is not broader than what was shown** (`emandateViolations`, otherwise `DISPLAY_MISMATCH`):
   - shown `start_date` <= `nbf` and shown `end_date` >= `exp` (also for the recurrence dates), compared in
     milliseconds; only date-times with an explicit offset are accepted;
   - the shown per-operation ceiling (`max_amount`, else `amount` unless `amount_variable`) >= the mandate's
     effective per-operation limit (the smaller of `per_operation` and `total`);
   - the shown total (`total_amount`; `amount` for a single non-recurring payment; unbounded for a recurrence
     without `total_amount`) >= the mandate total, and an unlimited mandate never passes a bounded display;
   - when a payment is shown: the mandate has limits in the same currency, the payee id is a host pattern and
     covers every mandate counterparty, and a mandate open to any counterparty fails;
   - the payee `name` equals its `id`, a `website` is `https://<id>` for a concrete host only, and a `logo`
     must be in `allowedPayeeLogos`;
   - amounts must convert exactly to ISO 4217 minor units (no negative values, exponents or extra decimals);
   - fields Plenipo cannot enforce (`execution_date`, `recurrence.number`, a frequency other than `INDA`,
     `min_amount`, `initial_amount`, `apr`, `creditor_id`, `pisp`, `sct_inst`, `amount_earmarked`, unknown
     members) fail, because the person would have seen a restriction nobody checks;
   - with `purposeCheck: 'exact'` (default) the purpose equals `describe(mandate)`. With `'none'` the purpose
     is free text and binds nothing, so the e-mandate must show a `payment_payload`: a mandate without limits
     or open to any counterparty cannot be approved that way.
   A display wider than the mandate is accepted.
4. Policy: `emandate.refuse`, `emandate.allowedActions` (every mandate action must be covered, so `*` is never
   covered by `payments.*`), `emandate.maxDelegationDepth`, `emandate.allowPidBinding: false`; failures give
   `ROOT_POLICY`. `purposeCheck: 'none'` is refused with `CONFIGURATION` unless both `allowedActions` and
   `maxDelegationDepth` are set, since actions and depth are then not shown at all.
5. The PID presentation is verified as before. If the e-mandate is bound to `pid`, its key binding must sign
   the transaction data. If bound to `sca`:
   - `emandate.scaTrust` and `emandate.scaVcts` must be configured (`CONFIGURATION` otherwise);
   - the SCA presentation is signed by a trusted PSP (explicit keys or x5c, `ATTESTATION_UNTRUSTED`), has an
     accepted vct, and its key binding JWT has the same `nonce` and `aud` as the PID's, signs the transaction
     data hash, and carries TS12 `jti`, `response_mode` and `amr` with two categories;
   - the SCA attestation is tied to the PID holder (see below);
   - it must carry a status list entry (`emandate.requireScaStatus`, default true), which is checked
     (`ATTESTATION_REVOKED`, or `STATUS_UNAVAILABLE` when the list cannot be fetched);
   - when `scaTrust.certificateRevocation` is set, the PSP certificate path is checked with CRL/OCSP
     (`ATTESTATION_UNTRUSTED` when revoked or not verifiable);
   - in `verifyAuthorization` both checks run after the invocation and scope checks, in
     `handleMandateResponse` after the response is bound to the request.
6. `handleMandateResponse` also checks that the SCA key binding names the request's `response_mode`.

The Decision carries `root_binding: { type, credential, sca_issuer, sca_holder_binding,
authentication_code }` for e-mandate roots.

### Tying the SCA attestation to the PID holder

With TS12 only the SCA key binding JWT signs the e-mandate. The PID shares its nonce and audience, but those
are chosen by the platform that sent the request. A malicious platform can collect a PID presentation from
Alice (for example from a request she thinks is a login, using the same nonce) and an SCA approval from
Mallory, and present them as one root: the Decision would name Alice as the principal of a mandate she never
approved. The test `does not let a platform pair one person's PID with another person's SCA approval`
reproduces it.

The SCA attestation is therefore accepted only when:

- it has the same holder key (`cnf`) as the PID (`sca_holder_binding: 'cnf'`); or
- `emandate.scaIdentityClaims` lists claims (for example a national personal number the bank puts in its
  attestation) that are disclosed in both credentials and equal (`'claims'`); request them with
  `createMandateRequest({ emandate: { scaIdentityClaims } })`; or
- the relying party opts in to `emandate.scaSameResponseBinding: true` (`'same_response'`), accepting the
  attack above. A mismatch of configured identity claims is never overridden by this option, and a mandate
  on behalf of a legal person never accepts it.

Real SCA attestations will usually have their own key and no identity claims, so a deployment has to choose.
A bank verifying its own SCA attestation can instead map the attestation subject to its customer; Plenipo does
not do that.

### Protected claims and selective disclosure

SD-JWT VC forbids issuers to make `iss`, `nbf`, `exp`, `iat`, `cnf`, `vct`, `vct#integrity` and `status`
selectively disclosable. A non-compliant issuer that does lets the holder withhold them, and an absent
`status` or `exp` reads as "never revoked" or "never expires". Plenipo therefore:

- refuses any PID, SCA or representation presentation that discloses one of these claims, at any depth;
- reads `status` and `exp` only from the issuer-signed plain text, never from disclosures: a withheld
  digest cannot be told from an absent claim;
- requires `exp` in the PID and in every attestation, `status` in representation attestations, `status` in
  SCA attestations by default (`emandate.requireScaStatus`), and `status` in the PID by default
  (`requirePidStatus`, `ROOT_INVALID` when missing). A provider that issues short-lived PIDs without status
  lists must be declared: `TrustedIssuer.withoutStatusList: true` for a key-trusted provider, or its `iss` in
  `pidProvidersWithoutStatus` for an x5c-trusted one. For a declared provider a withheld status is accepted,
  so declare only providers that never use status lists. `requirePidStatus: false` turns the requirement off
  for all providers. The test PID provider sets `withoutStatusList` on its `trusted` entry when created
  without a status list;
- residual: `nbf` is honoured only when it is in plain text; a provider that made it disclosable lets the
  holder present a credential before its start. Plenipo cannot detect this without refusing every credential
  with selectively disclosable claims.

### PID binding (not TS12-conformant)

`emandate: { credential: 'pid' }` binds the e-mandate to the PID key binding JWT, which gives the same
person-to-approval binding as `plenipo_mandate`. TS12 wallets refuse it; it serves wallets whose transaction
data types are configurable (walt.id profiles) and tests. Verifiers configured with `emandate` accept it
unless `emandate.allowPidBinding` is `false`; verifiers without `emandate` refuse every e-mandate root with
`ROOT_POLICY`.

### API

All of these come from `plenipo/experimental`, except `createMandateRequest` and the option types of
`VerifyOptions` and `RootOptions`, which come from `plenipo`.

```ts
mandateToEmandate(mandate, { payee?, describe? }): EmandatePayload      // throws if it cannot show the mandate faithfully
encodeEmandateTransactionData(payload, { credentialId?, type? }): string
emandateViolations(payload, mandate, { purposeCheck?, describe? }): EmandateViolation[]  // kind: shape | binding | display
describeMandate(mandate): string
toMajorUnits(minor, currency): number;  toMinorUnits(major, currency): number | undefined
parseDateTime(value): number | undefined
createMandateRequest({ ..., transactionDataType: 'emandate', emandate: { credential?, scaVcts?, scaIdentityClaims?, type?, payee?, describe? } })
VerifyOptions.emandate / RootOptions.emandate: EmandateVerifyOptions
  { refuse?, types?, scaTrust?, scaVcts?, allowPidBinding?, allowedActions?, maxDelegationDepth?,
    purposeCheck?, describe?, scaIdentityClaims?, scaSameResponseBinding? }
checkAttestationStatus(deferred, { now, statusFetcher?, statusCache? })
checkAttestationCertificates(deferredCertificateCheck, now)
currencyMinorDigits(currency): number;  NON_DECIMAL_CURRENCY_EXPONENTS
disclosedProtectedClaims(presentation): string[];  PROTECTED_CLAIMS
EmandateCheckOptions.allowedPayeeLogos;  EmandateVerifyOptions.requireScaStatus
```

Amounts and limits are integers in the ISO 4217 minor unit of their currency (cents for EUR, but whole units
for JPY and thousandths for KWD); TS12 shows them in major units with `currencyMinorDigits` decimals.

### Deviations and limits

- TS12 v1.0 has no agentic-commerce variant yet. The mapping above is an approximation: a TS12 payee is one
  payee with a payment-system identifier, while Plenipo uses host names and may allow several; `frequency
  INDA` with `amount_variable` describes "any number of payments up to the ceiling"; `reference_number` shows
  a hash. If TS12 is amended for agents, the mapping should follow it.
- The wallet only renders the e-mandate if the SCA attestation metadata lists the type, i.e. if the payer's
  PSP enables it. No SCA Attestation Rulebook exists yet; the SCA vct is configuration.
- The agent key is never shown. The person cannot tell which agent receives the mandate, only that it is the
  one named in the hashed mandate. This is also true of `plenipo_mandate` in practice.
- The purpose text is English by default and must be recomputed identically by the verifier.
- Date-only values allowed by the TS12 prose are refused, as the TS12 schema requires date-times.

## 2. Legal persons and role mandates

### Context

- European Business Wallet regulation, Council general approach (2025/0358(COD); text in doc 9684/26 of
  2 June 2026, outcome of proceedings in ST 10346/26 of 10 June 2026): art. 3(19) defines an authorisation
  as "the granting or recognition of a right or permission by a European Business Wallet owner"; recital 18 and art. 5(1)(j) make such authorisations
  technical, without effect on powers of attorney or legal mandates; art. 6(2)(b) requires that "conflicts
  of roles, over-delegation, or expired authorisations are automatically detected and prevented in
  real-time"; art. 9 uses the EUID as the owner identifier.
- EWC RFC005 defines LPID (legal person identification data) as an SD-JWT VC with `legal_person_id` (EUID)
  and `legal_person_name`.

There is no standard yet for an attestation that says "this natural person may act for this legal person,
within these powers". Plenipo defines an experimental one, with a configurable vct so that a real register
format can be mapped later.

### Model

A root mandate may carry `principal: { type: 'legal_person', euid, role? }`. It is part of the mandate, so it
is shown by the wallet (in `plenipo_mandate`, and in the e-mandate purpose text) and bound by hash. Use
`createLegalMandate`.

The natural person approves in their wallet with their PID and presents, in the same response, a
representation attestation. `createMandateRequest` adds the DCQL query `representation` automatically when the
mandate has a legal principal.

### Attestation format: `urn:plenipo:representation:1`

SD-JWT VC, signed by a business register or by the legal person's own Business Wallet, key-bound with `cnf`.

| Claim | Type | Meaning |
| --- | --- | --- |
| `iss`, `iat`, `nbf`, `exp`, `vct`, `cnf` | standard | `exp` bounds the mandate lifetime |
| `status` | Token Status List reference | required by default, so the attestation can be revoked in real time |
| `legal_person_id` | string | EUID (RFC005 name) |
| `legal_person_name` | string, disclosable | registered name (RFC005 name) |
| `representative` | object, members disclosable | identity of the natural person (e.g. `given_name`, `family_name`, `personal_administrative_number`), for claim binding |
| `role` | object, **plain text** | see below; the whole object must be signed in clear |
| `role.code` | string | e.g. `managing_director`, `procurator` |
| `role.name` | string, optional | display name |
| `role.basis` | `legal_representation` or `power_of_attorney` | where the power comes from; technical Business Wallet roles are not accepted |
| `role.valid_from`, `role.valid_until` | integers, optional | role validity |
| `powers` | object, **plain text** | see below; the whole object must be signed in clear |
| `powers.actions` | string[] | Plenipo action patterns the role may grant |
| `powers.counterparties` | string[], optional | host patterns |
| `powers.limits` | `{ currency, per_operation?, total? }`, optional | ISO 4217 minor units |
| `powers.max_delegation_depth` | integer, optional | maximum `delegation.max_depth` of a mandate given in this role |

**`role` and `powers` must not be selectively disclosable, at any depth.** Their optional members are
restrictions, and a withheld restriction would read as "unrestricted": a register making `powers.limits` or
`role.valid_until` disclosable would let the holder (or a platform that shapes the DCQL query) drop them. The
verifier reads both objects from the issuer-signed JWT payload, not from the disclosed claims, and refuses
the attestation (`ATTESTATION_INVALID`) if either is missing there or contains `_sd` digests or array
element digests. `exp` and `status` are also required.

### Verification

With `representation: { trust, acceptedVcts?, identityClaims?, euidScopes?, acceptedBases?, requireStatus? }`
configured (otherwise `CONFIGURATION`):

1. The root carries exactly the presentations it needs; a missing representation presentation gives
   `ATTESTATION_INVALID`, an unneeded one `MALFORMED`.
2. The attestation is signed by an issuer trusted under `representation.trust` (explicit keys or x5c chains,
   as for PID providers), for the identity in its `iss`; otherwise `ATTESTATION_UNTRUSTED`. With
   `euidScopes`, the issuer may only attest for the listed EUIDs or prefixes (`IT*`), so a company's own
   Business Wallet cannot attest for another company.
3. Its key binding JWT has the same `nonce` and `aud` as the PID's, and its vct is accepted.
4. Claims are well formed, `legal_person_id` equals the mandate's `principal.euid`, `role.code` equals
   `principal.role` when given, the basis is accepted, a status entry exists (unless `requireStatus: false`).
5. The role is valid now (`valid_from` with clock skew, `valid_until` and attestation `exp` without), on every
   verification, not only at approval.
6. The attestation is tied to the PID holder: same `cnf` key (`holder_binding: 'cnf'`), or, when
   `identityClaims` is configured, those claims are disclosed in the PID and in `representative` and equal
   (`'claims'`). Otherwise `ATTESTATION_INVALID`.
7. The mandate is within the role's powers (`rolePowerViolations`, otherwise `ROLE_EXCEEDED`): every action
   covered, counterparties within the role's, same currency, effective per-operation limit and total not
   above the role's (a role total requires a mandate total), delegation depth not above
   `max_delegation_depth`, and the mandate window inside the role window and before the attestation `exp`.
8. The status list is checked (`ATTESTATION_REVOKED` when revoked or suspended, `STATUS_UNAVAILABLE` when it
   cannot be fetched). It must be signed for the attestation issuer under the same trust and served from the
   issuer's origin (or `trust.statusOrigins`). With `representation.trust.certificateRevocation`, the register
   certificate path is also checked with CRL/OCSP (`ATTESTATION_UNTRUSTED`). In `verifyAuthorization` these
   run after the invocation and scope checks, so an unauthenticated caller causes no fetch.
9. A delegation in the chain may not carry `principal`; only the root says on whose behalf the agent acts.

The Decision then has:

```json
{
  "principal": {
    "type": "legal_person",
    "euid": "ITRM.RM1234567",
    "legal_name": "Acme S.p.A.",
    "role": { "code": "managing_director", "name": "Amministratore delegato", "basis": "legal_representation" },
    "representative": { "given_name": "Mario", "family_name": "Rossi" }
  },
  "representation": { "register": "https://register.example", "trusted_via": "x5c", "holder_binding": "cnf" }
}
```

`requiredPrincipalClaims` still refers to the PID claims of the representative.

Identity claims listed in `representation.identityClaims` (and `emandate.scaIdentityClaims`) are added to
the PID DCQL query by `createMandateRequest`, so claim binding works without listing them in `disclose`.

### Shared trust anchors

PID providers, PSPs and registers may be certified under the same CA (for example one national anchor). A
certificate issued for one role would then be accepted in another: a PSP certificate could sign "PIDs", a
PID provider certificate could sign representation attestations. Configure each trust (`trustAnchors`,
`emandate.scaTrust`, `representation.trust`) with `requiredPolicyOids` or `requiredEkus` that only the
intended role carries, or with separate anchors. Plenipo does not impose a default policy, to stay
compatible with existing configurations.

### Holder binding trade-off

- **Same key (`cnf`)**: cryptographic. The person who signed with the PID key also holds the attestation key.
  It needs the register (or the Business Wallet) to issue the attestation to the key of the PID, which EUDI
  wallets do not do by default (keys are usually per credential).
- **Identity claims**: works with independent keys. It shows the attestation names the PID holder, not that
  the same device holds both keys. Names collide; prefer unique identifiers. Both presentations are still
  bound to the same request, and in the `plenipo_mandate` and PID-bound forms the PID key binding signs the
  mandate, so the approver is the person the PID names.

Same-response binding alone is not offered for representation attestations.

### Limits

- The attestation format is Plenipo's own; a register-issued standard (or LPID plus a separate mandate
  credential) should replace it when one exists. `acceptedVcts` lets a deployment accept another vct with
  the same claims.
- The register is trusted both for the existence of the legal person and for the role; LPID is not checked
  separately.
- A role total limit caps each mandate's total; spending is not aggregated across mandates of the same role.
- A mandate cannot outlive the attestation, so short-lived attestations mean short mandates.
- Chains of powers of attorney (a procurator granting a sub-power) are not modelled.

## HTTP transport

The `Plenipo-Chain` header carries the root as is: `asMandateChain` accepts the optional `root.mandate` (an
object) and `root.presentations` (only `sca` and `representation`, non-empty strings up to 64 KiB each), and
keeps refusing any other member. Roots with extra presentations are larger: raise `maxChainHeaderBytes`
and the HTTP server's header size limit accordingly.

## Error codes added

`DISPLAY_MISMATCH`, `ROOT_POLICY`, `ATTESTATION_UNTRUSTED`, `ATTESTATION_INVALID`, `ATTESTATION_REVOKED`,
`ROLE_EXCEEDED` (appended to `DenyCode`; also `RootError.code`).

## Security review (R1 to R10)

Regression tests in test/root-review.test.ts cover the findings of the independent review: role and powers
made selectively disclosable (R1); payee name, website and logo not following the enforced counterparty
(R2); free-text purpose under `purposeCheck: 'none'` (R3); protected claims disclosed or withheld (R4);
revocation of PSP and register certificates (R5); e-mandate and legal person roots over the HTTP transport,
through a gateway (R6); identity claims in the PID query (R7); ISO 4217 minor units (R8); no PID status or
certificate fetch before the response is bound to the request (R9); purpose length and control characters
(R10). A second review added: a PID status the holder withholds (P2-2, now refused unless the provider is
declared as issuing PIDs without status) and U+2028/U+2029 and spacing in the purpose (P2-8).

## Attacks covered by tests (test/root.test.ts)

Tampered `reference_number`; mandate swapped after approval; each display field narrower than the mandate
(per-operation, total, single payment, start, end, recurrence dates, payee, payee id not enforceable,
currency, purpose, frequency, number of payments, execution date, minimum amount, creditor id, fractional
start second); unlimited mandate shown with amounts; any-counterparty mandate shown with a payee; inexact
amounts; unknown transaction data type in the wallet and in the verifier; schema-breaking payload; SCA key
binding without the hash; hash signed by the PID instead of the SCA attestation; missing TS12 `jti`/`amr`;
wrong response mode; SCA presentation from another request; untrusted, revoked SCA attestation; PID paired
with another person's SCA approval; policy allow-list including wildcard actions; lifetime policy; malformed
roots and extra presentations; replay and state. For legal persons: untrusted register; EUID scope; revoked
and suspended attestation; status list signed by another register; status URI outside the issuer origin;
status fetched only after the invocation; attestation without status; ended, future and expired role or
attestation; each power exceeded (action, wildcard, per-operation, total, unlimited total, currency, missing
limits, depth, outliving the role); counterparties; other holder key without and with identity claims; another
person's attestation; undisclosed identity claims; missing presentation; presentation from another request;
other legal person or role; technical role basis; PID in place of the attestation; missing configuration;
attestation without a legal principal; delegation setting a principal; same-response SCA binding for a
legal person.

## Sources

- EUDI TS12 v1.0.1:
  https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts12-electronic-payments-SCA-implementation-with-wallet.md
  and its schemas `api/ts12-urn-eudi-sca-emandate-1-data-model.json`, `api/ts12-urn-eudi-sca-payment-1-data-model.json`.
- ARF discussion topic on SCA with the wallet:
  https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/main/docs/discussion-topics/aa-rr-support-of-electronic-payments-SCA-with-wallet.md
- Council general approach on European Business Wallets: https://data.consilium.europa.eu/doc/document/ST-9684-2026-INIT/en/pdf
  and https://data.consilium.europa.eu/doc/document/ST-10346-2026-ADD-1/en/pdf
- EWC RFC005 (LPID): https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc005-issue-legal-person-identification-data.md
