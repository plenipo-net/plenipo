# Changelog

## Unreleased

## 0.4.1 (25 October 2026)

Documentation and release process only; the library code is unchanged from 0.4.0.
- README: new "Why Plenipo" section and a link to the npm package.
- Releases: a version tag publishes to npm through trusted publishing and creates the GitHub release
  from this file.
- Dependabot: weekly grouped updates for the library, the sandbox and GitHub Actions.

## 0.4.0 (25 October 2026, first public release)

Breaking
- Delegate SD-JWT links are refused by default. Verifiers accept them with
  `delegationFormats: ['jws', 'sd-jwt']`; without it such a link is denied with `MALFORMED`.
- TS12 e-mandate roots are refused by default with `ROOT_POLICY`. Verifiers and `handleMandateResponse`
  accept them when `emandate` is set (`emandate: {}` for e-mandates bound to the PID, with `scaTrust` and
  `scaVcts` for those bound to an SCA attestation).
- The helpers of the experimental extensions moved from `plenipo` to `plenipo/experimental`: Delegate
  SD-JWT (`delegateMandateSdJwt`, `parseDelegation`, `createDelegateTransactionData`, ...), TS12
  e-mandates (`mandateToEmandate`, `encodeEmandateTransactionData`, `emandateViolations`, ...) and
  legal persons (`createLegalMandate`, `checkRepresentation`, `representationQuery`, ...).
- Problem types are now `https://plenipo.net/problems/<code>`.
- Node 22 or later (Node 20 reached end of life).
- `@modelcontextprotocol/sdk` is no longer a runtime dependency; the npm package no longer ships `docs/`
  (they are on GitHub).

Added
- `docs/spec.md`: the Plenipo 0.1 profile, the wire formats and verification rules in normative form.
- `test-vectors/plenipo-0.1.json`: 12 interoperability vectors with the expected decisions, checked by
  the test suite and regenerated with `npm run vectors`.
- `examples/bank-gateway.ts` (`npm run example:gateway`): the HTTP gateway in front of a payments API.
- Sandbox: `docker compose up` from `sandbox/` runs it on any operating system; generic Claude Desktop
  and Claude Code bridge configuration. The payees are fictional companies on `.example` hosts.
- Property-based tests (fast-check) on the parsers of untrusted input and on verification of tampered
  chains and invocations.
- Contribution guide with DCO sign-off, security policy, code of conduct, roadmap, issue and pull
  request templates, release workflow with npm trusted publishing.

Fixed
- `hasDuplicateJsonKeys` looped forever on text with an unterminated string. The gateway only calls it
  on bodies that `JSON.parse` accepted, so it was not reachable there, but the function is exported;
  it now throws instead. Found by the new property-based tests.
- Opening the same approval link twice no longer loses an approved mandate. The second response
  used to fail with `ROOT_INVALID`, mark the request as failed and make the MCP bridge drop the
  mandate the platform had just recorded.
  - Library: a response to a request already answered fails with `REPLAY` instead of
    `ROOT_INVALID`, so a reused request is told apart from an invalid root.
  - Platform: an approved request is final. A later response gets HTTP 409 and changes nothing,
    and the request object is answered with HTTP 410 once approved.
  - Wallet: reopening a pending or approved request shows the request already received; a 409 from
    the platform is shown as "already answered, the earlier answer stands".
  - Bridge: `mandate_status` adopts a mandate the platform holds as active even when the request
    reports a later failure, provided it names the bridge's own key.
- Sandbox: new scenario `double-approval` (17 scenarios).

## 0.3.0 (19 October 2026)

Added
- TS12 alignment: mandates can be approved as `urn:eudi:sca:emandate:1` transaction data bound to
  the full mandate by hash, with checks that the mandate is never wider than what the wallet showed
  (docs/root.md).
- Legal persons: mandates on behalf of a company, approved by a representative who presents a role
  attestation; the mandate cannot exceed the role's powers, and the role is re-checked at every
  verification (experimental, docs/root.md).
- Delegate SD-JWT: delegations in the format of draft-gco-oauth-delegate-sd-jwt-00, alongside JWS,
  with identical checks (docs/delegation.md).
- Trust: EU Lists of Trusted Entities (ETSI TS 119 602, JSON/JAdES), leaf certificates as anchors,
  CRL and OCSP checking with off / soft-fail / hard-fail policies (docs/trust.md).
- `ExternalSigner`: every signature can be produced by a key in a KMS or HSM.
- Shared stores for Postgres and Redis: atomic spending ledger, nonces, OpenID4VP sessions,
  revocation registry (docs/stores.md).
- Bank integration: HTTP gateway with route mapping, RFC 9457 problem documents, status list
  service with admin API, hash-chained signed audit log, OPA and Cedar export (docs/integration.md).
- Sandbox: PID provider, wallet, agent platform, bank (MCP and REST), live dashboard, scripted and
  LLM agents, 16 scenarios, an MCP bridge for Claude Desktop and Claude Code, a Mac guide, walt.id configuration and public-host deployment files (docs/sandbox.md).

Changed
- New deny codes `STATUS_UNAVAILABLE` (a status list could not be obtained) and `INTERNAL`
  (a store or registry failed). A status list that was obtained but did not verify keeps its
  revocation code.
- A reservation is released when the nonce store fails after the amount was reserved.

Security review (19 October 2026)
- An independent review in three areas found 27 issues, 6 of them high: role limits that could be
  hidden through selective disclosure (legal persons); counterparty and amount self-declared by the
  agent when an MCP tool had no extractor; HTTP gateway releasing reservations on client disconnect or
  downstream errors; routes matched more loosely by Express than by the gateway; form-encoded bodies
  executing unsigned fields; and medium ones such as invocations not bound to their chain, payee names
  in TS12 displays not checked, principals identified by display name in policy exports.
- All are fixed with a regression test each; the reviewers' original exploits now fail against the
  code. Breaking changes that came with the fixes:
  - `createInvocation` requires the `chain`; invocations carry `chain_hash`.
  - `guardTool` requires `counterparty` and `amount` (an extractor or `null`); the handler receives the
    decision; a throwing handler leaves the reservation pending.
  - Mandates with unknown members are refused; `purpose` is limited to 500 characters without control
    characters.
  - Settlement releases a reservation only when the action certainly did not run; stale reservations
    are counted as spent by the sweep until reconciled (`reconcile`).
  - Gateway default arguments include `media_type`; JSON bodies only; Cedar types `Plenipo::Person`
    and `Plenipo::LegalPerson`.
- New: `expected.counterparty/amount = null` for operations with no counterparty or no money (reads,
  card block) under a mandate with limits; store retention checks; `Plenipo-Outcome` header.

Second review (19 October 2026)
- A second independent review of the fixes found 8 more issues, 1 high: the Node and Express adapters
  normalised paths (backslashes, dot segments) differently from Express routing. Also: a PID status
  that a non-compliant provider made disclosable could be withheld; `counterparty: null` lifted
  counterparty restrictions on money-moving calls; MCP tools returning `isError` released
  reservations; reconciliation could not correct under-counting; line separators in `purpose`.
- All fixed with regression tests; the reviewers' exploits fail against the code. Changes:
  ambiguous request targets are refused (400), GET/HEAD bodies refused, duplicate JSON keys refused;
  PID status required by default (`requirePidStatus`, per-provider opt-out); protected claims read only
  from issuer-signed plaintext; `counterparty: null` only together with `amount: null`; MCP tools state
  their outcome in `_meta['plenipo/outcome']`; late evidence of execution corrects releases (schema v3).

## 0.2.0 (19 October 2026)

PID status and mandate revocation with IETF Token Status List, PID providers trusted through X.509
chains, OpenID4VP wallet leg, two security review rounds.

## 0.1.0 (18 October 2026)

Wallet-anchored mandates, attenuating delegation, invocations, verification, spending limits, MCP
guard.
