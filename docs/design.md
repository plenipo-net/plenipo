# Plenipo design

> This document explains the core model and the reasons behind it. The rules themselves are in
> [spec.md](spec.md). The rest is described in its own documents: [root](root.md) (TS12 e-mandate,
> legal persons, experimental), [delegation](delegation.md) (Delegate SD-JWT, experimental),
> [trust](trust.md) (trusted lists, CRL, OCSP), [stores](stores.md), [integration](integration.md)
> (HTTP gateway, audit, policy export) and [sandbox](sandbox.md).

Plenipo lets a person authorise an AI agent with a mandate that is anchored to
their European Digital Identity Wallet, and lets any service check that mandate
before the agent acts.

## Goals

- The root of every mandate is a PID presentation from an EUDI Wallet (or
  IT-Wallet in Italy). Plenipo introduces no new identity, no new root keys and
  no new cryptography.
- Every sub-delegation can only narrow authority. This is enforced by the
  verifier, not left to the delegator.
- Every mandate expires. Every mandate can be revoked, and revoking a mandate
  revokes everything delegated from it.
- A service gets one answer, ALLOW or DENY, with a machine-readable reason and
  the full path of authority that produced it.
- An agent never sees the person's wallet keys or PID disclosures beyond what
  the mandate needs.

Out of scope for now: zero-knowledge predicates on the PID, hosted services.

## Actors

| Actor | Holds | Does |
| --- | --- | --- |
| Principal | EUDI Wallet with a PID | approves a mandate in the wallet |
| PID provider | issuer key, on an EU trusted list | issued the PID, nothing at runtime |
| Agent | its own key pair | presents the mandate chain and signs each invocation |
| Sub-agent | its own key pair | receives a narrower mandate from an agent |
| Relying party | trusted PID issuer keys | verifies chain and invocation, then acts |

## The mandate

A mandate is a JSON object. It carries no personal data: who the principal is
comes from the PID presentation that authorises the root.

```json
{
  "v": "0.1",
  "id": "8c1f…",
  "agent": { "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
  "actions": ["travel.book"],
  "counterparties": ["*.rotaia.example"],
  "limits": { "currency": "EUR", "per_operation": 15000, "total": 30000 },
  "nbf": 1792360000,
  "exp": 1792964800,
  "delegation": { "max_depth": 1 },
  "purpose": "Book train tickets for the Milan trip"
}
```

- `actions` are dotted names. A trailing `.*` covers every action below it,
  and `*` covers everything.
- `counterparties` are host names. `*.example.com` covers sub-domains and
  `example.com` itself. Omitting the field means any counterparty.
- `limits` are integers in the ISO 4217 minor unit of their currency (cents
  for EUR, whole yen for JPY, thousandths for KWD; see `currencyMinorDigits`).
  `per_operation` caps a single invocation, `total` caps the sum spent under this mandate and everything
  delegated from it.
- `nbf` and `exp` are mandatory. The default policy rejects a lifetime above
  90 days.
- `delegation.max_depth` is how many further hops are allowed below this
  mandate. 0 or absent means no sub-delegation.

## Root authorisation: the wallet signs the mandate

The root uses OpenID for Verifiable Presentations transaction data, the same
mechanism the EUDI ecosystem uses to authorise payments and qualified
signatures.

1. The agent platform builds the mandate and wraps it as a transaction data
   object `{ "type": "plenipo_mandate", "credential_ids": ["pid"], "mandate": … }`,
   base64url-encoded.
2. It requests a PID presentation from the principal's wallet with that
   transaction data. The wallet shows the mandate to the person.
3. On approval the wallet returns the PID as an SD-JWT VC with a key binding
   JWT whose `transaction_data_hashes` contains the SHA-256 of the encoded
   transaction data.

The root of the chain is the pair `{ transaction_data, presentation }`. Anyone
can verify, offline and at any later time, that a PID issued by a trusted
provider was presented by the device that holds it, and that this device
approved exactly this mandate.

A mandate cannot outlive the PID that authorised it: `exp` must not exceed the
PID `exp` when the PID has one.

## Sub-delegation

An agent delegates by signing a child mandate with the key named in its own
mandate. The delegation is a compact JWS, `typ: plenipo-delegation+jwt`, whose
payload is `{ mandate, parent_id, parent_hash, iat }`. `parent_hash` is the
SHA-256 of the canonical JSON (RFC 8785) of the parent mandate.

The verifier enforces attenuation at every hop:

| Field | Rule |
| --- | --- |
| actions | each child action is covered by a parent action |
| counterparties | if the parent restricts, the child restricts within it |
| limits | each parent limit is present in the child, same currency, value not higher |
| nbf, exp | child window inside the parent window |
| delegation | parent allows at least one more hop; child depth is at most parent depth minus 1 |

This is the rule that the IETF Delegate SD-JWT draft leaves out, and the main
reason Plenipo exists.

## Invocation

When the agent at the end of the chain acts, it signs an invocation JWS,
`typ: plenipo-invocation+jwt`, with its own key:

```json
{ "mandate": "<leaf mandate id>", "action": "travel.book",
  "counterparty": "www.rotaia.example",
  "amount": { "value": 8900, "currency": "EUR" },
  "aud": "https://api.rotaia.example", "nonce": "…", "iat": 1792361000,
  "chain_hash": "<SHA-256 of the chain>" }
```

`chain_hash` binds the invocation to the exact chain it is presented with. It
is the base64url SHA-256 of the RFC 8785 JSON of
`{ "typ": "plenipo-chain", "root": { transaction_data, presentation, mandate?,
presentations? }, "delegations": [ … ] }`, with the members a root does not
have left out (`chainHash(chain)`; `createInvocation` requires `chain` and sets
it). The verifier requires it and denies a mismatch with
`INVOCATION_MANDATE_MISMATCH`. Without it the invocation would be bound only to
the leaf mandate id, which delegators choose and which is public: an agent key
used as the leaf of two chains (a shared executor) could have the invocation it
signed for one principal replayed on the other principal's chain, charged to
the other principal's limits.

The relying party checks audience, freshness (120 seconds by default) and a
single-use nonce. A nonce store is mandatory; a relying party that issues its
own nonces rejects the ones it never issued in the same store.

Every field of the invocation is untrusted input and is validated strictly
before any comparison: the action is a concrete name without wildcards, the
counterparty is a concrete lowercase host name, the amount is a non-negative
safe integer in minor units with an ISO 4217 currency.

A relying party that does not use the MCP guard passes `expected`
(action, counterparty, amount, arguments) to `verifyAuthorization`, so the
decision is bound to what it is about to do. An ALLOW returns the verified
invocation.

## Verification

`verifyAuthorization()` returns `{ decision: "ALLOW" | "DENY", code, reason, principal, path }`.
The checks run in this order and stop at the first failure (the normative list is in
[spec.md](spec.md), section 6):

1. Root: PID signature by a trusted issuer (explicit key, or an x5c chain to a
   configured trust anchor whose leaf names the issuer), key binding,
   transaction data hash, mandate syntax and lifetime policy. Transaction data must be strict
   base64url of canonical JSON (RFC 8785), so the bytes the wallet displayed
   and the bytes enforced cannot differ (no duplicate keys, no padding tricks).
2. Each delegation: signature by the parent agent key, parent hash, depth
   (at most 5 hops), attenuation.
3. Time: every mandate in the chain is inside its validity window. Clock skew
   is tolerated on `nbf`, never on `exp`.
4. Revocation: no mandate in the chain is revoked in the registry.
5. Invocation: signature by the leaf agent key, strict shape, mandate and chain
   hash, audience, freshness, match with `expected`.
6. Scope: action, counterparty, per-operation limit and currency on every
   mandate in the chain.
6b. Network checks, only now that the caller is authenticated: PID provider
   certificate revocation when configured, the PID status list, and the status
   list of every mandate that carries `status`.
7. Spending: an atomic reservation against every total limit in the chain.
8. Replay: the nonce is consumed last, so a denied invocation keeps its nonce.

`principal` contains only the PID claims the wallet disclosed for the root.

## Trust in PID providers

Verifiers trust PID providers in one of two ways, or both:

- `trustedIssuers`: explicit `{ iss, jwk }` entries, for tests and closed
  deployments.
- `trustAnchors`: PEM certificates of the CAs listed on the PID provider
  trusted lists. The PID must carry an `x5c` header and an `iss`. The chain
  must be valid now; every CA in it must have basic constraints `CA=true`,
  `keyCertSign` when key usage is present, and a path length that allows the
  intermediates below it; the anchor cannot sign directly; name constraints
  and unknown critical extensions are rejected. The leaf must be an end-entity
  certificate with `digitalSignature`, a P-256 key, optionally one of
  `requiredPolicyOids` (and every CA on the path that restricts policies must
  allow it or anyPolicy), an extended key usage among `requiredEkus` when it
  has one (a critical EKU is rejected when no `requiredEkus` is configured),
  and must name the PID `iss`: exactly as a URI SAN, or
  by DNS SAN only when `iss` is a bare https origin.

The identity a signer must have always comes from the verifier's context (the
PID `iss`, a status list origin), never from a claim of the token being
verified. Loading the anchors from the EU trusted lists (LoTL, ETSI TS 119 612)
is left to the deployment.

## Status

Plenipo uses IETF Token Status List (`typ: statuslist+jwt`) for both the PID
and the mandates. Tokens must carry `exp`, `sub` must equal the URI, lists are
fetched over https only, without redirects, within 5 seconds and up to 1 MB.

- PID: by default the token must be signed by the PID provider (its listed key,
  or a certificate under the anchors that names the PID `iss`) and the list
  must be on the origin of the PID `iss`. A different status signer is accepted
  only through `pidStatusTrust`, which names who may sign and from which
  origins. A revoked or suspended PID, or a list that was obtained but does not
  verify, denies with `PID_REVOKED`; a list that cannot be obtained at all
  denies with `STATUS_UNAVAILABLE`. A PID must carry a status entry
  (`requirePidStatus`, default true; otherwise `ROOT_INVALID`), read only from
  the issuer-signed plain text, because a status the provider made selectively
  disclosable could be withheld by the holder of a revoked PID. Providers that
  issue short-lived PIDs without status are declared explicitly:
  `TrustedIssuer.withoutStatusList` for providers trusted by key,
  `pidProvidersWithoutStatus` (their `iss`) for providers trusted through x5c.
  `pidStatus: 'skip'` (offline tests) disables both the check and the
  requirement.
- Mandates: `createMandate({ status })` puts a status reference in the mandate,
  so it is covered by the wallet approval and by delegation signatures. The
  agent platform allocates the entry with `StatusListPublisher`, flips it to
  revoke or suspend, and serves `token()` at the URI. Verifiers configure
  `mandateStatusTrust`; the signer must be named for the list's origin, and the
  origin must be in `statusOrigins` (or be the origin of a trusted issuer).
  A URI outside those origins is refused without any request, so a delegator
  cannot point the verifier at internal addresses. A mandate with `status` and
  no `mandateStatusTrust` denies with `CONFIGURATION`.
- Status lists are checked after the invocation signature and the scope, so a
  caller without a valid invocation causes no network traffic.
- Lists use two bits per entry (valid, invalid, suspended) and indexes are
  allocated at random. `StatusListCache` keys entries by URI, signer identity
  and trust configuration, and keeps them for the shortest of its maximum age,
  the token `ttl` and the token `exp`: that bound is the revocation latency a
  verifier accepts.
- The list itself (`status_list.lst`) is decoded by Plenipo: strict base64url,
  ZLIB inflate stopped at `maxListBytes` (default 1 MiB, that is 4 194 304
  entries at 2 bits; configurable in `checkStatus` options), `bits` in
  {1, 2, 4, 8}, and the requested entry read directly from the bytes (entry i
  at bit (i·bits) mod 8 of byte ⌊i·bits/8⌋, least significant bit first, as in
  the Token Status List draft). The cache keeps the inflated bytes, never an
  array of entries, and includes the bound in its key. A 2 KB token that
  inflates to megabytes is refused instead of blocking the event loop.
- Mandates are closed objects: for version 0.1, members other than `v`, `id`,
  `agent` (`jwk` only), `actions`, `counterparties`, `limits` (`currency`,
  `per_operation`, `total`), `nbf`, `exp`, `delegation` (`max_depth`),
  `purpose`, `status` (`status_list` with `uri` and `idx`) and `principal` are
  refused (`MALFORMED`) rather than ignored, because an unknown member may be a
  constraint someone meant to apply.
- Network and library errors go in the decision's `detail` for logs; the
  `reason` the MCP guard returns to callers stays generic. This includes the
  signature errors of JWS delegations and invocations, whose `reason` is a
  fixed sentence.

## Spending and replay

- `RevocationRegistry.isRevoked(mandateId)` remains for local, immediate
  revocation. Revoking any mandate in the chain denies everything below it.
- `SpendingLedger.reserve(entries, amount)`, `commit(id)`, `release(id)`.
  `reserve` checks every total in the chain and adds the amount as pending in
  one atomic step, so concurrent invocations cannot overspend. Entries are
  keyed by mandate hash, not by the id a delegator chose. The MCP guard
  commits after the tool succeeds and releases otherwise; direct callers of
  `verifyAuthorization` must do the same with the returned `reservation`.
- `NonceStore.consume(nonce)`, mandatory.

## OpenID4VP

`createMandateRequest` and `handleMandateResponse` implement the wallet leg.
`handleMandateResponse` checks `state` before anything else, reports only
known wallet error codes, checks that the response answers this request
(mandate, key binding nonce and audience) before any network access, then
checks certificate revocation and PID and attestation status (PID status
unless `pidStatus: 'skip'`), and consumes the session
through a required `sessions` store, so a response is redeemed once (a second
one fails with `REPLAY`, not `ROOT_INVALID`, so callers can tell a reused
request from a bad root); an error response does not consume it. The session store must be separate from the
invocation nonce store, because the state is visible to anyone who sees the
request. Relying parties can restrict which platforms' roots they accept
with `acceptedRootAudiences`. See [interop.md](interop.md) for the request
shape and the state of support in real wallets.

## MCP guard

`guardTool(handler, options)` wraps an MCP tool handler. The client sends the
chain and the invocation in the request `_meta` under `plenipo/authorization`.
The guard verifies them with `expected` set from the tool call (action,
counterparty, amount, arguments), denies with a structured error or calls the
handler, then commits or releases the spending reservation.

`counterparty` and `amount` are required options, as in the HTTP gateway
routes: a function that reads the value from the tool arguments, or `null`
when the tool has none. A function that returns nothing (or an invalid
amount, or throws) refuses the call before verification; with `null`, an
invocation that declares a counterparty or amount is refused and its
reservation released.

`null` is also a declaration to the verifier (`expected.counterparty: null`,
`expected.amount: null`): the call has no counterparty, or moves no money.
This is how one mandate for paying bills can also read the balance or block a
card. Only the relying party may make this declaration; the agent cannot,
because an invocation that declares an amount or counterparty on such a call is
refused. The two declarations are not symmetric:

- `amount: null` disables every spending limit in the chain for that call: no
  per-operation check, no total, no reservation. Use it only for operations
  that cannot move money in any way.
- `counterparty: null` lifts counterparty restrictions only when `amount` is
  `null` too. A call that may move money without a payee the relying party can
  name (a card top-up, buying fund units) under a mandate restricted to some
  counterparties is refused with `COUNTERPARTY_NOT_PERMITTED`: the money could
  otherwise end up anywhere. Mandates without counterparty restrictions are
  unaffected.

Settlement follows one rule: release only when it is certain the action did
not run. The handler states the outcome in its result,
`_meta['plenipo/outcome']` (`OUTCOME_META_KEY`): `executed` commits,
`not-executed` releases, `unknown` (or any other value) leaves the
reservation pending. The guard removes the key before returning the result to
the client. Without a stated outcome, a success commits and an `isError`
result stays pending, because a tool may report an error after the money has
moved (a receipt or notification step failing). The reservation is also
released when `onDecision` throws (the call is then refused with `INTERNAL`
before the handler runs). When the handler throws, the outcome is unknown and
the reservation stays pending. A pending reservation counts against the
limits, and a shared ledger's sweep counts it as spent until reconciled
(docs/stores.md). A tool that validates before acting should mark its early
failures `not-executed`, so they do not consume budget.

The handler receives the verified decision as its third argument (principal,
path of authority, exact invocation). `now` may be a function, read at every
call.

## Compatibility

- PID format: SD-JWT VC, `vct` `urn:eudi:pid:1`, as in the ARF.
- Root binding: OpenID4VP 1.0 transaction data, DCQL, `direct_post.jwt`.
- Status: IETF Token Status List, for PID and mandates.
- Trust: X.509 chains in `x5c`, anchored to configured CAs.
- Delegations: JWS with ES256. A later version will also emit and read the
  IETF Delegate SD-JWT and Mastercard Verifiable Intent formats.
