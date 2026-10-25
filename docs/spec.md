# Plenipo profile 0.1

Status: draft, implemented by Plenipo 0.4. This document defines the wire formats and the verification
rules a conforming implementation follows, so that an agent platform, a wallet integration and a relying
party built by different people interoperate. The reasons behind the rules are in [design.md](design.md).

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119 and RFC 8174.

## 1. Conventions

- **base64url** is the URL-safe alphabet of RFC 4648 section 5, without padding.
- **Canonical JSON** is the JSON Canonicalization Scheme of RFC 8785.
- **hash(x)** is the SHA-256 digest of the UTF-8 bytes of the string x, encoded in base64url.
- **Times** are integers in seconds since the Unix epoch.
- **Amounts** are non-negative safe integers in the ISO 4217 minor unit of their currency: hundredths
  for EUR, units for JPY, thousandths for KWD.
- **Agent keys** are P-256 keys used with ES256 (RFC 7518). Implementations MUST NOT accept other
  algorithms for delegations and invocations in this profile.

## 2. Mandate

A mandate is a JSON object. It carries no personal data.

| Member | Required | Rule |
| --- | --- | --- |
| `v` | yes | The string `"0.1"`. |
| `id` | yes | A string of at least 8 characters chosen by the issuer, unique within the chain. |
| `agent.jwk` | yes | Public JWK of the agent the mandate is given to. It MUST NOT contain a private member (`d`). |
| `actions` | yes | Non-empty array of action names (2.1). |
| `counterparties` | no | Non-empty array of host patterns (2.2). Absent means any counterparty. |
| `limits` | no | `{ currency, per_operation?, total? }`: an ISO 4217 code and at least one of the two amounts. |
| `nbf`, `exp` | yes | Validity window, `nbf < exp`. |
| `delegation.max_depth` | no | Integer from 0 to 5: further hops allowed below this mandate. Absent means 0. |
| `purpose` | no | Human-readable text shown to the person, at most 500 characters. |
| `status` | no | `{ status_list: { uri, idx } }`, an IETF Token Status List entry. |

A verifier MUST reject a mandate with members it does not know, except those defined by an extension
it implements (section 9).

### 2.1 Actions

An action is a dotted name of lowercase letters, digits, `_` and `-`, such as `payments.transfer`. In a
mandate, `x.*` covers every action below `x` and `*` covers every action. In an invocation an action
MUST be concrete: no wildcard.

### 2.2 Counterparties

A counterparty is a DNS host name. In a mandate, patterns are compared without regard to case, and
`*.example.com` covers `example.com` and any host below it. In an invocation a counterparty MUST be a
concrete lowercase host name of at most 253 characters.

## 3. Root authorisation

The root of a chain is the approval of the first mandate by a natural person, given with an EUDI
Wallet over OpenID for Verifiable Presentations 1.0.

1. The agent platform builds the transaction data object
   `{ "type": "plenipo_mandate", "credential_ids": ["pid"], "mandate": <mandate> }`
   and encodes it as the base64url of its canonical JSON.
2. It requests a PID presentation (`vct` `urn:eudi:pid:1`) with that transaction data.
3. The wallet shows the mandate and, on approval, returns the PID as an SD-JWT VC with a key binding
   JWT whose `transaction_data_hashes` contains hash(transaction data). `transaction_data_hashes_alg`,
   when present, MUST be `sha-256`.

The root object is `{ "transaction_data": <string>, "presentation": <string> }`. A verifier MUST:

- decode the transaction data strictly: unpadded base64url whose decoded bytes are exactly the canonical
  JSON of the parsed object, with `type` equal to `plenipo_mandate`;
- verify the PID signature against a trusted PID provider, by explicit key or by an X.509 chain to a
  configured trust anchor;
- verify the key binding JWT with the PID holder key (`cnf.jwk`) and check that it contains the hash;
- check the PID status list entry when the PID has one, and refuse a PID without one unless its provider
  is configured as issuing PIDs without status (the status list itself is fetched late, see section 6);
- refuse a mandate whose `exp` is later than the PID `exp`;
- apply its lifetime policy (90 days by default).

## 4. Delegation

An agent delegates by signing a child mandate with the key named in its own mandate. The delegation is a
compact JWS with protected header `{ "alg": "ES256", "typ": "plenipo-delegation+jwt" }` and payload:

```json
{ "mandate": <child mandate>, "parent_id": <parent id>, "parent_hash": hash(canonical JSON of the parent), "iat": <time> }
```

The payload MUST NOT contain other members. A chain MUST NOT contain more than 5 delegations. For each
delegation the verifier MUST check the signature with the parent `agent.jwk`, `parent_id` and
`parent_hash`, that the parent allows one more hop, and attenuation:

| Member | Rule |
| --- | --- |
| `actions` | every child action is covered by a parent action |
| `counterparties` | if the parent restricts, the child restricts within it |
| `limits` | every parent limit is present in the child, same currency, value not higher |
| `nbf`, `exp` | child window inside the parent window |
| `delegation` | child `max_depth` at most parent `max_depth` minus 1 |

## 5. Invocation

When the agent at the end of the chain acts, it signs a compact JWS with protected header
`{ "alg": "ES256", "typ": "plenipo-invocation+jwt" }` and payload:

| Member | Required | Rule |
| --- | --- | --- |
| `mandate` | yes | `id` of the leaf mandate. |
| `action` | yes | Concrete action name. |
| `counterparty` | no | Concrete host name. |
| `amount` | no | `{ value, currency }`. |
| `aud` | yes | Identifier of the relying party. |
| `nonce` | yes | Single-use string of 1 to 256 characters, issued by the relying party or random. |
| `iat` | yes | Signing time. |
| `chain_hash` | yes | See below. |
| `args_hash` | no | hash(canonical JSON of the call arguments), `{}` when there are none. |

Members not listed here are ignored. `chain_hash` is hash of the canonical JSON of
`{ "typ": "plenipo-chain", "root": <root object>, "delegations": [ <delegation>, … ] }`, where the root
object carries only the members it has. It binds the invocation to the exact chain it is presented with.

## 6. Verification

The verifier runs these checks in order and stops at the first failure:

1. Shape: the chain has a root and at most 5 delegations, and the invocation is a string.
2. Root (section 3), without network access: signatures, key binding, transaction data, policy.
3. Each delegation (section 4).
4. Time: every mandate is inside its window. Clock skew MAY be tolerated on `nbf` and `iat`, never on
   `exp`.
5. Local revocation: no mandate is revoked in the verifier's own registry.
6. Invocation: signature by the leaf `agent.jwk`, strict shape, `mandate`, `chain_hash`, `aud`, freshness
   (120 seconds by default), and equality with what the relying party is about to do when it states it.
7. Scope on every mandate of the chain: action, counterparty, currency, per-operation limit.
8. Checks that need the network: revocation of the PID provider certificate when configured, the PID
   status list, and the status list of every mandate that has one.
9. Spending: an atomic reservation against every total limit of the chain.
10. Replay: the nonce is consumed last, so a denied invocation does not use up its nonce.

Checks that fetch anything over the network come after the invocation has been authenticated and
scoped, so a caller without a valid invocation cannot make the verifier fetch URLs.

A relying party MAY declare that a call has no counterparty, no amount, or both. A call without an amount
is subject to no spending limit only when the relying party declares that it moves no money; counterparty
restrictions are lifted only when it declares both.

The result is ALLOW, or DENY with one of these codes and, where it applies, the depth `at` of the mandate
that failed (0 for the root):

`CONFIGURATION`, `MALFORMED`, `INVOCATION_MISMATCH`, `ROOT_INVALID`, `PID_ISSUER_UNTRUSTED`,
`PID_REVOKED`, `TX_DATA_MISMATCH`, `LIFETIME_POLICY`, `DELEGATION_SIGNATURE_INVALID`,
`DELEGATION_PARENT_MISMATCH`, `DELEGATION_NOT_ALLOWED`, `ATTENUATION_VIOLATION`, `NOT_YET_VALID`,
`EXPIRED`, `REVOKED`, `INVOCATION_SIGNATURE_INVALID`, `INVOCATION_MANDATE_MISMATCH`, `INVOCATION_STALE`,
`AUDIENCE_MISMATCH`, `REPLAY`, `ACTION_NOT_PERMITTED`, `COUNTERPARTY_NOT_PERMITTED`, `CURRENCY_MISMATCH`,
`LIMIT_PER_OPERATION`, `LIMIT_TOTAL`, `DISPLAY_MISMATCH`, `ROOT_POLICY`, `ATTESTATION_UNTRUSTED`,
`ATTESTATION_INVALID`, `ATTESTATION_REVOKED`, `ROLE_EXCEEDED`, `STATUS_UNAVAILABLE`, `INTERNAL`.

A verifier MUST deny when in doubt: an unreachable status list, a store that fails and an unknown member
all lead to DENY.

## 7. HTTP binding

An agent sends two request headers:

- `Plenipo-Chain`: base64url of the JSON `{ "root": …, "delegations": [ … ] }`, at most 64 KiB by default;
- `Plenipo-Invocation`: the invocation JWS, at most 8 KiB by default.

A denial is answered with `application/problem+json` (RFC 9457). Its `type` is
`https://plenipo.net/problems/` followed by the code in lowercase, for example
`https://plenipo.net/problems/limit_per_operation`.

When a protected API reports whether it executed the operation, it does so with the response header
`Plenipo-Outcome: executed | not-executed | unknown`. The gateway commits the spending reservation on
`executed`, releases it on `not-executed` and leaves it pending for reconciliation on `unknown`.

## 8. MCP binding

An MCP client passes the chain and the invocation in the request `_meta` under `plenipo/authorization`
as `{ "chain": …, "invocation": … }`. A tool reports its outcome in the result `_meta` under
`plenipo/outcome`, with the same values as the HTTP header.

## 9. Extensions

These extensions are implemented and experimental. They follow drafts that are still changing, a verifier
accepts them only when configured to, and their formats may change in a minor release:

- Delegate SD-JWT links, a second wire format for delegations ([delegation.md](delegation.md));
- TS12 e-mandate roots, transaction data type `urn:eudi:sca:emandate:1` ([root.md](root.md));
- mandates on behalf of a legal person, with the representation attestation
  `urn:plenipo:representation:1` ([root.md](root.md)).

## 10. Test vectors

[`test-vectors/plenipo-0.1.json`](../test-vectors/plenipo-0.1.json) holds chains, invocations and the
decisions a conforming verifier reaches, with the trusted PID provider key and the verifier clock for
each. `npm run vectors` regenerates them; the committed file is the reference.

## 11. Versioning

The mandate member `v` names the format. A change that a verifier of the previous version would
misread changes `v`; additions that a verifier must understand to stay safe are new extensions, refused
by verifiers that do not implement them.
