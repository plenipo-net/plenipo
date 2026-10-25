# Delegate SD-JWT delegations

> Experimental. The Delegate SD-JWT format follows an individual IETF draft that has expired, so its
> API lives in `plenipo/experimental` and verifiers accept it only when asked to
> (`delegationFormats: ['jws', 'sd-jwt']`). The compact JWS format is the stable one.

Plenipo supports sub-delegations in two wire formats:

- the original compact JWS, `typ: plenipo-delegation+jwt` (unchanged);
- a Delegate SD-JWT, following
  [draft-gco-oauth-delegate-sd-jwt-00](https://datatracker.ietf.org/doc/html/draft-gco-oauth-delegate-sd-jwt)
  (Gareth Oliver, Google; individual draft published 21 April 2026, expired
  23 October 2026 with no -01 and no working group successor), in a strict
  profile defined here.

Both formats carry the same thing, a child mandate signed by the parent agent,
and the verifier applies exactly the same checks to both. When both are enabled
a chain may mix them freely: each entry of `chain.delegations` is detected on its own.

## Why a second format

The Delegate SD-JWT draft extends SD-JWT (RFC 9901) so that the Key Binding JWT
of a credential becomes itself an SD-JWT (a KB-SD-JWT) that issues the next
credential in a chain. It is the closest thing to a standard for "a holder
delegates to an agent". Speaking it lets Plenipo delegations be produced and
inspected with SD-JWT tooling, and leaves a path open for wallets that issue
delegations themselves (section 7.1 of the draft).

The draft deliberately leaves policy out. It has no attenuation rules, no
spending fields, no depth limit and no revocation; section 8.2 only says that an
issuer or holder may put constraints "as visible claims", whose meaning it does
not define. Plenipo supplies that meaning: the profile below puts a Plenipo
mandate in a visible claim, and the verifier enforces Plenipo attenuation on it.

## The Plenipo profile

A delegation in Delegate SD-JWT form is one string:

```
<KB-SD-JWT>~<Delegate Payload Disclosure>~
```

The KB-SD-JWT is a JWS signed with ES256 by the parent agent, with the key named
in the parent mandate's `agent.jwk` (for the root mandate, the key the wallet
approved in the transaction data).

Protected header:

```json
{ "alg": "ES256", "typ": "kb+sd-jwt+kb" }
```

Payload, and nothing else:

```json
{
  "iat": 1792361000,
  "_sd_alg": "sha-256",
  "delegate_payload": [{ "...": "<SHA-256 of the Delegate Payload Disclosure>" }]
}
```

The Delegate Payload Disclosure is the base64url encoding of the canonical JSON
(RFC 8785) of `[salt, payload]`, where the payload is:

```json
{
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
  "plenipo_mandate": { "v": "0.1", "id": "…", "agent": { "jwk": { … } }, "actions": ["travel.book"], … },
  "parent_id": "<id of the parent mandate>",
  "parent_hash": "<SHA-256 of the RFC 8785 JSON of the parent mandate>",
  "nbf": 1792360000,
  "exp": 1792964800
}
```

- `plenipo_mandate` is the child mandate, exactly as in the JWS format's
  `mandate` claim. It is the "visible claim" of draft section 8.2.
- `parent_id` and `parent_hash` bind the delegation to the parent mandate, as in
  the JWS format.
- `cnf.jwk` is the child agent key, the key that will sign the next delegation
  or the invocation. It must be the same key (same RFC 7638 thumbprint) as
  `plenipo_mandate.agent.jwk`.
- `nbf` and `exp` repeat the mandate's window so that a verifier that knows
  only the draft still sees when the delegation expires (draft section 8.3
  recommends a short `exp`). They must equal the mandate's values.

In draft terms every Plenipo link is a KB-SD-JWT+KB: it binds a key in `cnf`,
and the holder of that key proves possession later, either by signing the next
link or by signing the invocation. The invocation plays the role of the final
key binding JWT of a dSD-JWT+KB.

## API

```ts
import { delegateMandateSdJwt, parseDelegation, createDelegateTransactionData } from 'plenipo/experimental';

// Same parameters, same checks and same errors as delegateMandate.
const token: string = await delegateMandateSdJwt({ parent, parentAgentKey, child, policy });

// Detects the format and decodes WITHOUT verifying, for logging and routing only.
const parsed = parseDelegation(token);
// { format: 'jws' | 'sd-jwt', header, payload: { mandate, parent_id, parent_hash, iat }, cnf? }
```

`delegateMandateSdJwt` validates the child (`validateMandate`), checks that the
parent allows another hop (`allowsDelegation`) and that the child narrows the
parent (`attenuationViolations`), and throws otherwise, exactly like
`delegateMandate`.

`verifyAuthorization` accepts Delegate SD-JWT links only with
`delegationFormats: ['jws', 'sd-jwt']`; by default such a link is refused with
`MALFORMED`. When enabled, a delegation that contains `~` is handled as a
Delegate SD-JWT, any other as a compact JWS. A JWS never contains `~`, and each
format checks its own `typ`, so one cannot be passed off as the other.

Also exported from `plenipo/experimental`: `DELEGATE_SDJWT_TYP` (`kb+sd-jwt+kb`), `PLENIPO_MANDATE_CLAIM`
(`plenipo_mandate`), `DELEGATE_TX_DATA_TYPE` (`delegate`),
`MAX_DELEGATION_LENGTH` (65536) and the types `DelegationFormat`,
`ParsedDelegation`, `DelegateTransactionData`, `DelegateTransactionDataInput`.

## Verification

For each link the verifier runs the same steps, in the same order, with the same
deny codes, whatever the format:

| Step | JWS | Delegate SD-JWT | Deny code |
| --- | --- | --- | --- |
| signature by the parent agent key, ES256, expected `typ` | `jwtVerify` | `compactVerify`, then `typ`; then the disclosure's SHA-256 must equal the signed digest | `DELEGATION_SIGNATURE_INVALID` |
| payload structure | only `mandate`, `parent_id`, `parent_hash`, `iat` | see below | `MALFORMED` |
| `parent_id` and `parent_hash` | same | same | `DELEGATION_PARENT_MISMATCH` |
| child mandate syntax and lifetime policy | same | same | `MALFORMED` |
| parent allows another hop | same | same | `DELEGATION_NOT_ALLOWED` |
| attenuation | same | same | `ATTENUATION_VIOLATION` |

Both formats are closed: a JWS delegation payload may contain only `mandate`,
`parent_id`, `parent_hash` and `iat` (anything else is `MALFORMED`), as the
Delegate SD-JWT profile below refuses claims it does not define, because a
member the verifier ignored could be a constraint the delegator meant.

Chain length (at most 5), time windows, revocation, scope of the invocation,
status lists and the spending ledger are checked afterwards on the list of
mandates, which is the same whatever format each link used. The invocation's
`chain_hash` covers every delegation token exactly as presented, whatever its
format, so an invocation signed for a chain with a JWS link is not accepted
with the same link re-issued as a Delegate SD-JWT (or re-signed), and vice
versa: the agent signs a new invocation for the chain it actually presents.

The profile structure check refuses, with `MALFORMED`:

- anything other than exactly one disclosure followed by the trailing `~`
  (no key binding JWT appended, no `~~` concatenation, no extra disclosures);
- a token longer than 64 KiB, checked before parsing;
- a `crit` or `b64` header parameter (refused as a signature problem);
- payload claims other than `iat` (required integer), `_sd_alg` (absent or
  `sha-256`) and `delegate_payload` (exactly one `{"...": digest}` element,
  no decoys);
- a disclosure that is not RFC 8785 canonical JSON of `[salt, object]`, which
  also rules out duplicate keys that two parsers could read differently;
- any `_sd`, `_sd_alg` or `...` key anywhere in the Delegate Payload, or nesting
  deeper than 16 levels;
- Delegate Payload claims other than the six listed above;
- a `cnf` that is not `{ jwk }`, contains a private key, or is not the child
  mandate's agent key;
- `nbf` or `exp` that differ from the mandate.

## Security considerations

**Selective disclosure cannot hide a constraint.** SD-JWT lets a holder replace
claims by digests (`_sd`, or `{"...": digest}` in arrays) and decide later which
ones to reveal. For a credential about a person that protects privacy. For a
delegation it is dangerous: a mandate grows wider when a constraint disappears.
If a delegator put `counterparties` behind a digest and the presenter left that
disclosure out, a verifier that processed the token as plain SD-JWT would see a
child mandate valid for every counterparty, wider than what was signed and
possibly still within the parent, so attenuation would not catch it. Plenipo
therefore refuses any digest anywhere in the Delegate Payload, refuses
disclosures other than the Delegate Payload itself, and refuses claims it does
not understand, because an unknown claim could be a constraint the delegator
meant and the verifier would silently ignore. The only selective disclosure
left is the one the draft requires: the Delegate Payload as a whole is a
disclosure, and it must be present.

**The disclosure is not signed, its digest is.** The verifier recomputes the
SHA-256 of the disclosure string and compares it with the signed digest before
decoding it, so a swapped or re-salted disclosure is refused as
`DELEGATION_SIGNATURE_INVALID`, and nothing the parent did not sign is parsed.

**Identity comes from the chain, not from the token.** The verification key of
each link is the parent mandate's `agent.jwk`; header parameters such as `jwk`,
`kid` or `x5c` are ignored. `cnf` is only accepted when it names the key the
child mandate already names, so the token cannot bind one key while the mandate
names another.

**No format confusion.** A JWS delegation with a `~` appended, a JWS with the
SD-JWT `typ`, an SD-JWT with the JWS `typ`, a PID key binding JWT (`kb+jwt`) and
a non-delegating KB-SD-JWT (`kb+sd-jwt`) are all refused.

**Fail closed.** Every error raised while handling an SD-JWT link becomes a DENY;
library messages go to `detail`, never to `reason`.

## Deviations from the draft, and ambiguities

The draft is an early individual submission and is inconsistent in places.
Where it is ambiguous Plenipo chose the stricter reading.

1. **Chain layout.** The draft concatenates the whole chain in one string,
   `<SD-JWT>~~<KB-SD-JWT 1>~…~<KB-SD-JWT n>~…`, and the first KB-SD-JWT is
   signed by the key in the original credential's `cnf`. In Plenipo the root is
   a PID presentation plus transaction data, and the first delegation is signed
   by the agent key the wallet approved in the mandate, not by the wallet's
   holder key. So each link is carried on its own in `chain.delegations`, and
   the chain array plays the role of the `~~` concatenation. A draft-style
   concatenated string is refused.
2. **Binding to the previous link.** The draft binds each KB-SD-JWT to the
   preceding component with `sd_hash` or, when that is absent,
   `issuer_jwt_hash`. Section 5.1.3 and 5.1.4 disagree on whether `sd_hash`
   covers the disclosures. Plenipo binds to the parent *mandate* with
   `parent_id` and `parent_hash` instead, as the JWS format does. This keeps
   links interchangeable between formats (a child stays valid if its parent's
   delegation is re-issued or re-encoded), and the root has no preceding
   KB-SD-JWT to hash. `sd_hash` and `issuer_jwt_hash` are refused rather than
   ignored, so no one relies on a binding Plenipo does not check.
3. **`typ`.** Sections 2.2 and 5.1.4 and the IANA registration (A.2) use
   `kb+sd-jwt+kb`; section 6 uses `kb-sd-jwt+kb`. Plenipo emits `kb+sd-jwt+kb`
   and accepts both. It does not accept `kb+sd-jwt` (a final link without key
   binding), because every Plenipo link binds a key.
4. **`delegate_payload`.** Section 5.1.4 calls it an "array of JSON Objects"
   that must be replaced by disclosures when there is more than one; section
   7.1 calls it a digest. Plenipo always uses one array element in the RFC 9901
   array-element form `{"...": digest}` with its disclosure, and refuses decoys
   and multiple delegate payloads. The draft does not state the array-element
   syntax; it is inferred from RFC 9901 section 4.2.2.
5. **Delegate Payload placement.** `cnf` and every constraint live in the
   Delegate Payload, as section 5.1.4 requires ("All claims that are expected
   to be found in the issuer-signed JWT Payload … MUST instead be claims in the
   Delegate Payload"). The signed JWT carries only `iat`, `_sd_alg` and
   `delegate_payload`.
6. **`aud` and `nonce`.** RFC 9901 requires them in a key binding JWT used for a
   presentation; the draft does not say whether a delegation needs them. A
   Plenipo delegation is not a presentation to a particular verifier, so they
   are not used and are refused. Freshness and audience are checked on the
   invocation.
7. **Hash algorithm.** Only `sha-256`. The draft names none for
   `delegate_payload` or `issuer_jwt_hash`.
8. **Canonical disclosure.** RFC 9901 does not require canonical JSON in
   disclosures; Plenipo does, for the same reason as for the root transaction
   data.
9. **JSON serialization** (draft section 5.1.2) is not supported.
10. **Policy.** Attenuation, depth (5 hops and `max_depth`), spending limits and
    their shared ledger, expiry and revocation are Plenipo's, and apply to
    Delegate SD-JWT links exactly as to JWS links. The draft defines none of
    them.

## OpenID4VP `delegate` transaction data (helper)

Section 7.1 lets a verifier ask a wallet to issue a delegation as part of an
OpenID4VP presentation, with transaction data of type `delegate`.
`createDelegateTransactionData` builds that object:

```ts
const { transactionData, encoded, delegatePayloadDigest } = createDelegateTransactionData({
  credentialIds: ['pid'],
  delegatePayload: { cnf: { jwk: agentJwk }, plenipo_mandate: mandate },
  format: 'dSD-JWT+KB', // default; dSD-JWT is also accepted
  delegateDisclosures: [], // optional
});
// transactionData = { type: 'delegate', credential_ids: ['pid'], format: 'dSD-JWT+KB',
//                     delegate_payload_disclosure: '<base64url [salt, payload]>' }
// encoded = base64url of its RFC 8785 JSON, for the request's transaction_data array
// delegatePayloadDigest = SHA-256 of the disclosure, expected in the wallet's delegate_payload
```

It is a helper only: it is not wired into `createMandateRequest`, and Plenipo
roots still use `plenipo_mandate`. No wallet is known to support `delegate`.
Points the draft leaves open:

- it says "the transaction_type delegate"; OpenID4VP 1.0 names the member
  `type`, which is what the helper uses, together with the `credential_ids`
  OpenID4VP requires;
- `format` is `dSD-JWT` or `dSD-JWT+KB`; the helper requires `cnf` in the
  payload for `dSD-JWT+KB`;
- `delegate_disclosures` is described as "containing the
  delegate_payload_disclosure", which reads as a drafting error; the helper
  treats it as the optional list of disclosures for selectively disclosable
  claims inside the Delegate Payload, and omits it when empty;
- the draft says the wallet "MAY include additional decoy digests"; a Plenipo
  verifier would refuse those, so a wallet-issued delegation meant for Plenipo
  must not use them.

## Limits

- Delegate SD-JWT links are accepted only below the root; the root is always a
  PID presentation with `plenipo_mandate` transaction data.
- Tokens from other Delegate SD-JWT implementations verify only if they follow
  this profile; generic delegations with their own constraint claims are
  refused, by design.
- The draft may change incompatibly; this profile tracks -00.

## Sources

- draft-gco-oauth-delegate-sd-jwt-00:
  <https://datatracker.ietf.org/doc/html/draft-gco-oauth-delegate-sd-jwt>,
  status page <https://datatracker.ietf.org/doc/draft-gco-oauth-delegate-sd-jwt/>
- RFC 9901, Selective Disclosure for JSON Web Tokens:
  <https://www.rfc-editor.org/rfc/rfc9901>
- RFC 7638, JSON Web Key Thumbprint; RFC 8785, JSON Canonicalization Scheme;
  OpenID for Verifiable Presentations 1.0 (transaction data).
