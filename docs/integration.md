# Integrating Plenipo in front of an API

This document is for a bank (or any relying party) that wants AI agents to call
its APIs under a Plenipo mandate. It describes what travels on the wire, how a
request is bound to the agent's signed invocation, the gateway that enforces
it, the error catalogue, the status list service, the audit log and the export
to external policy engines. Everything here is in `plenipo` (`src/http/`,
`src/audit.ts`, `src/policy-export.ts`) and has no dependency on a web
framework, OPA or Cedar.

```
agent ──HTTP + Plenipo-Chain + Plenipo-Invocation──▶ gateway ──▶ bank API
                                                       │  verifyAuthorization(expected = the request)
                                                       │  ledger reserve → commit / release
                                                       │  audit log (hash chain)
                                                       └─ optional policy engine (OPA, Cedar)
platform ──admin API──▶ status list service ◀──GET── verifiers
```

Three deployment shapes work with the same code:

- **In-process middleware**: `toNodeListener(gateway.handle)` or
  `expressMiddleware(gateway)` in the API server itself.
- **Edge or sidecar**: `gateway.handle` is a Fetch-API handler
  (`(Request) => Promise<Response>`) and runs on Node, Deno, Bun or an edge
  runtime, with `downstream` forwarding to the API.
- **Decision only**: `gateway.authorize(request)` returns the decision and a
  `settle` function, for frameworks that call the handler themselves.

## 1. HTTP transport

An agent sends two request headers:

| Header | Value |
| --- | --- |
| `Plenipo-Chain` | unpadded base64url (RFC 4648 §5) of the UTF-8 JSON `MandateChain`: `{"root":{"transaction_data":"…","presentation":"…"},"delegations":["<jws>",…]}` |
| `Plenipo-Invocation` | the invocation compact JWS, as returned by `createInvocation` |

`authorizationHeaders(chain, invocation)` builds both. The gateway reads them
with `parseAuthorizationHeaders`, which is strict:

- **Sizes first.** `Plenipo-Chain` longer than `maxChainHeaderBytes`
  (default 64 KiB) or `Plenipo-Invocation` longer than
  `maxInvocationHeaderBytes` (default 8 KiB) is refused with 431 before any
  decoding.
- **Strict encoding.** Only `[A-Za-z0-9_-]`, no padding, and the value must
  re-encode to itself. The invocation must be three base64url segments.
- **Exact shape.** The decoded chain must have exactly `root` and
  `delegations`; `root` exactly `transaction_data` and `presentation` (both
  strings); at most 5 delegations, each a compact JWS. Extra members are
  refused rather than ignored.
- **One of each.** A repeated header reaches the gateway joined with `", "`,
  which fails the encoding check, so an intermediary cannot append a second
  chain.
- **Not forwarded.** The gateway removes both headers before calling the API
  (`forwardAuthorizationHeaders: false` by default): the chain carries the PID
  disclosures, and API logs should not.

Header limits elsewhere in the path matter more than the gateway's own. Node's
`http` server refuses requests whose headers exceed 16 KiB unless it is created
with `maxHeaderSize`; reverse proxies and load balancers have their own limits
(nginx `large_client_header_buffers`, for instance). With the test fixtures an
encoded chain is about 3 KiB with the root alone and 6–7 KiB with three
delegations; a production PID with a longer x5c chain and more disclosed claims
adds a few KiB. Set those limits explicitly and keep them consistent with
`maxChainHeaderBytes`.
TLS is assumed: the headers are bearer-like evidence for a single invocation.

### Chain by reference (future)

A chain is the same for every call an agent makes under a mandate, so sending
it on each request is wasteful. A later version may accept
`Plenipo-Chain-Ref: <id>` instead of `Plenipo-Chain`, resolved from a cache
that the agent filled earlier (for example by `PUT /plenipo/chains/<id>` with
the chain as body, where `<id>` is the SHA-256 of its canonical JSON, so the
client cannot make the bank store one chain under another chain's id). The
reference changes nothing in verification: the full chain is verified on each
request, and the invocation is still signed by the leaf agent, so a poisoned
cache entry can only cause a denial. Not implemented in this version.

## 2. Binding the invocation to the request

The agent's invocation says what it is about to do: action, counterparty,
amount and a hash of the arguments. The gateway must check that the HTTP
request does exactly that, otherwise an agent (or someone who captured an
invocation) could sign a payment of 10 EUR and send one of 10,000. The bank
supplies a route table; the gateway derives `expected` for
`verifyAuthorization` from each request:

```ts
import { createGateway, InMemoryNonceStore, toNodeListener } from 'plenipo';

const gateway = createGateway({
  routes: [
    {
      method: 'POST',
      path: '/accounts/:account/payments',
      action: 'payments.sepa.credit_transfer',
      counterparty: (r) => (r.json() as any).creditor_host,
      amount: (r) => {
        const b = r.json() as any;
        return { value: b.amount_minor, currency: b.currency };
      },
      // args: default, see below
    },
    {
      method: 'GET',
      path: '/accounts/:account/balance',
      action: 'accounts.balance.read',
      counterparty: null,
      amount: null,
    },
  ],
  verify: { audience: 'https://api.bank.example', nonces, ledger, trustAnchors, mandateStatusTrust },
  downstream: (request, ctx) => api(request, ctx),
  audit,
});
http.createServer({ maxHeaderSize: 80 * 1024 }, toNodeListener(gateway.handle, { origin: 'https://api.bank.example' }));
```

Rules, all enforced:

- `counterparty` and `amount` must each be a function or `null`. Leaving one
  out is a configuration error, because an unbound field is exactly how
  counterparty smuggling happens.
- A function that returns `undefined`, throws, or returns an invalid amount
  (not a non-negative safe integer in minor units with an ISO 4217 code) makes
  the gateway answer 400 `request_unmapped` without calling the verifier.
- With `null`, the gateway tells the verifier that the call has no
  counterparty, or moves no money (`expected.counterparty = null`,
  `expected.amount = null`): an invocation that declares that field is refused,
  and the mandates' counterparty restrictions or spending limits do not apply
  to the call, so no amount is reserved. A post-verification check refuses the
  same case again with 422 `invocation_mismatch`, as a second guard.
- `action` is fixed per route and must be concrete (no wildcard).
- **Arguments.** Unless the route sets its own `args` function, the invocation
  must carry `args_hash = argsHash({ method, path, query, media_type, body })`,
  where `method` is the upper-case method, `path` the raw (percent-encoded) URL
  path as sent, `query` an object of query parameters (a repeated name becomes
  an array, in order; `{}` when there are none), `media_type` the normalised
  JSON media type (`application/json`, or `application/<x>+json`, lower case,
  without parameters) or `null` when there is no body, and `body` the
  JSON-parsed body, or `null` when empty. `argsHash` is SHA-256 over RFC 8785
  canonical JSON, so key order and whitespace do not matter. `args: null` turns
  argument binding off; only do that when action, counterparty and amount
  determine the whole operation.
- **Content type.** The gateway reads a body as JSON (for the default
  arguments, and whenever a route function calls `ctx.json()`) only when the
  request declares it as JSON: exactly one `Content-Type` of
  `application/json` or `application/<x>+json`, with no parameter other than
  `charset=utf-8`, and no `Content-Encoding`. Anything else is refused with 415
  `unsupported_media_type` before verification. The API receives the body with
  that normalised `Content-Type`, so it cannot parse it as a form or under
  another type and execute fields the agent never signed. A route that accepts
  other bodies must define its own `args` (and read `ctx.body` or `ctx.text()`);
  the original `Content-Type` is then forwarded unchanged.

The default binding covers the debtor account in the path and every body field,
so changing the IBAN, the remittance information or the account in the URL all
fail with 422. On the agent side:

```ts
// amount_minor: integer in the ISO 4217 minor unit of the currency (cents for EUR, not for JPY or KWD).
const body = { creditor_host: 'shop.example', amount_minor: 12000, currency: 'EUR', iban: 'IT…' };
const invocation = await createInvocation(agentKey, {
  chain,                 // the exact chain sent in Plenipo-Chain; the invocation signs its hash
  mandateId: leaf.id,
  action: 'payments.sepa.credit_transfer',
  counterparty: body.creditor_host,
  amount: { value: body.amount_minor, currency: body.currency },
  aud: 'https://api.bank.example',
  nonce, // issued by the bank, or random if the bank's nonce store accepts that
  args: { method: 'POST', path: '/accounts/acc-1/payments', query: {}, media_type: 'application/json', body },
});
await fetch(url, { method: 'POST', headers: { ...authorizationHeaders(chain, invocation), 'content-type': 'application/json' }, body: JSON.stringify(body) });
```

Read-only routes work under any mandate that covers their action: declaring
`amount: null` and `counterparty: null` is how a route says the call moves no
money and has no counterparty, so a mandate with spending limits and a
counterparty list can still authorise a balance read. Declare `null` only for
operations that really cannot move money or reach a third party: the bank is
the one that knows, and the mandate's limits are not consulted for such calls.

Route matching is at least as permissive as common routers, so a request
cannot reach a protected handler by a spelling the gateway does not recognise:
literal segments are compared percent-decoded and case-insensitively, one
trailing slash is accepted, a `GET` route also covers `HEAD`, and `:name`
parameters are percent-decoded, non-empty and without `/`. A request that
matches no route gets 404 `no_route`. With `unmatched: 'pass'`, unmatched
requests are forwarded unchecked, except any request whose path equals or
extends a protected route pattern in any letter case, with any method, any
number of empty segments or a longer path (`/accounts/1/payments/x/confirm`):
those are refused with 404, because some router might still dispatch them to a
protected handler.

**The checked path is the routed path.** URL parsers normalise: the WHATWG
parser turns `\` into `/` and resolves `.`, `..` and `%2e` segments, while
Node accepts the raw request target and Express routes on it. Checking a
normalised copy would let `/accounts/123\..\456/payments` be verified as
account 456 and executed as account `123\..\456`. The Node and Express
adapters therefore never normalise and then authorise: they refuse with 400
`malformed_target` any request target that URL parsing would change, and in
particular any path with a backslash, a `.` or `..` segment in any spelling
(`%2e`, `.%2E`, …), an encoded slash, backslash or control character (`%2f`,
`%5c`, `%00`–`%1f`, `%7f`), a leading `//`, a fragment, or a raw space, control
or non-ASCII character. The gateway applies the same check to the URL of every
Fetch request, including those it would pass through.

Handlers must take path parameters from `req.plenipo.params` (Express) or the
`params` given to `downstream`: those are the values the invocation was
verified against. With the target check they equal Express's `req.params`, but
a handler that reads the verified values does not depend on that.

These rules close the known differences with routers such as Express, but they
cannot know every router's behaviour. Two deployments narrow the question
further:

- **Per-route middleware.** `plenipoRoute(route, gatewayOptions)` returns
  middleware to put on the protected route itself
  (`app.post('/accounts/:account/payments', plenipoRoute(…), handler)`), so the
  router decides which requests reach the check, and no request reaches the
  handler without it. The router and the gateway still read the path
  separately; the target check above is what keeps them reading the same
  thing. `route.path` must be the full path including any mount prefix;
  otherwise every request is refused.
- **`gateway.handle` with `downstream`.** The API receives the `Request` the
  gateway checked, so there is nothing to reinterpret.

When the gateway runs as a separate proxy in front of the API, the API must
also normalise paths the same way (`..`, `%2F`, trailing slashes, case);
otherwise a request could be authorised for one route and executed as another.

The gateway reads at most `maxBodyBytes` (default 1 MiB) of body, refusing
larger requests with 413, and hands the API a new `Request` with the same body.
A `GET` or `HEAD` request that carries a body (`Content-Length` above 0 or any
`Transfer-Encoding`) is refused with 400 `body_not_allowed` by the Node and
Express adapters: the checked request has no body there, but a body parser
would still give one to the handler. A JSON body with an object that repeats a
member name (at any depth, compared after unescaping) is refused with 400
`malformed_body`, because JSON parsers disagree on which value wins. A
`Plenipo-Outcome` header sent by the client is removed before the API sees the
request; only the API's response may carry one.

## 3. The gateway

For a matched route, `gateway.handle(request)`:

1. parses the headers, reads the body, derives `expected` from the route;
2. calls `verifyAuthorization(chain, invocation, { ...verify, expected })`;
3. on DENY answers with a problem document (section 4);
4. on ALLOW, refuses a counterparty/amount the route does not carry, runs the
   optional `policy` hook, appends the decision to the audit log, and calls
   `downstream`;
5. **settles the reservation** (below). A throwing API produces 500
   `processing_error` with no detail; the error goes to `onError`. Every
   settlement is appended to the audit log.

### Settlement

A reservation is released only when it is certain that the action did not run.
Releasing after an action that did run lets an agent spend past its total
limit, so an unknown outcome is never treated as a failure:

| What happened | Outcome |
| --- | --- |
| a refusal before the API is called (policy, counterparty/amount mismatch, audit failure) | release |
| the API answered 2xx | commit |
| the API answered 4xx | release (a definite refusal); `clientErrorOutcome: 'pending'` if your API can answer 4xx after acting |
| the API answered 5xx, 1xx or 3xx, threw, timed out, or returned something that is not a `Response` | **pending** |

A `303 See Other` after a successful POST is therefore pending too: the amount
stays counted until reconciled or swept, which over-counts but never lets an
agent overspend. APIs that answer 303 on success should set
`Plenipo-Outcome: executed`.
| the API set `Plenipo-Outcome: executed`, `not-executed` or `unknown` | commit, release or pending, whatever the status |

`Plenipo-Outcome` is a response header the protected API can set to state the
outcome explicitly (for example a 503 when the core system refused before
acting); the gateway removes it before the response reaches the client.

**Pending** means the reservation is left as it is: it keeps counting against
the limits, and the expiry sweep of the Postgres and Redis ledgers turns stale
pending reservations into `expired_spent`, which still counts as spent (see
docs/stores.md). To settle it, reconcile against the core banking system:
`ledger.reconcile(reservationId, 'executed')` when the operation went through,
`ledger.reconcile(reservationId, 'not_executed')` when it certainly did not,
which gives the amount back; or call `settle({ outcome: 'commit' | 'release' })`
if you still hold the `authorize` result and the reservation has not expired.
The reservation id is in the audit record of the decision and of the pending
settlement. This matches `guardTool`, which also leaves a reservation pending
when its handler throws. `commit` and `release`
are final; `pending` is not, so a later commit or release still applies. A
ledger that fails on commit or release also leaves the reservation pending and
reports through `onError`.

The client's abort signal is never forwarded to the API: an agent that hangs up
must not cancel a call whose effect may already be underway, nor turn an
executed action into an apparent failure. Give the downstream call its own
timeout; when it fires, the outcome is pending.

The commit happens when the API returns its `Response`, before a streamed body
is fully sent. An API that can fail after that point should settle itself
through `authorize` instead.

`gateway.authorize(request)` returns `{ kind: 'deny', response }`,
`{ kind: 'pass', request }` or `{ kind: 'allow', decision, request, settle }`.
Call `settle({ status })`, `settle({ error })` or `settle({ outcome:
'commit' | 'release' | 'pending' })`; `gateway.outcomeForStatus(status)` gives
the status rule above. A reservation never settled stays pending. Pass the
response as second argument (`settle({ status }, response)`) to keep it for
idempotent replays.

### Idempotent retries

An agent that loses the answer to a payment cannot tell whether it went
through. With `verify.idempotency` set to an `IdempotencyStore`, it can retry
safely: every attempt of one intention carries the same idempotency key
(`createInvocation({ …, idempotencyKey })`, a fresh `nonce` each time), and at
most one attempt reaches the API.

```ts
const gateway = createGateway({
  routes,
  verify: { ...verifyOptions, ledger, idempotency: new PostgresIdempotencyStore(pool) },
  downstream,
});
```

The gateway ends the attempt with the same rule as the reservation: a commit
marks the key executed and keeps the response (status, `Content-Type` and body,
up to `maxReplayBytes`, default 64 KiB, at most `MAX_REPLAY_BODY_BYTES`), a
release frees the key, a pending outcome blocks it until reconciled. Only a
committed request that carries a key is read: the gateway reads its body once,
for at most a second, and hands the client a response rebuilt from what it read
followed by the rest of the stream, so a large or streamed body reaches the
client unchanged and is simply not kept. In authorize mode, pass what to keep
as `settle({ status }, { status, contentType, body })`. A retry is then
answered without calling the API:

| The first attempt | The retry gets |
| --- | --- |
| executed, response kept | that response, with `Plenipo-Replay: true` |
| executed, response not kept (too large, streamed) | 409 `already_executed` |
| still running | 409 `idempotency_in_progress`, with `Retry-After` |
| outcome unknown (5xx, timeout, crash) | 409 `idempotency_unresolved`, until reconciled |
| a refusal (4xx, policy) | nothing: the key was freed, the retry runs |
| a key reused for another body | 422 `idempotency_conflict` |

A verifier without an idempotency store refuses invocations that carry a key
(`configuration`, 500), because it could not keep the promise; tell agents
which routes accept keys. Reconcile unknown outcomes as for reservations
(docs/stores.md, "Idempotency keys").

A key is scoped to the audience and the chain, and compared by action,
counterparty, amount and argument hash: it does not name the route or the
tool. Give each operation its own action, or arguments that tell it apart.
With the default `args` of a route, method and path are part of the argument
hash, so routes never share a key. For MCP tools, where the arguments are the
tool's own, two tools with the same action and the same arguments would: a
balance read and an account freeze both called with `{}` must not share
`accounts.read`.

### Revocation latency

A revoked mandate stops being accepted when the verifier sees the new status
list. With a `StatusListCache`, that happens after the cache lifetime: the
shortest of its maximum age (60 s by default), the list `ttl` and the list
`exp`. With shared HTTP caches in front of the status service, add the
`Cache-Control` max-age the service sends (bounded by the `ttl`).

For routes that move money, set `maxStatusAgeSeconds` on the route (or on the
verify options of a `guardTool`): a cached list older than that is fetched
again, and the default fetcher asks caches on the way for a copy no older
than that (`Cache-Control: max-age=<n>`). `0` fetches the list on every
request; reads can keep using the cache. The verifier cannot see how long an
HTTP cache kept the copy it gets: with a CDN in front of the status service,
make it honour request `Cache-Control` or bypass it for status lists, and a
custom `statusFetcher` should pass the bound on.

```ts
{ method: 'POST', path: '/payments', action: 'payments.transfer', counterparty, amount, maxStatusAgeSeconds: 5 }
```

### Express

`expressMiddleware(gateway)` does the same for `(req, res, next)` stacks. On
ALLOW it removes the `Plenipo-Chain` and `Plenipo-Invocation` headers from
`req.headers` and `req.rawHeaders` (they carry PID disclosures), sets
`req.plenipo = { decision, route, params, settle }` and calls `next()`. The
status of the finished response decides the outcome with the rules above;
`req.plenipo.settle('executed' | 'not-executed' | 'unknown')` decides it
explicitly and takes precedence. If the connection closes before the response
finishes (the client hung up, or the handler failed mid-response), the
reservation stays pending: the handler may still be running the transfer.

The middleware binds the invocation to the body bytes the handlers will act on.
If the request stream is still unread it reads it itself, whatever `req.body`
holds (body-parser 1.x sets `req.body = {}` for a type it does not handle and
leaves the stream for a later parser), sets `req.body` to the parsed JSON, and
marks the stream consumed so later parsers skip it. If a JSON parser already
consumed the body, it uses `req.body`; if a non-JSON parser consumed it, the
request is refused with 415. Prefer `plenipoRoute` on each protected route over
one `expressMiddleware` with `unmatched: 'pass'`.

Options worth setting:

| Option | Default | Purpose |
| --- | --- | --- |
| `audit` | none | `AuditLog` receiving every decision and settlement |
| `auditFailure` | `deny` | an ALLOW that cannot be recorded is refused with 503 `audit_unavailable` |
| `policy` | none | `(decision, ctx) => boolean`; false or a throw refuses with 403 `policy_denied` |
| `onEvent`, `onError` | none | metrics and internal errors; exceptions in them are ignored |
| `unmatched` | `deny` | `pass` forwards unprotected paths without checks (never paths that touch a protected route) |
| `clientErrorOutcome` | `release` | outcome of a 4xx from the API; `pending` if it can answer 4xx after acting |
| `realm`, `retryAfterSeconds` | none, 5 | `WWW-Authenticate` realm and `Retry-After` |

Denials on protected routes are audited even when they come from
unauthenticated requests, so put rate limiting in front of the gateway; it does
not limit request rates itself.

## 4. Errors

Denials are RFC 9457 problem documents (`application/problem+json`,
`Cache-Control: no-store`):

```json
{
  "type": "https://plenipo.net/problems/limit_total",
  "title": "The amount would exceed a total limit in the chain",
  "status": 403,
  "code": "limit_total",
  "at": 1
}
```

`code` is a stable machine code (the DenyCode in lower case, or a gateway
code); `at` is the index in the chain where verification failed (0 is the root
mandate), when it applies. The body **never** carries the verifier's `reason`
or `detail`: reasons quote hosts, amounts and library messages, details carry
network errors. Both go to the audit log. 401 responses carry
`WWW-Authenticate: Plenipo error="<code>"`; 503 responses carry `Retry-After`.
The tables are exported (`DENY_PROBLEMS`, `GATEWAY_PROBLEMS`,
`problemForDecision`) so a bank can translate them into its own catalogue.

| DenyCode | HTTP | Kind |
| --- | --- | --- |
| `CONFIGURATION` | 500 | configuration |
| `MALFORMED` | 400 | request |
| `INVOCATION_MISMATCH` | 422 | request |
| `ROOT_INVALID`, `PID_ISSUER_UNTRUSTED`, `TX_DATA_MISMATCH` | 401 | authentication |
| `PID_REVOKED`, `ATTESTATION_REVOKED` | 401 | authentication |
| `DELEGATION_SIGNATURE_INVALID`, `DELEGATION_PARENT_MISMATCH` | 401 | authentication |
| `NOT_YET_VALID`, `EXPIRED` | 401 | authentication |
| `REVOKED` | 401 | authentication |
| `DISPLAY_MISMATCH`, `ATTESTATION_UNTRUSTED`, `ATTESTATION_INVALID` | 401 | authentication |
| `INVOCATION_SIGNATURE_INVALID`, `INVOCATION_MANDATE_MISMATCH`, `INVOCATION_STALE`, `AUDIENCE_MISMATCH` | 401 | authentication |
| `REPLAY` | 409 | conflict |
| `LIFETIME_POLICY`, `DELEGATION_NOT_ALLOWED`, `ATTENUATION_VIOLATION` | 403 | authorization |
| `ACTION_NOT_PERMITTED`, `COUNTERPARTY_NOT_PERMITTED`, `CURRENCY_MISMATCH` | 403 | authorization |
| `LIMIT_PER_OPERATION`, `LIMIT_TOTAL` | 403 | authorization |
| `ROOT_POLICY`, `ROLE_EXCEEDED` | 403 | authorization |
| `STATUS_UNAVAILABLE` | 503 | infrastructure |
| `INTERNAL` | 500 | infrastructure |

The split is: 401 when the presented credentials are not valid (signatures,
trust, time, revocation, audience: the agent needs a new mandate or
invocation), 403 when they are valid but do not cover the request, 409 for
replay, 422 when the request contradicts what the agent signed.

Infrastructure failures have their own codes:

- `STATUS_UNAVAILABLE` (503, with `Retry-After`): a status list could not be
  obtained at all (network error, HTTP error, size limit). A list that was
  obtained but failed verification (wrong signer, origin outside the
  configuration, bad signature, expired) is not an outage: it stays `REVOKED`,
  `PID_REVOKED` or `ATTESTATION_REVOKED`, 401.
- `INTERNAL` (500): an unexpected exception aborted verification, typically a
  ledger, nonce store or registry that failed. Any amount reserved before the
  failure is released.
- `CONFIGURATION` is a server-side problem the caller cannot fix.

Gateway codes:

| Code | HTTP | When |
| --- | --- | --- |
| `authorization_required` | 401 | a Plenipo header is missing |
| `malformed_authorization` | 400 | header encoding or chain shape is wrong |
| `header_too_large` | 431 | a header exceeds its limit |
| `body_too_large` | 413 | the body exceeds `maxBodyBytes` |
| `request_unmapped` | 400 | the route could not read counterparty, amount or arguments |
| `unsupported_media_type` | 415 | a body read as JSON is not declared as JSON (or is encoded) |
| `malformed_target` | 400 | the request target is not in normal form (backslash, dot segment, encoded slash, …) |
| `body_not_allowed` | 400 | a `GET` or `HEAD` request carries a body |
| `malformed_body` | 400 | a JSON body is invalid or repeats a member name |
| `no_route` | 404 | no protected route matches |
| `policy_denied` | 403 | the policy hook refused |
| `status_unavailable` | 503 | a status list could not be checked |
| `audit_unavailable` | 503 | the decision could not be recorded |
| `processing_error` | 500 | unexpected internal failure |
| `admin_forbidden`, `entry_unknown`, `entry_revoked`, `method_not_allowed` | 403, 404, 409, 405 | status list admin API |

### Mapping to an existing error catalogue

Banks that expose PSD2 APIs often use the Berlin Group NextGenPSD2 style of
error messages, where errors are listed as `tppMessages` entries with a
`category` and a `code`. The following is an *example* of how a bank could map
Plenipo codes onto codes of that style; it is not a statement of conformance
with the NextGenPSD2 specification, and the codes should be checked against
the version of the implementation guidelines the bank implements.

| Plenipo code | Example NextGenPSD2-style code |
| --- | --- |
| `malformed`, `malformed_authorization`, `request_unmapped` | `FORMAT_ERROR` |
| `expired`, `not_yet_valid` | `CONSENT_EXPIRED` |
| `revoked`, `pid_revoked`, `root_invalid`, `tx_data_mismatch`, `delegation_*`, `attenuation_violation` | `CONSENT_INVALID` |
| `invocation_signature_invalid`, `invocation_mandate_mismatch`, `audience_mismatch`, `invocation_stale` | `TOKEN_INVALID` |
| `pid_issuer_untrusted` | `CERTIFICATE_INVALID` |
| `action_not_permitted`, `counterparty_not_permitted`, `currency_mismatch`, `limit_*`, `lifetime_policy`, `policy_denied` | `SERVICE_BLOCKED` |
| `invocation_mismatch` | `FORMAT_ERROR` (or a bank-specific code) |
| `replay` | bank-specific code: no direct equivalent |
| `status_unavailable`, `audit_unavailable`, `processing_error`, `configuration` | the bank's generic internal error |

```ts
const BG: Record<string, string> = { limit_total: 'SERVICE_BLOCKED', expired: 'CONSENT_EXPIRED' /* … */ };
const p = problemForDecision(decision);
return Response.json({ tppMessages: [{ category: 'ERROR', code: BG[p.code] ?? 'FORMAT_ERROR', text: p.title }] }, { status: p.status });
```

## 5. Status list service

`createStatusService` serves mandate status lists (IETF Token Status List,
2-bit entries) and an admin API:

| Request | Result |
| --- | --- |
| `GET {publicPrefix}<list-id>` (default `/status/`) | 200, `application/statuslist+jwt` |
| `POST {adminPrefix}<list-id>/entries/<idx>/revoke` (default `/admin/status/`) | 200 `{list, idx, status: "invalid"}` |
| `POST …/entries/<idx>/suspend` | 200 `{…, status: "suspended"}` |
| `POST …/entries/<idx>/reinstate` | 200 `{…, status: "valid"}`, 409 `entry_revoked` if revoked |
| `POST {adminPrefix}<list-id>/allocate` | 201, a status reference for a new mandate |

- **Caching.** `Cache-Control: public, max-age=N` with N = min(token `ttl`,
  time to `exp`, `maxCacheSeconds`), so no shared cache keeps a list longer
  than verifiers may. An `ETag` (hash of the token) allows `If-None-Match`/304.
  Revocation therefore takes effect within the list `ttl` (default 60 s in
  `ManagedStatusList` since 0.5, 300 s before); pick a ttl that matches the
  bank's tolerance. A verifier can require a fresher list for some calls with
  `maxStatusAgeSeconds` (see "Revocation latency" below).
- **No open admin.** `authorize(request, op)` is required; the service refuses
  to start without it. It runs before the service reveals whether a list or
  entry exists. Return `true`, or `{ actor }` to record who acted; anything else
  is 403. Use credentials a browser does not attach on its own (mTLS, bearer
  tokens), not cookies. `handleAdmin` and `handlePublic` let you serve the admin
  API on an internal listener only.
- **Revocation is final.** A revoked entry cannot be suspended or reinstated
  (also when it was revoked directly on a `StatusListPublisher` served with
  `publisherSource`; the admin API reads the publisher's state);
  suspension is the reversible state. Unallocated entries are 404.
- **Audit.** With `audit`, every admin operation is appended. A reinstatement
  is recorded *before* it is applied and refused (503) if it cannot be recorded,
  since it restores authority; revocations are applied first, so an audit outage
  never delays a revocation.
- **Persistence.** `ManagedStatusList` keeps its state in a `StatusListStore`
  (`init`, `get`, `allocate`, `setStatus`). `InMemoryStatusListStore` is the
  reference; a database implementation must make `allocate` and `setStatus`
  atomic and keep "invalid is final" inside the same atomic step. The list
  re-signs its token when the store `version` changes or the cached token is
  older than its ttl, so several instances can share one store. Indexes are
  allocated at random.
- An existing `StatusListPublisher` can be served with `publisherSource`
  (in-memory, not persisted; tokens cached for 5 s).
- The list `uri` (what mandates carry, and what verifiers match against the
  token `sub`) must be the public URL at which the service serves the list.
  Verifiers fetch it over HTTPS only, from origins in `mandateStatusTrust`.

## 6. Audit log

`AuditLog` appends records to an `AuditStore` (`InMemoryAuditStore`,
`JsonlFileAuditStore` with optional `fsync`). Appends are serialised, so
concurrent requests cannot fork the chain. A record:

| Field | Content |
| --- | --- |
| `v`, `seq`, `ts` | version 1, sequence from 0, ISO time |
| `prev` | `hash` of the previous record (`AUDIT_GENESIS` for the first) |
| `event` | `decision`, `settlement`, `status_change`, `checkpoint` |
| `decision`, `code`, `problem` | ALLOW/DENY, DenyCode, problem code sent to the client |
| `reason`, `detail` | internal explanation; `detail` truncated to 512 characters |
| `mandate_ids` | the path from the root mandate |
| `invocation_hash`, `invocation` | SHA-256 of the compact invocation; its verified claims (ALLOW) |
| `principal`, `pid_issuer` | minimised PID claims; issuer |
| `reservation`, `settlement`, `http` | ledger reservation, commit/release, method/path/status |
| `evidence` | the compact invocation (default), or also the chain (`evidence: 'full'`) |
| `hash`, `sig` | SHA-256 of the canonical record without `hash`/`sig`; optional signature |

**Minimisation.** By default only `given_name` and `family_name` are kept from
the PID, plus the issuer (`redaction.principalClaims` changes the list; `[]`
keeps none). For a legal person the record keeps `{ type: 'legal_person',
euid, legal_name, role, representative }`, where `representative` holds the
kept PID claims of the person who approved. Every ALLOW record also carries
`principal_id`, the stable identifier of that person (see section 7), so two
people with the same name are never confused. The PID presentation is never
stored unless `evidence: 'full'` is configured. The compact invocation is kept
by default: it contains no personal data and is what proves, in a dispute, what
the agent signed. Of the verified invocation claims only the known ones
(`mandate`, `action`, `counterparty`, `amount`, `aud`, `nonce`, `iat`,
`args_hash`, `chain_hash`) are copied.

**Robustness.** Every record is sanitised before hashing: lone UTF-16
surrogates become U+FFFD, strings are cut at 64 KiB, non-finite numbers become
null. An agent therefore cannot choose values that make its decision
unrecordable. With `auditFailure: 'continue'`, a decision whose full record
cannot be written is followed by an attempt at a minimal record (decision,
mandate ids, reservation) before the request proceeds; only if that fails too
does the request run unrecorded, which is what `continue` accepts.

**Signatures.** With `signer: { key, every }` records are signed (compact JWS,
`typ: plenipo-audit+jwt`, over `{seq, hash}`): every record by default, or every
n-th; `checkpoint()` appends a signed record on demand (on a timer, at
shutdown). Because records are chained, a signature on record n vouches for all
records up to n.

**Verification.** `verifyAuditLog(records, opts)` checks versions, consecutive
`seq`, the `prev` link, each `hash` and, with `key`, each signature. It detects
an edited, deleted, inserted or reordered record anywhere except the tail.

Rule for signatures: **when a key is given, every record must be signed**
(`requireSignatures` defaults to `all`), so a log rewritten without the key,
with recomputed hashes and stripped signatures, is refused. For a log written
with `signer.every > 1` or checkpoints, verify after a checkpoint with
`requireSignatures: 'head'`: the last record must be signed, and through the
hash chain its signature covers every earlier record, so unsigned records
after a signed one are refused too. `requireSignatures: 'none'` with a key is
the explicit weak mode: it checks the signatures present and reports in
`unauthenticated` how many trailing records no signature covers.

Truncating the tail back to a signed record is only detectable against a head
kept elsewhere: `expectedHead` (for example the last checkpoint hash published
to a WORM store or to a supervisor). Keep the signing key outside the host that
writes the log.

**Retention.** The log serves disputes (what did the agent sign, under which
mandate, what did the bank decide and when) and supervisory audits. Payment
and anti-money-laundering record-keeping rules usually require keeping such
records for years (in Italy, for example, ten years for accounting records
under art. 2220 of the Civil Code and for AML data under Legislative Decree
231/2007); GDPR requires minimisation and storage limitation. The defaults
follow that: identifiers, hashes and the agent's signature are kept, personal
data is reduced to the name. To prune records past their retention period,
keep the hash of the last pruned record and verify the remainder with
`anchor`. Check the actual retention periods with the bank's compliance
function; this document is not legal advice.

**Operations.** One writer per store. A failed append makes the log re-read the
store head before the next append; a JSONL file ending with an incomplete line
(crash during a write) makes appends fail until it is repaired, rather than
continuing a broken chain. The gateway refuses ALLOW decisions it cannot record
unless `auditFailure: 'continue'`.

## 7. Policy engines

Plenipo answers "does this agent hold authority for this request"; the bank
may still want its own rules. `toOpaInput(decision, opts)` and
`toCedarRequest(decision, opts)` turn an ALLOW decision into input for Open
Policy Agent and Cedar; the gateway's `policy` hook is where to call them.

### Principal identity

Policies about a person (block lists, per-person caps) need an identifier that
is not a display name: two people can be called Mario Rossi, and a legal-person
mandate has a company and a representative rather than a name. Both exports and
the audit log use `principalIdentity(decision)`:

| Principal | `id` | `id_basis` |
| --- | --- | --- |
| legal person | its EUID | `euid`; the representative gets their own person identifier below |
| natural person with a unique claim disclosed (`principalIdClaims`, default `personal_administrative_number`) | hash of issuer and claim value | `claim:<name>` |
| otherwise, with the PID holder key | hash of issuer and `pid_holder_jkt` | `holder_key` |
| otherwise | hash of issuer and every disclosed claim | `disclosed_claims` |

Whether a decision is on behalf of a legal person is decided by
`decision.representation`, which the verifier sets only after checking a
representation attestation (`isLegalPersonDecision`), never by the shape of
`principal`: a natural person's PID could disclose claims named `type` or
`euid`. For per-person policies that must not fall back to the holder key or
the disclosed claims, pass `requireIdClaim: true` (to `toOpaInput`,
`toCedarRequest` or `principalIdentity`): when no unique claim was disclosed
they throw `PrincipalIdentityError`, and a gateway `policy` hook that throws
refuses the request. The audit log never requires it, so a decision is always
recorded.

`pid_holder_jkt` is a new optional field of the ALLOW decision: the RFC 7638
thumbprint of the PID holder key (`cnf.jwk`). It never collides between people,
but a wallet that uses a different key for each PID copy (batch issuance for
unlinkability) gives the same person several identifiers; request a unique
claim at the wallet when per-person rules must hold across copies. Identifiers
are hashes, so names never appear in them; a claim-based identifier is still
pseudonymous personal data under GDPR.

### OPA input document

`toOpaInput` returns the document to send as `{"input": …}` to OPA's Data API
(`POST /v1/data/<package path>`):

| Path | Type | Content |
| --- | --- | --- |
| `plenipo` | string | schema version, `"1"` |
| `principal.type` | string | `natural_person` or `legal_person` |
| `principal.id`, `principal.id_basis` | string | stable identifier and how it was derived (above) |
| `principal.issuer`, `principal.trusted_via` | string | PID provider; `issuer` or `x5c` |
| `principal.claims` | object | natural person: PID claims, default `given_name`, `family_name` (`principalClaims` to change) |
| `principal.euid`, `principal.legal_name`, `principal.role` | string, string/null, object | legal person: EUID, name, `{code, name, basis}` |
| `principal.representative` | object | legal person: `{id, id_basis, claims}` of the person who approved |
| `root.type`, `root.mandate_id` | string | `eudi_pid`; id of the mandate the wallet approved |
| `chain.depth` | number | delegations below the root (0 = the root agent acts) |
| `chain.mandate_ids`, `chain.exp` | array, number | ids root first; earliest expiry |
| `agent.jkt`, `agent.root_jkt` | string | RFC 7638 SHA-256 thumbprints of the leaf and root agent keys |
| `action`, `counterparty`, `amount` | string, string/null, object/null | from the verified invocation |
| `limits[]` | array | per mandate with limits: `depth`, `mandate_id`, `currency`, `per_operation`, `total`, and with `ledger`: `spent`, `residual` (after this operation's reservation) |
| `invocation` | object | `aud`, `iat`, `nonce`, `args_hash` |
| `time` | object | `epoch`, `iso`, `time_zone`, `local_hour` (0–23), `weekday` (1 = Monday) in `timeZone` (default UTC) |
| `request` | object/null | `method`, `path` when given |

```ts
const gateway = createGateway({
  /* … */
  policy: async (decision, ctx) => {
    const input = await toOpaInput(decision, { ledger, timeZone: 'Europe/Rome', request: { method: ctx.method, path: ctx.path } });
    const res = await fetch('http://127.0.0.1:8181/v1/data/plenipo/example/allow', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ input }),
      signal: AbortSignal.timeout(500),
    });
    return res.ok && (await res.json()).result === true; // anything else refuses
  },
});
```

Example Rego policy (**example only**, not a recommendation):

```rego
# EXAMPLE ONLY: illustrates the input document, not a recommended policy.
package plenipo.example

default allow := false

allow if count(deny) == 0

deny contains "payments above 1,000.00 EUR are not executed at night" if {
	startswith(input.action, "payments.")
	input.amount.currency == "EUR"
	input.amount.value > 100000
	night
}

deny contains "delegation chains deeper than 2 are not accepted" if input.chain.depth > 2

night if input.time.local_hour >= 22

night if input.time.local_hour < 6
```

### Cedar request

`toCedarRequest` returns `{ principal, action, resource, context, entities }`
with entities in Cedar's JSON entity format (`uid`, `attrs`, `parents`; entity
references as `{"__entity": {type, id}}`):

| Entity | Id | Attributes | Parents |
| --- | --- | --- | --- |
| `Plenipo::Person` | person `id` (above) | `id_basis`, `issuer`, `trusted_via`, `claims` | none |
| `Plenipo::LegalPerson` | EUID | `euid`, `legal_name`, `role_code`, `role_name`, `role_basis`, `representative` (a `Plenipo::Person`) | none |
| `Plenipo::Mandate` | mandate id | `depth`, `actions`, `counterparties`, `nbf`, `exp`, limits with `spent`/`residual` | parent mandate, or the principal (person or legal person) for the root |
| `Plenipo::Agent` (request principal) | leaf key thumbprint | `depth`, `mandate` | leaf mandate, principal |
| `Plenipo::Action` (request action) | dotted action | none | the next shorter prefix, so `payments.sepa.transfer` is in `payments` |
| `Plenipo::Operation` (request resource) | hash of the invocation | `amount`, `currency`, `counterparty` | its counterparty |
| `Plenipo::Counterparty` | host | `host` | none |

`context` carries `depth`, `chain_length`, `root_type`, `principal_type`, `pid_trusted_via`,
`time`, `local_hour`, `weekday`, `chain_exp`, and when present `amount`,
`currency`, `min_residual` (smallest residual total in the chain) and
`request`. Amounts are integers in minor units (Cedar `Long`). Exporting extra
PID claims with `principalClaims` only works if they are strings, integers,
booleans, arrays or records: Cedar has no floating point numbers or null. When
policies are validated against a Cedar schema, declare the action groups
(`payments`, `payments.sepa`, …) in the schema as well.

Example Cedar policies (**example only**, not a recommendation):

```cedar
// EXAMPLE ONLY: illustrates the exported request, not a recommended policy.
permit (principal, action, resource);

forbid (principal, action in Plenipo::Action::"payments", resource)
when {
  context has amount && context.currency == "EUR" && context.amount > 100000 &&
  (context.local_hour >= 22 || context.local_hour < 6)
};

forbid (principal, action, resource)
when { context.depth > 2 };
```

## 8. Security notes and limits

- The gateway fails closed: a missing route mapping, an unreadable field, an
  unexpected exception, an unrecordable ALLOW or a throwing policy hook all
  refuse the request. A reservation is released only when the action certainly
  did not run (a refusal before the API is called, a 4xx, or an explicit
  `not-executed`); an unknown outcome leaves it pending for reconciliation.
- No problem document carries internal text. The only occurrence-specific
  member is `at`, the chain index.
- The gateway relies on `verifyAuthorization` for everything cryptographic and
  on the nonce store for replay; use a shared nonce store and ledger when
  several gateway instances serve the same API.
- The audit log has one writer. Several gateway instances need one log each (and
  verification per log) or a store that serialises appends globally.
- The Node adapter buffers request and response bodies; it is not meant for
  streaming uploads or downloads.
- Not implemented: chain by reference, request rate limiting, a database
  `StatusListStore` or `AuditStore`, conformance with any banking API standard.
