# Sandbox

`sandbox/` is a simulation environment for Plenipo: a PID provider, a wallet, an agent platform, a
bank and AI agents, each an HTTP service, started with one command and observed on a live dashboard.
It is a separate npm package that depends on the library through `"plenipo": "file:.."`; the
library does not depend on it, and the library's test suite does not run it. How to run it and how
to demo it are in [sandbox/README.md](../sandbox/README.md); real wallets and the public host in
[sandbox/level2/README.md](../sandbox/level2/README.md).

## Design

- **Separate parties, HTTP only.** The launcher passes each service its configuration (trust
  anchors, the platform's status list key, accepted platforms), as a deployment would; at runtime
  the services only talk over HTTP: OpenID4VP between platform and wallet, status lists between
  bank and issuers, MCP or REST between agents and bank.
- **The library unchanged.** The PID provider and the wallet wrap `plenipo/testing`
  (`createTestCertificateAuthority`, `createTestPidProvider`, `createTestWallet`); the platform uses
  `createMandateRequest`, `handleMandateResponse`, `delegateMandate`, `createInvocation` and
  `StatusListPublisher`; the bank uses `guardTool` for MCP and `verifyAuthorization` for REST.
- **Identities are https names**, because verifiers fetch status lists over https only. Locally a
  fetcher maps each name to the service that publishes it, with the library fetcher's limits; on
  the public host the same names are real.
- **The platform holds its hosted agents' keys and signs whatever they ask**; agents that hold their
  own key (the MCP bridge) register only the public key. Enforcement is the bank's job, which is what
  the demo shows.
- **Scenarios are data plus checks** (`src/scenarios.ts`): the same code prints PASS/FAIL for a
  live audience and runs as the e2e test suite on free ports.
- **The LLM agent** gets the bank's MCP tools; each `tool_use` becomes a signed invocation bound to
  the exact arguments the server will see, attached in `_meta` under `plenipo/authorization`.

## Security considerations

The sandbox moves no real money, but it is meant to run on a public host, so it applies the same
posture as the library:

- Every network input is bounded: request bodies (256 KB by default, 512 KB for wallet responses),
  headers (64 KB, for chains in REST headers), outbound fetches (no redirects, 5 s, 1 MB, 256 KB
  for request objects), and validated before use (scopes, amounts, claims, ids, URLs).
- The sandbox wallet verifies the request object like a wallet must: ES256, `typ`, `x5c` chain to a
  configured RP CA naming the `x509_san_dns` host (with the library's `verifyX5c`), `client_id`
  equal to the signed one, exactly one transaction data entry of a known type, canonical encoding.
  With `SANDBOX_STRICT_CLIENT_ID=1` the `response_uri` must be https on the client's host.
- Wallet error responses are unauthenticated; the platform records them as a refusal but does not
  consume the session, so a genuine approval still counts. A valid response is redeemable once.
- Internal errors are logged, never returned; DENY reasons go to callers, library `detail` only to
  the bank's event log.
- Pages are self-contained with a strict Content-Security-Policy (no external scripts or styles),
  and every value is escaped (server side) or set as text (dashboard).
- Admin endpoints (PID issuance and revocation, the bank clock) require a bearer token when
  `SANDBOX_ADMIN_TOKEN` is set; on the public host only the OpenID4VP and status list paths are
  reachable without the demo login.
- The ledger and nonce stores sit behind a factory: in memory, or the library's Postgres or Redis
  stores. A wrong URL or a missing driver stops the start instead of falling back to memory; a
  reservation left pending (a tool that threw) is swept to `expired_spent`, still counted, until it is
  reconciled.

Regression tests for these are in `sandbox/test/sandbox.e2e.ts` (untrusted RP CA, unsigned request
object, double redemption of a wallet response, body limit, unauthenticated MCP and REST calls,
status fetcher refusing unmapped and non-https URLs).

## What the sandbox suggested for the library

The first version of the sandbox reported six points; the library has since addressed them, and the
sandbox uses the result:

1. The guarded handler receives the verified decision as its third argument (the bank finds the
   account from `decision.principal`).
2. `guardTool` accepts `now` as a function (the bank's clock, which the `expired` scenario moves).
3. `counterparty: null` / `amount: null` declare a call without counterparty or money: read and card
   tools no longer need the bank's host in the mandate or an amount of 0, and reserve nothing.
4. PID signer identity on the EU test PKI: still to check against a real EU test PID (level 2, B).
5. TS12: `createMandateRequest({ transactionDataType: 'emandate' })`; the platform offers it, bound to
   the PID, and the sandbox wallet shows the TS12 summary.
6. `issuePid` and `lastStatus`: the PID provider now reads the status reference from the issued PID.

## The MCP bridge

`src/bridge/core.ts` holds everything an MCP client needs to act under a mandate, with no transport:
the agent key (generated locally, only its public key goes to the platform), the mandate request and
its approval, the approved chain, and signing and forwarding of the bank's tools. State goes through a
`BridgeStateStore` (a 0600 JSON file for the stdio bridge), so the same core can serve a hosted variant
behind Streamable HTTP with one store per session. `src/bridge/server.ts` exposes it as an MCP server
with the low-level SDK server, so the bank's JSON schemas pass through unchanged.

## Limits

- One process; restarting loses mandates and PIDs (the shared stores keep ledger, nonces and sessions).
- PID issuance is a POST, not OpenID4VCI; the people and accounts are fictitious.
- No run against walt.id or a phone has been done (see the level 2 status table).
- The dashboard trusts the services it polls; it is an operator view, not an audit log.
