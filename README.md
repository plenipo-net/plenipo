# Plenipo

[![CI](https://github.com/plenipo-net/plenipo/actions/workflows/ci.yml/badge.svg)](https://github.com/plenipo-net/plenipo/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/plenipo)](https://www.npmjs.com/package/plenipo)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Mandates, not full powers.** Plenipo lets a person authorise an AI agent from their
European Digital Identity Wallet, and lets any service check that authority before the
agent acts.

A plenipotentiary is an envoy who acts for someone and presents credentials to prove it.
Plenipo gives AI agents the same thing, with one difference: the powers are never full.
Every mandate has a scope, limits and an expiry, every sub-delegation can only narrow it,
and the person can revoke it at any time.

> Status: 0.5, experimental. The cryptography is real; wallets, PID providers and banks in
> the examples and the sandbox are test doubles. The code went through security reviews by independent
> AI review agents (two rounds for 0.3, one for 0.5), and their findings are fixed (see
> [CHANGELOG.md](CHANGELOG.md)); it has not yet been audited by an external security firm. Do not use it
> to protect real money or real data yet.

## Why Plenipo

The EU Digital Identity (EUDI) Wallet is the state-recognised identity that every EU
Member State must offer its citizens under eIDAS 2. It lets a person prove who they are
online with the strength of an ID card at a counter, disclose only the data a service
needs, and approve a specific piece of content, such as a payment, with that identity.

The wallet assumes the person is present. AI agents act when the person is not, and
today they do it with passwords, API keys or saved cards: full powers, with no limits,
no expiry, and no way for a service to know who authorised them. Plenipo lets a person
approve a mandate in their EUDI Wallet once (allowed actions and counterparties,
spending limits, expiry), lets the agent attach proof of that approval to every
request, and lets any service verify it before acting. Sub-delegation can only narrow
a mandate, and the person can revoke it at any time.

## How it works

```
 Person's EUDI Wallet                Agent                    Sub-agent             Service (MCP tool)
 ────────────────────                ─────                    ─────────             ──────────────────
 approves the mandate  ──root──▶  holds mandate  ──delegates──▶  narrower mandate
 (PID + key binding over                                         signs invocation ──▶  verifies chain,
  the mandate hash)                                                                    limits, revocation
                                                                                       ALLOW / DENY
```

1. **Root.** The agent platform asks the wallet for a PID presentation with the mandate as
   OpenID4VP transaction data. The wallet shows the mandate; on approval its key binding
   JWT carries the hash of exactly that mandate. Experimental extensions let the mandate travel
   as the TS12 `urn:eudi:sca:emandate:1` type that certified EUDI wallets render, and let a
   representative give a mandate on behalf of a company within the powers of their role.
2. **Delegation.** An agent can pass a narrower mandate to a sub-agent, signed with its own
   key. The verifier enforces that actions, counterparties, limits, validity and depth only
   shrink.
3. **Invocation.** The acting agent signs what it is about to do: action, counterparty,
   amount, audience, nonce and a hash of the call arguments.
4. **Verification.** The service gets ALLOW or DENY with a machine-readable code, the full
   path of authority and only the PID claims the person chose to disclose.

The wire formats and verification rules are specified in [docs/spec.md](docs/spec.md), with
[test vectors](test-vectors/plenipo-0.2.json) for other implementations. The reasons behind them are
in [docs/design.md](docs/design.md).

## Install

```bash
npm install plenipo
```

[plenipo on npm](https://www.npmjs.com/package/plenipo).

Node 22 or later. ES modules only.

## Try it

From a clone of this repository:

```bash
npm ci
npm test                   # forged delegations, x5c, CRL/OCSP, status lists, OpenID4VP, TS12, shared stores, test vectors
                           # (Postgres and Redis tests run when the servers are available, and skip otherwise)
npm run demo               # OpenID4VP approval, agent, sub-agent, a rail operator's MCP server
npm run example:gateway    # a bank's HTTP API behind the Plenipo gateway

cd sandbox && docker compose up --build   # a bank, a wallet, an agent platform and a live dashboard
```

The [sandbox](sandbox/README.md) also runs with Node, has 17 scripted scenarios and an MCP bridge
that lets Claude Desktop or Claude Code act as the agent. More in [examples/](examples/README.md).

The demo prints:

```
Booking bot: Roma-Milano 18 Oct, 89.00 euro
  rail.example: ALLOW, acting for Mario Rossi, chain depth 1
Booking bot: Milano-Roma 20 Oct, first class, 120.00 euro
  rail.example: DENY LIMIT_PER_OPERATION, amount 12000 exceeds 10000 on mandate 1
...
The person revokes the mandate; the platform flips its entry in the status list.
  rail.example: DENY REVOKED, mandate 0 is revoked in its status list
```

## Use it

```ts
import { createMandate, delegateMandate, createInvocation, verifyAuthorization, generateAgentKey } from 'plenipo';

const agent = await generateAgentKey();
const mandate = createMandate({
  agentJwk: agent.publicJwk,
  actions: ['travel.*'],
  counterparties: ['*.rail.example'],
  limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
  ttlSeconds: 7 * 24 * 3600,
  maxDepth: 1,
});

// The wallet approves `encodeMandateTransactionData(mandate)` and returns the root.
const chain = { root, delegations: [] };

const invocation = await createInvocation(agent.privateKey, {
  chain,                        // the invocation signs the hash of the chain it is presented with
  mandateId: mandate.id, action: 'travel.book', counterparty: 'www.rail.example',
  amount: { value: 8900, currency: 'EUR' }, aud: 'mcp://rail.example',
});

const decision = await verifyAuthorization(chain, invocation, {
  trustAnchors,                 // CA certificates from the PID provider trusted lists
  mandateStatusTrust,           // who signs the mandate status lists
  audience: 'mcp://rail.example',
  nonces,                       // single-use nonce store, mandatory
  ledger,                       // atomic spending reservations, needed for total limits
  expected: { action: 'travel.book', counterparty: 'www.rail.example', amount: { value: 8900, currency: 'EUR' } },
});
// On ALLOW, commit decision.reservation after acting, or release it if you do not act.
```

To get the root from a real wallet, `createMandateRequest` builds the OpenID4VP request
(DCQL for the PID, the mandate as transaction data, encrypted response) and
`handleMandateResponse` turns the wallet's answer into the root. See
[docs/interop.md](docs/interop.md) for what wallets need to support.

On an MCP server, wrap a tool with `guardTool` from `plenipo/mcp`. The client sends the chain
and the invocation in the request `_meta` under `plenipo/authorization`. The guard must say how
it reads the counterparty and the amount from the tool arguments, or pass `null` when the tool
has none; it never trusts what the agent declares on its own:

```ts
const bookTrain = guardTool<{ route: string; price_cents: number }>(handler, {
  action: 'travel.book',
  counterparty: () => 'www.rail.example',
  amount: (a) => ({ value: a.price_cents, currency: 'EUR' }),
  trustAnchors, audience: 'mcp://rail.example', nonces, ledger,
});
```

## What is in the box

| Area | Module | Docs |
| --- | --- | --- |
| Mandates, delegation, invocations, verification | `plenipo` | [spec](docs/spec.md), [design](docs/design.md) |
| Wallet leg: OpenID4VP | `plenipo` | [interop](docs/interop.md) |
| Experimental: Delegate SD-JWT links, TS12 e-mandate roots, legal persons and roles | `plenipo/experimental` | [delegation](docs/delegation.md), [root](docs/root.md) |
| Trust: x5c chains, EU Lists of Trusted Entities (ETSI TS 119 602), CRL and OCSP | `plenipo` | [trust](docs/trust.md) |
| Keys in a KMS or HSM (`ExternalSigner`) | `plenipo` | this README |
| Shared stores on Postgres and Redis: ledger, nonces, idempotency keys, sessions, revocation | `plenipo` | [stores](docs/stores.md) |
| Idempotent retries: one signed key per intention, at most one attempt runs | `plenipo` | [spec](docs/spec.md), [integration](docs/integration.md) |
| Bank integration: HTTP gateway, problem+json errors, status list service, audit log, OPA and Cedar export | `plenipo` | [integration](docs/integration.md) |
| MCP guard | `plenipo/mcp` | [design](docs/design.md) |
| Test PID provider, wallet and CA (development only) | `plenipo/testing` | [examples](examples/README.md) |
| Sandbox and walt.id setup | `sandbox/` | [sandbox](docs/sandbox.md), [sandbox/README](sandbox/README.md) |

## Where it sits

| Project | What it does | Difference |
| --- | --- | --- |
| IETF Delegate SD-JWT (Google draft) | delegation chains for SD-JWT | no attenuation, revocation or required expiry; Plenipo enforces all three |
| Mastercard Verifiable Intent | layered SD-JWT mandates for commerce | anchored to card issuers; Plenipo is anchored to the EUDI Wallet PID |
| KYA Brasil | agent mandates signed with ICP-Brasil certificates | same idea on Brazil's PKI; Plenipo targets eIDAS 2 |
| Wallet4Agent (Talao) | identity and credential wallet for agents | gives agents a wallet; Plenipo gives people a way to authorise agents |

Plenipo aims to stay compatible with these formats rather than add another one.

## Roadmap

See [ROADMAP.md](ROADMAP.md). Changes by version are in [CHANGELOG.md](CHANGELOG.md).

## Limits

- One third-party wallet so far: walt.id Wallet API 2, a server-side wallet, approved a
  `plenipo_mandate` and a TS12 e-mandate bound to the PID, with a test PID from the sandbox, and the
  sandbox bank enforced them ([docs/interop.md](docs/interop.md)). No phone wallet yet: the EUDI
  reference wallet core declares accepted types since release 0.31.0; IT-Wallet does not accept
  custom types.
- With TS12, the e-mandate is approved with a bank's SCA attestation, not the PID. Tying that
  attestation to the PID holder needs the same holder key or identity claims the bank includes;
  see [docs/root.md](docs/root.md).
- The legal-person model (role attestations from a register) is Plenipo's own, pending the
  European Business Wallet implementing acts.
- Trusted lists: only the JSON (JAdES compact) binding of ETSI TS 119 602 is verified; XML lists
  (the EU LOTL and national TSLs) are refused.
- Delegate SD-JWT follows individual draft -00, which expired on 23 October 2026 without a
  successor; it is experimental and off by default.
- Status lists are cached up to a bounded age, which is the revocation latency verifiers accept
  (60 s by default; calls that move money can require a fresher list with `maxStatusAgeSeconds`).
- An idempotency key whose first attempt has an unknown outcome blocks retries until the service
  reconciles it; the library lists such keys but does not reconcile them with a core banking system.

## Contributing and security

Contributions are welcome: read [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md), not in public issues.

## License

Apache 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Fabio Lalli and the Plenipo
contributors.
