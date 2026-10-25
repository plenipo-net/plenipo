# Plenipo sandbox

A working simulation of the whole Plenipo flow, with every party as a separate HTTP service:
a person approves a mandate for an AI agent in their EUDI wallet, the agent pays bills at a bank
through MCP, and the bank checks every call against the mandate. One command starts everything;
a live dashboard shows each decision as it happens.

```
                 ┌──────────────┐ PID (SD-JWT VC)      ┌──────────────┐
                 │ PID provider │─────────────────────▶│    Wallet    │  Maria Rossi, Luca Bianchi
                 │  test CA,    │                      │ consent page │
                 │  status list │                      └──────┬───────┘
                 └──────┬───────┘         OpenID4VP 1.0       │ approve: PID + KB-JWT over the mandate hash
                        │ status     request_uri / response_uri▼
                        │          ┌──────────────────────────────────┐
                        │          │ Agent platform                   │  agent keys, sub-delegation,
                        │          │ "my mandates", revoke / suspend  │  mandate status list
                        │          └───────────────┬──────────────────┘
                        │                          │ chain + signed invocation
                        │      ┌──────────────┐    ▼  (MCP _meta or REST headers)
                        └─────▶│     Bank     │◀── scripted agent / Claude
                    status     │ MCP + PSD2-  │
                    lists      │ like REST    │──▶ ALLOW / DENY + code ──▶ dashboard
                               └──────────────┘
```

Everything that decides is real: the PID is an SD-JWT VC signed under an X.509 chain, the wallet
leg is OpenID4VP 1.0 with DCQL, transaction data and an encrypted `direct_post.jwt` response,
revocation goes through IETF Token Status Lists, and the bank runs the Plenipo verifier unchanged.
What is simulated: the people, the PID issuance (a POST instead of OpenID4VCI), the wallet's user
interface, and the bank's accounts.

## Run it

With Docker, on any operating system, from the repository root:

```bash
cd sandbox && docker compose up --build
```

Or with Node 22, from the repository root:

```bash
npm ci                 # the library
cd sandbox && npm ci   # the sandbox
npm run sandbox        # builds the library, starts the five services, prints the URLs
```

Either way the services listen on 127.0.0.1 only:

| Service | URL | What it is |
| --- | --- | --- |
| Dashboard | http://127.0.0.1:4400 | Live view: mandates and chains, every bank decision, ledger use against limits, revocations. Open this first. |
| PID provider | http://127.0.0.1:4401 | A test CA standing in for an EU trusted list entry, a PID issuer certified by it, and the PID status list (`/status/1`). Its page can revoke or suspend a PID. |
| Wallet | http://127.0.0.1:4402 | `plenipo/testing`'s wallet behind a consent page. Holds a PID for Maria Rossi and one for Luca Bianchi. Checks the request object's certificate, refuses unknown transaction data types, shows purpose, actions, counterparties, limits and validity, and posts the OpenID4VP response on approval. |
| Agent platform | http://127.0.0.1:4403 | Creates mandate requests, serves `request_uri`, receives the wallet response, holds the agents' keys and signs their invocations, creates sub-delegations, publishes the mandate status list (`/status/mandates`). "My mandates" page with suspend / reinstate / revoke. |
| Bank | http://127.0.0.1:4404 | Two accounts, a payee register (Lumen, AcquaViva, TeleNord, Rotaia, an e-shop), an MCP server at `/mcp` with `get_balance`, `list_payees`, `transfer`, `block_card`, each wrapped with `guardTool`, and a PSD2-like REST API at `/psd2/v1`. Every decision goes to its event log. |

Then, in a second terminal:

```bash
npm run scenarios -- --attach      # all scripted scenarios against the running sandbox (shows on the dashboard)
npm run scenarios                  # the same, on private ports, without a running sandbox
npm run scenarios -- replay expired   # only some scenarios
npm test                           # the e2e suite: every scenario, the LLM loop, attacks on the HTTP surface
```

The library's own `npm test` at the repository root does not run the sandbox suite (its files are
named `*.e2e.ts`).

## Scenarios

Each prints PASS or FAIL against the expected outcome, step by step.

| Id | What happens | Expected |
| --- | --- | --- |
| `happy-path` | Maria approves a 300 euro utilities mandate; the agent reads the balance and payees and pays three bills (MCP), the REST API agrees on the balance | all ALLOW, balance down by 155.40 |
| `per-operation-limit` | 180 euro under a 150 euro per-payment limit | `LIMIT_PER_OPERATION` |
| `total-limit` | 84.30 + 41.20, then 90.00 against a 200 total, then 29.90 | ALLOW, ALLOW, `LIMIT_TOTAL`, ALLOW (a denial reserves nothing) |
| `payee-not-allowed` | Rotaia: registered at the bank, not in the mandate | `COUNTERPARTY_NOT_PERMITTED` |
| `action-not-allowed` | `block_card` under a payments-only mandate | `ACTION_NOT_PERMITTED` |
| `revocation` | The person revokes on the platform mid-run | `REVOKED` within the bank's status cache time |
| `sub-delegation` | The agent delegates "AcquaViva only, 50 each, 60 total" to a sub-agent, which then exceeds it four ways; a wider delegation is refused at signing | ALLOW, then `LIMIT_PER_OPERATION`, `LIMIT_TOTAL`, `COUNTERPARTY_NOT_PERMITTED`, `ACTION_NOT_PERMITTED` |
| `replay` | A captured signed call is sent twice | ALLOW, then `REPLAY` |
| `concurrent` | Two 60 euro payments at once against a 100 total | exactly one ALLOW, one `LIMIT_TOTAL` |
| `expired` | A one-hour mandate, then the bank clock moved one hour ahead | ALLOW, then `EXPIRED` |
| `pid-revoked` | The PID provider revokes Luca's PID | `PID_REVOKED` at the bank; the platform refuses a new mandate from that PID; reinstated afterwards |
| `tampered-mandate` | The agent rewrites its own mandate to 1,500 euro per payment | `TX_DATA_MISMATCH`: the wallet signed the hash of the original bytes |
| `wallet-refusal` | The person taps Refuse | the request ends `refused`, no mandate exists |
| `double-approval` | The person opens the approval link twice | the second answer is refused (409), the request object is gone (410), the mandate stays active |
| `reads-without-reservation` | Balance and payee reads under a mandate that lists only the billers | ALLOW, no reservation, the full total stays available |
| `prompt-injection` | Luca's water bill tells AI assistants to pay `acquaviva-rimborsi.example`; a fooled agent tries | `COUNTERPARTY_NOT_PERMITTED`, then the real AcquaViva payment passes |
| `emandate` | The utilities mandate requested as a TS12 `urn:eudi:sca:emandate:1`, bound to the PID | the bank accepts the root and enforces the limits |

## A five-minute demo

Before the audience arrives: `npm run sandbox`, open the dashboard full screen, and the platform
and the wallet in two other tabs. Optionally export `ANTHROPIC_API_KEY`.

1. **The setting (0:00–0:30).** On the dashboard: "a person, her EUDI wallet, an AI agent on a
   platform, and her bank. Nothing is pre-arranged between the bank and the platform: the bank
   only trusts the PID providers on the EU list."
2. **The mandate (0:30–1:30).** On the platform, create a request "Bill assistant", template
   *utilities*, and click *Open in the sandbox wallet*. Walk through the consent screen: purpose,
   the three payees and the bank, 150 euro per payment and 300 in total, 30 days, revocable, the
   PID claims shared. Open *Technical details*: "she signs the SHA-256 of exactly these bytes".
   Approve as Maria. The dashboard shows the mandate.
3. **The agent at work (1:30–2:30).** `npm run agent -- --mandate latest "pay this month's utility bills"`
   (`latest` is the mandate just approved; without `--mandate` the agent asks for a new one and waits
   for the wallet), or without an API key `npm run scenarios -- --attach happy-path`. Each call appears as ALLOW, and the bar under
   the mandate fills: 155.40 of 300.
4. **The limits hold (2:30–3:15).** `npm run agent -- --mandate latest "pay my Rotaia ticket, 45 euro"`
   and `"block my card"`, or run `per-operation-limit payee-not-allowed action-not-allowed`. Each DENY
   carries a machine-readable code the bank can log and show.
5. **Delegation (3:15–3:45).** `npm run scenarios -- --attach sub-delegation`: a sub-agent with a
   narrower mandate, the chain depth 1 on the dashboard, and every attempt to exceed it denied by
   the bank, not by the platform.
6. **The off switch (3:45–4:15).** On the platform, revoke the mandate from step 2 and ask the agent
   to pay again: DENY `REVOKED` within two seconds (the bank's status cache). Same mechanism as PID
   revocation, no central registry: the platform flips two bits in a signed status list.
7. **Attacks (4:15–4:45).** `npm run scenarios -- --attach replay tampered-mandate concurrent`.
8. **What is real (4:45–5:00).** Real cryptography and standards (SD-JWT VC, OpenID4VP 1.0, Token
   Status List, MCP); simulated people, PID issuance and accounts. Level 2 replaces the wallet with
   walt.id and the EUDI reference wallet on a phone, on a public host (`level2/README.md`).

Questions that tend to come up:

- *Is this PSD2 SCA?* No: it is the authority layer above it. The PID proves who granted the
  mandate; the mandate bounds what the agent may do. EUDI TS12 defines `urn:eudi:sca:emandate:1`
  for mandates bound to an account attestation, and notes it may be extended for agentic commerce;
  Plenipo can carry its mandate as such an e-mandate (the `emandate` scenario, or the e-mandate box on
  the platform page); in the sandbox it is bound to the PID.
- *How does the bank find the account?* From the PID claims the wallet disclosed (here name and
  birth date, matched against the bank's customer record). A production bank would match its KYC
  data, or ask for an account attestation in the same presentation.
- *How fast is revocation?* As fast as the bank's status cache: 2 seconds here, configurable.
- *Several bank instances?* Start with `PLENIPO_PG_URL` or `PLENIPO_REDIS_URL`: the ledger, the nonces
  and the OpenID4VP sessions then live in Postgres or Redis (the library's shared stores), the bank
  sweeps reservations left pending, and the dashboard lists those whose outcome is unknown.

## Claude Desktop and Claude Code (MCP bridge)

`npm run bridge` runs a stdio MCP server (built to `dist/bridge.js` by `npm run build:bridge`) that lets
Claude act at the bank: it holds the agent key itself, asks the platform for a mandate with
`request_mandate` and returns the wallet link for you to approve, mirrors the bank's tools and signs
every call for its exact arguments and chain. The bridge runs with Node on your machine, also when the
sandbox runs in Docker: `cd sandbox && npm ci && npm run build:bridge`.

In Claude Desktop (Settings, Developer, Edit Config) add an entry with absolute paths, since Claude
Desktop does not start servers from your shell:

```json
{
  "mcpServers": {
    "plenipo-bank": {
      "command": "/absolute/path/to/node",
      "args": ["/absolute/path/to/plenipo/sandbox/dist/bridge.js"],
      "env": {
        "PLENIPO_PLATFORM_URL": "http://127.0.0.1:4403",
        "PLENIPO_BANK_URL": "http://127.0.0.1:4404",
        "PLENIPO_DASHBOARD_URL": "http://127.0.0.1:4400"
      }
    }
  }
}
```

In Claude Code, from the repository root (the URLs above are the defaults):

```bash
claude mcp add --transport stdio --scope user plenipo-bank -- "$(command -v node)" "$PWD/sandbox/dist/bridge.js"
```

A step-by-step guide for macOS, with a guided demo and the prompts to type, is in
[docs/mac.md](../docs/mac.md).

## Remote MCP (hosted gateway)

With `SANDBOX_AGENT_GATEWAY=1` the sandbox also serves the bridge over Streamable HTTP on port 4405,
for MCP clients that connect to a URL instead of starting a process (Claude on the web with a custom
connector, Claude Desktop remote connectors). The endpoint is `/mcp`, or `/mcp/<SANDBOX_MCP_TOKEN>`
when a token is set.

Every MCP session gets its own bridge. Its first `request_mandate` starts a journey (agent key, mandate
request, mandate) under a demo code of six characters, given to Claude in that answer and in every
`mandate_status`. A client may open several connections for one conversation, so the journey belongs
to the code, not to the connection: a later connection continues it with `mandate_status` and
`demo_code` (journeys are kept 24 hours, in memory). Connections that never call a tool get no code,
leave nothing in the feeds and close after 10 minutes; used ones after two idle hours. The bridge tags
its dashboard events with the code, and the dashboard follows the request and mandate ids through the
platform, wallet and bank events, so one journey can be watched on its own:

| URL on the dashboard | What |
| --- | --- |
| `/demo/<code>` | the dashboard page, showing that session only |
| `/api/demo/<code>` | its events as JSON (`known`, `events`), readable from any origin |
| `/api/demo/<code>/stream` | the same as Server-Sent Events; a page may open it before the session starts |

With `SANDBOX_PUBLIC_SCENARIOS=1` the gateway also lists the scripted scenarios at `GET /scenarios`
and runs one on `POST /scenarios/<id>/run` (no body, so a page on another origin can call it without
a preflight). The answer is `202` with a fresh demo code and its watch link; the run then shows up in
that code's feed like a Claude session does. The two scenarios that change state every session shares
(`expired` moves the bank clock, `pid-revoked` revokes a PID) are not offered. Ten runs per hour per
address, three at a time.

Limits for a public host: at most 500 open sessions (`SANDBOX_MAX_SESSIONS`), 300 new sessions per hour
for all clients together, 120 requests per minute on one session. Remote MCP clients connect from
their provider's servers, so the client address (`SANDBOX_CLIENT_IP_HEADER` behind a proxy) limits
only the scenario runs, which come from visitors' browsers. When `SANDBOX_ADMIN_TOKEN` is set, posting
dashboard events needs it, so nobody else can write into a session's feed.

With `SANDBOX_ACCOUNT_SCOPE=mandate` the bank opens a copy of the person's account for every root
mandate, with the opening balance and every bill unpaid; delegated mandates use their root's. Visitors
of a public sandbox then never find each other's payments: two conversations paying "my electricity
bill" both find it open.

## The LLM agent

```bash
export ANTHROPIC_API_KEY=sk-ant-...
npm run agent -- "pay this month's utility bills"
npm run agent -- --person luca --auto-approve "pay only the water bill"
npm run agent -- --mandate latest "what is my balance?"   # or the short id from the platform page
```

Claude receives the task and the bank's four MCP tools (schemas from `tools/list`). For every
`tool_use`, the agent client normalises the arguments to the tool's schema, asks the platform (which
holds the agent's key) to sign an invocation bound to exactly that call, and sends it in the MCP
request `_meta` under `plenipo/authorization`, the key `guardTool` reads (`META_KEY` in `src/mcp.ts`).
A DENY goes back to the model as an error tool result; the system prompt tells it not to work
around refusals, but nothing depends on that: the bank enforces the mandate whatever the model does.

The model defaults to `claude-sonnet-5-5` (fast enough for a live demo); set
`PLENIPO_AGENT_MODEL` (or `--model`) to e.g. `claude-opus-5-5`. Without a key the command explains
how to enable it and points to the scripted scenarios. The e2e suite tests the loop with a scripted
stand-in for the model, offline.

Each tool publishes how a call maps to an invocation in its `_meta` (`plenipo/binding`: action,
audience, which argument is the counterparty and which the amount). This is a sandbox convention;
the guard checks the invocation against the actual call regardless.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `SANDBOX_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` in containers) |
| `SANDBOX_PORT_BASE`, `SANDBOX_PORT_<SERVICE>` | 4400–4404 | Ports (`DASHBOARD`, `PID`, `WALLET`, `PLATFORM`, `BANK`) |
| `SANDBOX_STATUS_CACHE_SECONDS` | 2 | How long the bank reuses a verified status list: the revocation latency |
| `SANDBOX_ADMIN_TOKEN` | none | When set, PID issuance and revocation and the bank clock require `Authorization: Bearer <token>` |
| `SANDBOX_STRICT_CLIENT_ID` | off | `1`: the sandbox wallet requires `response_uri` on https at the client_id host |
| `PLENIPO_PID_ISSUER` | `https://pid.sandbox.plenipo.test` | PID `iss` and status list origin |
| `PLENIPO_PLATFORM_ORIGIN` | `https://platform.sandbox.plenipo.test` | Mandate status list signer; its host is the `x509_san_dns` client_id |
| `PLENIPO_BANK_HOST` | `bank.sandbox.plenipo.test` | The bank's host: counterparty of reads and card operations, root of its audiences |
| `SANDBOX_PUBLIC_URL_<SERVICE>` | the local URL | URLs announced to browsers and wallets (public host) |
| `PLATFORM_RP_KEY`, `PLATFORM_RP_CHAIN`, `WALLET_RP_ANCHORS` | generated | Request-object certificate and its CA, from `npm run rp-cert` |
| `PLENIPO_EXTRA_PID_ANCHORS` | none | Extra PID trust anchors (PEM files, comma separated) |
| `PLENIPO_EXTRA_PID_ISSUERS_FILE` | none | Extra PID issuers by key: JSON `[{ "iss", "jwk" }]` |
| `PLENIPO_PID_STATUS_TRUST_FILE` | none | PID status lists on another origin: JSON `{ "trustAnchors": [pem files], "statusOrigins": [...] }` |
| `SANDBOX_ALLOW_PUBLIC_STATUS` | off | `1`: fetch status lists of unknown origins from the internet (https, 5 s, 1 MB) |
| `PLENIPO_PG_URL`, `PLENIPO_REDIS_URL` | none | Shared stores for the bank's ledger and nonces and the platform's sessions (`pg` / `ioredis` are optional dependencies) |
| `SANDBOX_STORES` | from the URLs, else `memory` | `memory`, `postgres` or `redis` |
| `PLENIPO_STORE_PREFIX` | `plenipo_` / `plenipo` | Table or key prefix, to share a server |
| `SANDBOX_PENDING_TTL_SECONDS` | 900 | How long a reservation may stay pending before the sweep counts it as spent |
| `ANTHROPIC_API_KEY`, `PLENIPO_AGENT_MODEL` | none, `claude-sonnet-5-5` | LLM agent |
| `SANDBOX_AGENT_GATEWAY` | off | `1`: serve the hosted MCP gateway on `SANDBOX_PORT_AGENT` (4405) |
| `SANDBOX_PUBLIC_SCENARIOS` | off | `1`: visitors may run the scripted scenarios through the gateway, each under its own demo code |
| `SANDBOX_ACCOUNT_SCOPE` | `person` | `mandate`: a fresh copy of the account per root mandate (public sandbox) |
| `SANDBOX_REFILL_SECONDS` | none | With the `person` scope: this often, accounts below half their opening balance get it back |
| `SANDBOX_MCP_TOKEN` | none | Secret path segment of the gateway endpoint: `/mcp/<token>` |
| `SANDBOX_WATCH_URL` | the dashboard's `/demo/<code>` | Page where a person watches a session; the code is appended as `?code=` |
| `SANDBOX_MAX_SESSIONS`, `SANDBOX_SESSION_IDLE_SECONDS` | 500, 7200 | Open gateway sessions, and when an idle one that called a tool is closed |
| `SANDBOX_CLIENT_IP_HEADER` | none | Header with the client address set by the proxy in front (`fly-client-ip` on Fly.io) |
| `SANDBOX_DOMAIN`, `SANDBOX_FRONT_PORT`, `SANDBOX_FRONT_HOST` | none, none, `0.0.0.0` | Hosted: one public port dispatching by host name (`src/front.ts`) |
| `SANDBOX_DEMO_LOGIN` | none | Hosted: `user:password` basic auth in front of everything a wallet, an MCP client or a showcase page does not need |
| `SANDBOX_RESTART_AT` | none | Hosted: `HH:MM` UTC; the process exits then and the platform restarts it clean |

The identities are https names because verifiers fetch status lists over https only; in level 1 the
sandbox maps each of them to the local service that serves it (`src/fetcher.ts`, with the same
limits as the library's fetcher: no redirects, 5 seconds, 1 MB, nothing outside the map).

## Layout

```
src/
  main.ts, sandbox.ts       launcher and wiring
  services/                 pid-provider, wallet, platform, bank (+ stores), dashboard
  agent/                    client (platform, wallet, MCP, REST), llm loop, cli
  bridge.ts, bridge/        the MCP bridge for Claude Desktop / Claude Code (core, MCP server, state file)
  services/agent-gateway.ts the bridge over Streamable HTTP, one per session, with demo codes
  front.ts                  hosted: one port, dispatch by host name, optional demo login
  scenarios.ts              the scripted scenarios; run-scenarios.ts runs them
  catalog.ts                people, payees, bills, mandate templates
  http.ts, events.ts, fetcher.ts, binding.ts, ui/
test/                       end-to-end suites: scenarios, bridge over stdio and over HTTP, front door, Postgres and Redis stores
scripts/mac-setup.sh        macOS setup (see docs/mac.md)
level2/                     real wallets (walt.id, EUDI reference wallet) and the public host
deploy/                     Dockerfile; docker-compose.yml and Caddyfile for a VPS; fly.toml for Fly.io
```

## Limits

- One process; mandates, PIDs and balances are in memory, so restarting forgets them (the shared
  stores keep the ledger, nonces and sessions, but a restart still issues new test keys).
- Test keys are generated at start-up; the PID issuance endpoint is a shortcut for OpenID4VCI.
- The platform signs any invocation its hosted agents ask for: that is deliberate, the bank is the one
  that enforces. Agents that hold their own key (the MCP bridge) send only their public key.
