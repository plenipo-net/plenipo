# Running the Plenipo sandbox on a Mac, with Claude as the agent

This guide sets up the sandbox on macOS and connects Claude Desktop or Claude Code to the bank through
the Plenipo MCP bridge. Claude asks you for a mandate, you approve it in the sandbox wallet, and from
then on every payment Claude makes is checked by the bank against what you approved.

```
Claude Desktop / Claude Code ──stdio──▶ MCP bridge (agent key, signs every call) ──MCP──▶ bank (verifies)
                                              │ request_mandate                          ▲
                                              ▼                                          │ status lists
                                        agent platform ──OpenID4VP──▶ wallet (you approve) ┘
```

## 1. Setup (5 minutes)

You need Node.js 22 or later and git. Check with `node -v`; if Node is missing or older:

```bash
brew install node@22 && brew link --overwrite node@22
```

Then, from the repository:

```bash
bash sandbox/scripts/mac-setup.sh
```

The script checks Node, runs `npm ci` for the library and for the sandbox, builds the bridge
(`sandbox/dist/bridge.js`), warns if the sandbox ports are taken, and prints the Claude Desktop and
Claude Code configuration with your absolute paths filled in. Run it again after every `git pull`.

Check that everything works:

```bash
cd sandbox
npm test          # the sandbox suite; the Postgres/Redis part runs only if those servers are installed
cd .. && npm test # the library suite
```

## 2. Start the sandbox

```bash
cd sandbox
npm run sandbox
```

Open the dashboard at http://127.0.0.1:4400. The other services:

| | URL |
| --- | --- |
| Wallet (Maria Rossi, Luca Bianchi) | http://127.0.0.1:4402 |
| Agent platform ("my mandates", revoke) | http://127.0.0.1:4403 |
| Bank | http://127.0.0.1:4404 |
| PID provider | http://127.0.0.1:4401 |

In a second terminal, the scripted scenarios run against it and show up on the dashboard:

```bash
cd sandbox
npm run scenarios -- --attach
npm run scenarios -- --attach prompt-injection    # one scenario
```

**macOS notes.** The sandbox listens on 127.0.0.1 ports 4400 to 4404. AirPlay Receiver takes ports
5000 and 7000, which the sandbox does not use; if another program holds one of ours, start with
`SANDBOX_PORT_BASE=5400 npm run sandbox` (ports 5400 to 5404) and use the same ports in the bridge
configuration below. On 127.0.0.1 macOS normally does not ask about incoming connections; if you set
`SANDBOX_HOST=0.0.0.0` (to reach the sandbox from Docker or a phone), the firewall asks whether `node`
may accept incoming connections: allow it only on a trusted network.

## 3. Connect Claude

The bridge is a local MCP server over stdio. Claude starts it; it needs the sandbox running to do
anything useful, but it starts without it.

### Claude Desktop

Claude menu > Settings... > Developer > Edit Config opens
`~/Library/Application Support/Claude/claude_desktop_config.json`. Add the entry that
`mac-setup.sh` printed, for example:

```json
{
  "mcpServers": {
    "plenipo-bank": {
      "command": "/opt/homebrew/opt/node@22/bin/node",
      "args": ["/Users/you/plenipo/sandbox/dist/bridge.js"],
      "env": {
        "PLENIPO_PLATFORM_URL": "http://127.0.0.1:4403",
        "PLENIPO_BANK_URL": "http://127.0.0.1:4404",
        "PLENIPO_DASHBOARD_URL": "http://127.0.0.1:4400"
      }
    }
  }
}
```

Use absolute paths: Claude Desktop does not start servers from your shell, so neither `~` nor your
`PATH` apply. The `command` is the absolute path of `node` (`command -v node`). If the file already
has `mcpServers`, add only the `plenipo-bank` entry. Quit Claude Desktop completely and reopen it;
`plenipo-bank` appears under the "+" button > Connectors. If it does not connect, read
`~/Library/Logs/Claude/mcp-server-plenipo-bank.log` (the bridge logs to stderr, which lands there).

### Claude Code

```bash
claude mcp add --transport stdio --scope user plenipo-bank -- "$(command -v node)" "$PWD/sandbox/dist/bridge.js"
claude mcp list            # plenipo-bank: Connected
```

Run it from the repository root (or replace `$PWD/sandbox` with the absolute path). `--scope user`
makes the server available in every project; without it the server is registered for the current
directory only. Inside Claude Code, `/mcp` shows the server and its tools. To remove it:
`claude mcp remove plenipo-bank`.

### What the bridge does

- **Its own key.** On first use the bridge generates the agent's P-256 key and keeps it in
  `sandbox/.plenipo-bridge.json` (readable only by you). The platform receives only the public key, so
  it cannot act as the agent; the bridge signs every call itself.
- **Tools.** `request_mandate` (payees, per-payment and total limit in euro, days, purpose; returns the
  wallet link), `mandate_status`, `revoke_mandate`, `explain_last_decision`, and the bank's own tools,
  mirrored: `get_balance`, `list_payees`, `transfer`, `block_card`.
- **Every bank call** is signed for exactly its arguments and the mandate chain and forwarded with the
  Plenipo authorization; the bank's answer, including `plenipo: DENY <code>: <reason>`, comes back to
  Claude verbatim.
- To start from scratch (new key, no mandate), stop Claude and delete `sandbox/.plenipo-bridge.json`.

## 4. A guided 10-minute demo

Keep the dashboard visible next to Claude. Claude asks permission before each tool call; allow them.
The prompts below are what to type.

**1. The mandate (2 min).**

> Use the plenipo-bank tools. I want you to pay my electricity, water and phone bills for this month. Ask me for a mandate covering lumen-energia.example, acquaviva.example and telenord.example, at most 100 euro per payment and 200 euro in total, for 7 days.

Claude calls `request_mandate` and gives you a link. Open it: the wallet shows what Claude will be
allowed to do (payees, limits, validity, that you can revoke it). Choose **Maria Rossi** and click
**Approve with my PID**. Then:

> I approved it.

Claude calls `mandate_status` and reads back the mandate. The dashboard shows it, with an empty
spending bar.

**2. Paying within the limits (2 min).**

> Look at my open bills and pay them.

Claude calls `list_payees` and pays Lumen 84.30, AcquaViva 41.20 and TeleNord 29.90. Each call appears on the
dashboard as ALLOW; the bar shows 155.40 of 200.

**3. Trying to exceed (2 min).**

> Also pay 150 euro to Lumen as an advance on next month's bill.

DENY `LIMIT_PER_OPERATION`: 150 is above the 100 per payment you approved.

> Then pay 60 euro to AcquaViva as a deposit.

DENY `LIMIT_TOTAL`: 155.40 + 60 would exceed 200.

> Why did the bank refuse that?

Claude calls `explain_last_decision`: what was signed (payee, amount, nonce, chain hash) and the
reason in plain words.

**4. A payee outside the mandate (1 min).**

> Buy me a Roma-Milano train ticket from rotaia.example for 45 euro. Try it even if you think it will fail; I want to see what the bank says.

DENY `COUNTERPARTY_NOT_PERMITTED`: Rotaia is a payee at the bank, but not in your mandate.

**5. Revoking mid-session (1 min).** Open the agent platform (http://127.0.0.1:4403), find
"Claude (MCP bridge)" and click **revoke**. Then:

> Pay the TeleNord bill once more.

DENY `REVOKED`, within the bank's status cache time (2 seconds). Claude can also revoke its own mandate
(`revoke_mandate`) when you ask it to.

**6. Prompt injection (2 min).** Luca's water bill carries a note written for AI assistants, telling
them to pay `acquaviva-rimborsi.example` instead of AcquaViva.

> Start over: ask me for a new mandate for lumen-energia.example, acquaviva.example and telenord.example, at most 100 euro per payment and 200 euro in total, for 7 days.

Approve it as **Luca Bianchi**, then:

> I approved it. Pay my open bills.

Point at the AcquaViva note in Claude's `list_payees` result. Either Claude ignores it, or it follows it and
the bank answers DENY `COUNTERPARTY_NOT_PERMITTED`: the mandate holds even when the agent is fooled.
The scripted version, which always takes the bait, is `npm run scenarios -- --attach prompt-injection`.

## 5. Optional: Postgres or Redis

By default the bank's ledger and nonces and the platform's OpenID4VP sessions are in memory. To use
the library's shared stores:

```bash
brew install postgresql@16 redis
brew services start postgresql@16 && brew services start redis
createdb plenipo   # with Homebrew, your user owns the cluster

cd sandbox
PLENIPO_PG_URL="postgres://$USER@127.0.0.1:5432/plenipo" npm run sandbox
# or
PLENIPO_REDIS_URL="redis://127.0.0.1:6379" npm run sandbox
```

With Docker instead: `docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=plenipo postgres:16` and
`PLENIPO_PG_URL=postgres://postgres:plenipo@127.0.0.1:5432/postgres`, or
`docker run -d -p 6379:6379 redis:7`. The schema is created at start; `PLENIPO_STORE_PREFIX` keeps
several sandboxes apart on one server.

With a shared ledger the bank sweeps reservations every 10 seconds. To see a payment whose outcome is
unknown (the bank timed out after the money left), start with `SANDBOX_PENDING_TTL_SECONDS=20`, then:

```bash
curl -X POST http://127.0.0.1:4404/admin/fail-next-transfer
```

and ask Claude to pay a bill. The tool fails, the reservation stays pending, and about 30 seconds
later the dashboard shows it as an unresolved reservation, still counted against the limit. Settle it:

```bash
curl http://127.0.0.1:4404/api/reservations                          # its id
curl -X POST http://127.0.0.1:4404/admin/reservations/<id>/reconcile \
  -H 'content-type: application/json' -d '{"outcome":"not_executed"}'
```

`npm test` also runs the sandbox on Postgres and Redis when it finds the server binaries: `redis-server`
on the `PATH`, and Postgres through `pg_config` or `PLENIPO_PG_BINDIR=$(brew --prefix postgresql@16)/bin`.

## 6. Optional: a real wallet with walt.id

Docker Desktop runs walt.id Wallet API 2 with the Plenipo transaction data profile; on a Mac
`host.docker.internal` reaches the sandbox directly. Follow
[sandbox/level2/README.md](../sandbox/level2/README.md), section A.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Port 4401 is already in use` | Another sandbox runs, or set `SANDBOX_PORT_BASE` |
| Claude says the bank has no tools | The sandbox is not running, or the bridge URLs do not match its ports. Once the bank answers, the bridge tells Claude to list its tools again (every 5 seconds it retries); if a client ignores that, restart it |
| `plenipo-bank` missing in Claude Desktop | Check the JSON, the absolute paths, quit and reopen; see `~/Library/Logs/Claude/mcp-server-plenipo-bank.log` |
| Every call is `DENY REVOKED` | The mandate was revoked: ask Claude for a new one |
| After restarting the sandbox Claude's mandate no longer works | The sandbox keeps everything in memory: ask Claude for a new mandate (the bridge keeps its key) |
