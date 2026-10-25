# Examples

Both run in a single process with test keys: a test PID provider and a test wallet stand in for the
EUDI ones. Never use the `plenipo/testing` keys outside development.

| Script | Command | What it shows |
| --- | --- | --- |
| [demo.ts](demo.ts) | `npm run demo` | The whole flow over MCP: the agent platform asks the wallet for a mandate over OpenID4VP, an agent delegates a narrower mandate to a booking bot, a rail operator's MCP server guards its tool with `guardTool`, and the person revokes the mandate through a status list. |
| [bank-gateway.ts](bank-gateway.ts) | `npm run example:gateway` | A bank puts `createGateway` in front of an HTTP payments API. Payments to a listed payee pass, a payee outside the mandate and an amount above the limit are refused with `application/problem+json`, and a balance route declared as moving no money passes. With `PLENIPO_PG_URL` set, nonces and spending totals live in Postgres. |

For a simulation with every party as a separate service, a wallet consent page, a dashboard and Claude
as the agent, see the [sandbox](../sandbox/README.md).
