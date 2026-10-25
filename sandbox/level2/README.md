# Level 2: real wallets and a public host

Level 1 runs every party in one process with a test wallet. Level 2 replaces the wallet with real
ones and puts the sandbox on the internet, so a phone can scan the QR code:

- **A. walt.id Wallet API 2**, configured to accept `plenipo_mandate` transaction data;
- **B. the EUDI reference wallet** on Android, with a test PID from the EU test issuer;
- **C. a public host**, `sandbox.plenipo.net` behind Caddy, which B needs.

Each section separates what was **verified** (by running it here, or by reading the source at a
named commit) from what is **to be verified** on the first real run.

| | Status on 19 October 2026 |
| --- | --- |
| Sandbox with a file-based RP certificate, admin token, strict client_id, HTTPS `request_uri`/`response_uri` through Caddy | **Run here** (first version): all 13 scenarios then defined pass behind Caddy (local CA), the protected and public paths answer as intended |
| `waltid-e2e.ts` (import a holder key and a PID into Wallet API 2, preview, present, pay at the bank) | **Run here against a stand-in** that implements the same five Wallet API 2 endpoints: our side of the flow passes. Not run against walt.id itself, see below |
| walt.id images | **Not run**: this environment's egress policy refuses `registry-1.docker.io` and `ghcr.io` (HTTP 403), and building from source needs Maven Central, the Gradle plugin portal and `maven.waltid.dev`, also refused. The steps below are written from the walt.id source and docs |
| walt.id behaviour relevant to Plenipo | **Read in the source**, `walt-id/waltid-identity` at `d53d7bc` (17 Oct 2026) |
| EUDI wallet core transaction data API | **Read in the source**, `eu-digital-identity-wallet/eudi-lib-android-wallet-core` branch `release/0.31.0` at `54eab4d` (2 Oct 2026) |
| TS12 e-mandate fields | **Read in the spec**, TS12 v1.0.1 (`eudi-doc-standards-and-technical-specifications` at `ee91a29`) |
| Device runs (Android, walt.id) | **To do**: none has been done |

## The RP certificate (needed by A, B and C)

Real wallets accept an `x509_san_dns` request object only if its certificate chains to a CA they
trust and names the client's DNS host. Level 1 generates one at every start; for level 2 make one
that survives restarts:

```bash
cd sandbox
npm run rp-cert -- --dns platform.sandbox.plenipo.test --out level2/state --waltid level2/waltid/config
#   on the public host: --dns platform.sandbox.plenipo.net --out deploy/secrets
```

It writes `rp-ca.pem` (the CA the wallet must trust), `rp-chain.pem` and `rp-key.pem` (the
platform's signing certificate, P-256, DNS SAN = the host, clientAuth EKU, which walt.id checks), and
with `--waltid` the Wallet API 2 `wallet-service.conf` that trusts the CA. Start the sandbox with:

```bash
PLATFORM_RP_KEY=level2/state/rp-key.pem PLATFORM_RP_CHAIN=level2/state/rp-chain.pem \
WALLET_RP_ANCHORS=level2/state/rp-ca.pem npm run sandbox
```

The TLS certificate of the public host (Let's Encrypt, through Caddy) is a different thing: it
protects the connection, while the RP certificate signs the request object and identifies the
client to the wallet.

## A. walt.id Wallet API 2

### What Wallet API 2 does with our request (read in the source)

- **Transaction data types are an allowlist.** `transaction-data-profiles.conf` loads the accepted
  types into a registry; a request with any other `type` is rejected
  (`TransactionDataRequestValidator.kt`, `TransactionDataTypeRegistry.requireKnown`). Our profile
  file adds `plenipo_mandate`.
- **Structure checks** that our request already meets: `credential_ids` not empty and pointing to a
  DCQL query of format `dc+sd-jwt` that requires holder binding (the DCQL default is `true`);
  `transaction_data_hashes_alg`, when present, must include `sha-256`.
- **Hash**: SHA-256 of the base64url string as received, base64url-encoded
  (`TransactionDataHashing.kt`), exactly what Plenipo verifies.
- **KB-JWT**: `aud` is the full `client_id` (with the `x509_san_dns:` prefix), plus `nonce` and
  `transaction_data_hashes` (`SdJwtVcPresenter.kt`). Plenipo's `handleMandateResponse` requires the
  same `aud` and `nonce`.
- **`x509_san_dns`** (`X509SanDns.kt`): `x5c` required; chain validated against
  `clientIdTrust.x509TrustAnchors` "including client-auth usage"; signature by the leaf; the DNS name
  must be a SAN of the leaf. The `response_uri` host is not required to match (only a
  `redirect_uri` is). The DNS name must end in a 2 to 6 letter TLD: `plenipo.test` passes.
- **Encrypted response**: `direct_post.jwt` with ECDH-ES to the `client_metadata.jwks` key, which
  must carry a `kid`, and A128GCM from `encrypted_response_enc_values_supported`: what
  `createMandateRequest` sends.
- **API**: `POST /wallet`, `POST /wallet/{id}/keys/import` (`{"key":{"type":"jwk","jwk":…}}`),
  `POST /wallet/{id}/credentials/import` (`{"rawCredential": …}`, bound to a held key by `cnf`),
  `POST /wallet/{id}/credentials/present/preview` (the consent data, including decoded
  `transactionData`) and `POST /wallet/{id}/credentials/present` (`{"requestUrl", "keyId"}`).
  Wallet API 2 is an API: the consent screen is the integrator's, `preview` is what it shows.

### Files

| File | Purpose |
| --- | --- |
| `waltid/config/transaction-data-profiles.conf` | walt.id's four default profiles plus `plenipo_mandate` (field `mandate`) and `urn:eudi:sca:emandate:1` (field `payload`, see below) |
| `waltid/config/_features.conf` | no accounts, in-memory stores, so the script can create a wallet without logging in. Local use only |
| `waltid/config/web.conf`, `dev-mode.conf` | port 7006, as in walt.id's compose |
| `waltid/config/wallet-service.conf` | generated by `npm run rp-cert -- --waltid …` (trusts the sandbox RP CA); `.example` shows the shape |
| `waltid/docker-compose.yaml` | Wallet API 2 alone with this configuration |
| `waltid/docker-compose.override.yaml` | the same, as an override for walt.id's own `docker-compose/` stack |
| `waltid-e2e.ts` | the end-to-end run (below) |

**The two profiles.** `plenipo_mandate` carries one field, `mandate`: the mandate object that the
bank enforces (purpose, actions, counterparties, limits, `nbf`, `exp`, delegation depth, status
entry, agent key). `urn:eudi:sca:emandate:1` is TS12 section 4.3.4, verified in the spec: its details
are in `payload` with `transaction_id` (required, at most 36 characters), `date_time`, `start_date`,
`end_date`, `reference_number`, `creditor_id`, `purpose` (required when `payment_payload` is absent,
at most 1000 characters) and `payment_payload` (a `urn:eudi:sca:payment:1` object, for
merchant-initiated payments). TS12 binds it to an **SCA attestation of the account**, not to the PID,
and adds `jti`, `amr` and `response_mode` to the KB-JWT; TS12 also notes the type "may get amended …
to also cover usages in the context of agentic commerce". Plenipo now produces and verifies this type
(`createMandateRequest({ transactionDataType: 'emandate' })`); the sandbox platform offers it bound to
the PID, which a TS12 wallet accepts only if configured to (TS12 binds e-mandates to SCA attestations).

### Steps

Docker on the machine that runs the sandbox.

```bash
cd sandbox
# 1. RP certificate, and walt.id's wallet-service.conf trusting it
npm run rp-cert -- --dns platform.sandbox.plenipo.test --out level2/state --waltid level2/waltid/config

# 2. The sandbox, reachable from containers: the platform announces host.docker.internal in request_uri
SANDBOX_HOST=0.0.0.0 SANDBOX_PUBLIC_URL_PLATFORM=http://host.docker.internal:4403 \
PLATFORM_RP_KEY=level2/state/rp-key.pem PLATFORM_RP_CHAIN=level2/state/rp-chain.pem \
WALLET_RP_ANCHORS=level2/state/rp-ca.pem npm run sandbox
#    (0.0.0.0 exposes the sandbox to your network: firewall it, or bind to the docker bridge address)

# 3. walt.id Wallet API 2 with the Plenipo configuration
cd level2/waltid && docker compose up -d && cd ../..
curl http://localhost:7006/transaction-data-profiles     # plenipo_mandate must be listed

# 4. The run: key and PID into walt.id, mandate request, preview, present, payments at the bank
npm run waltid-e2e
```

`waltid-e2e` prints each step. Expected end: `ALLOW` for an 84.30 Lumen payment, `DENY
LIMIT_PER_OPERATION` for 180.00, `PASS: walt.id end to end`; the dashboard shows the mandate
"Bill assistant (walt.id)".

**The PID.** By default the sandbox PID provider issues Maria's PID to the key the script imported
into walt.id (`POST /issue` is the sandbox's stand-in for OpenID4VCI), so the bank already trusts its
CA. To use a PID from walt.id's Issuer API 2 instead, the bank and the platform must trust that
issuer: `PLENIPO_EXTRA_PID_ANCHORS=ca.pem` when the PID carries an `x5c` whose leaf names the PID
`iss` (as a URI SAN, or as a DNS SAN when `iss` is a bare https origin), or
`PLENIPO_EXTRA_PID_ISSUERS_FILE` with `[{ "iss": "...", "jwk": {...} }]`. The PID must be an SD-JWT VC
with `vct` `urn:eudi:pid:1`, ES256, a `cnf.jwk`, and disclosable `given_name`, `family_name` and
`birthdate` (the bank matches the account on these three).

### To verify on the first real run

1. Wallet API 2 starts with `_features.conf` empty (no `auth`, no persistence) and the reduced config set.
2. It fetches an `http://` `request_uri` and posts to an `http://` `response_uri` (nothing in the
   resolver forbids it; if it does, use the public host of section C).
3. The chain check accepts a leaf issued directly by the anchor, with the anchor only in the trust
   list (not in `x5c`), which is how `rp-chain.pem` is built.
4. `vp_token` comes back as `{"pid": ["<presentation>"]}` (OpenID4VP 1.0 arrays), which
   `handleMandateResponse` requires.
5. `credentials/import` binds the PID to the imported key through `cnf.jwk`.
6. Whether walt.id's web or Compose demo wallets render unknown transaction data types (the
   `preview` API returns them in any case).

## B. EUDI reference wallet (Android)

### Test PID (verified on 19 October 2026)

The EU test issuer is `https://issuer.eudiw.dev` (source:
`eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py`). Its OpenID4VCI metadata lists
`eu.europa.ec.eudi.pid_vc_sd_jwt` with format `dc+sd-jwt`, `vct` `urn:eudi:pid:1`, signed with
ES256. In the reference app, add a document from the EU issuer and pick the PID in SD-JWT VC format;
the issuer lets you enter test identity data. Credential offers can also be started from
`https://issuer.eudiw.dev/credential_offer`.

For the bank and the platform to accept it (**to verify** with a real PID):

- **Trust anchor.** The EU test PIDs are signed under the "PID Issuer CA 02" certificates of the EUDI
  Wallet Reference Implementation (one per test country; walt.id ships three of them in its
  `wallet-service.conf`). Put the right CA in a PEM file and set `PLENIPO_EXTRA_PID_ANCHORS`. Plenipo
  also requires the signing certificate to **name the PID `iss`** (URI SAN equal to `iss`, or DNS
  SAN when `iss` is a bare https origin). If the EU test certificates do not, Plenipo refuses the PID
  with `PID_ISSUER_UNTRUSTED`, and the library needs an option for it (reported as an open point).
- **Status list.** If the PID carries a status list on another origin than its `iss` (the EU test
  revocation service runs separately), create `pid-status.json` with
  `{ "trustAnchors": ["eu-status-ca.pem"], "statusOrigins": ["https://<status host>"] }`, set
  `PLENIPO_PID_STATUS_TRUST_FILE=pid-status.json` and `SANDBOX_ALLOW_PUBLIC_STATUS=1`.
- **Claims.** The bank needs `given_name`, `family_name` and `birthdate` (PID Rulebook names for
  SD-JWT VC), and the sandbox accounts are Maria Rossi (1984-03-12) and Luca Bianchi (1979-11-02):
  enter one of them at the test issuer, or add your test identity to `PERSONS` in `src/catalog.ts`.

### Transaction data in wallet core 0.31.0 (verified in the source)

- `OpenId4VpConfig.Builder().withTransactionDataTypes(...)` declares the accepted types; the default
  is none, and a request with an undeclared type is answered `invalid_transaction_data`.
- Custom types are supported: `TransactionDataType.raw("plenipo_mandate")` declares a type read as
  plain JSON (only the OpenID4VP members are checked); a typed parser can be written by extending
  `TransactionType` (README, "Declaring a type of your own"). `sha-256` is mandatory and supported.
- The presentation is bound by `transaction_data_hashes` in the KB-JWT: "a hash of the transaction
  data string exactly as received", the binding Plenipo verifies. The `TransactionDataDeviceSigned`
  requirement applies to `mso_mdoc` only; Plenipo uses SD-JWT VC.
- `configureOpenId4Vp { withClientIdSchemes(ClientIdScheme.X509SanDns) }` and the default
  `EncryptionPolicy.HAIP` (encrypted responses only) match what the platform sends
  (`direct_post.jwt`). The verifier certificate is checked by the `ReaderTrustStore`
  (`configureReaderAuthentication`).

### What to change in a fork of the reference app (to verify)

1. In the wallet core configuration of `eudi-app-android-wallet-ui`, add
   `.withTransactionDataTypes(TransactionDataType.raw("plenipo_mandate"))`.
2. Add the sandbox RP CA (`rp-ca.pem` from the public host, section C) to the reader trust
   configuration, or have the platform's certificate issued under a CA the app already trusts.
3. Render the mandate on the consent screen from `match.transactionData` (purpose, actions,
   counterparties, limits, validity): the wallet must show what the person signs. Without this the
   person approves an opaque blob; do not demo it that way.
4. Scan the QR code on `https://platform.sandbox.plenipo.net/requests/<id>`: the app must reach the
   public `request_uri` and `response_uri`, so B needs C.

## C. Public host

A VPS with Docker, and DNS records for `sandbox.plenipo.net` and its subdomains (`pid.`, `wallet.`,
`platform.`, `bank.`; a wildcard `*.sandbox.plenipo.net` works) pointing to it. Ports 80 and 443
open. Nothing has been deployed.

```bash
git clone <this repository> plenipo && cd plenipo/sandbox
npm --prefix .. ci && npm ci          # only to run the certificate script
npm run rp-cert -- --dns platform.sandbox.plenipo.net --out deploy/secrets
cd deploy && cp env.example .env      # set ACME_EMAIL, DEMO_PASSWORD_HASH, SANDBOX_ADMIN_TOKEN
docker compose up -d --build
```

What it runs (`deploy/`): one container with the five services (`Dockerfile`, built from the
repository root) and Caddy (`Caddyfile`), which obtains Let's Encrypt certificates and routes:

| Host | Public without login | Behind the demo login (basic auth) |
| --- | --- | --- |
| `platform.sandbox.plenipo.net` | `/request/*` (`request_uri`), `/response/*` (`response_uri`), `/status/mandates` | the "my mandates" page, the API agents use |
| `pid.sandbox.plenipo.net` | `/status/1`, `/trust-anchor.pem` | the PID admin page |
| `sandbox.plenipo.net` | | the dashboard |
| `wallet.sandbox.plenipo.net` | | the sandbox wallet |
| `bank.sandbox.plenipo.net` | | accounts, MCP, REST |

A phone wallet needs only the first row. In this configuration the identities are real https
names (`PLENIPO_PID_ISSUER=https://pid.<domain>`, `PLENIPO_PLATFORM_ORIGIN=https://platform.<domain>`,
so the client_id is `x509_san_dns:platform.<domain>`), the sandbox wallet runs in strict mode
(`response_uri` must be https on the client_id host), and admin endpoints need
`SANDBOX_ADMIN_TOKEN`. Inside the container the bank still fetches status lists from the local
services, so the public host is not on the verification path.

To run agents and scenarios against the public sandbox, open a shell in the container
(`docker compose exec sandbox sh`) and use `npm run scenarios -- --attach` or `npm run agent`
there: the container already has `SANDBOX_ADMIN_TOKEN` and `PLENIPO_BANK_HOST`. The sandbox wallet
then fetches the public `request_uri`, so the VPS must reach its own public names (it normally does).

Before a live session: restart the container for a clean state (everything is in memory), check
`https://platform.<domain>/status/mandates` and `https://pid.<domain>/status/1` load without a
login, and approve one mandate from the phone end to end.
