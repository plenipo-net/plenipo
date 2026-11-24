# Interoperability with real wallets

Plenipo speaks OpenID4VP 1.0 to the wallet. `createMandateRequest` builds a
request that a conformant wallet can process:

- `response_type=vp_token`, `response_mode=direct_post.jwt` (encrypted with
  ECDH-ES and A128GCM to a key in `client_metadata.jwks`, as HAIP requires) or
  `direct_post`;
- a DCQL query for one `dc+sd-jwt` credential with `vct_values`
  `["urn:eudi:pid:1"]`, asking only for the claims you list;
- one `transaction_data` entry of type `plenipo_mandate`, bound to the `pid`
  query;
- an optional signed request object (`typ: oauth-authz-req+jwt`, `x5c` in the
  header for `x509_san_dns:` and `x509_hash:` client identifiers), to serve at
  `request_uri`;
- `MandateRequest.disclosure`: every claim the request asks for, with its
  purpose, for relying parties that must justify each attribute they request.

`handleMandateResponse` decrypts the response, checks `state`, takes the one
presentation for `pid`, verifies the PID (trusted issuer or x5c chain, status
list) and the key binding JWT, and binds the result to this request through the
key binding `nonce` and `aud`.

## What a wallet must support

Everything above is standard OpenID4VP and SD-JWT VC except one thing: the
wallet has to accept transaction data of type `plenipo_mandate`, show the
mandate to the person, and include the hash of the transaction data in
`transaction_data_hashes`. OpenID4VP requires wallets to reject requests with
a transaction data type they do not support, so a wallet that does not know
the type refuses the request instead of silently signing something the person
has not seen. That is the right behaviour, and it means interoperability is a
matter of registering the type, not of changing the protocol.

| Wallet | Status (November 2026) | What to do |
| --- | --- | --- |
| walt.id Wallet API 2 | Transaction data types are configurable through transaction data profiles. | **Works.** With the profile in `sandbox/level2/waltid/config`, Wallet API 2 (`stable`, October 2026) approved a `plenipo_mandate` and the bank enforced it, end to end, on 25 October 2026 (`sandbox/level2/README.md`). |
| EUDI reference wallet (Android) | Wallet core 0.32.0 accepts custom types (`TransactionDataType.raw`); the reference app declines what its consent screen cannot show. | **Works.** The fork [plenipo-net/eudi-wallet-android](https://github.com/plenipo-net/eudi-wallet-android) declares `plenipo_mandate` and shows every limiting field. On 15 November 2026 (`plenipo-v0.1.2`, Android emulator) it approved a mandate with a PID from the EU test issuer, and the bank allowed and refused payments within it (#44, `sandbox/level2/README.md`). |
| EUDI reference wallet (iOS) | The wallet kit hands custom types over as raw JSON. | **Works.** The fork [plenipo-net/eudi-wallet-ios](https://github.com/plenipo-net/eudi-wallet-ios) shows the same consent rows. On 15 November 2026 (`plenipo-v0.1.2`, iOS simulator) it approved a mandate with a PID from the EU test issuer, and the bank allowed and refused payments within it (#44, `sandbox/level2/README.md`). |
| IT-Wallet (app IO) | Opening to citizens since 23 November 2026. The specification (1.4.7) has `transaction_data` as an optional request parameter, bound through `transaction_data_hashes`; whether the app shows a type it does not know is not known. | **In preparation.** Profile `it-wallet-1` builds requests with the `x509_hash` client identifier and the Italian PID type; nothing has run against an Italian wallet yet. See [it-wallet.md](it-wallet.md). |

## Testing against a wallet

1. Serve the request object returned by `createMandateRequest({ signer })` at a
   `request_uri` over HTTPS, and expose `response_uri` to receive the POST.
2. Show `authorizationRequestUrl(clientId, requestUri)` as a QR code or link.
3. Pass the POST body, the stored session and a `sessions` store to
   `handleMandateResponse`; the store makes each response redeemable once.
4. Use the returned `root` as the root of the mandate chain.

For `x509_san_dns:` client identifiers the wallet checks that the leaf
certificate in the request object names the DNS host; register the
certificate's CA with the wallet under test, as you would for any verifier.

The test wallet in `plenipo/testing` follows the same rules as a real one: it
refuses transaction data types it does not know, honours `response_mode`,
encrypts to the key in `client_metadata`, and binds the key binding JWT to
`client_id` and `nonce`. It is what the test suite uses. Runs against real
wallets cannot be done from this repository's CI; they are recorded in
`sandbox/level2/README.md` (walt.id on 25 October, the EUDI reference wallet on
Android on 15 November 2026).

What a real run with EU test PIDs needs from the verifier, learned on 15 November:

- the EU list of test PID providers as trust source, with its signer pinned;
- the status list origins the PIDs point to (`https://revocation.eudiw.dev`),
  and, for that origin, the issuer identity whose certificate signs its lists
  (`TrustConfig.statusSigners`);
- a request that the person approves within the session lifetime (10 minutes by
  default): the request object does not yet tell the wallet (#51).

## Towards a standard type

The plan is to map `plenipo_mandate` onto a type that wallets will ship anyway.
The ARF topic on transaction data (TS12) defines payment and signature
authorisation; a mandate to an agent is close to a standing payment
authorisation with a scope. Plenipo can already carry the mandate as a TS12
e-mandate (`urn:eudi:sca:emandate:1`), bound to the full mandate by hash; that
path is experimental while TS12 is a draft (see [root.md](root.md)). For its
own type `plenipo_mandate` Plenipo keeps an exact display contract: the wallet shows `purpose`, `actions`,
`counterparties`, `limits`, `nbf` and `exp`, and nothing the person did not see
is enforced, because verifiers check the hash of the exact bytes.
