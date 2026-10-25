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
  header for `x509_san_dns:` client identifiers), to serve at `request_uri`.

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

| Wallet | Status (October 2026) | What to do |
| --- | --- | --- |
| walt.id wallet | Transaction data types are configurable through transaction data profiles. | Add a profile for `plenipo_mandate` with a display template for the mandate fields. |
| EUDI reference wallet (Android wallet core) | Transaction data for SD-JWT VC presentations was merged on the `release/0.31.0` branch in September 2026. It is opt-in: the wallet declares the types it accepts, and the documented example is `QES_APPROVAL`. | Check in the code whether custom types can be declared; if they can, declare `plenipo_mandate` in a fork of the reference app and render the mandate on the consent screen. If not, propose the type upstream. |
| IT-Wallet (app IO) | No public support for custom transaction data types. | Needs agreement with the scheme operator; see the roadmap. |

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
`client_id` and `nonce`. It is what the test suite uses. A run against a real
device cannot be done from this repository's CI and has not been done yet.

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
