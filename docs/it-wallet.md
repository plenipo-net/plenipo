# IT-Wallet

Status: **in preparation**. Profile `it-wallet-1` is implemented and tested against the test wallet in
`plenipo/testing`. Nothing has run against an Italian wallet yet.

## What changed in November 2026

The public IT-Wallet in the IO app began opening to citizens and residents on 23 November 2026,
progressively and to randomly selected users; activation needs an electronic identity card (CIE). The
AgID regulation adopted on 23 October 2026 (determination no. 164) opens registration to private wallet
providers, attestation issuers, verifiers of electronic attestations and aggregators, and sets up an
experimentation space.

In the IT-Wallet System a bank that checks a mandate is a *verifier of electronic attestations*, the
relying party of the European model. It may run the verification itself or rely on an aggregator, which
registers on its own. Either way the bank keeps its obligations as relying party.

## What the specification says, and what Plenipo does

From the IT-Wallet technical specification, version 1.4.7 (September 2026):

| Rule | Plenipo |
| --- | --- |
| Remote flow on OpenID4VP 1.0, signed request object, DCQL query | as for every wallet |
| `response_mode` `direct_post.jwt`, response encrypted with ECDH-ES on P-256 and AES-GCM | default (`encryptResponse: true`) |
| Client identifier prefixes `openid_federation` or `x509_hash` | `x509_hash` from profile `it-wallet-1`; `openid_federation` not yet |
| Relying party publishes an Entity Configuration at `/.well-known/openid-federation` and is trusted through a federation Trust Chain | not yet |
| `transaction_data` optional in the request object; for `dc+sd-jwt` its hashes go in `transaction_data_hashes` of the key binding JWT | how `plenipo_mandate` is bound already |
| PID as SD-JWT VC, type `urn:eudi:pid:it:1` in the examples | default PID type of the profile, overridable |
| Verifiers justify every attribute they request | `MandateRequest.disclosure`, with `requireClaimPurposes` in the profile |

The open question is the one no relying party can settle in code: whether the IT-Wallet app shows a
transaction data type it does not know, such as `plenipo_mandate`, to the person and signs it, or refuses
the request. The specification says that for mdoc credentials a wallet refuses types the issuer has not
authorised; it says nothing more for SD-JWT VC. Only a run with an Italian wallet answers it.

## Using the profile

```ts
import { createMandateRequest, handleMandateResponse } from 'plenipo';
import { itWalletRequestOptions, itWalletRequestProblems, itWalletVerifyDefaults } from 'plenipo/experimental';

const req = await createMandateRequest(
  itWalletRequestOptions({
    mandate,
    responseUri: 'https://agents.example/response',
    signer: { key: rpPrivateKey, x5c: rpCertificateChain }, // client_id = x509_hash of x5c[0]
  }),
);
itWalletRequestProblems(req.params, req.requestObject); // [] when no known rule is broken
req.disclosure; // every claim requested, with its purpose

const { root } = await handleMandateResponse(body, req.session, {
  trustedIssuers,
  sessions,
  now,
  ...itWalletVerifyDefaults(),
});
```

Defaults: claims `given_name`, `family_name` and `personal_administrative_number` (the stable identifier
used as `principal_id`), each with a stated purpose; a request that asks for a claim without a purpose is
refused. Pass `disclose`, `claimPurposes` and `pidVcts` to change them.

`x509HashClientId(certificate)` gives the `x509_hash` client identifier of any certificate, and
`createMandateRequest` refuses an `x509_hash` client identifier that does not match the signing
certificate.

## Not yet

- `openid_federation` client identifiers and an Entity Configuration for the relying party.
- Trust in Italian PID providers through the federation Trust Chain. Today the PID provider is trusted
  as for any wallet: `trustedIssuers` or `trustAnchors`.
- A conformance run against the Remote Credential Verifier Test Matrix of the specification.
- Verification through an aggregator, where the aggregator verifies the presentation and Plenipo checks
  its binding to the mandate. Under discussion: it changes the trust model and what a relying party can
  claim.

## Sources

- IT-Wallet technical specification: https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/
  (remote flow, relying party endpoints, credential data model)
- AgID, regulation for registration and experimentation (23 October 2026): https://www.agid.gov.it/en/node/467
