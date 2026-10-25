# Trust layer: trusted lists, direct anchors, certificate revocation

This document covers how a Plenipo verifier decides that a PID provider (or a
status list signer) is trusted, beyond the explicit keys and PEM anchors of
v0.2: loading EU Lists of Trusted Entities, anchors that are the provider's own
signing certificate, and CRL/OCSP checking of x5c chains.

Everything here is opt-in. A verifier configured as in v0.2 behaves exactly as
before: no list is loaded, no revocation data is fetched.

## Where trust comes from in the EUDI ecosystem

- **PID providers, wallet providers, providers of relying party access and
  registration certificates and public-sector attestation providers** are
  notified by Member States and published by the Commission as *Lists of
  Trusted Entities* (LoTE), ETSI TS 119 602 V1.1.1 (2025-11). The EU profiles
  (Annex D onwards) fix the LoTE type, the service type identifiers and a
  maximum of six months between `ListIssueDateTime` and `NextUpdate`. The
  lists carry no service status: being listed is being trusted.
- **Qualified trust services** keep the classic model: the EU List of Trusted
  Lists (LOTL, `https://ec.europa.eu/tools/lotl/eu-lotl.xml`) pointing to the
  national Trusted Lists, all ETSI TS 119 612 XML signed with XAdES.

A LoTE service lists its certificates in `ServiceDigitalIdentity`. They may be
CA certificates (the provider's PKI) or end-entity certificates (the
provider's signing certificate itself); the reference implementation from the
EUDI project accepts both ("EndEntityOrCA"). Plenipo now accepts both.

## Lists of Trusted Entities

```ts
import { loadTrustedList, trustConfigFromLists, LOTE_TYPE, LOTE_SERVICE_TYPE } from 'plenipo';

const list = await loadTrustedList(documentBytes, {
  signerCertificates: [commissionListSignerPem], // from the OJ publication or the LOTL pointer
  expectedType: LOTE_TYPE.pidProviders,
  minSequenceNumber: lastSeenSequenceNumber,      // optional anti-rollback
  maxValiditySeconds: 183 * 86400,                // optional: the EU profiles' six months
});
const pidTrust = trustConfigFromLists(list, {
  serviceTypes: [LOTE_SERVICE_TYPE.pidIssuance],
  base: { requiredPolicyOids, certificateRevocation },
});
const pidStatusTrust = trustConfigFromLists(list, { serviceTypes: [LOTE_SERVICE_TYPE.pidRevocation] });

await verifyAuthorization(chain, invocation, { ...pidTrust, audience, nonces /* ... */ });
```

### API

- `loadTrustedList(document: string | Uint8Array, opts): Promise<TrustedList>`
  verifies and parses one list. It never fetches anything. Options:
  `signerCertificates` (PEM or base64 DER, required for signed lists),
  `unsigned: 'accept-for-testing'`, `now`, `expectedType`,
  `minSequenceNumber`, `maxValiditySeconds`, `algorithms` (default ES256,
  ES384, ES512, PS256, PS384, PS512), `skewSeconds` (default 300),
  `maxBytes` (default 5 MB), `requireSignerMatchesOperator` (default false).
  The result carries the type, version, sequence number, issue time,
  `nextUpdate`, operator names, territory, distribution points, the entities
  with their services (names, type, status, certificates, public keys, subject
  names, SKIs, other ids, supply points) and how the list was accepted.
- `listedServices(lists, { serviceTypes, acceptedStatuses?, now? })` returns
  the active services of the given types. A service without `ServiceStatus`
  (the EU profiles) is active; a service with a status is taken only when the
  status is in `acceptedStatuses`; a status starting in the future is skipped.
- `trustConfigFromLists(lists, { serviceTypes, acceptedStatuses?, base?,
  publicKeysAsIssuersOfSupplyPoints? }): TrustConfig` turns every certificate
  of the matching services into a trust anchor, keeping the settings of
  `base`. With `publicKeysAsIssuersOfSupplyPoints`, P-256 keys published in
  `PublicKeyValues` become `trustedIssuers` for the service's https supply
  point URIs (off by default: a supply point is where a service is reached,
  not necessarily the credential `iss`). JWKs with private parts are ignored.
- `fetchTrustedList(url, { timeoutMs?, maxBytes? })` is an optional helper:
  HTTPS only, no redirects, 10 s and 5 MB by default. Its output still goes
  through `loadTrustedList`.
- `LOTE_TYPE`, `LOTE_SERVICE_TYPE`: the URIs of the EU profiles.
- Errors are `TrustListError` with a message that names the failed check.

### What is verified, exactly

The loader supports the **JSON binding signed as a compact JWS**, which is
what the EUDI reference distribution points publish (`*.jwt`, as configured in
the EUDI consultation library), what that library parses, and what the
OpenWallet Foundation SDK (`@owf/eudi-lote`) produces. TS 119 602 clause 6.8 requires an
AdES signature at baseline B; for JSON that is JAdES (ETSI TS 119 182-1). Of
JAdES baseline B in compact serialization, Plenipo verifies:

- the JWS is compact with an attached payload; `b64: false` and `sigD`
  (detached payloads) are refused;
- `alg` is in the accepted list (`none` and HMAC never are);
- the signing certificate is identified by `x5c` (leaf first) and/or
  `x5t#S256`, and is **byte-identical to one of `signerCertificates`**; when
  both are present they must name the same certificate; a list identifying
  its signer only by `kid`, `sigX5ts` or `x5t#o` is refused;
- `crit`, when present, is a non-empty array of parameters understood here
  (only `sigT`), each present in the header (RFC 7515 4.1.11);
- `sigT`, when present, is an RFC 3339 UTC time without fractional seconds,
  not in the future (beyond the skew) and within the signer certificate's
  validity;
- the signer certificate is valid now and, if it has key usage, allows
  `digitalSignature` or `nonRepudiation`;
- the signature verifies under the pinned certificate's key;
- optionally (clause 6.8), the signer subject has `C` = `SchemeTerritory` and
  `O` = one of the `SchemeOperatorName` values.

Then the payload must match the LoTE JSON schema (bounded: 10 000 entities,
256 services per entity, 64 identities per service, 4 KB strings, 64 KB per
certificate, 5 MB per document), and the list must be fresh:
`ListIssueDateTime` not in the future, `NextUpdate` present (a `null`
NextUpdate marks a closed list, which is refused) and strictly in the future
(clause 6.3.15: an expired list "shall be discarded"), and after the issue
time.

**Not verified:** path validation or revocation of the list signer
certificate (it is pinned instead, as the LOTL pins the signers of each list),
JAdES levels above B (timestamps, long-term validation data), signature
policies (`sigPl`), commitment types, counter-signatures, the JWS JSON
serialization, the `typ` header (the OWF SDK writes `trustlist+jwt`; the
specification text we could read does not mandate a value), list pointers
(`PointersToOtherLoTE`, which are not followed), service history, and the
profile rules on entity information URIs. XML documents (the XML binding of
TS 119 602, national Trusted Lists and the LOTL, all XAdES) are refused with
an explicit error: correct XAdES validation needs XML canonicalisation and
reference processing that a minimal implementation would get wrong. To use
TS 119 612 lists, extract the anchors with a dedicated validator (for example
`@owf/eudi-tl`, which verifies XAdES and pins the LOTL signers) and pass them
as `trustAnchors`.

An unsigned plain-JSON list is accepted only with
`unsigned: 'accept-for-testing'`. A JWS is never accepted without verifying
it, whatever the flag.

### Why not `@owf/eudi-lote` at runtime

The package (Apache-2.0, OpenWallet Foundation Labs, identity-common-ts,
v0.5.0) creates, signs and schema-validates LoTE documents in the JWT
encoding, but it does not verify signatures, and it adds three runtime
dependencies. Plenipo uses it only in its tests, to check that a list made and
signed with it loads with Plenipo's verifier. Note that the OWF SDK names the
pointer field `PointersToOtherLoTE` while the EUDI Kotlin library uses
`PointerToOtherLoTE`; Plenipo reads neither.

## Direct signing certificates as anchors

A trust anchor that is **not a CA** (no basic constraints `CA=true`) vouches
only for itself: an x5c whose leaf is byte-identical to it is trusted, the
rest of the x5c plays no part, and the anchor can never act as the issuer of
another certificate. All leaf checks still apply: validity, `digitalSignature`,
policies, EKU, no name constraints, P-256 key, and the certificate must name
the expected identity (the PID `iss`) in its subject alternative names. A CA
anchor presented as the signer is still refused.

## Certificate revocation (CRL and OCSP)

```ts
import { httpRevocationFetcher, RevocationCache } from 'plenipo';

const certificateRevocation = {
  policy: 'hard-fail',                 // 'off' (default) | 'soft-fail' | 'hard-fail'
  fetcher: httpRevocationFetcher(),    // no network unless a fetcher is given
  cache: new RevocationCache(),        // statuses and CRLs kept until nextUpdate
};
await verifyAuthorization(chain, invocation, { trustAnchors, certificateRevocation, /* ... */ });
```

- `TrustConfig.certificateRevocation` enables checking wherever that trust
  is used: `verifyRoot`, `handleMandateResponse`, status list signers
  (`mandateStatusTrust`, `pidStatusTrust`). `VerifyOptions.certificateRevocation`
  covers the PID provider path and the PID status list signer under the PID
  trust.
- `resolveSigningKeyAsync(header, name, trust, now)` is the async counterpart
  of `resolveSigningKey`. The synchronous function is unchanged, except that it
  refuses an x5c signer when revocation is enabled, so a caller cannot skip
  the check by using it. `ResolvedKey` now carries `chain` (the validated path,
  leaf first, ending with the anchor) and `revocation` (the report).
- `checkCertificateRevocation(chain, opts, now)` checks a validated path
  directly; `checkChainRevocation` does the same and throws `TrustError`.
- `RootResult.pidCertificateChain` exposes the PID provider path.
- `httpRevocationFetcher({ timeoutMs?, maxCrlBytes?, maxOcspBytes?,
  allowHttp?, allowedHosts? })`: http(s) only, no redirects, no credentials in
  URLs, 5 s, 10 MB per CRL, 64 KB per OCSP response. Plain http is allowed by
  default because revocation data is signed and RFC 5280 recommends http
  distribution points; set `allowHttp: false` to require https.
- Options: `methods` (default `['ocsp', 'crl']`), `crls` (CRLs supplied out of
  band, verified like fetched ones), `ocspNonce` (default false),
  `skewSeconds` (default 300, never applied to nextUpdate),
  `maxAgeWithoutNextUpdate` (default 3600 s), `maxCrlBytes`.
- `RevocationCache` remembers how each status was obtained and serves a cached
  `good` only to a check whose options it satisfies: not to a check requiring
  `ocspNonce` when the answer had none, not past the requesting
  `maxAgeWithoutNextUpdate` for an OCSP answer without nextUpdate, and not to
  a check whose `methods` exclude the method it came from. A cached `revoked`
  is served to every check.

### Policies

- `off`: no check. Default, so existing deployments keep their behaviour.
- `soft-fail`: a certificate proven revoked is rejected. A certificate whose
  status cannot be obtained (no URL, no fetcher, network or HTTP error,
  timeout, size limit, OCSP `tryLater`/`internalError`/`unauthorized`) is
  accepted, and the report says `undetermined`.
- `hard-fail`: every certificate below the anchor must be proven good.
  **Recommended for production.** A certificate with neither a CRL
  distribution point nor an OCSP responder cannot be proven good and is
  rejected; supply its CRL through `crls` if it is distributed another way.

In both checking modes, revocation data that was obtained but does not verify
is a rejection, not an unavailability: wrong signature, wrong issuer, wrong
responder, missing OCSPSigning EKU, stale or future data, OCSP `unknown`,
response for another certificate, nonce mismatch, malformed data. Soft-fail
cannot protect against an attacker who blocks the traffic; it only tolerates
outages.

### What is checked

The check runs on a path that has already validated to an anchor, so every URL
contacted was put in a certificate by a trusted CA. Each certificate except
the anchor is checked against the next one as its issuer. The anchor is not
checked (its status is the list's business), nor is a leaf trusted directly
as an anchor (it has no issuer in the path).

OCSP (RFC 6960, RFC 5019 profile):

- request with a SHA-1 CertID (identification only) over the issuer name and
  key, the serial, and optionally a 32-byte nonce (RFC 8954);
- response status `successful` and type `id-pkix-ocsp-basic`, size bounded,
  at most 4 certificates and 32 single responses;
- signer: the issuing CA itself (responder ID by name or key hash), or a
  delegated responder certificate included in the response that is issued
  and signed by that CA, valid now, carries `id-kp-OCSPSigning`, has
  `digitalSignature` if key usage is present and no unknown critical
  extension; the signature over the exact `tbsResponseData` bytes verifies
  (ECDSA P-256/384/521 with SHA-2, RSA PKCS#1 v1.5 with SHA-2, Ed25519);
- a single response whose CertID (SHA-1 or SHA-2) matches the certificate;
  `producedAt` and `thisUpdate` not in the future; `nextUpdate` in the future,
  or, without one, `thisUpdate` within `maxAgeWithoutNextUpdate`; no unknown
  critical extension;
- `good` accepts, `revoked` rejects, `unknown` rejects.

The delegated responder's own revocation is not checked (RFC 6960 4.2.2.2.1
leaves it to `id-pkix-ocsp-nocheck` or short-lived responder certificates).

CRL (RFC 5280 6.3, complete CRLs only):

- issuer name equal to the issuer's subject; the issuer's key usage, if
  present, includes `cRLSign`; signature algorithm fields agree; the signature
  over the exact `tbsCertList` bytes verifies;
- `thisUpdate` not in the future; `nextUpdate` present and in the future;
- delta CRLs, indirect CRLs (`indirectCRL`, `certificateIssuer` entries),
  attribute-certificate CRLs, reason-partitioned CRLs and unknown critical
  extensions are refused; `onlyContainsUserCerts` / `onlyContainsCACerts`
  and the issuing distribution point name restrict which certificates the CRL
  covers, and a CRL fetched from a distribution point must belong to it;
- every listed serial is revoked, whatever the reason code (a hold too).

Distribution points with a separate `cRLIssuer` or `reasons` are skipped, as
are non-http(s) URIs (LDAP). At most 2 OCSP URLs and 3 CRL URLs are tried per
certificate. Parsing is bounded in bytes, depth and node count.

### Where it runs

- In `verifyAuthorization`, after the invocation signature and the scope
  checks, next to the status lists: an unauthenticated caller causes no
  revocation traffic. A revoked or undeterminable PID provider certificate
  denies with `PID_ISSUER_UNTRUSTED`; the details go to `detail`.
- In `verifyRoot` used on its own, after the presentation, key binding and
  transaction data hash have verified.
- For status list signers, inside `checkStatus` before the token signature is
  checked (the x5c path has validated by then). A failure denies with
  `REVOKED` (mandates) or `PID_REVOKED` (PID status). The status list cache
  keys on the revocation policy, so a list accepted without a check is never
  served to a check that requires one.

## Security notes

- The list loader never trusts the list to say who signed it: the signer
  certificate comes from the caller.
- Lists can be replayed until their `NextUpdate`; pass `minSequenceNumber`
  from the last list you accepted to refuse an older one.
- Revocation data is cached until its `nextUpdate`. That interval, chosen by
  the CA, is the revocation latency the verifier accepts. Use `ocspNonce` with
  responders that support it when freshness matters more than caching.
- All anchors from a list go into one pool, as with hand-configured anchors:
  any listed PID provider CA can certify any `iss` it puts in a certificate.
  Binding each anchor to the identities of its entity is not done yet.
- Name constraints are still unsupported, and a path containing them is still
  rejected.

## Limits and open points

- XML lists (TS 119 612 LOTL and national TLs, XML binding of TS 119 602)
  are not loaded; see above.
- The EU reference LoTE distribution points
  (`https://trustedlist.serviceproviders.eudiw.dev/LOTE/json/*.jwt`) could not
  be reached from the development environment, so loading has been tested
  against lists produced by Plenipo's test operator and by `@owf/eudi-lote`,
  not against a published list. Real lists may name the PID provider
  differently from the SAN URI that Plenipo requires on the leaf.
- No OCSP stapling, no CRL delta processing, no AIA `caIssuers` chasing.
- RSA-PSS signatures on CRLs and OCSP responses are not accepted.

## Sources

- ETSI TS 119 602 V1.1.1 (2025-11), Lists of trusted entities:
  https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
- ETSI TS 119 182-1 V1.1.1, JAdES:
  https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf
- `@owf/eudi-lote` and `@owf/eudi-tl`:
  https://github.com/openwallet-foundation-labs/identity-common-ts
- EUDI reference library for TS 119 602 consultation:
  https://github.com/eu-digital-identity-wallet/eudi-lib-kmp-etsi-1196x2
- RFC 5280 (CRLs, path validation), RFC 6960 and RFC 5019 (OCSP), RFC 8954
  (OCSP nonce), RFC 7515 (JWS).
