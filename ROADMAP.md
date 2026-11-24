# Roadmap

Plenipo is experimental. This is the direction, not a commitment to dates.

## Next

- Interoperability with real wallets: walt.id Wallet API 2 (October 2026) and the EUDI reference
  wallet on Android and iOS (November 2026) work; next IT-Wallet, which opened to citizens on
  23 November 2026, with the results published in [docs/interop.md](docs/interop.md). Profile
  `it-wallet-1` is the first step ([docs/it-wallet.md](docs/it-wallet.md)); then `openid_federation`
  client identifiers, trust in Italian PID providers through the federation Trust Chain, and a
  conformance run against the verifier test matrix of the IT-Wallet specification.
- A profile for wallets that cannot show a new transaction data type, using the OpenID4VP
  `transaction_data` mechanism they already support.
- Verifier as a service: a container image with configuration, health checks and metrics.
- Key management adapters for at least one cloud KMS and for PKCS#11.

## Later

- A stable 1.0 API and profile, with a conformance suite that other implementations can run.
- A verifier SDK for Java and an agent SDK for Python.
- Following TS12 and a European representation attestation as they settle, and moving those
  extensions out of `plenipo/experimental` when they do.
- Zero-knowledge predicates on the PID.

Proposals are welcome as issues.
