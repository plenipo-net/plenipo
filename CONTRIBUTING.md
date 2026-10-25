# Contributing to Plenipo

Thank you for helping. Plenipo decides whether an AI agent may act with someone's money or data, so
changes are held to the bar of security code: small, tested, and explained.

## Before you start

- For anything larger than a fix, open an issue first and describe the problem. Changes to the wire
  formats or to the verification rules in [docs/spec.md](docs/spec.md) need agreement before code.
- Do not report vulnerabilities in issues or pull requests: see [SECURITY.md](SECURITY.md).

## Development

Node 22 or later.

```bash
npm ci
npm run typecheck
npm test
```

Postgres and Redis tests run when `PLENIPO_TEST_PG_URL` and `PLENIPO_TEST_REDIS_URL` point to servers,
and skip otherwise; CI runs them. The sandbox has its own suite: `cd sandbox && npm ci && npm test`.

## Pull requests

- One topic per pull request, with tests. A change to verification needs a test for the case it
  allows and for the case it refuses.
- When a rule of the profile changes, update [docs/spec.md](docs/spec.md) and regenerate the test
  vectors with `npm run vectors` in the same pull request.
- Add a line to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md).
- Fail closed: when in doubt, deny. New inputs are validated strictly before they are compared.
- No new runtime dependency without a reason stated in the pull request.

## Developer Certificate of Origin

Every commit must be signed off, to certify that you wrote it or have the right to submit it under the
project license, as stated in the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "Explain the change"
```

This adds `Signed-off-by: Your Name <you@example.com>` to the commit message. The DCO app checks
every pull request for it. There is no separate contributor agreement.

## Code of conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
