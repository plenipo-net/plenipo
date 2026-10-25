# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: on the repository page open **Security**, then
**Report a vulnerability**. Do not open a public issue, pull request or discussion.

Please include what is affected, how to reproduce it, and what an attacker gains. A failing test is the
best report.

We acknowledge reports within 5 working days and agree a disclosure date with the reporter, normally
within 90 days. Credit is given in the advisory unless you prefer otherwise.

## Supported versions

Plenipo is experimental (0.x). Fixes go into the latest minor release only.

## Scope

In scope: the library in `src/`, the profile in `docs/spec.md`, and the test vectors. The sandbox and
`plenipo/testing` use throwaway test keys by design; issues there are in scope only when they affect
the library or could mislead an integrator into an unsafe setup.

## Status of reviews

The code has been through two rounds of security review by independent AI review agents, with
proof-of-concept exploits; all findings are fixed and listed in [CHANGELOG.md](CHANGELOG.md). It has
not yet been audited by an external security firm.
