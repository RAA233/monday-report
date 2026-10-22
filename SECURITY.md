# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately via GitHub's private vulnerability reporting on this
repository (**Security → Report a vulnerability**). That channel reaches the
copyright holders and keeps the report out of public view until a fix exists.

Please include: the affected component and version/commit, reproduction steps
or a proof of concept, the impact you believe it has, and any suggested fix.

We aim to acknowledge reports within 7 days. We will tell you plainly whether
we consider the issue valid, and we will credit you in the advisory unless you
prefer otherwise.

## Scope

This project handles operational drilling reports and is designed for
multi-tenant deployment, so the following are in scope and taken seriously:

- Cross-tenant data access (IDOR, missing tenant comparison, RLS bypass)
- Authentication or authorisation bypass on any route
- Audit-chain forgery or undetected tampering
- Signed-URL forgery, replay, or scope escalation
- Archive/upload handling (zip-slip, path traversal, decompression bombs)
- Server-side request forgery in the optional online-AI egress path
- Licence-verification bypass in the offline edition
- Secret or credential disclosure in logs, errors, exports, or evidence

## Known and documented limitations

These are **already known, deliberately documented, and tracked** — they are
not new findings. Please do not report them as vulnerabilities; do feel free to
contribute fixes.

| Limitation | Tracked as |
|---|---|
| Audit **tail truncation is undetected**. The HMAC chain proves authenticity of recorded events, not that none were removed. There is no external anchor. | `audit-tail-truncation-detection`, `docs/AUDIT_INTEGRITY.md` |
| HMAC proves event authenticity, **not transactional consistency**. Whole-snapshot concurrent mutation is last-writer-risk. | `docs/AUDIT_INTEGRITY.md` |
| Cross-process correction atomicity is **not** provided. | `correction-cross-process-atomicity`, `docs/FIELD_CORRECTIONS.md` |
| Production-target database and queue adapters are **NOT_ACCEPTED**. Behaviour is proven only in disposable test infrastructure. | `production-database-adapter`, `production-queue-adapter`, [STATUS.md](STATUS.md) |
| No dependency vulnerability scanning in CI. | `dependency-vuln-scan` |
| Malware scanning is a built-in baseline only; no external scanner integration. | `external-malware-scanner` |
| Offline licensing deters copying but **cannot** make client-controlled hardware tamper-proof. Clock-rollback detection is bounded. | `packaging/offline/README.md` |

The authoritative list of 28 tracked controls is
`evals/ga/blocker_registry.v1.json`. See [STATUS.md](STATUS.md).

## Supported versions

This project is **pre-1.0 and not generally available**
(`release_recommendation: GA_BLOCKED`). There are no released versions and no
security backport branches. Fixes land on `main`.

**Do not deploy this to production with real customer data.** See
[STATUS.md](STATUS.md) for exactly what is and is not proven.

## Secrets

If you believe a secret was committed to this repository, report it privately
as above.

For reference, the pre-release audit found no secret, key, token, credential,
or private path in tracked content or in Git history. The only
credential-shaped strings are intentional test fixtures inside the
secret-scanner's own corpus (`scripts/*_secret_scan_guard.py`). Offline
licence signing keys are never committed, never packaged, and are supplied to
the issuer CLI only via an explicit file path or environment reference.
