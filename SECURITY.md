# Security Policy

## Supported version

Security fixes are applied to the latest commit on `main` and to the currently deployed production artifact. Older commits and self-managed forks are not covered unless a separate support agreement says otherwise.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability and do not include credentials, personal data, document contents, presigned URLs, access tokens, database addresses, or environment-variable values in screenshots or logs.

Use GitHub's private vulnerability reporting or a private repository Security Advisory:

1. Open the repository **Security** tab.
2. Choose **Report a vulnerability**.
3. Include the affected commit/deployment, reproducible steps, impact, and the smallest safe proof of concept.
4. Redact all customer and production data.

If private vulnerability reporting is unavailable, contact a repository owner through a previously verified private business channel. Do not send secrets over a new or unverified address.

## Response targets

The following are proposed internal operating targets, not a contractual SLA. A repository owner must approve staffing and the final incident-response policy before commercial launch.

| Severity | Initial acknowledgement | Triage target | Remediation target |
|---|---:|---:|---:|
| Critical | 4 business hours | 1 business day | Immediate mitigation; permanent fix within 72 hours where feasible |
| High | 1 business day | 2 business days | 7 calendar days |
| Medium | 2 business days | 5 business days | 30 calendar days |
| Low | 5 business days | 10 business days | Next planned release |

Targets start after the report reaches a monitored private channel and may change when a fix requires third-party coordination. The team will communicate status and compensating controls privately.

## Safe-harbor boundaries

Only test accounts, data, and deployments you own or have explicit written authorization to assess. Do not perform denial of service, social engineering, persistence, destructive actions, bulk data access, credential stuffing, or tests against other tenants. Stop immediately if real customer or employee data becomes visible.

## Operational security requirements

- Secrets belong in the deployment platform's secret store, never in Git, browser bundles, tickets, chat messages, or screenshots.
- Production administrator accounts require unique high-entropy credentials and, before formal commercial launch, MFA.
- Rotate a credential immediately if it is exposed, even when it was shared intentionally during troubleshooting.
- Preserve request IDs and timestamps when reporting an incident; do not copy full authorization headers or presigned URLs.
- Follow [the commercial readiness report](docs/COMMERCIAL_READINESS_REVIEW.zh-CN.md) for current release blockers and compensating controls.
