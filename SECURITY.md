# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could
expose tenant information, credentials, or weaken the assessor's read-only
boundary.

Report the issue privately through GitHub's **Security advisories** tab. Include
the affected version, reproduction steps, potential impact, and any suggested
mitigation. Do not include live tenant identifiers, access tokens, policy
exports, or user information.

## Security boundary

Policy Atlas is designed to collect configuration evidence through read-only
Microsoft Graph permissions and write reports locally. Review requested Graph
scopes before granting consent. A generated report is diagnostic guidance, not
a certified audit or authorization to change production policy.
