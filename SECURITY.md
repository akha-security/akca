# Security Policy

## Supported versions

AKCA is currently in its initial public-development phase. Security fixes are
applied to the latest release and the default branch.

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |
| Earlier snapshots | No |

## Reporting a vulnerability in AKCA

Please do not disclose a vulnerability in AKCA through a public GitHub issue.
Use GitHub's private vulnerability reporting feature on
[the AKCA repository](https://github.com/akha-security/akca/security/advisories/new).

Include, when possible:

- Affected version or commit
- Operating system and Go version
- Reproduction steps or a minimal test case
- Security impact and realistic attack scenario
- Relevant logs with credentials and target data removed
- Any suggested mitigation

You should receive an acknowledgement within seven days. Investigation and fix
timelines depend on severity and reproducibility.

## Scanner findings are not AKCA vulnerabilities

Do not use this channel to disclose vulnerabilities found in third-party targets.
Report those issues privately to the affected owner or their authorized
disclosure program. Never include customer data, live credentials, or private
target evidence in this repository.

## Safe harbor

Good-faith research against AKCA itself is welcome when it avoids privacy
violations, service disruption, data destruction, and testing systems without
authorization.
