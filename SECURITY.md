# Security Policy

## Supported Versions

Security updates are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.3.x   | :white_check_mark: |
| 1.2.x   | :white_check_mark: |
| < 1.2.0 | :x:                |

---

## Reporting a Vulnerability

We take the security of zn, the MCP Gateway, and our client SDKs seriously. If you have discovered a security vulnerability, please report it to us responsibly.

* **Email:** [security@usezn.com](mailto:security@usezn.com)
* **Response Time:**
  * Initial acknowledgment: **within 24 hours**
  * Triage & severity assessment: **within 48 hours**
  * Remediation & patch release: typically within 7–14 days depending on complexity

Please include detailed reproduction steps, proof-of-concept payloads or scripts, and affected components or commits. Testing against local Docker containers or isolated test accounts is strongly encouraged.

---

## Safe Harbor

We consider security research conducted in accordance with this policy to be authorized. If you make a good-faith effort to avoid privacy violations, data destruction, and service interruption, we commit to:
* Not pursuing legal action against you.
* Working with you transparently to understand and validate the issue.
* Publicly acknowledging your contribution (unless you prefer anonymity).

---

## Security Hall of Fame

We gratefully acknowledge independent security researchers who have helped protect the zn ecosystem through coordinated, responsible disclosure:

| Date | Identifier | Summary | Researcher |
| :--- | :--- | :--- | :--- |
| **2026-09-07** | [SEC-2026-01](docs/advisories/SEC-2026-01.md) | Control-plane authorization gap on policy and consensus handlers | **[WinstonRedGuard (github.com/WRG-11)](https://github.com/WRG-11)** |

---

## Security Advisories

* [SEC-2026-01](docs/advisories/SEC-2026-01.md) — *Control-plane authorization gap in zn management API (Remediated in commit 6ebce2f)*
