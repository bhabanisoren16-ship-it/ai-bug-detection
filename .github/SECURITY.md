# Security Policy & Data Privacy Shield

## Security Architecture & Zero-Trust Posture

The **AI Bug Detection & Highlighting System** enforces defense-in-depth principles:

1. **Zero Credentials in Code**:
   - All secret credentials, API keys, private certificates, and tokens must strictly reside in environment variables or cloud secret managers (AWS Secrets Manager, Google Secret Manager, HashiCorp Vault).
   - Committing `.env` files or hardcoded credential literals is blocked by CI/CD linters and automated secret scanners.

2. **Automated Crawler & Bot Lockout**:
   - Automated crawlers, Googlebot, and scraping bots are blocked at the perimeter (`HTTP 403 Forbidden`).
   - `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet, noimageindex, notranslate` is enforced on all HTTP responses.
   - All paths are disallowed in `robots.txt`.

3. **Defensive Web Shield**:
   - HTTP Strict Transport Security (`max-age=31536000; includeSubDomains; preload`).
   - Cross-Origin-Opener-Policy (`same-origin`) & Cross-Origin-Resource-Policy (`same-origin`).
   - Restrictive Content Security Policy (`object-src 'none'; base-uri 'self'; frame-ancestors 'self'`).
   - 2MB body limit preventing memory exhaustion DoS (`HTTP 413`).
   - Token-bucket request throttling (`HTTP 429`).
   - Null-byte injection and path traversal defenses (`HTTP 400`).

4. **Information Disclosure Prevention**:
   - Server identity is masked (`Server: gws`) to prevent runtime fingerprinting.
   - Internal filesystem paths and environment details are sanitized from all public error messages.

## Reporting a Vulnerability

If you discover a security vulnerability within this project, please report it privately:
- Do **NOT** file a public GitHub issue.
- Please email the maintainer or submit a Private Security Advisory via GitHub.
- You will receive an acknowledgment within 24 hours and a remediation update within 72 hours.
