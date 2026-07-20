# Security headers

The TLS edge and backend defense-in-depth apply CSP, `nosniff`, referrer and permissions policies, frame denial, COOP, CORP, and route-appropriate cache control. HSTS is emitted only for HTTPS.

The production CSP restricts all content to the same origin, forbids objects, limits base and form targets, denies framing, and contains no `unsafe-eval`. Inline scripts are not allowed. The existing UI currently requires `unsafe-inline` for compatible styling; removing it requires a tested nonce/hash migration.

Authenticated API, login, session, MFA, operations, and report responses are not shared-cacheable. Hashed assets are immutable; `index.html` revalidates. Review headers through the TLS proxy after every frontend or proxy change.
