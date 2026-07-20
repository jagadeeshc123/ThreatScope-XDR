# TLS reverse proxy

The production edge is a single Nginx service serving the static Vite build and proxying `/api` to the internal backend. It listens internally on unprivileged ports 8080 and 8443; host port mappings default to 80 and 443. The backend has no host port.

TLS 1.2 and 1.3 are enabled. Older protocols, anonymous/export/null suites, session tickets, proxy redirects, directory indexes, dotfiles, backup artifacts, and source maps are disabled. Clients must verify the certificate and hostname. Deployment owners supply and rotate trusted certificates; Phase 19 does not issue certificates.

HTTPS responses include HSTS with a one-year max-age. `includeSubDomains` is not enabled implicitly and preload remains disabled. Confirm every covered hostname before adding either. HTTP only redirects and does not carry HSTS. The smoke certificate is self-signed, localhost-only, short-lived, and never a production certificate.
