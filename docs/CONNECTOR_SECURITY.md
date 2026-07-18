# Connector Security

Outbound HTTP is HTTPS-only with certificate and hostname verification. Exact allowlisted public hosts on port 443 are default. Userinfo, fragments, credential queries, IP literals, localhost, loopback, private/link-local/multicast/reserved/unspecified/metadata addresses, wildcard hosts, redirects, unbounded bodies, and proxy bypasses are rejected. IPv4/IPv6 DNS answers are validated and TLS connections pin a validated address; retries resolve again.

Private egress requires Administrator permission, exact host, narrow CIDR/ports, reason, confirmation, audit, and retest. No eval, exec, subprocess, shell, arbitrary SQL/import/filesystem/network path, TLS bypass, external deletion, or real containment exists.
