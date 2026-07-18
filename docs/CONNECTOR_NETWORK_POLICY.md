# Connector Network Policy

Default public_https policy: exact host, port 443, no redirect, 256 KiB request, 512 KiB response. approved_private requires Administrator reason, narrow host/CIDR/ports, explicit confirmation, audit, and fresh test. local_test_only belongs only to the internal test sink. DNS is required; mixed public/private answers fail. TLS verification cannot be disabled.
