# Connector Credentials

Set THREATSCOPE_CONNECTOR_SECRETS_KEY to a Fernet key in the backend environment. It is excluded from database backups and never logged. Missing, invalid, or mismatched keys fail secret operations closed without hiding catalog/status metadata.

Secrets are accepted only on create/replace/rotate, encrypted before persistence, and never returned. Status exposes configured/type/safe suffix/timestamps/version only. Mask placeholders are rejected; empty input does not erase. Explicit removal replaces active ciphertext with a removal marker and disables the connector. Restore requires the matching key, revalidation, retest, explicit activation, and never replays deliveries automatically.

Inbound HMAC rotation keeps the immediately previous signing value only inside the encrypted credential envelope for a hard-coded five-minute overlap. A later rotation replaces that overlap, and verification rejects the previous value after its timestamp expires. The overlap value and timestamp are never exposed through status, audit, activity, notification, report, or backup metadata.
