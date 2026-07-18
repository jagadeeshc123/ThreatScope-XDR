# Connector Troubleshooting

- Credential unavailable: supply the matching environment key; never place it in UI/database.
- SSRF/DNS denial: use an exact safe hostname or narrow Administrator private approval.
- TLS failure: repair certificate/hostname; bypass is unavailable.
- Open circuit: inspect safe attempts, correct/test, then reset with reason.
- Dead letter: correct terminal cause and explicitly replay; the original remains.
- Inbound failure: verify raw-body signing, timestamp seconds, schema, and unique event ID.

Diagnostics make no external requests. Local Test Sink is offline verification, not evidence of external delivery or containment.
