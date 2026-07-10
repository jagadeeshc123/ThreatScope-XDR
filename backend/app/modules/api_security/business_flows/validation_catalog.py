VALIDATION_GUIDANCE = {
    "missing_prerequisite": "Document the prerequisite and enforce the expected sequence server-side.",
    "missing_state_validation": "Define and validate the server-side state before and after this step.",
    "insufficient_role": "Confirm the minimum role and enforce function-level authorization server-side.",
    "missing_authorization": "Document the authorization and ownership requirement for the sensitive operation.",
    "missing_confirmation": "Require an explicit, auditable confirmation before the irreversible action.",
    "replay_sensitive": "Document idempotency or replay controls for this state-changing operation.",
    "client_state_trust": "Treat client-controlled state as untrusted and derive authoritative state server-side.",
    "missing_ownership": "Document and enforce ownership or tenant scope for the referenced object.",
    "early_data_exposure": "Release restricted data only after the required authorization and workflow gates.",
}

MANUAL_SUFFIX = " This is a possible business-flow weakness based on configured metadata; manual validation is required and runtime behavior was not tested."
