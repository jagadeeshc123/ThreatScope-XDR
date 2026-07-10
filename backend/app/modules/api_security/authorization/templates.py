MANUAL_VALIDATION_CHECKLIST = [
    "Confirm the expected role with the API owner.",
    "Compare documented access expectations across roles.",
    "Verify object ownership and tenant-isolation requirements.",
    "Inspect whether sensitive fields are readable or writable for this role.",
    "Record evidence from an authorized test environment; no runtime validation was performed here.",
    "Mark the review accepted, rejected, or needs testing.",
]

OBJECT_LEVEL_CHECKLIST = [
    "Confirm which actor may access each object identifier.",
    "Document own, assigned, tenant, organization, or global scope.",
    "Verify tenant isolation expectations with the API owner.",
] + MANUAL_VALIDATION_CHECKLIST[-2:]

FUNCTION_LEVEL_CHECKLIST = [
    "Confirm the minimum role required for this operation.",
    "Compare the expected decision for ordinary and privileged roles.",
    "Review destructive and administrative actions in an authorized test environment.",
] + MANUAL_VALIDATION_CHECKLIST[-2:]

PROPERTY_LEVEL_CHECKLIST = [
    "Confirm whether each sensitive property is readable, writable, or server-managed.",
    "Review mass-assignment protections with the API owner.",
    "Compare documented property exposure across roles.",
] + MANUAL_VALIDATION_CHECKLIST[-2:]
