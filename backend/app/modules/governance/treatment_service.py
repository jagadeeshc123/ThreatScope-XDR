"""Treatment workflow rules. Treatment plans never execute technical actions."""

WORKFLOW_DISCLAIMER = "Treatment records are workflow plans only and do not execute technical remediation."


def preserves_actual_residual(before, risk):
    return risk.residual_score == before
