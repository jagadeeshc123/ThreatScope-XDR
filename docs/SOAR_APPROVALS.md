# SOAR-Lite approvals and analyst input

Approvals cover execution, step, sensitive action, containment simulation, and rollback. A request stores a bounded reason/context, server-calculated permission, optional user/role assignment, minimum approval count, separation flag, and expiration. Decisions are immutable and unique per user. Eligibility, active/unlocked account state, permission, assignment, separation, and expiry are rechecked when deciding—not trusted from stale UI state.

Multi-person requests remain partially approved until the exact minimum is reached. A rejection is terminal for that approval and follows the safe failure outcome. Duplicate decisions, reused/rejected/expired approvals, IDOR, and simultaneous duplicate resume are rejected. Sensitive action and rollback self-approval is denied when another eligible Administrator is available. Approval context never exposes credentials, session hashes/tokens, MFA material, or raw evidence.

Analyst-input steps accept at most 20 server-described fields of short text, long text, select, multi-select, boolean, integer, date, or datetime. Password, secret, token, file, HTML, Markdown HTML, JavaScript, and executable schemas are prohibited. Only the assigned user or eligible review role may submit once before expiry. The validated response maps into execution output and resumes once. Cancellation and expiration preserve request history.

Permissions are `soar:view`, `soar:manage`, `soar:execute`, `soar:approve`, `soar:review`, `soar:rollback`, `soar:export`, `soar:sensitive_actions`, and `soar:action_policy_manage`. Administrators have all. Security Analysts view/manage/execute/review/export. Auditors view/export. Executive Viewers receive dashboard aggregates only. Registered Users have no SOAR permission. Custom roles remain supported by the established role editor.

