# Document Threat Analysis Manual Smoke Checklist

- [ ] Open `/document-threats` with no records and confirm all metrics are zero/empty.
- [ ] Upload a safe PDF and confirm SHA-256, page count, status, structure, and original-file non-retention notice.
- [ ] Upload inert JavaScript/OpenAction fixtures and confirm static-risk wording; no script executes.
- [ ] Upload an inert URI fixture and confirm sanitized copy-only text with no clickable external link.
- [ ] Upload an inert embedded-artifact fixture and confirm only metadata/hash appear with no download/run/launch action.
- [ ] Upload an encrypted fixture and confirm limited-analysis wording without a high-risk result from encryption alone.
- [ ] Generate, view, refresh, and download a report; confirm all 15 sections and static-analysis disclaimer.
- [ ] Test list filters, pagination, row navigation, and confirmed deletion of derived records.
- [ ] Confirm document dashboard metrics, global search results, notifications, and activity use backend data.
- [ ] Directly refresh every `/document-threats` route and confirm HTTP 200.
- [ ] Confirm Web Exposure, API Security, and SOC Monitor continue to operate.
