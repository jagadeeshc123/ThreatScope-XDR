# SOC Monitor Manual Smoke Checklist

- [ ] Open `/soc` with empty SOC tables and confirm all metrics are zero/empty.
- [ ] Create a simulator source and generate `mixed_demo` with seed `42`; confirm the safety disclaimer and reserved documentation IPs.
- [ ] Confirm generation does not automatically run detections.
- [ ] Run enabled rules twice and confirm the second run does not duplicate alerts or high/critical notifications.
- [ ] Open a brute-force alert and verify its timeline, correlated events, rule, notes, and status actions.
- [ ] Run local mock enrichment and confirm it is clearly labelled as non-live demonstration intelligence.
- [ ] Add the alert IP to the simulated blocklist and confirm the page states that no real firewall changes occur.
- [ ] Import `backend/tests/fixtures/soc_monitor/nested-secrets.jsonl` and confirm secrets are `[REDACTED]` in event details and search.
- [ ] Generate, view, refresh, and download a SOC HTML report; confirm all 15 sections and disclaimers.
- [ ] Refresh `/soc`, `/soc/sources`, `/soc/imports`, `/soc/events`, an event detail, `/soc/rules`, `/soc/alerts`, an alert detail, `/soc/simulator`, `/soc/blocklist`, `/soc/reports`, and a report detail directly.
- [ ] Confirm main dashboard SOC metrics, global SOC search links, bell notifications, and SOC activity use backend data.
- [ ] Confirm Web Exposure and API Security pages continue to load and operate.
