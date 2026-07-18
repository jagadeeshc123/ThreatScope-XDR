# STIX 2.1 and TAXII 2.1

STIX accepts JSON bundles up to 5 MiB and 5,000 objects. Preview validates IDs, types, duplicates, and bounds; unsafe objects remain quarantine metadata and no referenced URL is fetched. Promotion uses existing Threat Intelligence normalization and attribution.

TAXII uses an exact HTTPS API root/collection, shared SSRF/TLS policy, bounded pages/objects/response, and an added_after cursor. Cursor state changes only after successful persistence. Tests inject mocked transport; no uncontrolled network is used.
