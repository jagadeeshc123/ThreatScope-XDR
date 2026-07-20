# Feature engineering

The 42 feature definitions identify source ownership, data type, aggregation, units, missing-data behavior, privacy classification, approved windows and methods, peer eligibility, and seasonality support. Extraction reads only bounded stored records and emits finite aggregate values; it never fetches a URL or invokes external code.

Supported deterministic transformations include counts, rates, ratios, percentiles, medians, MAD, IQR, EWMA, rate of change, and consecutive failures. NaN, infinity, negative values where prohibited, unreasonable cardinality, oversized scope, and unsafe identifiers fail closed. Feature and input hashes make repeated computation explainable and comparable.

Peer groups use server-approved keys and minimum group sizes. Individual peer identities are not disclosed. Raw email bodies, document text, credentials, tokens, connector payloads, and personal profiles are excluded from analytics output.
