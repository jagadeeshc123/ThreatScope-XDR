# Analyst feedback

Feedback labels are server-owned: confirmed or likely true positive, uncertain, benign expected behavior, false positive, duplicate, and insufficient context. Each record includes confidence and a reason.

Feedback is append-only and revisioned. A later assessment creates another revision; it does not rewrite the historical analyst record. Evaluation aggregates only reviewed labels and exposes sample counts and limitations alongside any quality estimate.

Feedback informs review and future explicit detector versions. It does not automatically retrain a detector, close a case, change source evidence, suppress an entity, punish a user, or execute containment.
