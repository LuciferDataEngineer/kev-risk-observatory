# Execution evidence

- `live-summary-2026-10-29.json` summarizes a real CISA/FIRST download and load.
- `live-source-manifest-2026-10-29.json` identifies its public endpoints, retrieval times, content hashes, and attribution.
- `sql-results-2026-10-29.json` records the six analytical queries after an identical-source replay. Query numbers match `sql/analysis.sql`.
- `validation.json` records observed test, replay, integrity, packaging, and SQL checks.
- `synthetic-summary.json` and `synthetic-review-queue.csv` come from deliberately fictional fixtures in `tests/fixtures/`; they demonstrate missing-score handling and are not real vulnerability intelligence.

Raw live source files and the local warehouse are retained locally but excluded from the repository. Re-fetching a current-download URL later may produce different data. The public execution evidence records what was observed; exact replay requires the saved raw inputs and the same analytical date.
