# Executed validation

Validated on **29 October 2026** with **Python 3.14.7** and **SQLite 3.53.4** on the development machine. The analytical reference date was `2026-10-29`. [Machine-readable evidence](examples/validation.json) accompanies these results.

## Offline acceptance tests

```bash
PYTHONPATH=src python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

**Result: 26 tests passed.** Fixtures are explicitly fictional. Tests exercise full ingestion, idempotency, catalog revisions, removal/reactivation, source-extension preservation, missing/stale enrichment, changed score days, and gzip input.

Failure cases cover duplicate matched identifiers, incomplete/empty catalogs, missing required fields, invalid dates, future sources, older catalog regression, invalid/nonfinite score values, and missing source-date metadata. A fault injected during database loading verifies that partial catalog/history writes roll back. An injected export failure verifies the committed warehouse remains usable, an error is recorded, and replay regenerates exports. Latest-snapshot omission tests verify that previously stored scores never silently replace missing enrichment.

Source checksum and SQLite integrity/foreign-key checks are also exercised. Resource warnings were treated as errors.

## Live-source smoke run

```bash
PYTHONPATH=src python3 -m kev_risk run --data-dir data --as-of 2026-10-29
```

| Observation | Result |
|---|---|
| Run status | Success |
| CISA catalog version | `2026.10.28` |
| CISA publication timestamp | `2026-10-28T19:00:04.807700+00:00` |
| Active KEV records | 1,762 |
| EPSS score date | `2026-10-28` |
| EPSS input records parsed | 396,966 |
| KEV records matched | 1,762 |
| Missing / stale scores | 0 / 0 |
| Known ransomware association | 361 catalog records |

See [the live summary](examples/live-summary-2026-10-29.json) and [source URLs, retrieval timestamps, and hashes](examples/live-source-manifest-2026-10-29.json). These counts describe the retrieved public snapshots; they do not establish company exposure or patch backlog.

## Identical-source replay

The saved live inputs were replayed with the same analytical date. Full ordered contents of `kev_current`, `kev_history`, and `epss_daily` were compared before and after: **identical**. Each table retained 1,762 rows. New run-audit, artifact, and snapshot-membership records were expected and preserved. `PRAGMA integrity_check` returned `ok`; `PRAGMA foreign_key_check` returned no violations.

All six queries in [sql/analysis.sql](sql/analysis.sql) executed against that warehouse. [Recorded outputs](examples/sql-results-2026-10-29.json) include zero revision/change rows where only an identical snapshot was replayed, rather than inventing history.

## Installation and reproducibility

Created a clean virtual environment, installed the package from this repository with `pip install .`, and executed the offline CLI successfully. No third-party runtime dependencies were installed. The package build uses setuptools.

The synthetic example returns three active KEV-like rows, two matching scores, and one missing score. See [synthetic summary](examples/synthetic-summary.json) and [synthetic review extract](examples/synthetic-review-queue.csv). Names and descriptions in that extract are fictional.

## CI and boundaries

The [GitHub Actions workflow](.github/workflows/ci.yml) installs the package, runs the acceptance tests, and executes the offline CLI on Python 3.11 and 3.14. Its live status is shown by the README badge and repository Actions page; local results alone do not establish remote CI success.

No production deployment, concurrent-writer load test, performance benchmark, automatic scheduler for this pipeline, or third-party BI integration is claimed. A successful feed retrieval today does not guarantee future source availability. The implementation and operational limits are described in [DATA_MODEL.md](docs/DATA_MODEL.md) and [OPERATIONS.md](docs/OPERATIONS.md).
