# Operations and recovery

## Run and inspect

Run `make demo` for a reproducible offline example, `make test` for tests, or `make live` for current public feeds. The live command uses UTC for its default analytical date. Supply `--as-of` explicitly when a business process uses a different calendar date. One execution should run at a time for each data directory.

Each invocation creates:

- `raw/<run_id>/kev.json` and `raw/<run_id>/epss.csv.gz` — retained source bytes. Replayed uncompressed EPSS files keep their original bytes despite this conventional filename; format detection checks gzip magic bytes.
- `warehouse.sqlite` — relational data and execution history.
- `exports/review_queue.csv` — active KEV records enriched with the selected EPSS snapshot.
- `exports/summary.json` — source identifiers, checksums, counts, and caveats.

Downloads use a 45-second socket timeout and up to three attempts for transient network errors, HTTP 429, and server errors, with bounded backoff. Each source is limited to 50 MiB; EPSS parsing is bounded at two million rows. These are guardrails, not an SLA or a total wall-clock deadline. Long individual text rows and decompressed byte volume are not independently bounded; operate against the documented trusted publishers.

No API keys, paid services, or additional databases are needed. CI validates offline behavior; it does not automatically refresh or commit live data.

## Quality gates

The loader rejects malformed or incomplete catalogs, duplicate KEV IDs, missing required fields, invalid dates, future-dated source snapshots relative to `as_of`, invalid score metadata, nonfinite/out-of-range scores, and duplicate matched EPSS IDs. Unknown optional KEV attributes survive in `extra_json` and raw evidence.

Review `score_status` coverage and the catalog count after a live refresh. A valid source can still change unexpectedly. This implementation does not automatically quarantine a self-consistent but unusually small catalog, set an incident alert, or infer whether an upstream publisher made a mistake.

## Failure handling

1. The command returns a nonzero exit status. Read its error, then inspect the latest `pipeline_runs` record if a database was initialized.
2. If download/validation/loading failed, the previously committed business state remains authoritative. The failed attempt and retained source metadata remain for investigation.
3. Fix the source or local condition and rerun. Do not delete the warehouse to clear a routine failure.
4. If the error says the load succeeded but a derived export failed, the database is already committed. Resolve the filesystem problem, then replay the same sources to regenerate exports. A database success status alone is insufficient; also check `error` and the command exit status.
5. A process terminated abruptly may leave an audit record at `running` and partial raw files. Check whether a writer is still active before investigating or retrying. There is no automatic abandoned-run reconciliation.

Use an offline replay when investigating:

```bash
PYTHONPATH=src python3 -m kev_risk run \
  --data-dir replay-data \
  --as-of 2026-10-29 \
  --kev-file data/raw/RUN_ID/kev.json \
  --epss-file data/raw/RUN_ID/epss.csv.gz
```

Replace `RUN_ID` with a real retained run identifier. Keep replay directories outside Git or add them to your local exclusions. A fresh directory avoids reversing the current warehouse's catalog history. Replaying yesterday's data with today's analytical date changes age-based fields; it is not an exact dated reproduction.

## Back up safely

Keep source snapshots and the database together. For a live SQLite database, use the SQLite backup API rather than copying only the main file while a writer is active:

```python
import sqlite3
from contextlib import closing

with closing(sqlite3.connect("data/warehouse.sqlite")) as source:
    with closing(sqlite3.connect("warehouse-backup.sqlite")) as destination:
        source.backup(destination)
```

Backups and local paths must not be committed to the public repository. The loader appends audit/source evidence on every execution; an explicit retention policy is a future operational decision. No automatic deletion is performed.

## Extend deliberately

| Requirement | Next design change |
|---|---|
| Multiple workers or users | PostgreSQL, explicit roles, and a run-level concurrency lock |
| Large raw history | Versioned object storage and a documented retention policy |
| Scheduled refresh with alerting | An orchestrator with retries, freshness alerts, and failure routing |
| Asset-specific remediation | Authorized inventory/exposure joins and reviewed business rules |
| Reconstruct every EPSS correction | Append-only score revision table with both source and observation time |
| BI consumption | A separately deployed dashboard using reviewed metrics and source-date labels |
| Evolving warehouse schema | Versioned migrations with backup and rollback rehearsal |

These are proposed extensions. They have not been deployed or benchmarked by this project.
