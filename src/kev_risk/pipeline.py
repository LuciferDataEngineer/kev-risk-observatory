"""Transactional snapshot ETL with raw provenance and slowly changing history.

The inputs are public intelligence, not an inventory of an organization's assets.
EPSS is a probability estimate; membership in KEV is evidence of exploitation.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import shutil
import sqlite3
import time
import urllib.error
import urllib.request
import uuid
from datetime import date, datetime, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_SOURCE_BYTES = 50 * 1024 * 1024
MAX_EPSS_ROWS = 2_000_000
SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT,
    as_of TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('running','success','failed')),
    error TEXT, catalog_version TEXT, catalog_released TEXT, epss_score_date TEXT,
    kev_rows INTEGER, epss_matches INTEGER
);
CREATE TABLE IF NOT EXISTS source_artifacts (
    run_id TEXT NOT NULL REFERENCES pipeline_runs(run_id),
    source_name TEXT NOT NULL, source_url TEXT NOT NULL, raw_path TEXT NOT NULL,
    sha256 TEXT NOT NULL, byte_size INTEGER NOT NULL, retrieved_at TEXT NOT NULL,
    PRIMARY KEY(run_id, source_name)
);
CREATE TABLE IF NOT EXISTS kev_current (
    cve_id TEXT PRIMARY KEY, vendor TEXT NOT NULL, product TEXT NOT NULL,
    vulnerability_name TEXT NOT NULL, date_added TEXT NOT NULL,
    description TEXT NOT NULL, required_action TEXT NOT NULL, due_date TEXT NOT NULL,
    ransomware_use TEXT NOT NULL, notes TEXT NOT NULL, extra_json TEXT NOT NULL,
    row_hash TEXT NOT NULL, is_active INTEGER NOT NULL CHECK(is_active IN (0,1)),
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    last_changed_run TEXT NOT NULL REFERENCES pipeline_runs(run_id)
);
CREATE TABLE IF NOT EXISTS kev_history (
    history_id INTEGER PRIMARY KEY, cve_id TEXT NOT NULL REFERENCES kev_current(cve_id),
    revision INTEGER NOT NULL, valid_from TEXT NOT NULL, valid_to TEXT,
    is_active INTEGER NOT NULL CHECK(is_active IN (0,1)), row_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES pipeline_runs(run_id),
    UNIQUE(cve_id, revision)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_history_open ON kev_history(cve_id) WHERE valid_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_kev_vendor_active ON kev_current(vendor, is_active);
CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_current(date_added);
CREATE TABLE IF NOT EXISTS epss_daily (
    cve_id TEXT NOT NULL REFERENCES kev_current(cve_id), score_date TEXT NOT NULL,
    epss REAL NOT NULL CHECK(epss BETWEEN 0 AND 1),
    percentile REAL NOT NULL CHECK(percentile BETWEEN 0 AND 1),
    model_version TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES pipeline_runs(run_id),
    PRIMARY KEY(cve_id, score_date)
);
CREATE INDEX IF NOT EXISTS idx_epss_score_date ON epss_daily(score_date);
CREATE TABLE IF NOT EXISTS epss_snapshot_members (
    run_id TEXT NOT NULL REFERENCES pipeline_runs(run_id),
    cve_id TEXT NOT NULL REFERENCES kev_current(cve_id),
    PRIMARY KEY(run_id, cve_id)
);
CREATE TABLE IF NOT EXISTS warehouse_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), as_of TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES pipeline_runs(run_id), catalog_released TEXT NOT NULL
);
CREATE VIEW IF NOT EXISTS vulnerability_review AS
SELECT k.cve_id, k.vendor, k.product, k.vulnerability_name, k.date_added,
       k.description, k.required_action, k.due_date, k.ransomware_use,
       e.epss, e.percentile, e.score_date, e.model_version,
       CASE WHEN e.cve_id IS NULL THEN 'missing'
            WHEN julianday(s.as_of)-julianday(e.score_date)>2 THEN 'stale'
            ELSE 'current' END AS score_status,
       CASE WHEN k.ransomware_use='Known' THEN 'Known ransomware evidence'
            WHEN e.cve_id IS NULL THEN 'Review - missing EPSS'
            WHEN julianday(s.as_of)-julianday(e.score_date)>2 THEN 'Review - stale EPSS'
            WHEN e.epss>=0.5 THEN 'EPSS at least 50%'
            WHEN e.epss>=0.1 THEN 'EPSS 10% to under 50%'
            ELSE 'Other known exploited' END AS review_cohort,
       CAST(julianday(s.as_of)-julianday(k.date_added) AS INTEGER) AS days_since_added,
       MAX(0,CAST(julianday(s.as_of)-julianday(k.due_date) AS INTEGER)) AS days_past_due,
       s.as_of
FROM kev_current k CROSS JOIN warehouse_state s
JOIN pipeline_runs r ON r.run_id=s.run_id
LEFT JOIN epss_daily e ON e.cve_id=k.cve_id AND e.score_date=r.epss_score_date
    AND e.score_date<=s.as_of AND EXISTS (
        SELECT 1 FROM epss_snapshot_members m WHERE m.run_id=s.run_id AND m.cve_id=k.cve_id
    )
WHERE k.is_active=1;
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _date(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {label}: {value!r}") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"{label} must use YYYY-MM-DD")
    return value


def _cve(value: str) -> bool:
    import re
    return isinstance(value, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", value) is not None


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, SCHEMA_VERSION):
        conn.close()
        raise RuntimeError(f"Unsupported schema version {version}; expected {SCHEMA_VERSION}")
    if version == 0:
        conn.executescript(SCHEMA)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        conn.commit()
    return conn


def _copy_or_download(local_file: str | Path | None, url: str, destination: Path) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if local_file is not None:
        source = Path(local_file).resolve()
        if source.stat().st_size > MAX_SOURCE_BYTES:
            raise ValueError(f"Source exceeds {MAX_SOURCE_BYTES} bytes")
        shutil.copyfile(source, destination)
        location = source.as_uri()
    else:
        location = url
        request = urllib.request.Request(url, headers={"User-Agent": "VulnSignal/1.0 public-data-etl"})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=45) as response, destination.open("wb") as output:
                    received = 0
                    while chunk := response.read(1024 * 1024):
                        received += len(chunk)
                        if received > MAX_SOURCE_BYTES:
                            raise ValueError(f"Source exceeds {MAX_SOURCE_BYTES} bytes")
                        output.write(chunk)
                break
            except urllib.error.HTTPError as exc:
                if attempt == 2 or (exc.code != 429 and exc.code < 500):
                    raise RuntimeError(f"Source download failed with HTTP {exc.code}: {url}") from exc
                time.sleep(2 ** attempt)
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt == 2:
                    raise RuntimeError(f"Source download failed: {url}: {exc}") from exc
                time.sleep(2 ** attempt)
    digest = hashlib.sha256()
    with destination.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"source_url": location, "raw_path": str(destination.resolve()),
            "sha256": digest.hexdigest(), "byte_size": destination.stat().st_size,
            "retrieved_at": _now()}


def _parse_kev(path: Path, as_of: str) -> tuple[dict, dict[str, dict]]:
    with path.open(encoding="utf-8-sig") as stream:
        catalog = json.load(stream)
    if not isinstance(catalog, dict):
        raise ValueError("KEV catalog must be a JSON object")
    rows = catalog.get("vulnerabilities")
    if not isinstance(rows, list) or not rows:
        raise ValueError("KEV catalog must contain a nonempty vulnerabilities list")
    if type(catalog.get("count")) is not int or catalog["count"] != len(rows):
        raise ValueError("KEV declared count does not match its complete snapshot")
    if not isinstance(catalog.get("catalogVersion"), str) or not catalog["catalogVersion"]:
        raise ValueError("Missing KEV catalogVersion")
    released = catalog.get("dateReleased")
    if not isinstance(released, str):
        raise ValueError("Missing KEV dateReleased")
    try:
        parsed_release = datetime.fromisoformat(released.replace("Z", "+00:00"))
        if parsed_release.tzinfo is None:
            raise ValueError("KEV dateReleased needs a timezone")
    except ValueError as exc:
        raise ValueError("KEV dateReleased must be an ISO timestamp with timezone") from exc
    catalog["dateReleased"] = parsed_release.astimezone(timezone.utc).isoformat()
    if parsed_release.astimezone(timezone.utc).date().isoformat() > as_of:
        raise ValueError("KEV catalog was released after --as-of; use a historical snapshot")
    field_map = {"vendorProject": "vendor", "product": "product", "vulnerabilityName": "vulnerability_name",
                 "dateAdded": "date_added", "shortDescription": "description", "requiredAction": "required_action",
                 "dueDate": "due_date", "knownRansomwareCampaignUse": "ransomware_use"}
    result = {}
    for raw in rows:
        if not isinstance(raw, dict) or not _cve(raw.get("cveID")):
            raise ValueError("Invalid or missing CISA cveID")
        cve = raw["cveID"]
        if cve in result:
            raise ValueError(f"Duplicate KEV CVE: {cve}")
        row = {"cve_id": cve}
        for source_key, target_key in field_map.items():
            if not isinstance(raw.get(source_key), str) or not raw[source_key].strip():
                raise ValueError(f"Missing or invalid {source_key} for {cve}")
            row[target_key] = raw[source_key]
        _date(row["date_added"], f"{cve} dateAdded")
        _date(row["due_date"], f"{cve} dueDate")
        if row["date_added"] > as_of:
            raise ValueError(f"{cve} dateAdded is after --as-of")
        if row["ransomware_use"] not in ("Known", "Unknown"):
            raise ValueError(f"Unexpected ransomware classification for {cve}")
        row["notes"] = raw.get("notes", "")
        if not isinstance(row["notes"], str):
            raise ValueError(f"Invalid notes for {cve}")
        row["extra_json"] = _canonical({k: v for k, v in raw.items() if k not in {*field_map, "cveID", "notes"}})
        row["row_hash"] = hashlib.sha256(_canonical(row).encode()).hexdigest()
        result[cve] = row
    return catalog, result


def _parse_epss(path: Path, wanted: set[str], as_of: str) -> tuple[str, str, dict[str, tuple], int]:
    with path.open("rb") as probe:
        compressed = probe.read(2) == b"\x1f\x8b"
    opener = gzip.open if compressed else open
    with opener(path, "rt", encoding="utf-8-sig", newline="") as stream:
        first_line = stream.readline(65536)
        if not first_line.startswith("#"):
            raise ValueError("EPSS input needs its #model_version/score_date metadata header")
        metadata = dict(item.split(":", 1) for item in first_line.strip().lstrip("#").split(",") if ":" in item)
        model_version = metadata.get("model_version", "").strip()
        score_timestamp = metadata.get("score_date", "").strip()
        score_date = _date(score_timestamp[:10], "EPSS score_date")
        if len(score_timestamp) > 10:
            try:
                score_instant = datetime.fromisoformat(score_timestamp.replace("Z", "+00:00"))
                if score_instant.tzinfo is None:
                    raise ValueError("timestamp needs a timezone")
            except ValueError as exc:
                raise ValueError("EPSS score_date must be an ISO date or timestamp with timezone") from exc
            score_date = score_instant.astimezone(timezone.utc).date().isoformat()
        if not model_version:
            raise ValueError("Missing EPSS model_version")
        if score_date > as_of:
            raise ValueError("EPSS score_date is after --as-of; use a historical snapshot")
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or not {"cve", "epss", "percentile"}.issubset(reader.fieldnames):
            raise ValueError("EPSS requires cve, epss and percentile columns")
        result = {}
        total = 0
        for total, row in enumerate(reader, start=1):
            if total > MAX_EPSS_ROWS:
                raise ValueError("EPSS exceeds the bounded row limit")
            cve = row.get("cve")
            if not _cve(cve):
                raise ValueError(f"Invalid EPSS CVE at row {total}")
            # Validate the entire source, even though only KEV scores enter the warehouse.
            try:
                epss, percentile = float(row["epss"]), float(row["percentile"])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid EPSS numeric value for {cve}") from exc
            if not all(math.isfinite(x) and 0 <= x <= 1 for x in (epss, percentile)):
                raise ValueError(f"EPSS probability/percentile outside [0,1] for {cve}")
            if cve in wanted:
                if cve in result:
                    raise ValueError(f"Duplicate EPSS CVE: {cve}")
                result[cve] = (epss, percentile)
        if total == 0:
            raise ValueError("EPSS input contains no data rows")
    return score_date, model_version, result, total


def _revision(conn: sqlite3.Connection, row: dict, active: int, run_id: str, at: str) -> None:
    cve = row["cve_id"]
    latest = conn.execute("SELECT COALESCE(MAX(revision),0) FROM kev_history WHERE cve_id=?", (cve,)).fetchone()[0]
    conn.execute("UPDATE kev_history SET valid_to=? WHERE cve_id=? AND valid_to IS NULL", (at, cve))
    payload = {k: v for k, v in row.items() if k not in ("first_seen", "last_seen", "last_changed_run", "is_active")}
    conn.execute("""INSERT INTO kev_history(cve_id,revision,valid_from,is_active,row_hash,payload_json,run_id)
                    VALUES(?,?,?,?,?,?,?)""", (cve, latest+1, at, active, row["row_hash"], _canonical(payload), run_id))


def _load(conn: sqlite3.Connection, catalog: dict, rows: dict[str, dict], score_date: str,
          model: str, scores: dict, run_id: str, as_of: str) -> None:
    previous = conn.execute("SELECT * FROM warehouse_state WHERE singleton=1").fetchone()
    if previous and (catalog["dateReleased"] < previous["catalog_released"] or as_of < previous["as_of"]):
        raise ValueError("Refusing an older KEV snapshot or analysis date; replay into a separate data directory")
    at = _now()
    for cve, row in rows.items():
        old = conn.execute("SELECT * FROM kev_current WHERE cve_id=?", (cve,)).fetchone()
        changed = old is None or old["row_hash"] != row["row_hash"] or not old["is_active"]
        if old is None:
            columns = list(row) + ["is_active", "first_seen", "last_seen", "last_changed_run"]
            values = list(row.values()) + [1, as_of, as_of, run_id]
            conn.execute(f"INSERT INTO kev_current ({','.join(columns)}) VALUES ({','.join('?' for _ in values)})", values)
        elif changed:
            updates = {**row, "is_active": 1, "last_seen": as_of, "last_changed_run": run_id}
            conn.execute(f"UPDATE kev_current SET {','.join(k+'=?' for k in updates)} WHERE cve_id=?", [*updates.values(), cve])
        else:
            conn.execute("UPDATE kev_current SET last_seen=? WHERE cve_id=?", (as_of, cve))
        if changed:
            _revision(conn, row, 1, run_id, at)
    active = conn.execute("SELECT * FROM kev_current WHERE is_active=1").fetchall()
    for old in active:
        if old["cve_id"] not in rows:
            conn.execute("UPDATE kev_current SET is_active=0,last_changed_run=? WHERE cve_id=?", (run_id, old["cve_id"]))
            _revision(conn, dict(old), 0, run_id, at)
    for cve, (epss, percentile) in scores.items():
        conn.execute("INSERT INTO epss_snapshot_members VALUES(?,?)", (run_id, cve))
        # A corrected same-day upstream score replaces its daily fact; raw snapshots retain both inputs.
        conn.execute("""INSERT INTO epss_daily VALUES(?,?,?,?,?,?)
            ON CONFLICT(cve_id,score_date) DO UPDATE SET epss=excluded.epss,
            percentile=excluded.percentile,model_version=excluded.model_version,run_id=excluded.run_id
            WHERE epss_daily.epss<>excluded.epss OR epss_daily.percentile<>excluded.percentile
               OR epss_daily.model_version<>excluded.model_version""", (cve, score_date, epss, percentile, model, run_id))
    conn.execute("""INSERT INTO warehouse_state VALUES(1,?,?,?) ON CONFLICT(singleton) DO UPDATE SET
                    as_of=excluded.as_of,run_id=excluded.run_id,catalog_released=excluded.catalog_released""",
                 (as_of, run_id, catalog["dateReleased"]))


def _summary(conn: sqlite3.Connection, run_id: str, source_rows: int) -> dict:
    run = dict(conn.execute("SELECT * FROM pipeline_runs WHERE run_id=?", (run_id,)).fetchone())
    counts = conn.execute("""SELECT COUNT(*) AS active_kev,
        SUM(CASE WHEN score_status='current' THEN 1 ELSE 0 END) AS current_scores,
        SUM(CASE WHEN score_status='stale' THEN 1 ELSE 0 END) AS stale_scores,
        SUM(CASE WHEN score_status='missing' THEN 1 ELSE 0 END) AS missing_scores,
        SUM(CASE WHEN ransomware_use='Known' THEN 1 ELSE 0 END) AS known_ransomware
        FROM vulnerability_review""").fetchone()
    return {"run_id": run_id, "status": run["status"], "as_of": run["as_of"],
            "catalog_version": run["catalog_version"], "catalog_released": run["catalog_released"],
            "epss_score_date": run["epss_score_date"], "epss_source_rows": source_rows,
            **dict(counts), "epss_matches_in_snapshot": run["epss_matches"],
            "review_cohorts": {r[0]: r[1] for r in conn.execute("SELECT review_cohort,COUNT(*) FROM vulnerability_review GROUP BY 1 ORDER BY 1")},
            "caveats": ["Review cohorts are descriptive enrichment, not patch priorities or an asset-specific risk assessment.",
                        "KEV is known exploitation evidence; a low or missing EPSS score does not negate it.",
                        "CISA due dates are source dates for relevant directives, not universal organizational deadlines."]}


def _export(conn: sqlite3.Connection, directory: Path, summary: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    cursor = conn.execute("SELECT * FROM vulnerability_review ORDER BY review_cohort,epss DESC,cve_id")
    temp_csv = directory / f".review-queue-{summary['run_id']}.tmp"
    with temp_csv.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow([column[0] for column in cursor.description])
        for row in cursor:
            # Neutralize spreadsheet formula prefixes in upstream text exports.
            writer.writerow(["'"+v if isinstance(v, str) and v.lstrip().startswith(("=", "+", "-", "@")) else v for v in row])
    temp_csv.replace(directory / "review_queue.csv")
    temp_json = directory / f".summary-{summary['run_id']}.tmp"
    temp_json.write_text(json.dumps(summary, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    temp_json.replace(directory / "summary.json")


def run_pipeline(data_dir: str | Path, *, as_of: str | date | None = None,
                 kev_file: str | Path | None = None, epss_file: str | Path | None = None) -> dict:
    """Load one validated snapshot; failed runs retain raw evidence and an audit record.

    Logical data mutations commit in one SQLite transaction. Exports are derived
    after commit and can always be regenerated by rerunning the same snapshot.
    """
    day = as_of.isoformat() if isinstance(as_of, date) else as_of
    day = _date(day or datetime.now(timezone.utc).date().isoformat(), "as_of")
    root = Path(data_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    conn = _connect(root / "warehouse.sqlite")
    run_id = uuid.uuid4().hex
    loaded = False
    try:
        conn.execute("INSERT INTO pipeline_runs(run_id,started_at,as_of,status) VALUES(?,?,?,'running')", (run_id, _now(), day))
        conn.commit()
        raw_dir = root / "raw" / run_id
        sources = []
        for name, local, url, filename in (("cisa_kev", kev_file, KEV_URL, "kev.json"),
                                           ("first_epss", epss_file, EPSS_URL, "epss.csv.gz")):
            artifact = _copy_or_download(local, url, raw_dir / filename)
            conn.execute("INSERT INTO source_artifacts VALUES(?,?,?,?,?,?,?)",
                         (run_id, name, artifact["source_url"], artifact["raw_path"], artifact["sha256"], artifact["byte_size"], artifact["retrieved_at"]))
            conn.commit()
            sources.append(artifact)
        catalog, rows = _parse_kev(raw_dir / "kev.json", day)
        score_date, model, scores, source_rows = _parse_epss(raw_dir / "epss.csv.gz", set(rows), day)
        with conn:
            _load(conn, catalog, rows, score_date, model, scores, run_id, day)
            conn.execute("""UPDATE pipeline_runs SET status='success',finished_at=?,catalog_version=?,catalog_released=?,
                            epss_score_date=?,kev_rows=?,epss_matches=? WHERE run_id=?""",
                         (_now(), catalog["catalogVersion"], catalog["dateReleased"], score_date, len(rows), len(scores), run_id))
        loaded = True
        summary = _summary(conn, run_id, source_rows)
        summary["sources"] = [{"name": name, "sha256": artifact["sha256"], "bytes": artifact["byte_size"]}
                              for name, artifact in zip(("cisa_kev", "first_epss"), sources)]
        _export(conn, root / "exports", summary)
        return summary
    except Exception as exc:
        conn.rollback()
        if loaded:
            # The committed warehouse remains correct; make export failure explicit.
            conn.execute("UPDATE pipeline_runs SET error=? WHERE run_id=?", (f"Load succeeded; derived export failed: {exc}"[:2000], run_id))
        else:
            conn.execute("UPDATE pipeline_runs SET status='failed',finished_at=?,error=? WHERE run_id=?", (_now(), str(exc)[:2000], run_id))
        conn.commit()
        raise
    finally:
        conn.close()
