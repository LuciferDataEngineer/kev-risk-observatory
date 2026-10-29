"""Offline acceptance tests against synthetic fixtures; no network is required."""
from __future__ import annotations

import copy
from contextlib import closing
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kev_risk import pipeline
from kev_risk.pipeline import run_pipeline

FIXTURES = Path(__file__).parent / "fixtures"
CVE1 = "CVE-2026-900001"
CVE2 = "CVE-2026-900002"
CVE3 = "CVE-2026-900003"


class PipelineAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.data_dir = self.work / "data"
        self.catalog = json.loads((FIXTURES / "kev.json").read_text())
        self.scores = (FIXTURES / "epss.csv").read_text()
        self.kev_file = self.work / "kev.json"
        self.epss_file = self.work / "epss.csv"
        self.write_inputs()

    def write_inputs(self):
        self.kev_file.write_text(json.dumps(self.catalog), encoding="utf-8")
        self.epss_file.write_text(self.scores, encoding="utf-8")

    def run_etl(self, *, as_of="2026-10-29", epss_file=None):
        self.write_inputs()
        return run_pipeline(
            self.data_dir,
            as_of=as_of,
            kev_file=self.kev_file,
            epss_file=epss_file or self.epss_file,
        )

    def rows(self, statement, parameters=()):
        with closing(sqlite3.connect(self.data_dir / "warehouse.sqlite")) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(statement, parameters)]

    def scalar(self, statement, parameters=()):
        with closing(sqlite3.connect(self.data_dir / "warehouse.sqlite")) as connection:
            return connection.execute(statement, parameters).fetchone()[0]

    def test_complete_load_filters_scores_and_keeps_missing_as_null(self):
        summary = self.run_etl()
        self.assertIsInstance(summary, dict)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_history"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM epss_daily"), 2)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM pipeline_runs WHERE status='success'"), 1)
        first = self.rows("SELECT * FROM vulnerability_review WHERE cve_id=?", (CVE1,))[0]
        self.assertAlmostEqual(first["epss"], 0.9)
        self.assertEqual(first["score_status"], "current")
        self.assertEqual(first["days_since_added"], 9)
        self.assertEqual(first["days_past_due"], 2)
        missing = self.rows("SELECT * FROM vulnerability_review WHERE cve_id=?", (CVE3,))[0]
        self.assertIsNone(missing["epss"])
        self.assertIsNone(missing["percentile"])
        self.assertEqual(missing["score_status"], "missing")

    def test_identical_replay_does_not_duplicate_business_rows(self):
        self.run_etl()
        original_hashes = self.rows("SELECT cve_id,row_hash FROM kev_current ORDER BY cve_id")
        self.run_etl()
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_history"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM epss_daily"), 2)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM pipeline_runs WHERE status='success'"), 2)
        self.assertEqual(original_hashes, self.rows("SELECT cve_id,row_hash FROM kev_current ORDER BY cve_id"))

    def test_changed_advisory_retains_prior_revision(self):
        self.run_etl()
        old_hash = self.scalar("SELECT row_hash FROM kev_current WHERE cve_id=?", (CVE1,))
        self.catalog["vulnerabilities"][0]["shortDescription"] = "Corrected fictional description."
        self.run_etl()
        new_hash = self.scalar("SELECT row_hash FROM kev_current WHERE cve_id=?", (CVE1,))
        self.assertNotEqual(old_hash, new_hash)
        history = self.rows("SELECT * FROM kev_history WHERE cve_id=? ORDER BY revision", (CVE1,))
        self.assertEqual(len(history), 2)
        self.assertEqual([row["revision"] for row in history], [1, 2])
        self.assertIsNotNone(history[0]["valid_to"])
        self.assertIsNone(history[1]["valid_to"])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_history"), 4)

    def test_removed_advisory_is_inactivated_and_can_be_reactivated(self):
        self.run_etl()
        original = copy.deepcopy(self.catalog)
        self.catalog["vulnerabilities"] = self.catalog["vulnerabilities"][1:]
        self.catalog["count"] = 2
        self.run_etl()
        self.assertEqual(self.scalar("SELECT is_active FROM kev_current WHERE cve_id=?", (CVE1,)), 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM vulnerability_review WHERE cve_id=?", (CVE1,)), 0)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM epss_daily WHERE cve_id=?", (CVE1,)), 1)
        self.catalog = original
        self.run_etl()
        self.assertEqual(self.scalar("SELECT is_active FROM kev_current WHERE cve_id=?", (CVE1,)), 1)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_history WHERE cve_id=?", (CVE1,)), 3)

    def test_schema_extensions_are_preserved(self):
        self.run_etl()
        extras = json.loads(self.scalar("SELECT extra_json FROM kev_current WHERE cve_id=?", (CVE1,)))
        self.assertEqual(extras["forensicTriage"], "Synthetic extra source field retained for schema drift.")
        self.assertEqual(extras["cwes"], ["CWE-20"])

    def test_stale_scores_are_visible_and_not_treated_as_current(self):
        self.run_etl(as_of="2026-11-01")
        rows = self.rows("SELECT score_status,epss FROM vulnerability_review WHERE cve_id=?", (CVE1,))
        self.assertEqual(rows[0]["score_status"], "stale")
        self.assertAlmostEqual(rows[0]["epss"], 0.9)

    def test_invalid_score_rolls_back_changed_advisory_and_audits_failure(self):
        self.run_etl()
        original = self.rows("SELECT cve_id,row_hash FROM kev_current ORDER BY cve_id")
        self.catalog["vulnerabilities"][0]["shortDescription"] = "This change must be rolled back."
        self.scores = self.scores.replace("0.90,0.95", "1.90,0.95")
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl()
        self.assertEqual(original, self.rows("SELECT cve_id,row_hash FROM kev_current ORDER BY cve_id"))
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_history"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM epss_daily"), 2)
        failures = self.rows("SELECT error FROM pipeline_runs WHERE status='failed'")
        self.assertEqual(len(failures), 1)
        self.assertTrue(failures[0]["error"])

    def test_mid_load_database_failure_rolls_back_every_business_row(self):
        original_revision = pipeline._revision
        revision_calls = 0

        def fail_during_second_revision(*args, **kwargs):
            nonlocal revision_calls
            revision_calls += 1
            if revision_calls == 2:
                raise sqlite3.IntegrityError("Injected failure after second current-row insertion")
            return original_revision(*args, **kwargs)

        with patch.object(pipeline, "_revision", side_effect=fail_during_second_revision):
            with self.assertRaises(sqlite3.IntegrityError):
                self.run_etl()
        self.assertEqual(revision_calls, 2)
        for table in ("kev_current", "kev_history", "epss_daily", "warehouse_state"):
            self.assertEqual(self.scalar(f"SELECT COUNT(*) FROM {table}"), 0, table)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM source_artifacts"), 2)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM pipeline_runs WHERE status='failed'"), 1)
        self.assertIn("Injected failure", self.scalar("SELECT error FROM pipeline_runs"))
        # Retrying the preserved input succeeds without any manual database repair.
        self.run_etl()
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_history"), 3)

    def test_derived_export_failure_preserves_committed_load_and_is_recoverable(self):
        with patch.object(pipeline, "_export", side_effect=OSError("Injected export failure")):
            with self.assertRaises(OSError):
                self.run_etl()
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current"), 3)
        completed = self.rows("SELECT status,error FROM pipeline_runs")[0]
        self.assertEqual(completed["status"], "success")
        self.assertIn("Load succeeded; derived export failed", completed["error"])
        self.assertFalse((self.data_dir / "exports" / "review_queue.csv").exists())
        self.run_etl()
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_history"), 3)
        self.assertTrue((self.data_dir / "exports" / "review_queue.csv").is_file())
        self.assertTrue((self.data_dir / "exports" / "summary.json").is_file())

    def test_invalid_probability_and_percentile_values_are_rejected(self):
        original = self.scores
        for probability, percentile in [("-0.1", "0.95"), ("1.1", "0.95"), ("nan", "0.95"), ("inf", "0.95"), ("0.9", "nan"), ("0.9", "1.1"), ("0.9", "-0.1")]:
            with self.subTest(epss=probability, percentile=percentile):
                self.scores = original.replace("0.90,0.95", f"{probability},{percentile}")
                with self.assertRaises((ValueError, RuntimeError)):
                    self.run_etl()
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current"), 0)

    def test_duplicate_kev_identifier_is_rejected(self):
        self.catalog["vulnerabilities"].append(copy.deepcopy(self.catalog["vulnerabilities"][0]))
        self.catalog["count"] = 4
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl()

    def test_duplicate_epss_identifier_is_rejected(self):
        self.scores += f"{CVE1},0.3,0.4\n"
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl()

    def test_incomplete_catalog_does_not_remove_existing_advisories(self):
        self.run_etl()
        self.catalog["vulnerabilities"] = self.catalog["vulnerabilities"][:1]
        # Declared count is intentionally left at three.
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl()
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current WHERE is_active=1"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_history"), 3)

    def test_empty_catalog_is_rejected_without_mass_inactivation(self):
        self.run_etl()
        self.catalog["vulnerabilities"] = []
        self.catalog["count"] = 0
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl()
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current WHERE is_active=1"), 3)

    def test_invalid_source_date_is_rejected(self):
        self.catalog["vulnerabilities"][0]["dateAdded"] = "2026-02-30"
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl()

    def test_missing_source_contract_field_is_rejected(self):
        del self.catalog["vulnerabilities"][0]["requiredAction"]
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl()

    def test_score_snapshot_requires_provenance_date(self):
        self.scores = "\n".join(self.scores.splitlines()[1:]) + "\n"
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl()

    def test_multiple_score_days_preserve_history(self):
        self.run_etl()
        self.scores = self.scores.replace("2026-10-28T12:03:13Z", "2026-10-29T12:03:13Z").replace("0.90,0.95", "0.80,0.94")
        self.run_etl()
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM epss_daily"), 4)
        self.assertAlmostEqual(self.scalar("SELECT epss FROM vulnerability_review WHERE cve_id=?", (CVE1,)), 0.8)
        self.assertAlmostEqual(self.scalar("SELECT epss FROM epss_daily WHERE cve_id=? AND score_date='2026-10-28'", (CVE1,)), 0.9)

    def test_compressed_bulk_file_is_supported(self):
        compressed = self.work / "epss.csv.gz"
        with gzip.open(compressed, "wt", encoding="utf-8") as output:
            output.write(self.scores)
        self.run_etl(epss_file=compressed)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM epss_daily"), 2)

    def test_latest_snapshot_omission_does_not_reuse_prior_day_score(self):
        self.run_etl()
        self.scores = self.scores.replace("2026-10-28T12:03:13Z", "2026-10-29T12:03:13Z")
        self.scores = self.scores.replace(f"{CVE1},0.90,0.95\n", "")
        self.run_etl()
        current = self.rows("SELECT epss,percentile,score_status FROM vulnerability_review WHERE cve_id=?", (CVE1,))[0]
        self.assertIsNone(current["epss"])
        self.assertIsNone(current["percentile"])
        self.assertEqual(current["score_status"], "missing")
        self.assertAlmostEqual(self.scalar("SELECT epss FROM epss_daily WHERE cve_id=? AND score_date='2026-10-28'", (CVE1,)), 0.9)

    def test_same_day_corrected_snapshot_can_remove_a_score(self):
        self.run_etl()
        self.scores = self.scores.replace(f"{CVE2},0.20,0.70\n", "")
        self.run_etl()
        current = self.rows("SELECT epss,score_status FROM vulnerability_review WHERE cve_id=?", (CVE2,))[0]
        self.assertIsNone(current["epss"])
        self.assertEqual(current["score_status"], "missing")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM epss_daily WHERE cve_id=?", (CVE2,)), 1)

    def test_raw_sources_are_retained_with_matching_checksums(self):
        self.run_etl()
        sources = self.rows("SELECT * FROM source_artifacts ORDER BY source_name")
        self.assertEqual(len(sources), 2)
        for source in sources:
            raw = Path(source["raw_path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), source["sha256"])
            self.assertEqual(len(raw), source["byte_size"])
        self.assertEqual(self.scalar("PRAGMA integrity_check"), "ok")
        self.assertEqual(self.rows("PRAGMA foreign_key_check"), [])

    def test_older_catalog_is_rejected_without_reversing_history(self):
        self.run_etl()
        self.catalog["dateReleased"] = "2026-10-27T19:00:00Z"
        self.catalog["vulnerabilities"] = self.catalog["vulnerabilities"][:1]
        self.catalog["count"] = 1
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl(as_of="2026-10-30")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current WHERE is_active=1"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_history"), 3)
        self.assertEqual(self.scalar("SELECT as_of FROM warehouse_state"), "2026-10-29")

    def test_future_score_is_rejected_without_advancing_warehouse(self):
        self.run_etl()
        self.scores = self.scores.replace("2026-10-28T12:03:13Z", "2026-10-31T12:03:13Z")
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl(as_of="2026-10-30")
        self.assertEqual(self.scalar("SELECT as_of FROM warehouse_state"), "2026-10-29")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM epss_daily"), 2)

    def test_future_catalog_is_rejected(self):
        self.catalog["dateReleased"] = "2026-10-31T19:00:00Z"
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_etl()

    def test_offline_cli_builds_warehouse_and_reports_success(self):
        environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        completed = subprocess.run(
            [sys.executable, "-m", "kev_risk", "run", "--data-dir", str(self.data_dir),
             "--as-of", "2026-10-29", "--kev-file", str(self.kev_file), "--epss-file", str(self.epss_file)],
            env=environment, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM kev_current"), 3)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM pipeline_runs WHERE status='success'"), 1)


if __name__ == "__main__":
    unittest.main()
