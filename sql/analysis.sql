-- SQLite queries. Run against a completed warehouse, for example:
-- sqlite3 -header -column data/warehouse.sqlite < sql/analysis.sql
-- This optional CLI is separate from Python's built-in sqlite3 module.

-- 1. Enrichment coverage: denominator is active KEV rows, not the full EPSS universe.
SELECT as_of, score_status, COUNT(*) AS cve_count,
       ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct_of_active_kev
FROM vulnerability_review
GROUP BY as_of, score_status
ORDER BY score_status;

-- 2. Descriptive cohorts, not a patch policy. All rows have known exploitation.
SELECT review_cohort, COUNT(*) AS cve_count
FROM vulnerability_review
GROUP BY review_cohort
ORDER BY cve_count DESC, review_cohort;

-- 3. Vendor concentration measures this catalog's coverage, not relative security.
WITH vendor_counts AS (
    SELECT vendor, COUNT(*) AS active_kev,
           SUM(CASE WHEN ransomware_use = 'Known' THEN 1 ELSE 0 END) AS ransomware_associated
    FROM vulnerability_review
    GROUP BY vendor
)
SELECT DENSE_RANK() OVER (ORDER BY active_kev DESC) AS count_rank,
       vendor, active_kev, ransomware_associated
FROM vendor_counts
ORDER BY active_kev DESC, vendor
LIMIT 10;

-- 4. Recently observed catalog state changes with run provenance.
SELECT h.cve_id, h.revision, h.is_active, h.valid_from, h.valid_to,
       r.catalog_version, r.catalog_released, h.run_id
FROM kev_history AS h
JOIN pipeline_runs AS r ON r.run_id = h.run_id
WHERE h.revision > 1
ORDER BY h.valid_from DESC, h.cve_id
LIMIT 20;

-- 5. Changes between observed score days. Only compare within one model version.
-- A gap between observation days is visible; these are not necessarily consecutive days.
WITH changes AS (
    SELECT cve_id, model_version, score_date, epss,
           LAG(score_date) OVER (PARTITION BY cve_id, model_version ORDER BY score_date) AS previous_date,
           LAG(epss) OVER (PARTITION BY cve_id, model_version ORDER BY score_date) AS previous_epss
    FROM epss_daily
)
SELECT cve_id, model_version, previous_date, score_date,
       ROUND(epss - previous_epss, 6) AS probability_change
FROM changes
WHERE previous_epss IS NOT NULL
ORDER BY ABS(epss - previous_epss) DESC, cve_id
LIMIT 20;

-- 6. Audit distinguishes failed loads and successful loads with an export error.
SELECT run_id, started_at, finished_at, as_of, status, kev_rows, epss_matches, error
FROM pipeline_runs
ORDER BY started_at DESC
LIMIT 10;
