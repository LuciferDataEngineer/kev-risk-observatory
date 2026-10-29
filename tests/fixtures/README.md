# Synthetic offline fixtures

All vulnerability records, vendors, products and CVE identifiers in this folder are fictional test data. They are not vulnerability advisories or observations about real products. The fixtures mimic the public CISA KEV JSON and FIRST EPSS CSV formats.

The KEV fixture contains three records. EPSS matches the first two, deliberately omits the third, and includes one unrelated CVE to test filtering. The first record includes a source extension field (`forensicTriage`) and a `cwes` array to check schema evolution. Run with an explicit `--as-of 2026-10-29` for reproducible elapsed-day calculations.
