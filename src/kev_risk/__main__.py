"""Command-line entry point; pipeline errors produce a nonzero exit status."""

import argparse
import json
import sys

from .pipeline import run_pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the VulnSignal intelligence warehouse")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Ingest and validate a complete KEV and EPSS snapshot")
    run.add_argument("--data-dir", default="data", help="Raw, warehouse and export directory")
    run.add_argument("--as-of", help="Analysis date YYYY-MM-DD; defaults to today's UTC date")
    run.add_argument("--kev-file", help="Local CISA JSON snapshot; otherwise fetch live data")
    run.add_argument("--epss-file", help="Local FIRST CSV or CSV.gz; otherwise fetch live data")
    args = parser.parse_args()
    try:
        summary = run_pipeline(args.data_dir, as_of=args.as_of,
                               kev_file=args.kev_file, epss_file=args.epss_file)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"Pipeline failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
