"""DuckDB views over the committed data files, for the CLI and the analysis scripts.

Views:
  findings  all data/findings/*.parquet
  digests   data/state/digests.csv
  scans     data/state/scans.csv (n_findings cast to INTEGER)
  images    one row per (date, ref, scanner) that scanned OK, with app/variant/roles,
            so images with zero findings still count in averages
"""

from __future__ import annotations

from pathlib import Path

import duckdb

from .util import data_dir


def connect(base: Path | None = None) -> duckdb.DuckDBPyConnection:
    base = base or data_dir()
    con = duckdb.connect()
    findings_glob = base / "findings" / "*.parquet"
    if not list((base / "findings").glob("*.parquet")):
        raise SystemExit(f"no findings yet in {base / 'findings'}; run `cvd run` first")
    con.execute(f"CREATE VIEW findings AS SELECT * FROM read_parquet('{findings_glob}', union_by_name=true)")
    con.execute(
        f"CREATE VIEW digests AS SELECT * FROM read_csv('{base / 'state' / 'digests.csv'}', "
        "header=true, all_varchar=true)"
    )
    con.execute(
        f"CREATE VIEW scans AS SELECT date, ref, scanner, status, TRY_CAST(n_findings AS INTEGER) AS n_findings, "
        f"error FROM read_csv('{base / 'state' / 'scans.csv'}', header=true, all_varchar=true)"
    )
    con.execute(
        """
        CREATE VIEW images AS
        SELECT s.date, s.ref, s.scanner, d.app, d.variant, d.roles, d.index_digest
        FROM scans s JOIN digests d ON d.date = s.date AND d.ref = s.ref
        WHERE s.status = 'ok'
        """
    )
    return con


def latest_date(con: duckdb.DuckDBPyConnection) -> str:
    return con.execute("SELECT max(date) FROM images").fetchone()[0]
