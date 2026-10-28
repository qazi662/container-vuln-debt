"""Quick terminal summaries: `cvd summary` and `cvd suggest`."""

from __future__ import annotations

import duckdb
import pandas as pd

from .store import latest_date

PER_IMAGE_SQL = """
SELECT i.app, i.ref, i.variant, i.roles,
       count(DISTINCT f.vuln_id) FILTER (WHERE f.severity = 'CRITICAL') AS critical,
       count(DISTINCT f.vuln_id) FILTER (WHERE f.severity = 'HIGH') AS high,
       count(DISTINCT f.vuln_id) AS total,
       count(DISTINCT f.vuln_id) FILTER (WHERE f.fix_state = 'fixed') AS fixable,
       count(DISTINCT f.vuln_id) FILTER (WHERE f.in_kev) AS kev
FROM images i
LEFT JOIN findings f ON f.date = i.date AND f.ref = i.ref AND f.scanner = i.scanner
WHERE i.date = ? AND i.scanner = ?
GROUP BY ALL
"""


def per_image(con: duckdb.DuckDBPyConnection, date: str | None = None, scanner: str = "trivy") -> pd.DataFrame:
    date = date or latest_date(con)
    return con.execute(PER_IMAGE_SQL, [date, scanner]).df()


def summary(con: duckdb.DuckDBPyConnection, scanner: str = "trivy") -> str:
    date = latest_date(con)
    df = per_image(con, date, scanner).sort_values(["critical", "high", "total"], ascending=False)
    lines = [f"Scan date {date}, scanner {scanner}, {len(df)} images", ""]
    lines.append(df.drop(columns=["roles"]).to_string(index=False))
    return "\n".join(lines)


def suggest(con: duckdb.DuckDBPyConnection, ref: str, scanner: str = "trivy") -> str:
    """Rank the tracked tags of the same app by critical+high, then fixable, then total."""
    date = latest_date(con)
    df = per_image(con, date, scanner)
    row = df[df["ref"] == ref]
    if row.empty:
        apps = ", ".join(sorted(df["app"].unique()))
        return f"{ref} is not tracked in the {date} scan. Tracked apps: {apps}"
    app = row.iloc[0]["app"]
    same = df[df["app"] == app].copy()
    same["crit_high"] = same["critical"] + same["high"]
    same = same.sort_values(["crit_high", "fixable", "total"])
    cur = same[same["ref"] == ref].iloc[0]
    best = same.iloc[0]
    lines = [f"{app} tags scanned on {date} ({scanner}):", ""]
    lines.append(same[["ref", "variant", "critical", "high", "fixable", "kev", "total"]].to_string(index=False))
    lines.append("")
    if best["ref"] == ref:
        lines.append(f"{ref} already has the fewest critical and high findings among tracked {app} tags.")
    else:
        lines.append(
            f"Suggestion: {best['ref']} has {int(best['crit_high'])} critical/high vs {int(cur['crit_high'])} "
            f"for {ref}. Check it is compatible with your app (libc, shell, package manager) before switching."
        )
    return "\n".join(lines)
