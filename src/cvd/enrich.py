"""Add exploit signals to findings: CISA KEV membership and FIRST EPSS scores.

Both are cached per run date under data/cache/ so a rerun on the same day
gives the same answer. Network failures only warn; the scan still completes.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pandas as pd
import requests

from .util import data_dir

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"


def _cache() -> Path:
    p = data_dir() / "cache"
    p.mkdir(parents=True, exist_ok=True)
    return p


def load_kev(date: str, session: requests.Session | None = None) -> set[str] | None:
    path = _cache() / f"kev-{date}.json"
    try:
        if not path.exists():
            r = (session or requests).get(KEV_URL, timeout=60)
            r.raise_for_status()
            path.write_text(r.text)
        data = json.loads(path.read_text())
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as exc:  # noqa: BLE001
        print(f"warning: could not load CISA KEV: {exc}", file=sys.stderr)
        return None


def load_epss(cves: list[str], date: str, session: requests.Session | None = None,
              batch: int = 50) -> dict[str, tuple[float, float]]:
    """Return {cve: (epss, percentile)} for the given CVE ids, fetching only ones not cached today."""
    path = _cache() / f"epss-{date}.csv"
    known: dict[str, tuple[float, float]] = {}
    if path.exists():
        df = pd.read_csv(path)
        known = {r.cve: (r.epss, r.percentile) for r in df.itertuples()}
    wanted = sorted({c for c in cves if c.startswith("CVE-")} - known.keys())
    fetched, sess = [], session or requests.Session()
    try:
        for i in range(0, len(wanted), batch):
            chunk = wanted[i:i + batch]
            r = sess.get(EPSS_API, params={"cve": ",".join(chunk), "limit": batch * 2}, timeout=60)
            r.raise_for_status()
            for row in r.json().get("data", []):
                fetched.append({"cve": row["cve"], "epss": float(row["epss"]),
                                "percentile": float(row["percentile"])})
            time.sleep(0.2)
    except Exception as exc:  # noqa: BLE001
        print(f"warning: EPSS lookup incomplete: {exc}", file=sys.stderr)
    if fetched:
        new = pd.DataFrame(fetched)
        old = pd.read_csv(path) if path.exists() else new.iloc[0:0]
        pd.concat([old, new]).drop_duplicates("cve", keep="last").to_csv(path, index=False)
        known.update({r["cve"]: (r["epss"], r["percentile"]) for r in fetched})
    return known


def enrich(df: pd.DataFrame, date: str) -> pd.DataFrame:
    df = df.copy()
    kev = load_kev(date)
    if kev is not None:
        df["in_kev"] = pd.array(df["vuln_id"].isin(kev), dtype="boolean")
    else:
        df["in_kev"] = pd.array([pd.NA] * len(df), dtype="boolean")
    epss = load_epss(df["vuln_id"].unique().tolist(), date) if len(df) else {}
    df["epss"] = df["vuln_id"].map(lambda c: epss.get(c, (None, None))[0])
    df["epss_percentile"] = df["vuln_id"].map(lambda c: epss.get(c, (None, None))[1])
    return df
