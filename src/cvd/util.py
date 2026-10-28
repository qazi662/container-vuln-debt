"""Small shared helpers: paths, dates, gzip JSON, CSV upserts."""

from __future__ import annotations

import datetime as dt
import gzip
import json
import os
import re
from pathlib import Path

import pandas as pd


def root() -> Path:
    """Project root. Override with CVD_ROOT, otherwise the current directory."""
    return Path(os.environ.get("CVD_ROOT", Path.cwd())).resolve()


def data_dir() -> Path:
    return root() / "data"


def today_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def safe_name(text: str) -> str:
    """File system safe version of an image reference or digest."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")


def write_json_gz(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(obj, fh)


def read_json_gz(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def upsert_csv(path: Path, rows: list[dict], key: list[str]) -> pd.DataFrame:
    """Append rows to a CSV, replacing earlier rows with the same key (so reruns are idempotent)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    new = pd.DataFrame(rows)
    if path.exists() and path.stat().st_size > 0:
        old = pd.read_csv(path, dtype=str, keep_default_na=False)
        merged = pd.concat([old, new.astype(str)], ignore_index=True)
    else:
        merged = new.astype(str)
    if not merged.empty:
        merged = merged.drop_duplicates(subset=key, keep="last")
    merged.to_csv(path, index=False)
    return merged
