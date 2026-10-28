"""One weekly run: resolve -> SBOM (new digests only) -> scan with both scanners -> normalize -> enrich -> save.

Outputs (committed to git, small):
  data/state/digests.csv          one row per (date, ref): digest or missing/error status
  data/state/scans.csv            one row per (date, ref, scanner): ok/error and finding count
  data/state/versions/<date>.json scanner and database versions used that day
  data/findings/<date>.parquet    all normalized, enriched findings for that day
Outputs (not committed, large):
  data/sboms/                     cached SBOMs, reused until a tag's digest changes
  data/raw/<date>/<scanner>/      raw scanner JSON (uploaded as a CI artifact)
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

from . import scan as scanner_mod
from .config import Target, load_config
from .enrich import enrich
from .normalize import FINDING_COLUMNS, normalize
from .registry import Resolver
from .sbom import build_sbom
from .util import data_dir, safe_name, today_utc, upsert_csv, write_json_gz

IMAGE_COLUMNS = ["date", "app", "ref", "variant", "roles", "platform", "index_digest", "scanner"]


def resolve_all(targets: list[Target], platform: str, date: str) -> list[dict]:
    resolver = Resolver()
    rows = []
    for t in targets:
        try:
            digest = resolver.resolve(t.ref)
            status = "ok" if digest else "missing"
        except Exception as exc:  # noqa: BLE001
            digest, status = None, f"error: {exc}"[:300]
        rows.append({"date": date, "app": t.app, "ref": t.ref, "variant": t.variant, "roles": t.roles_str,
                     "platform": platform, "index_digest": digest or "", "status": status})
        mark = digest[:19] if digest else status
        print(f"  resolve {t.ref:<55} {mark}")
    return rows


def run(config_path: str = "config/images.yaml", date: str | None = None, only: list[str] | None = None,
        workers: int = 3, update_db: bool = True) -> pd.DataFrame:
    date = date or today_utc()
    platform, targets = load_config(config_path)
    if only:
        targets = [t for t in targets if t.app in only]
    if not targets:
        raise SystemExit("no targets selected")
    missing_tools = scanner_mod.check_tools()
    if missing_tools:
        raise SystemExit(f"missing tools on PATH: {', '.join(missing_tools)} (see README, Quick start)")

    state = data_dir() / "state"
    by_ref = {t.ref: t for t in targets}

    print(f"[1/5] resolving {len(targets)} tags")
    digest_rows = resolve_all(targets, platform, date)
    upsert_csv(state / "digests.csv", digest_rows, key=["date", "ref"])
    resolved = [r for r in digest_rows if r["status"] == "ok"]

    print(f"[2/5] building SBOMs for new digests ({len(resolved)} resolved)")
    sboms, scan_log = {}, []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(build_sbom, r["ref"], r["index_digest"], platform): r for r in resolved}
        for fut in as_completed(futs):
            r = futs[fut]
            try:
                sboms[r["ref"]] = fut.result()
            except Exception as exc:  # noqa: BLE001
                print(f"  sbom FAILED {r['ref']}: {exc}")
                for s in scanner_mod.SCANNERS:
                    scan_log.append({"date": date, "ref": r["ref"], "scanner": s, "status": "sbom-error",
                                     "n_findings": "", "error": str(exc)[:300]})

    print("[3/5] updating vulnerability databases")
    if update_db:
        scanner_mod.update_databases()
    versions_path = state / "versions" / f"{date}.json"
    versions_path.parent.mkdir(parents=True, exist_ok=True)
    versions_path.write_text(json.dumps(scanner_mod.tool_versions(), indent=2, default=str))

    print(f"[4/5] scanning {len(sboms)} SBOMs with {', '.join(scanner_mod.SCANNERS)}")
    frames = []
    digest_of = {r["ref"]: r["index_digest"] for r in resolved}

    def do_scan(ref: str, scanner: str):
        report = scanner_mod.scan_sbom(scanner, sboms[ref])
        write_json_gz(data_dir() / "raw" / date / scanner / f"{safe_name(ref)}.json.gz", report)
        return normalize(scanner, report)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(do_scan, ref, s): (ref, s) for ref in sboms for s in scanner_mod.SCANNERS}
        for fut in as_completed(futs):
            ref, s = futs[fut]
            t = by_ref[ref]
            try:
                rows = fut.result()
            except Exception as exc:  # noqa: BLE001
                print(f"  scan FAILED {s} {ref}: {exc}")
                scan_log.append({"date": date, "ref": ref, "scanner": s, "status": "scan-error",
                                 "n_findings": "", "error": str(exc)[:300]})
                continue
            scan_log.append({"date": date, "ref": ref, "scanner": s, "status": "ok",
                             "n_findings": len(rows), "error": ""})
            if rows:
                f = pd.DataFrame(rows, columns=FINDING_COLUMNS)
                values = [date, t.app, ref, t.variant, t.roles_str, platform, digest_of[ref], s]
                for pos, (col, val) in enumerate(zip(IMAGE_COLUMNS, values, strict=True)):
                    f.insert(pos, col, val)
                frames.append(f)
            print(f"  {s:<6} {ref:<55} {len(rows):>5} findings")
    upsert_csv(state / "scans.csv", scan_log, key=["date", "ref", "scanner"])

    print("[5/5] enriching with CISA KEV and EPSS, saving")
    findings = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(
        columns=IMAGE_COLUMNS + FINDING_COLUMNS)
    findings = enrich(findings, date)
    out = data_dir() / "findings" / f"{date}.parquet"
    out.parent.mkdir(parents=True, exist_ok=True)
    findings.to_parquet(out, index=False)
    ok = sum(1 for r in scan_log if r["status"] == "ok")
    print(f"done: {len(findings)} findings, {ok}/{len(scan_log)} scans ok -> {out}")
    return findings
