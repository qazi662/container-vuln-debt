"""Command line entry point: `cvd <command>`."""

from __future__ import annotations

import argparse
import sys


def cmd_check(args) -> int:
    from .config import load_config
    from .pipeline import resolve_all
    from .scan import check_tools
    from .util import today_utc

    platform, targets = load_config(args.config)
    if args.only:
        targets = [t for t in targets if t.app in args.only]
    print(f"config OK: {len(targets)} tags, platform {platform}")
    missing = check_tools()
    print("tools: all found" if not missing else f"tools MISSING: {', '.join(missing)}")
    rows = resolve_all(targets, platform, today_utc())
    bad = [r for r in rows if r["status"] != "ok"]
    print(f"\n{len(rows) - len(bad)}/{len(rows)} tags resolved")
    for r in bad:
        print(f"  FIX {r['ref']}: {r['status']}")
    return 1 if bad or missing else 0


def cmd_run(args) -> int:
    from .pipeline import run

    run(args.config, date=args.date, only=args.only, workers=args.workers, update_db=not args.skip_db_update)
    return 0


def cmd_summary(args) -> int:
    from .report import summary
    from .store import connect

    print(summary(connect(), scanner=args.scanner))
    return 0


def cmd_suggest(args) -> int:
    from .report import suggest
    from .store import connect

    print(suggest(connect(), args.ref, scanner=args.scanner))
    return 0


def cmd_validate_sbom(args) -> int:
    """Compare SBOM based Trivy results with a direct Trivy image scan on a sample of images."""
    from .normalize import normalize_trivy
    from .registry import parse_ref
    from .scan import scan_image_direct
    from .store import connect, latest_date

    con = connect()
    date = latest_date(con)
    sample = con.execute(
        "SELECT DISTINCT i.ref, i.index_digest, d.platform FROM images i JOIN digests d "
        "ON d.date = i.date AND d.ref = i.ref WHERE i.date = ? AND i.scanner = 'trivy' "
        "ORDER BY hash(i.ref) LIMIT ?", [date, args.sample]).fetchall()
    for ref, digest, platform in sample:
        sbom_ids = {r[0] for r in con.execute(
            "SELECT DISTINCT vuln_id FROM findings WHERE date = ? AND ref = ? AND scanner = 'trivy'",
            [date, ref]).fetchall()}
        direct = scan_image_direct(parse_ref(ref).with_digest(digest), platform)
        direct_ids = {r["vuln_id"] for r in normalize_trivy(direct)}
        union = sbom_ids | direct_ids
        jac = len(sbom_ids & direct_ids) / len(union) if union else 1.0
        print(f"{ref:<55} sbom={len(sbom_ids):>4} direct={len(direct_ids):>4} "
              f"only_direct={len(direct_ids - sbom_ids):>3} jaccard={jac:.2f}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cvd", description="Container vulnerability debt measurement")
    p.add_argument("--config", default="config/images.yaml")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("check", help="validate config, check tools, resolve every tag (no pulls)")
    s.add_argument("--only", nargs="+", help="limit to these apps")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("run", help="full weekly run")
    s.add_argument("--date", help="override run date (YYYY-MM-DD)")
    s.add_argument("--only", nargs="+", help="limit to these apps, e.g. --only node nginx")
    s.add_argument("--workers", type=int, default=3)
    s.add_argument("--skip-db-update", action="store_true", help="reuse current scanner databases")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("summary", help="per image table for the latest scan")
    s.add_argument("--scanner", default="trivy", choices=["trivy", "grype"])
    s.set_defaults(func=cmd_summary)

    s = sub.add_parser("suggest", help="lower risk tag of the same app, from the latest scan")
    s.add_argument("ref", help="a tracked tag, e.g. node:22")
    s.add_argument("--scanner", default="trivy", choices=["trivy", "grype"])
    s.set_defaults(func=cmd_suggest)

    s = sub.add_parser("validate-sbom", help="SBOM scan vs direct image scan on a sample")
    s.add_argument("--sample", type=int, default=5)
    s.set_defaults(func=cmd_validate_sbom)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
