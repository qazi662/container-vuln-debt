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

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
