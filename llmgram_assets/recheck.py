"""Daily link check of the listed assets.

Runs every published asset (and every asset this checker flagged) through
``AssetService.recheck`` and prints one JSON summary. Meant for a timer on the
server, with its own clone of the data repository so it never shares a
working tree with the MCP gateway:

    python -m llmgram_assets.recheck --git-checkout ~/llmgram-assets-mcp/recheck-data \\
        --ssh-key ~/.config/llmgram-assets-mcp/deploy_key

``--dry-run`` checks the links and reports what would change without writing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .service import RECHECK_STRIKES, AssetService
from .store import GitStore, LocalStore, StoreError

ACTOR = "linkcheck"


def run(service: AssetService, *, strikes: int = RECHECK_STRIKES, dry_run: bool = False) -> dict:
    results = [service.recheck(rec, ACTOR, strikes=strikes, dry_run=dry_run) for rec in service.store.list_records()]
    counts = Counter(r["result"] for r in results)
    return {
        "dry_run": dry_run,
        "checked": sum(n for k, n in counts.items() if k != "skipped"),
        "counts": dict(sorted(counts.items())),
        "changes": [r for r in results if r["result"] not in ("ok", "skipped")],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check the links of the listed assets again")
    parser.add_argument("--git-checkout", help="clone of the data repository (writes are pushed)")
    parser.add_argument("--ssh-key", help="write deploy key for the data repository")
    parser.add_argument("--local-root", help="plain directory store")
    parser.add_argument("--strikes", type=int, default=RECHECK_STRIKES, help="consecutive failures before flagging")
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    args = parser.parse_args(argv)
    if bool(args.git_checkout) == bool(args.local_root):
        parser.error("give exactly one of --git-checkout or --local-root")
    if args.strikes < 1:
        parser.error("--strikes must be at least 1")

    try:
        store = GitStore(Path(args.git_checkout), ssh_key=args.ssh_key) if args.git_checkout else LocalStore(Path(args.local_root))
        summary = run(AssetService(store), strikes=args.strikes, dry_run=args.dry_run)
    except StoreError as exc:
        sys.stderr.write(f"catalog unavailable: {exc}\n")
        return 2
    json.dump(summary, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 1 if summary["counts"].get("error") or summary["counts"].get("ambiguous") else 0


if __name__ == "__main__":
    sys.exit(main())
