import sys

from cognis_mil import make_cli
from .core import scan
from . import __version__


def _feeds_cli(argv):
    """`stigsentry feeds list|update|get <id> [--offline]` — bundled data feeds,
    filtered to the compliance feeds stigsentry actually consumes."""
    from . import datafeeds as df
    from . import feeds as ff

    relevant = set(ff.RELEVANT_FEEDS)
    cmd = argv[0] if argv else "list"
    rest = argv[1:]

    if cmd == "list":
        for f in ff.list_feeds():
            age = df.cached_age_hours(f["id"])
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {f['id']:30} {f.get('domain',''):11} [{fresh}]  {f['name']}")
        return 0

    if cmd == "update":
        ids = [a for a in rest if not a.startswith("-")] or ff.RELEVANT_FEEDS
        rc = 0
        for fid in ids:
            if fid not in relevant:
                print(f"  {fid}: not a stigsentry feed (allowed: {sorted(relevant)})",
                      file=sys.stderr)
                rc = 1
                continue
            try:
                pth = df.update(fid)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as e:
                print(f"  {fid}: {e}", file=sys.stderr)
                rc = 1
        return rc

    if cmd == "get":
        offline = "--offline" in rest
        pos = [a for a in rest if not a.startswith("-")]
        if not pos:
            print("usage: stigsentry feeds get <feed-id> [--offline]", file=sys.stderr)
            return 2
        fid = pos[0]
        if fid not in relevant:
            print(f"error: {fid} is not a stigsentry feed (allowed: {sorted(relevant)})",
                  file=sys.stderr)
            return 1
        try:
            import json
            data = df.get(fid, offline=offline, max_age_hours=24 * 30)
        except (KeyError, FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        text = json.dumps(data, indent=2) if isinstance(data, (dict, list)) else data
        print(text[:4000])
        return 0

    print("usage: stigsentry feeds list|update [<id>...]|get <id> [--offline]",
          file=sys.stderr)
    return 2


def main():
    # `stigsentry feeds ...` is a dedicated subcommand for the data-feed layer;
    # everything else falls through to the shared scan CLI (make_cli).
    if len(sys.argv) > 1 and sys.argv[1] == "feeds":
        raise SystemExit(_feeds_cli(sys.argv[2:]))
    make_cli("stigsentry", scan, version=__version__)


if __name__ == "__main__":
    main()
