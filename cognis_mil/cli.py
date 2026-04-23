import argparse, sys
from .exporters import to_console, to_json, to_markdown, to_sarif, to_oscal_skeleton

def make_cli(tool_name, scan_fn, version="0.1.0", extra_args=None):
    p = argparse.ArgumentParser(prog=tool_name, description=f"{tool_name} — Cognis Digital · Military/IC ecosystem")
    p.add_argument("target", nargs="?", default=".", help="Path/target")
    p.add_argument("--format", choices=["console","json","markdown","sarif","oscal"], default="console")
    p.add_argument("--out", help="Write output to file")
    p.add_argument("--fail-on", choices=["very_high","high","moderate","low","none"], default="none")
    p.add_argument("--classification", default="UNCLASSIFIED//FOR PUBLIC RELEASE",
                   help="Operator-supplied banner. PLACEHOLDER. Tool does not interpret.")
    p.add_argument("-v","--version", action="version", version=f"{tool_name} {version}")
    if extra_args:
        for a in extra_args: p.add_argument(*a["flags"], **{k:v for k,v in a.items() if k!="flags"})
    args = p.parse_args()
    result = scan_fn(args.target, **{k:v for k,v in vars(args).items()
                                      if k not in {"target","format","out","fail_on","version","classification"}})
    result.classification_placeholder = args.classification
    if hasattr(result, "finalize") and not result.composite_score: result.finalize()
    fmt = {"console":to_console,"json":to_json,"markdown":to_markdown,"sarif":to_sarif,"oscal":to_oscal_skeleton}[args.format]
    out = fmt(result)
    if args.out:
        open(args.out,"w").write(out); print(f"Wrote {args.out}", file=sys.stderr)
    else: print(out)
    if args.fail_on != "none":
        from .models import Severity
        thresh = {"very_high":[Severity.VERY_HIGH],
                  "high":[Severity.VERY_HIGH,Severity.HIGH],
                  "moderate":[Severity.VERY_HIGH,Severity.HIGH,Severity.MODERATE],
                  "low":[Severity.VERY_HIGH,Severity.HIGH,Severity.MODERATE,Severity.LOW]}[args.fail_on]
        if any(f.severity in thresh for f in result.findings): sys.exit(1)
    sys.exit(0)
