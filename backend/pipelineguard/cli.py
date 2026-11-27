"""Command line entry point — what CI pipelines run.

    python -m pipelineguard .github/workflows --fail-on high
    python -m pipelineguard .github/workflows --format sarif > pipelineguard.sarif
    python -m pipelineguard .github/workflows --write-fixes fixed/

Exit codes: 0 = PASS or WARN, 1 = FAIL, 2 = invalid input.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .analyzer import FAIL, Options, analyze
from .render import markdown, sarif, text
from .workflow import WorkflowError


def collect(paths: list[str]) -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            found = sorted([*p.glob("*.yml"), *p.glob("*.yaml")])
            if not found:
                raise WorkflowError(f"{raw}: no .yml/.yaml files")
            targets = found
        elif p.is_file():
            targets = [p]
        else:
            raise WorkflowError(f"{raw}: not found")
        for t in targets:
            files.append({"path": t.as_posix(), "content": t.read_text(encoding="utf-8")})
    return files


def _esc(value: str, prop: bool = False) -> str:
    value = str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return value.replace(":", "%3A").replace(",", "%2C") if prop else value


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pipelineguard", description="Security & performance auditor for GitHub Actions")
    p.add_argument("paths", nargs="*", default=[".github/workflows"], help="workflow files or directories")
    p.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low"])
    p.add_argument("--format", default="text", choices=["text", "json", "markdown", "sarif"])
    p.add_argument("--output", help="write the formatted report to this file instead of stdout")
    p.add_argument("--title", default="PipelineGuard")
    p.add_argument("--summary", action="store_true", help="also append Markdown to $GITHUB_STEP_SUMMARY")
    p.add_argument("--write-fixes", metavar="DIR", help="write auto-fixed copies of the workflows into DIR")
    args = p.parse_args(argv)

    try:
        report = analyze(collect(args.paths), Options(fail_on=args.fail_on))
    except (OSError, WorkflowError, ValueError) as exc:
        print(f"pipelineguard: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        out = json.dumps(report, indent=2)
    elif args.format == "sarif":
        out = json.dumps(sarif(report), indent=2)
    elif args.format == "markdown":
        out = markdown(report, args.title)
    else:
        out = text(report)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)

    if args.write_fixes:
        dest = Path(args.write_fixes)
        dest.mkdir(parents=True, exist_ok=True)
        for fx in report["fixes"]:
            target = dest / Path(fx["path"]).name
            target.write_text(fx["fixed"], encoding="utf-8")
            print(f"pipelineguard: wrote {target} ({len(fx['applied'])} fixes)", file=sys.stderr)

    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if args.summary and summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(markdown(report, args.title) + "\n\n")
    if os.getenv("GITHUB_ACTIONS") == "true":
        for f in report["findings"]:
            if f["severity"] in ("critical", "high"):
                print(
                    f"::error file={_esc(f['file'], True)},line={f['line']},title={_esc(f['rule_id'], True)}::"
                    + _esc(f"{f['title']} — {f['detail']}")
                )
        level = "error" if report["decision"] == FAIL else "warning" if report["decision"] == "WARN" else "notice"
        print(
            f"::{level}::{args.title}: {report['decision']} (score {report['score']}) — {'; '.join(report['reasons'])}"
        )
    return 1 if report["decision"] == FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
