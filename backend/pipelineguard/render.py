"""Render a report as plain text (terminals), Markdown (PR comments / job summary) or SARIF (code scanning)."""

from __future__ import annotations

from typing import Any

from . import __version__
from .rules import RULES

ICON = {"PASS": "✅", "WARN": "⚠️", "FAIL": "⛔"}
SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "⬜"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
REPO_URL = "https://github.com/syedshah7214/syed-pipelineguard"


def _where(f: dict) -> str:
    parts = [f"{f['file']}:{f['line']}"]
    if f.get("job"):
        parts.append(f"job {f['job']}")
    return " · ".join(parts)


def text(r: dict[str, Any]) -> str:
    s = r["findings_by_severity"]
    out = [
        f"PipelineGuard {r['tool_version']} — {r['decision']}  (score {r['score']}/100, grade {r['grade']})",
        "  " + "; ".join(r["reasons"]),
        f"  {r['totals']['files']} file(s), {r['totals']['jobs']} job(s), {r['totals']['steps']} step(s) · "
        f"critical {s['critical']} · high {s['high']} · medium {s['medium']} · low {s['low']}",
    ]
    if r["fixes"]:
        out.append(f"  auto-fix available: score {r['score']} → {r['score_after_fixes']} (run with --write-fixes DIR)")
    for f in r["files"]:
        if f.get("error"):
            out.append(f"  ! {f['path']}: {f['error']}")
    for f in r["findings"]:
        out.append(f"  [{f['severity'].upper():8}] {f['rule_id']} {_where(f)}")
        out.append(f"             {f['title']} — {f['detail']}")
    return "\n".join(out)


def markdown(r: dict[str, Any], title: str = "PipelineGuard") -> str:
    s = r["findings_by_severity"]
    lines = [
        f"### {ICON[r['decision']]} {title}: **{r['decision']}** · score **{r['score']}/100** (grade {r['grade']})",
        "",
        "> " + "; ".join(r["reasons"]),
        "",
        "| Critical | High | Medium | Low | Files | Jobs | Auto-fixable |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        f"| {s['critical']} | {s['high']} | {s['medium']} | {s['low']} | {r['totals']['files']} | "
        f"{r['totals']['jobs']} | {r['autofixable']} |",
        "",
    ]
    if r["fixes"]:
        lines += [
            f"**Auto-fix preview:** score {r['score']} → **{r['score_after_fixes']}** after "
            f"{sum(len(x['applied']) for x in r['fixes'])} safe edits.",
            "",
        ]
    shown = [f for f in r["findings"] if f["severity"] != "low"][:40]
    if shown:
        lines += ["| | Rule | Where | Finding |", "|---|---|---|---|"]
        for f in shown:
            detail = f["detail"].replace("|", "\\|")
            lines.append(
                f"| {SEV_ICON[f['severity']]} | `{f['rule_id']}` | `{_where(f)}` | **{f['title']}** — {detail} |"
            )
        lines.append("")
    lows = s["low"]
    if lows:
        lines.append(f"<details><summary>{lows} low-severity hygiene hint(s)</summary>\n")
        for f in r["findings"]:
            if f["severity"] == "low":
                lines.append(f"- `{f['rule_id']}` `{_where(f)}` — {f['detail']}")
        lines.append("\n</details>\n")
    lines.append(
        f"<sub>SYED PipelineGuard {r['tool_version']} · {r['rules_evaluated']} rules · static analysis only, "
        "nothing was executed.</sub>"
    )
    return "\n".join(lines)


def sarif(r: dict[str, Any]) -> dict[str, Any]:
    used = sorted({f["rule_id"] for f in r["findings"]})
    rules = []
    for rid in used:
        rule = RULES[rid]
        rules.append(
            {
                "id": rid,
                "name": rid.replace("-", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.remediation},
                "helpUri": rule.reference,
                "help": {"text": rule.remediation, "markdown": f"{rule.remediation}\n\n[Reference]({rule.reference})"},
                "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
                "properties": {
                    "tags": [rule.category, "github-actions"],
                    "security-severity": SECURITY_SEVERITY[rule.severity],
                },
            }
        )
    results = [
        {
            "ruleId": f["rule_id"],
            "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['title']}: {f['detail']}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": max(int(f["line"]), 1)},
                    }
                }
            ],
        }
        for f in r["findings"]
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SYED PipelineGuard",
                        "version": __version__,
                        "informationUri": REPO_URL,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
