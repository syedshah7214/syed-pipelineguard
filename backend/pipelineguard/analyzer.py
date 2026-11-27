"""Turn workflow files into one report: findings, score, gate decision and auto-fixes.

Scoring (deterministic, documented in the README):
  each file starts at 100 and loses 25 per critical, 12 per high, 5 per medium and
  2 per low finding (floor 0). The overall score is the mean of the file scores.
  Grade: A >= 90, B >= 80, C >= 65, D >= 50, else F.

Gate:
  FAIL  any finding at or above `fail_on` (default: high) or a file that does not parse
  WARN  any medium finding
  PASS  otherwise (low findings are hygiene hints)
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from . import __version__
from .autofix import fix
from .rules import RULES, SEV_RANK, SEVERITIES, SHA_RE, evaluate
from .workflow import MAX_FILES, Workflow, WorkflowError, parse_workflow

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
PENALTY = {"critical": 25, "high": 12, "medium": 5, "low": 2}


@dataclass
class Options:
    fail_on: str = "high"
    autofix: bool = True

    def __post_init__(self) -> None:
        if self.fail_on not in SEVERITIES:
            raise ValueError(f"fail_on must be one of {SEVERITIES}")


def score_of(findings: list[dict]) -> int:
    return max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))


def grade_of(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


def decide(findings: list[dict], errors: int, fail_on: str) -> tuple[str, list[str]]:
    threshold = SEV_RANK[fail_on]
    counts = Counter(f["severity"] for f in findings)
    blocking = [s for s in SEVERITIES if SEV_RANK[s] >= threshold and counts[s]]
    reasons: list[str] = []
    if errors:
        reasons.append(f"{errors} file(s) could not be parsed")
    if blocking:
        reasons.append(", ".join(f"{counts[s]} {s}" for s in blocking) + f" finding(s) at or above '{fail_on}'")
    if reasons:
        return FAIL, reasons
    if counts["medium"]:
        return WARN, [f"{counts['medium']} medium finding(s) to review"]
    return PASS, ["no blocking findings" + (f" ({counts['low']} low hygiene hints)" if counts["low"] else "")]


def _inventory(wfs: list[Workflow]) -> list[dict]:
    seen: dict[str, dict] = {}
    for wf in wfs:
        for job in wf.jobs:
            for step in job.steps:
                if not step.action:
                    continue
                key = f"{step.action}@{step.ref}"
                item = seen.setdefault(
                    key,
                    {
                        "action": step.action,
                        "ref": step.ref,
                        "pinned": bool(SHA_RE.match(step.ref or "")),
                        "github_owned": step.action.split("/")[0] in ("actions", "github"),
                        "uses": 0,
                    },
                )
                item["uses"] += 1
    return sorted(seen.values(), key=lambda a: (a["github_owned"], a["action"]))


def analyze(files: list[dict[str, str]], options: Options | None = None) -> dict[str, Any]:
    opts = options or Options()
    if not files:
        raise WorkflowError("no workflow files given")
    if len(files) > MAX_FILES:
        raise WorkflowError(f"at most {MAX_FILES} workflow files per analysis")

    parsed: list[Workflow] = []
    file_rows: list[dict] = []
    findings: list[dict] = []
    fixes: list[dict] = []
    errors = 0
    for f in files:
        path = str(f.get("path") or "workflow.yml")
        try:
            wf = parse_workflow(str(f.get("content", "")), path)
        except WorkflowError as exc:
            errors += 1
            file_rows.append({"path": path, "error": str(exc), "score": 0, "grade": "F"})
            continue
        parsed.append(wf)
        fs = evaluate(wf)
        findings.extend(fs)
        row = {
            "path": path,
            "name": wf.name,
            "triggers": sorted(wf.triggers),
            "jobs": len(wf.jobs),
            "steps": sum(len(j.steps) for j in wf.jobs),
            "findings": len(fs),
            "score": score_of(fs),
            "grade": grade_of(score_of(fs)),
            "error": None,
        }
        if opts.autofix and any(x["autofix"] for x in fs):
            result = fix(wf, fs)
            if result["applied"]:
                after = evaluate(parse_workflow(result["fixed"], path))
                result["score_after"] = score_of(after)
                result["findings_after"] = len(after)
                result["score_before"] = row["score"]
                row["score_after"] = result["score_after"]
                fixes.append(result)
        file_rows.append(row)

    if not parsed:
        raise WorkflowError("; ".join(r["error"] for r in file_rows))

    decision, reasons = decide(findings, errors, opts.fail_on)
    score = round(sum(r["score"] for r in file_rows) / len(file_rows))
    score_after = round(sum(r.get("score_after", r["score"]) for r in file_rows) / len(file_rows))
    sev = Counter(f["severity"] for f in findings)
    cat = Counter(f["category"] for f in findings)
    inventory = _inventory(parsed)
    third = [a for a in inventory if not a["github_owned"]]
    return {
        "tool_version": __version__,
        "decision": decision,
        "reasons": reasons,
        "score": score,
        "grade": grade_of(score),
        "score_after_fixes": score_after,
        "grade_after_fixes": grade_of(score_after),
        "files": file_rows,
        "findings": findings,
        "findings_by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
        "findings_by_category": dict(cat.most_common()),
        "autofixable": sum(1 for f in findings if f["autofix"]),
        "fixes": fixes,
        "inventory": inventory,
        "totals": {
            "files": len(file_rows),
            "jobs": sum(r.get("jobs", 0) for r in file_rows),
            "steps": sum(r.get("steps", 0) for r in file_rows),
            "actions": len(inventory),
            "third_party_actions": len(third),
            "third_party_pinned": sum(1 for a in third if a["pinned"]),
        },
        "options": {"fail_on": opts.fail_on, "autofix": opts.autofix},
        "rules_evaluated": len(RULES),
    }
