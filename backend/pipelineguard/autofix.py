"""Generate a fixed copy of a workflow.

Fixes are line edits on the original text (not a YAML re-dump), so comments,
ordering and formatting survive and the diff stays small enough to review.
Every fix is listed with the rule it addresses; anything that needs a human
decision (e.g. which SHA to pin) is left as a finding.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from .rules import DEPRECATED_MAJORS, EXPR_RE, UNTRUSTED_RE, cache_target, job_text, major
from .workflow import Job, Step, Workflow, parse_workflow


@dataclass
class _Edits:
    lines: list[str]
    inserts: dict[int, list[str]] = field(default_factory=dict)  # insert BEFORE 0-based index
    replaced: dict[int, str] = field(default_factory=dict)

    def insert_before(self, idx: int, new: list[str]) -> None:
        self.inserts.setdefault(idx, []).extend(new)

    def replace(self, idx: int, new: str) -> None:
        self.replaced[idx] = new

    def current(self, idx: int) -> str:
        return self.replaced.get(idx, self.lines[idx])

    def render(self) -> list[str]:
        out: list[str] = []
        for i, line in enumerate(self.lines):
            out.extend(self.inserts.get(i, []))
            out.append(self.replaced.get(i, line))
        out.extend(self.inserts.get(len(self.lines), []))
        return out


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip(" "))


def _step_bounds(lines: list[str], step: Step) -> tuple[int, int, int]:
    """(first index, end index exclusive, key indent) of a list-item step."""
    start = step.line - 1
    m = re.match(r"^(\s*)-\s+", lines[start])
    if m:
        dash, key = len(m.group(1)), len(m.group(0))
    else:  # mapping started on the line after a bare "-"
        key = _indent(lines[start])
        dash = key - 2
    end = start + 1
    while end < len(lines):
        s = lines[end]
        if s.strip() and not s.lstrip().startswith("#") and _indent(s) <= dash:
            break
        end += 1
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    return start, end, key


def _find_key(lines: list[str], start: int, end: int, indent: int, key: str) -> int | None:
    rx = re.compile(rf"^(\s*-\s+|\s*){re.escape(key)}\s*:")
    for i in range(start, end):
        m = rx.match(lines[i])
        if m and len(m.group(1)) == indent:
            return i
    return None


def _child_indent(lines: list[str], idx: int, end: int, parent: int) -> int:
    for i in range(idx + 1, end):
        if lines[i].strip():
            return _indent(lines[i]) if _indent(lines[i]) > parent else parent + 2
    return parent + 2


def _set_with(ed: _Edits, step: Step, key: str, value: str) -> bool:
    start, end, ind = _step_bounds(ed.lines, step)
    w = _find_key(ed.lines, start, end, ind, "with")
    if w is not None:
        if ed.lines[w].split(":", 1)[1].strip():  # inline `with: {…}` — leave to a human
            return False
        child = _child_indent(ed.lines, w, end, ind)
        ed.insert_before(w + 1, [" " * child + f"{key}: {value}"])
        return True
    u = _find_key(ed.lines, start, end, ind, "uses")
    if u is None:
        return False
    ed.insert_before(u + 1, [" " * ind + "with:", " " * (ind + 2) + f"{key}: {value}"])
    return True


def _env_name(expr: str, taken: set[str]) -> str:
    parts = [p for p in re.split(r"[.\[\]'\"]+", expr) if p and p not in ("github", "event")]
    base = re.sub(r"[^A-Z0-9_]", "_", "_".join(parts[-2:]).upper()) or "UNTRUSTED"
    name, n = base, 2
    while name in taken:
        name, n = f"{base}_{n}", n + 1
    taken.add(name)
    return name


def _fix_injection(ed: _Edits, step: Step) -> list[str]:
    start, end, ind = _step_bounds(ed.lines, step)
    run = _find_key(ed.lines, start, end, ind, "run")
    if run is None:
        return []
    names: dict[str, str] = {}
    taken = {str(k) for k in step.env}
    run_end = run + 1
    while run_end < end and not (ed.lines[run_end].strip() and _indent(ed.lines[run_end]) <= ind):
        run_end += 1
    for i in range(run, run_end):
        line = ed.current(i)

        def sub(m: re.Match) -> str:
            expr = m.group(1).strip()
            if not UNTRUSTED_RE.match(expr):
                return m.group(0)
            names.setdefault(expr, _env_name(expr, taken))
            return "${" + names[expr] + "}"

        new = EXPR_RE.sub(sub, line)
        if new != line:
            ed.replace(i, new)
    if not names:
        return []
    env_lines = [f"{n}: ${{{{ {e} }}}}" for e, n in names.items()]
    env = _find_key(ed.lines, start, end, ind, "env")
    if env is not None:
        child = _child_indent(ed.lines, env, end, ind)
        ed.insert_before(env + 1, [" " * child + s for s in env_lines])
    else:
        head = ed.lines[run]
        if re.match(r"^\s*-\s+run\s*:", head):  # `- run:` is the first key: split it
            ed.replace(
                run,
                head.replace("- run", "  run", 1)
                if run not in ed.replaced
                else ed.replaced[run].replace("- run", "  run", 1),
            )
            ed.insert_before(run, [" " * (ind - 2) + "- env:"] + [" " * (ind + 2) + s for s in env_lines])
        else:
            ed.insert_before(run, [" " * ind + "env:"] + [" " * (ind + 2) + s for s in env_lines])
    return list(names.values())


def _job_key_indent(lines: list[str], job: Job) -> int:
    return _indent(lines[job.line - 1])


TOP_LEVEL_JOBS = re.compile(r"^jobs\s*:")


def fix(wf: Workflow, findings: list[dict]) -> dict:
    lines = wf.text.splitlines()
    ed = _Edits(lines)
    applied: list[dict] = []
    rules_hit = {f["rule_id"] for f in findings}

    def note(rule_id: str, line: int, what: str) -> None:
        applied.append({"rule_id": rule_id, "line": line, "change": what})

    jobs_line = next((i for i, s in enumerate(lines) if TOP_LEVEL_JOBS.match(s)), None)

    if "PPG-SEC-006" in rules_hit and jobs_line is not None:
        ed.insert_before(jobs_line, ["permissions:", "  contents: read", ""])
        note(
            "PPG-SEC-006",
            jobs_line + 1,
            "Added top-level `permissions: contents: read` (grant writes per job if needed).",
        )
    if "PPG-PERF-003" in rules_hit and jobs_line is not None:
        ed.insert_before(
            jobs_line,
            [
                "concurrency:",
                "  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
                "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
                "",
            ],
        )
        note("PPG-PERF-003", jobs_line + 1, "Added a concurrency group that cancels superseded PR runs.")

    for job in wf.jobs:
        if "PPG-PERF-002" in rules_hit and not job.uses and job.timeout_minutes is None and job.line:
            ind = _job_key_indent(lines, job)
            ed.insert_before(job.line - 1, [" " * ind + "timeout-minutes: 30"])
            note("PPG-PERF-002", job.line, f"`{job.id}`: added `timeout-minutes: 30` (tune to your normal duration).")
        pushes = re.search(r"\bgit\s+push\b", job_text(job))
        for step in job.steps:
            if not step.line:
                continue
            # deprecated majors
            want = DEPRECATED_MAJORS.get(step.action or "")
            have = major(step.ref)
            if "PPG-REL-001" in rules_hit and want and have is not None and have < want:
                idx = next(
                    (i for i in range(step.line - 1, min(step.line + 3, len(lines))) if step.uses in lines[i]), None
                )
                if idx is not None:
                    new_uses = f"{step.uses.split('@')[0]}@v{want}"
                    ed.replace(idx, ed.current(idx).replace(step.uses, new_uses))
                    extra = " — v4 artifacts are immutable; use unique names per job" if "artifact" in step.uses else ""
                    note("PPG-REL-001", idx + 1, f"`{step.uses}` → `{new_uses}`{extra}.")
            if "PPG-PERF-001" in rules_hit:
                target = cache_target(job, step)
                if target and _set_with(ed, step, "cache", target):
                    note(
                        "PPG-PERF-001",
                        step.line,
                        f"`{step.action}`: enabled `cache: {target}` (needs a lock or requirements file in the repo).",
                    )
            if "PPG-SEC-010" in rules_hit and step.action == "actions/checkout" and not pushes:
                if str(step.with_.get("persist-credentials", "true")).lower() != "false":
                    if _set_with(ed, step, "persist-credentials", "false"):
                        note("PPG-SEC-010", step.line, "actions/checkout: `persist-credentials: false`.")
            if "PPG-SEC-002" in rules_hit and step.run:
                moved = _fix_injection(ed, step)
                if moved:
                    note(
                        "PPG-SEC-002",
                        step.line,
                        f"Moved untrusted input into env: {', '.join('$' + m for m in moved)}.",
                    )
            if step.run:
                start, end, _ = _step_bounds(lines, step)
                for i in range(start, end):
                    cur = ed.current(i)
                    new = cur
                    if "PPG-REL-004" in rules_hit:
                        new = re.sub(r"\bnpm\s+(install|i)(\s*)($|&&|;|\|)", r"npm ci\2\3", new)
                    if "PPG-REL-002" in rules_hit:
                        new = re.sub(
                            r"""echo\s+["']?::(set-output|save-state)\s+name=([\w-]+)::(.*?)["']?\s*$""",
                            lambda m: (
                                f'echo "{m.group(2)}={m.group(3)}" >> "$GITHUB_'
                                + ("OUTPUT" if m.group(1) == "set-output" else "STATE")
                                + '"'
                            ),
                            new,
                        )
                    if new != cur:
                        ed.replace(i, new)
                        rid = "PPG-REL-004" if "npm ci" in new and "npm ci" not in cur else "PPG-REL-002"
                        note(rid, i + 1, f"`{cur.strip()[:60]}` → `{new.strip()[:70]}`")

    fixed = "\n".join(ed.render()) + ("\n" if wf.text.endswith("\n") else "")
    diff = "".join(
        difflib.unified_diff(
            wf.text.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{wf.path}",
            tofile=f"b/{wf.path}",
            n=2,
        )
    )
    valid = True
    try:
        parse_workflow(fixed, wf.path)
    except ValueError:
        valid, fixed, diff, applied = False, wf.text, "", []
    applied.sort(key=lambda a: a["line"])
    return {"path": wf.path, "fixed": fixed, "diff": diff, "applied": applied, "valid": valid}
