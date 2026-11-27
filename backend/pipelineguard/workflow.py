"""Parse GitHub Actions workflow YAML into a small, typed model.

The loader keeps the source line of every mapping so findings can point at
`ci.yml:42` instead of "somewhere in the file". It also handles the YAML 1.1
quirk where a bare `on:` key is parsed as the boolean True.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

MAX_FILE_BYTES = 512_000
MAX_FILES = 50
LINE = "__line__"


class WorkflowError(ValueError):
    """Raised when a workflow file cannot be parsed or is not a workflow."""


class _LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _LineLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
    mapping[LINE] = node.start_mark.line + 1
    return mapping


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
# `on`, `yes`, `no` must stay strings: GitHub reads YAML keys like `on:` literally.
_LineLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:bool"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def strip_lines(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: strip_lines(v) for k, v in value.items() if k != LINE}
    if isinstance(value, list):
        return [strip_lines(v) for v in value]
    return value


@dataclass
class Step:
    index: int
    line: int
    name: str | None
    uses: str | None
    run: str | None
    with_: dict[str, Any]
    env: dict[str, Any]
    shell: str | None
    continue_on_error: Any
    raw: dict[str, Any]

    @property
    def label(self) -> str:
        if self.name:
            return str(self.name)
        if self.uses:
            return self.uses
        first = (self.run or "").strip().splitlines()
        return first[0][:60] if first else f"step {self.index + 1}"

    @property
    def action(self) -> str | None:
        """`actions/checkout` for `actions/checkout@v4` (sub-paths kept, ref dropped)."""
        if not self.uses or self.uses.startswith(("./", "docker://")):
            return None
        return self.uses.split("@", 1)[0].lower()

    @property
    def ref(self) -> str | None:
        if not self.uses or "@" not in self.uses:
            return None
        return self.uses.split("@", 1)[1]


@dataclass
class Job:
    id: str
    line: int
    name: str | None
    runs_on: Any
    permissions: Any
    timeout_minutes: Any
    container: Any
    services: dict[str, Any]
    uses: str | None  # reusable workflow call
    secrets: Any
    steps: list[Step]
    strategy: dict[str, Any]
    raw: dict[str, Any]

    @property
    def runner_labels(self) -> list[str]:
        r = self.runs_on
        if isinstance(r, str):
            return [r]
        if isinstance(r, list):
            return [str(x) for x in r]
        if isinstance(r, dict):
            labels = r.get("labels", [])
            labels = [labels] if isinstance(labels, str) else list(labels)
            if r.get("group"):
                labels.append(f"group:{r['group']}")
            return [str(x) for x in labels]
        return []


@dataclass
class Workflow:
    path: str
    text: str
    name: str | None
    triggers: dict[str, Any]
    permissions: Any
    concurrency: Any
    env: dict[str, Any]
    jobs: list[Job] = field(default_factory=list)

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    def has_trigger(self, *names: str) -> bool:
        return any(n in self.triggers for n in names)


def _triggers(on: Any) -> dict[str, Any]:
    if on is None:
        return {}
    if isinstance(on, str):
        return {on: {}}
    if isinstance(on, list):
        return {str(x): {} for x in on}
    if isinstance(on, dict):
        return {str(k): (v if v is not None else {}) for k, v in on.items() if k != LINE}
    raise WorkflowError("`on:` must be a string, list or mapping")


def _step(i: int, s: Any) -> Step:
    if not isinstance(s, dict):
        raise WorkflowError(f"step {i + 1} is not a mapping")
    return Step(
        index=i,
        line=s.get(LINE, 0),
        name=s.get("name"),
        uses=str(s["uses"]).strip() if s.get("uses") else None,
        run=str(s["run"]) if s.get("run") is not None else None,
        with_={k: v for k, v in (s.get("with") or {}).items() if k != LINE},
        env={k: v for k, v in (s.get("env") or {}).items() if k != LINE},
        shell=s.get("shell"),
        continue_on_error=s.get("continue-on-error"),
        raw=s,
    )


def _job(job_id: str, j: Any) -> Job:
    if not isinstance(j, dict):
        raise WorkflowError(f"job '{job_id}' is not a mapping")
    steps = j.get("steps") or []
    if not isinstance(steps, list):
        raise WorkflowError(f"job '{job_id}': steps must be a list")
    return Job(
        id=str(job_id),
        line=j.get(LINE, 0),
        name=j.get("name"),
        runs_on=strip_lines(j.get("runs-on")),
        permissions=strip_lines(j.get("permissions")),
        timeout_minutes=j.get("timeout-minutes"),
        container=strip_lines(j.get("container")),
        services={k: strip_lines(v) for k, v in (j.get("services") or {}).items() if k != LINE},
        uses=j.get("uses"),
        secrets=strip_lines(j.get("secrets")),
        steps=[_step(i, s) for i, s in enumerate(steps)],
        strategy=strip_lines(j.get("strategy") or {}),
        raw=j,
    )


def parse_workflow(text: str, path: str = "workflow.yml") -> Workflow:
    if not isinstance(text, str) or not text.strip():
        raise WorkflowError(f"{path}: file is empty")
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise WorkflowError(f"{path}: file is larger than {MAX_FILE_BYTES // 1000} KB")
    try:
        data = yaml.load(text, Loader=_LineLoader)  # noqa: S506 — SafeLoader subclass
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark else ""
        raise WorkflowError(f"{path}: invalid YAML{where}") from exc
    if not isinstance(data, dict):
        raise WorkflowError(f"{path}: top level must be a mapping")
    if "jobs" not in data or not isinstance(data["jobs"], dict) or not [k for k in data["jobs"] if k != LINE]:
        raise WorkflowError(f"{path}: not a GitHub Actions workflow (no `jobs:`)")
    jobs = [_job(k, v) for k, v in data["jobs"].items() if k != LINE]
    return Workflow(
        path=path,
        text=text,
        name=data.get("name"),
        triggers=_triggers(strip_lines(data.get("on"))),
        permissions=strip_lines(data.get("permissions")),
        concurrency=strip_lines(data.get("concurrency")),
        env={k: v for k, v in (data.get("env") or {}).items() if k != LINE},
        jobs=jobs,
    )
