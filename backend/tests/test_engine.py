import base64
import io
import json
import textwrap
import urllib.error
from pathlib import Path

import pytest
import yaml

from pipelineguard.analyzer import Options, analyze, grade_of, score_of
from pipelineguard.cli import main
from pipelineguard.github_fetch import FetchError, fetch_workflows, parse_repo
from pipelineguard.render import markdown, sarif, text
from pipelineguard.rules import RULES
from pipelineguard.workflow import WorkflowError, parse_workflow

SAMPLES = Path(__file__).resolve().parents[1] / "pipelineguard" / "samples"


def wf(src: str, path: str = "w.yml") -> list[dict]:
    return [{"path": path, "content": textwrap.dedent(src)}]


def ids(report: dict) -> set[str]:
    return {f["rule_id"] for f in report["findings"]}


def sample(name: str) -> dict:
    files = [{"path": f".github/workflows/{p.name}", "content": p.read_text()} for p in (SAMPLES / name).glob("*.yml")]
    return analyze(files)


# ------------------------------------------------------------------ parsing


def test_on_key_is_not_parsed_as_boolean():
    w = parse_workflow("on: [push, pull_request]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: [{run: ls}]\n")
    assert set(w.triggers) == {"push", "pull_request"}
    assert w.jobs[0].steps[0].line == 5


@pytest.mark.parametrize(
    "src,msg",
    [("", "empty"), ("a: [", "invalid YAML"), ("- 1", "top level"), ("name: x\non: push\n", "no `jobs:`")],
)
def test_parse_errors(src, msg):
    with pytest.raises(WorkflowError, match=msg):
        parse_workflow(src)


def test_all_files_invalid_raises_but_partial_failure_fails_gate():
    with pytest.raises(WorkflowError):
        analyze([{"path": "a.yml", "content": "a: ["}])
    good = "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps: [{run: ls}]\n"
    r = analyze([{"path": "a.yml", "content": "a: ["}, {"path": "b.yml", "content": good}])
    assert r["decision"] == "FAIL" and "could not be parsed" in r["reasons"][0]


# ------------------------------------------------------------------ samples


@pytest.mark.parametrize(
    "name,decision,must",
    [
        ("pwn-request-bot", "FAIL", {"PPG-SEC-001", "PPG-SEC-002", "PPG-SEC-005"}),
        ("legacy-node-ci", "FAIL", {"PPG-SUP-001", "PPG-REL-001", "PPG-REL-002", "PPG-REL-003", "PPG-REL-004"}),
        (
            "self-hosted-leak",
            "FAIL",
            {"PPG-SEC-003", "PPG-SEC-004", "PPG-SEC-007", "PPG-SEC-008", "PPG-SEC-009", "PPG-SEC-011", "PPG-SUP-003"},
        ),
        ("slow-monorepo-ci", "WARN", {"PPG-PERF-001", "PPG-PERF-003", "PPG-PERF-004", "PPG-PERF-005"}),
        ("hardened-release", "PASS", set()),
    ],
)
def test_samples(name, decision, must):
    r = sample(name)
    assert r["decision"] == decision
    assert must <= ids(r)


def test_hardened_sample_has_only_low_findings():
    r = sample("hardened-release")
    assert {f["severity"] for f in r["findings"]} <= {"low"} and r["grade"] == "A"


def test_every_rule_fires_somewhere_in_the_samples():
    fired = set().union(*(ids(sample(p.name)) for p in SAMPLES.iterdir() if p.is_dir()))
    extra = analyze(
        wf("""
        on: push
        jobs:
          rel:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/create-release@v1
              - uses: docker://alpine
        """)
    )
    fired |= ids(extra)
    assert set(RULES) - fired == set()


# ------------------------------------------------------------------ individual rules


def test_injection_ignores_safe_contexts_and_env_usage():
    r = analyze(
        wf("""
        on: pull_request
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - env:
                  T: ${{ github.event.pull_request.title }}
                run: echo "$T ${{ github.sha }} ${{ github.event.pull_request.number }} ${{ github.event.repository.name }}"
        """)
    )
    assert "PPG-SEC-002" not in ids(r)


def test_pwn_request_needs_head_checkout():
    base = """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                {extra}
        """
    assert "PPG-SEC-001" not in ids(analyze(wf(base.format(extra=""))))
    head = "with: {ref: '${{ github.event.pull_request.head.ref }}'}"
    assert "PPG-SEC-001" in ids(analyze(wf(base.format(extra=head))))


def test_sha_pinned_third_party_is_clean_and_git_push_keeps_credentials():
    r = analyze(
        wf("""
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: docker/setup-buildx-action@b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2 # v3.10.0
              - run: git push origin HEAD
        """)
    )
    assert not {"PPG-SUP-001", "PPG-SEC-010"} & ids(r)


def test_cache_not_flagged_when_enabled_or_not_installing():
    r = analyze(
        wf("""
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/setup-node@v4
                with: {cache: npm}
              - run: npm ci
          b:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/setup-python@v5
              - run: python -c 'print(1)'
        """)
    )
    assert "PPG-PERF-001" not in ids(r)


def test_secret_value_is_masked_in_detail():
    key = "AKIA" + "Q3EXAMPLE7MZ4TNH"
    r = analyze(wf(f"on: push\nenv:\n  K: {key}\njobs:\n  a:\n    runs-on: x\n    steps: [{{run: ls}}]\n"))
    f = next(f for f in r["findings"] if f["rule_id"] == "PPG-SEC-003")
    assert key not in f["detail"] and f["line"] == 3


# ------------------------------------------------------------------ scoring & gate


def test_scoring_and_grades():
    assert score_of([{"severity": "critical"}] * 5) == 0
    assert score_of([{"severity": "medium"}, {"severity": "low"}]) == 93
    assert [grade_of(s) for s in (95, 85, 70, 55, 10)] == list("ABCDF")


def test_fail_on_threshold():
    r = sample("slow-monorepo-ci")
    assert r["decision"] == "WARN"
    assert (
        analyze(
            [{"path": "x.yml", "content": (SAMPLES / "slow-monorepo-ci/test-matrix.yml").read_text()}],
            Options(fail_on="medium"),
        )["decision"]
        == "FAIL"
    )
    with pytest.raises(ValueError):
        Options(fail_on="nope")


# ------------------------------------------------------------------ autofix


@pytest.mark.parametrize("name", ["pwn-request-bot", "legacy-node-ci", "self-hosted-leak", "slow-monorepo-ci"])
def test_autofix_output_is_valid_and_better(name):
    r = sample(name)
    assert r["fixes"]
    for fx in r["fixes"]:
        assert fx["valid"]
        yaml.safe_load(fx["fixed"])
        assert fx["score_after"] >= fx["score_before"]
        assert fx["diff"].startswith("--- a/")
        after = ids(analyze([{"path": fx["path"], "content": fx["fixed"]}], Options(autofix=False)))
        fixed_rules = {a["rule_id"] for a in fx["applied"]}
        assert not (fixed_rules - {"PPG-SEC-002"}) & after


def test_autofix_injection_moves_input_to_env():
    r = sample("pwn-request-bot")
    fixed = r["fixes"][0]["fixed"]
    doc = yaml.safe_load(fixed)
    greet = doc["jobs"]["triage"]["steps"][1]
    assert greet["env"]["PULL_REQUEST_TITLE"] == "${{ github.event.pull_request.title }}"
    assert "${{" not in greet["run"]


def test_autofix_splits_bare_run_item():
    r = analyze(
        wf("""
        on: pull_request
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            timeout-minutes: 5
            steps:
              - run: echo "${{ github.head_ref }}"
        """)
    )
    step = yaml.safe_load(r["fixes"][0]["fixed"])["jobs"]["a"]["steps"][0]
    assert step == {"env": {"HEAD_REF": "${{ github.head_ref }}"}, "run": 'echo "${HEAD_REF}"'}


def test_autofix_can_be_disabled():
    files = [{"path": "a.yml", "content": (SAMPLES / "legacy-node-ci/ci.yml").read_text()}]
    assert analyze(files, Options(autofix=False))["fixes"] == []


# ------------------------------------------------------------------ renderers


def test_renderers():
    r = sample("self-hosted-leak")
    assert "FAIL" in text(r)
    md = markdown(r, "T")
    assert md.startswith("### ⛔ T: **FAIL**") and "PPG-SEC-003" in md
    s = sarif(r)
    run = s["runs"][0]
    assert s["version"] == "2.1.0" and len(run["results"]) == len(r["findings"])
    assert {x["id"] for x in run["tool"]["driver"]["rules"]} == ids(r)
    assert all(x["properties"]["security-severity"] for x in run["tool"]["driver"]["rules"])


# ------------------------------------------------------------------ CLI


def test_cli_exit_codes_and_outputs(tmp_path, capsys, monkeypatch):
    assert main([str(SAMPLES / "hardened-release")]) == 0
    assert "PASS" in capsys.readouterr().out
    assert main([str(SAMPLES / "pwn-request-bot"), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["decision"] == "FAIL"
    assert main([str(tmp_path / "missing")]) == 2
    out = tmp_path / "r.sarif"
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    code = main(
        [
            str(SAMPLES / "legacy-node-ci"),
            "--format",
            "sarif",
            "--output",
            str(out),
            "--summary",
            "--write-fixes",
            str(tmp_path / "fixed"),
        ]
    )
    assert code == 1
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert "PipelineGuard" in summary.read_text()
    assert (tmp_path / "fixed" / "ci.yml").exists()
    assert "::error file=" in capsys.readouterr().out


# ------------------------------------------------------------------ GitHub fetch


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_opener(routes):
    def opener(req, timeout):
        url = req.full_url
        for key, value in routes.items():
            if key in url:
                if isinstance(value, Exception):
                    raise value
                return FakeResp(json.dumps(value).encode())
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)

    return opener


def test_parse_repo():
    assert parse_repo("https://github.com/actions/checkout.git") == ("actions", "checkout")
    assert parse_repo("octo/hello-world") == ("octo", "hello-world")
    for bad in ("nope", "../x/y", "a/..", "https://evil.com/a/b c"):
        with pytest.raises(FetchError):
            parse_repo(bad)


def test_fetch_workflows_ok_and_errors():
    content = base64.b64encode(b"on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: ls}]\n").decode()
    routes = {
        "/contents/.github/workflows/ci.yml": {"encoding": "base64", "content": content},
        "/contents/.github/workflows": [
            {"type": "file", "name": "ci.yml", "path": ".github/workflows/ci.yml", "size": 50},
            {"type": "file", "name": "README.md", "path": ".github/workflows/README.md", "size": 5},
        ],
    }
    got = fetch_workflows("o/r", "main", opener=fake_opener(routes))
    assert got["repo"] == "o/r" and len(got["files"]) == 1 and "jobs" in got["files"][0]["content"]
    with pytest.raises(FetchError) as e:
        fetch_workflows("o/r", opener=fake_opener({}))
    assert e.value.status == 404
    limited = urllib.error.HTTPError("u", 403, "rate", {}, None)
    with pytest.raises(FetchError) as e:
        fetch_workflows("o/r", opener=fake_opener({"/contents/": limited}))
    assert e.value.status == 429
    with pytest.raises(FetchError):
        fetch_workflows("o/r", "bad ref!", opener=fake_opener(routes))


def test_fetch_depth_allowed_for_secret_scanners():
    r = analyze(wf("""
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with: {fetch-depth: 0}
              - uses: gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7
        """))
    assert "PPG-PERF-004" not in ids(r)
