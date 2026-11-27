import pytest
from fastapi.testclient import TestClient

from pipelineguard.api import create_app
from pipelineguard.github_fetch import FetchError

GOOD = "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps: [{run: ls}]\n"


def fake_fetcher(repo, ref=None):
    if repo == "missing/repo":
        raise FetchError("not found", 404)
    return {"repo": repo, "ref": ref, "files": [{"path": ".github/workflows/ci.yml", "content": GOOD}], "skipped": 0}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(str(tmp_path / "t.db"), cors=[], fetcher=fake_fetcher)) as c:
        yield c


def test_health_rules_samples(client):
    assert client.get("/health").json()["rules"] == 24
    rules = client.get("/api/v1/rules").json()
    assert len(rules) == 24 and {"id", "severity", "autofix"} <= set(rules[0])
    samples = client.get("/api/v1/samples").json()
    assert {s["name"] for s in samples} >= {"pwn-request-bot", "hardened-release"}
    body = client.get("/api/v1/samples/pwn-request-bot").json()
    assert body["files"][0]["path"] == ".github/workflows/pr-bot.yml"
    assert client.get("/api/v1/samples/nope").status_code == 404


def test_analyze_history_and_exports(client):
    files = client.get("/api/v1/samples/legacy-node-ci").json()["files"]
    r = client.post("/api/v1/analyze", json={"files": files, "name": "legacy", "source": "sample"})
    assert r.status_code == 200
    body = r.json()
    assert body["report"]["decision"] == "FAIL" and body["id"] == 1
    assert r.headers["x-content-type-options"] == "nosniff"
    client.post("/api/v1/analyze", json={"files": [{"path": "a.yml", "content": GOOD}], "name": "ok"})
    client.post("/api/v1/analyze", json={"files": [{"path": "a.yml", "content": GOOD}], "save": False})
    page = client.get("/api/v1/audits?limit=1").json()
    assert page["total"] == 2 and page["items"][0]["name"] == "ok"
    assert client.get("/api/v1/audits/1").json()["report"]["score"] == body["report"]["score"]
    assert "PipelineGuard · legacy" in client.get("/api/v1/audits/1/markdown").text
    assert client.get("/api/v1/audits/1/sarif").json()["version"] == "2.1.0"
    assert client.get("/api/v1/audits/99").status_code == 404
    st = client.get("/api/v1/stats").json()
    assert st["audits"] == 2 and st["fail"] == 1 and st["pass"] == 1 and st["workflows_scanned"] == 2


def test_validation(client):
    assert client.post("/api/v1/analyze", json={"files": []}).status_code == 422
    bad = client.post("/api/v1/analyze", json={"files": [{"path": "a.yml", "content": "a: ["}]})
    assert bad.status_code == 422 and "invalid YAML" in bad.json()["detail"]
    assert (
        client.post("/api/v1/analyze", json={"files": [{"path": "a", "content": GOOD}], "fail_on": "x"}).status_code
        == 422
    )
    huge = client.post("/api/v1/analyze", content=b"x" * 3_000_000, headers={"content-type": "application/json"})
    assert huge.status_code == 413
    assert client.get("/api/v1/audits?limit=0").status_code == 422


def test_scan_repo(client):
    r = client.post("/api/v1/scan-repo", json={"repo": "octo/demo", "ref": "main"})
    assert r.status_code == 200 and r.json()["name"] == "octo/demo@main"
    assert r.json()["report"]["decision"] == "PASS"
    assert client.post("/api/v1/scan-repo", json={"repo": "missing/repo"}).status_code == 404
    assert client.get("/api/v1/audits").json()["items"][0]["source"] == "repo"
