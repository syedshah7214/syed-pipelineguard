"""PipelineGuard HTTP API — powers the dashboard and keeps a local history of audits.

Run:  uvicorn pipelineguard.api:app --port 8200
"""

import json
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import __version__
from .analyzer import Options, analyze
from .github_fetch import FetchError, fetch_workflows
from .render import markdown, sarif
from .rules import RULES
from .workflow import MAX_FILE_BYTES, MAX_FILES, WorkflowError

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"
HISTORY_LIMIT = 500
MAX_BODY = MAX_FILE_BYTES * 4

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ('sample', 'upload', 'repo', 'ci')),
    decision    TEXT NOT NULL CHECK (decision IN ('PASS', 'WARN', 'FAIL')),
    score       INTEGER NOT NULL,
    grade       TEXT NOT NULL,
    score_after INTEGER NOT NULL,
    critical    INTEGER NOT NULL,
    high        INTEGER NOT NULL,
    medium      INTEGER NOT NULL,
    low         INTEGER NOT NULL,
    files       INTEGER NOT NULL,
    report      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audits_created ON audits(created_at);
"""

FailOn = Literal["critical", "high", "medium", "low"]


class WorkflowFile(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    content: str = Field(max_length=MAX_FILE_BYTES)


class AnalyzeRequest(BaseModel):
    files: list[WorkflowFile] = Field(min_length=1, max_length=MAX_FILES)
    name: str = Field(default="untitled", min_length=1, max_length=120)
    source: Literal["sample", "upload", "ci"] = "upload"
    fail_on: FailOn = "high"
    save: bool = True


class RepoRequest(BaseModel):
    repo: str = Field(min_length=3, max_length=200)
    ref: str | None = Field(default=None, max_length=200)
    fail_on: FailOn = "high"
    save: bool = True


def create_app(db_path: str | None = None, cors: list[str] | None = None, fetcher=fetch_workflows) -> FastAPI:
    db_path = db_path or os.getenv("PPG_DB_PATH", "pipelineguard.db")
    cors = (
        cors
        if cors is not None
        else [o for o in os.getenv("PPG_CORS_ORIGINS", "http://localhost:5175").split(",") if o]
    )

    def connect() -> sqlite3.Connection:
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        conn = connect()
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()
        yield

    app = FastAPI(
        title="SYED PipelineGuard",
        version=__version__,
        lifespan=lifespan,
        description="Security & performance auditor for GitHub Actions workflows.",
    )
    app.add_middleware(
        CORSMiddleware, allow_origins=cors, allow_methods=["GET", "POST"], allow_headers=["Content-Type"]
    )

    @app.middleware("http")
    async def guard(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY:
            return JSONResponse({"detail": "request is too large"}, status_code=413)
        started = time.perf_counter()
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Server-Timing"] = f"app;dur={(time.perf_counter() - started) * 1000:.1f}"
        return response

    def get_db() -> Iterator[sqlite3.Connection]:
        conn = connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    Db = Annotated[sqlite3.Connection, Depends(get_db)]

    def sample_dirs() -> dict[str, Path]:
        return {p.name: p for p in sorted(SAMPLES_DIR.iterdir()) if p.is_dir()}

    def load_sample(path: Path) -> dict:
        readme = path / "README.txt"
        return {
            "name": path.name,
            "description": readme.read_text(encoding="utf-8").strip() if readme.exists() else "",
            "files": [
                {"path": f".github/workflows/{f.name}", "content": f.read_text(encoding="utf-8")}
                for f in sorted(path.glob("*.y*ml"))
            ],
        }

    def save(conn: sqlite3.Connection, name: str, source: str, report: dict) -> int:
        sev = report["findings_by_severity"]
        cur = conn.execute(
            """INSERT INTO audits(name, source, decision, score, grade, score_after, critical, high, medium, low,
                                  files, report, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                name,
                source,
                report["decision"],
                report["score"],
                report["grade"],
                report["score_after_fixes"],
                sev["critical"],
                sev["high"],
                sev["medium"],
                sev["low"],
                report["totals"]["files"],
                json.dumps(report),
                datetime.now(UTC).isoformat(timespec="seconds"),
            ),
        )
        audit_id = cur.lastrowid
        conn.execute("DELETE FROM audits WHERE id <= ?", (audit_id - HISTORY_LIMIT,))
        return audit_id

    # ------------------------------------------------------------------ ops

    @app.get("/health", tags=["ops"])
    def health() -> dict:
        return {"status": "ok", "version": __version__, "rules": len(RULES)}

    # ------------------------------------------------------------------ reference data

    @app.get("/api/v1/rules", tags=["reference"])
    def rules() -> list[dict]:
        return [r.__dict__ for r in RULES.values()]

    @app.get("/api/v1/samples", tags=["reference"])
    def samples() -> list[dict]:
        out = []
        for path in sample_dirs().values():
            s = load_sample(path)
            out.append({"name": s["name"], "description": s["description"], "files": len(s["files"])})
        return out

    @app.get("/api/v1/samples/{name}", tags=["reference"])
    def sample(name: str) -> dict:
        path = sample_dirs().get(name)
        if not path:
            raise HTTPException(404, f"unknown sample '{name}'")
        return load_sample(path)

    # ------------------------------------------------------------------ analysis

    @app.post("/api/v1/analyze", tags=["audit"])
    def post_analyze(body: AnalyzeRequest, conn: Db) -> dict:
        try:
            report = analyze([f.model_dump() for f in body.files], Options(fail_on=body.fail_on))
        except WorkflowError as exc:
            raise HTTPException(422, str(exc)) from exc
        audit_id = save(conn, body.name, body.source, report) if body.save else None
        return {"id": audit_id, "name": body.name, "report": report}

    @app.post("/api/v1/scan-repo", tags=["audit"])
    def scan_repo(body: RepoRequest, conn: Db) -> dict:
        try:
            fetched = fetcher(body.repo, body.ref)
            report = analyze(fetched["files"], Options(fail_on=body.fail_on))
        except FetchError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        except WorkflowError as exc:
            raise HTTPException(422, str(exc)) from exc
        name = fetched["repo"] + (f"@{body.ref}" if body.ref else "")
        audit_id = save(conn, name, "repo", report) if body.save else None
        return {"id": audit_id, "name": name, "report": report, "skipped": fetched["skipped"]}

    @app.get("/api/v1/audits", tags=["audit"])
    def list_audits(
        conn: Db, limit: Annotated[int, Query(ge=1, le=100)] = 20, offset: Annotated[int, Query(ge=0)] = 0
    ) -> dict:
        total = conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0]
        rows = conn.execute(
            "SELECT id, name, source, decision, score, grade, score_after, critical, high, medium, low, files, "
            "created_at FROM audits ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return {"total": total, "limit": limit, "offset": offset, "items": [dict(r) for r in rows]}

    def _row(conn: sqlite3.Connection, audit_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "audit not found")
        return row

    @app.get("/api/v1/audits/{audit_id}", tags=["audit"])
    def get_audit(audit_id: int, conn: Db) -> dict:
        row = _row(conn, audit_id)
        return {
            "id": row["id"],
            "name": row["name"],
            "source": row["source"],
            "created_at": row["created_at"],
            "report": json.loads(row["report"]),
        }

    @app.get("/api/v1/audits/{audit_id}/markdown", tags=["audit"], response_class=PlainTextResponse)
    def get_markdown(audit_id: int, conn: Db) -> str:
        row = _row(conn, audit_id)
        return markdown(json.loads(row["report"]), f"PipelineGuard · {row['name']}")

    @app.get("/api/v1/audits/{audit_id}/sarif", tags=["audit"])
    def get_sarif(audit_id: int, conn: Db) -> dict:
        return sarif(json.loads(_row(conn, audit_id)["report"]))

    @app.get("/api/v1/stats", tags=["audit"])
    def stats(conn: Db) -> dict:
        r = conn.execute(
            """SELECT COUNT(*) n, SUM(decision='PASS') pass, SUM(decision='WARN') warn, SUM(decision='FAIL') fail,
                      COALESCE(SUM(critical),0) critical, COALESCE(SUM(high),0) high,
                      AVG(score) avg_score, AVG(score_after) avg_after, COALESCE(SUM(files),0) files
               FROM audits"""
        ).fetchone()
        return {
            "audits": r["n"],
            "pass": r["pass"] or 0,
            "warn": r["warn"] or 0,
            "fail": r["fail"] or 0,
            "critical_findings": r["critical"],
            "high_findings": r["high"],
            "workflows_scanned": r["files"],
            "avg_score": round(r["avg_score"]) if r["avg_score"] is not None else None,
            "avg_score_after_fixes": round(r["avg_after"]) if r["avg_after"] is not None else None,
        }

    return app


app = create_app()
