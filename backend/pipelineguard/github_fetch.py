"""Fetch the workflow files of a PUBLIC GitHub repository (read-only).

Uses the REST contents API. An optional server-side GITHUB_TOKEN raises the rate
limit from 60 to 5,000 requests/hour; it is never sent to the browser and only
needs public read access.
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import quote

from .workflow import MAX_FILE_BYTES, MAX_FILES

API = "https://api.github.com"
NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


class FetchError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def parse_repo(value: str) -> tuple[str, str]:
    v = value.strip().removesuffix(".git").rstrip("/")
    v = re.sub(r"^(https?://)?(www\.)?github\.com/", "", v)
    parts = v.split("/")
    if len(parts) < 2 or not NAME_RE.match(parts[0]) or not REPO_RE.match(parts[1]) or parts[1] in (".", ".."):
        raise FetchError("use the form owner/repo or https://github.com/owner/repo", 422)
    return parts[0], parts[1]


def _get(url: str, opener=urllib.request.urlopen) -> object:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "syed-pipelineguard",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 — fixed https host
    try:
        with opener(req, timeout=10) as res:
            return json.loads(res.read(MAX_FILE_BYTES * 2).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise FetchError(
                "repository, ref or .github/workflows not found (private repos are not supported)", 404
            ) from exc
        if exc.code in (403, 429):
            raise FetchError(
                "GitHub API rate limit reached — try again later or set GITHUB_TOKEN on the server", 429
            ) from exc
        raise FetchError(f"GitHub API responded {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError("could not reach api.github.com") from exc


def fetch_workflows(repo: str, ref: str | None = None, opener=urllib.request.urlopen) -> dict:
    owner, name = parse_repo(repo)
    if ref and not REF_RE.match(ref):
        raise FetchError("invalid ref", 422)
    q = f"?ref={quote(ref, safe='')}" if ref else ""
    listing = _get(f"{API}/repos/{owner}/{name}/contents/.github/workflows{q}", opener)
    if not isinstance(listing, list):
        raise FetchError(".github/workflows is not a directory", 422)
    entries = [e for e in listing if e.get("type") == "file" and str(e.get("name", "")).endswith((".yml", ".yaml"))]
    if not entries:
        raise FetchError("no workflow files in .github/workflows", 404)
    files = []
    for e in entries[:MAX_FILES]:
        if int(e.get("size", 0)) > MAX_FILE_BYTES:
            continue
        body = _get(f"{API}/repos/{owner}/{name}/contents/{quote(e['path'])}{q}", opener)
        if not isinstance(body, dict) or body.get("encoding") != "base64":
            continue
        files.append({"path": e["path"], "content": base64.b64decode(body["content"]).decode("utf-8", "replace")})
    return {"repo": f"{owner}/{name}", "ref": ref, "files": files, "skipped": max(0, len(entries) - len(files))}
