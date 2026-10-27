"""Storage backends: one JSON file per asset under ``entries/``.

``GitHubStore`` writes through the GitHub contents API, so every mutation is
a commit on the data repository. ``LocalStore`` is the same contract on a
directory, for tests and offline use. Both use optimistic concurrency: a write
carries the version it read and fails with ``Conflict`` if the file changed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import urllib.error
import urllib.request
from pathlib import Path

_ID = re.compile(r"^ast-[0-9a-f]{12}$")


class Conflict(RuntimeError):
    pass


class StoreError(RuntimeError):
    """Backend unreachable or refused; the mutation outcome may be unknown."""


def encode(record: dict) -> bytes:
    return (json.dumps(record, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode("utf-8")


def _check_id(asset_id: str) -> None:
    if not _ID.match(asset_id):
        raise ValueError("invalid asset id")


class LocalStore:
    def __init__(self, root: Path):
        self.entries = Path(root) / "entries"
        self.entries.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def list_records(self) -> list[dict]:
        return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.entries.glob("ast-*.json"))]

    def get(self, asset_id: str) -> tuple[dict | None, str | None]:
        _check_id(asset_id)
        path = self.entries / f"{asset_id}.json"
        if not path.exists():
            return None, None
        data = path.read_bytes()
        return json.loads(data), hashlib.sha256(data).hexdigest()

    def put(self, record: dict, version: str | None, message: str) -> str:
        _check_id(record["id"])
        path = self.entries / f"{record['id']}.json"
        with self._lock:
            current = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
            if current != version:
                raise Conflict(record["id"])
            data = encode(record)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, path)
            return hashlib.sha256(data).hexdigest()


class GitHubStore:
    API = "https://api.github.com"

    def __init__(self, repo: str, branch: str = "main", *, token: str | None = None, token_file: str | None = None, timeout: float = 15.0):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("repo must be owner/name")
        self.repo = repo
        self.branch = branch
        self._token = token
        self._token_file = token_file
        self.timeout = timeout
        self._blob_cache: dict[str, dict] = {}
        self._cache_lock = threading.Lock()

    def _auth(self) -> str:
        # The file is re-read on each call so a rotated token needs no restart.
        token = Path(self._token_file).read_text(encoding="utf-8").strip() if self._token_file else self._token
        if not token:
            raise StoreError("GitHub token not configured")
        return token

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(
            self.API + path,
            method=method,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            headers={
                "Authorization": f"Bearer {self._auth()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "llmgram-assets-mcp",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise FileNotFoundError(path) from None
            if exc.code in (409, 422) and method == "PUT":
                raise Conflict(path) from None
            raise StoreError(f"GitHub HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise StoreError(f"GitHub unreachable: {type(exc).__name__}") from None

    def list_records(self) -> list[dict]:
        with self._cache_lock:
            return self._list_records()

    def _list_records(self) -> list[dict]:
        tree = self._call("GET", f"/repos/{self.repo}/git/trees/{self.branch}?recursive=1")
        if tree.get("truncated"):
            raise StoreError("repository tree truncated")
        records, seen = [], set()
        for item in tree.get("tree", []):
            path = item.get("path", "")
            if item.get("type") != "blob" or not re.fullmatch(r"entries/ast-[0-9a-f]{12}\.json", path):
                continue
            sha = item["sha"]
            seen.add(sha)
            if sha not in self._blob_cache:
                blob = self._call("GET", f"/repos/{self.repo}/git/blobs/{sha}")
                self._blob_cache[sha] = json.loads(base64.b64decode(blob["content"]))
            records.append(self._blob_cache[sha])
        for sha in set(self._blob_cache) - seen:
            del self._blob_cache[sha]
        return records

    def get(self, asset_id: str) -> tuple[dict | None, str | None]:
        _check_id(asset_id)
        try:
            data = self._call("GET", f"/repos/{self.repo}/contents/entries/{asset_id}.json?ref={self.branch}")
        except FileNotFoundError:
            return None, None
        return json.loads(base64.b64decode(data["content"])), data["sha"]

    def put(self, record: dict, version: str | None, message: str) -> str:
        _check_id(record["id"])
        body = {
            "message": message,
            "content": base64.b64encode(encode(record)).decode("ascii"),
            "branch": self.branch,
        }
        if version:
            body["sha"] = version
        result = self._call("PUT", f"/repos/{self.repo}/contents/entries/{record['id']}.json", body)
        return result["content"]["sha"]


class GitStore:
    """Clone of the data repository; every write is a commit pushed to origin.

    Meant for a server holding a write deploy key scoped to this repository
    only (``ssh_key``). Reads fetch at most every ``fetch_interval`` seconds;
    writes always fetch first, so a rejected push means someone else wrote and
    is reported as ``Conflict``.
    """

    def __init__(self, checkout: Path, *, branch: str = "main", ssh_key: str | None = None,
                 fetch_interval: float = 60.0, author: str = "llmgram-assets MCP <assets@llmgram.app>"):
        self.checkout = Path(checkout)
        self.entries = self.checkout / "entries"
        self.branch = branch
        self.fetch_interval = fetch_interval
        self.author_name, _, email = author.partition(" <")
        self.author_email = email.rstrip(">")
        self._env = dict(os.environ)
        if ssh_key:
            self._env["GIT_SSH_COMMAND"] = f"ssh -i {ssh_key} -o IdentitiesOnly=yes -o BatchMode=yes"
        self._lock = threading.Lock()
        self._fetched_at = 0.0
        if not (self.checkout / ".git").exists():
            raise StoreError("checkout is not a git repository")

    def _git(self, *args: str) -> str:
        import subprocess

        try:
            result = subprocess.run(["git", "-C", str(self.checkout), *args], env=self._env,
                                    capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise StoreError(f"git {args[0]} failed: {type(exc).__name__}") from None
        if result.returncode != 0:
            raise StoreError(f"git {args[0]} failed: {result.stderr.strip()[-300:]}")
        return result.stdout

    def _sync(self, force: bool = False) -> None:
        import time

        if not force and time.monotonic() - self._fetched_at < self.fetch_interval:
            return
        self._git("fetch", "--quiet", "origin", self.branch)
        self._git("reset", "--quiet", "--hard", f"origin/{self.branch}")
        self._fetched_at = time.monotonic()

    def _read(self, asset_id: str) -> tuple[dict | None, str | None]:
        path = self.entries / f"{asset_id}.json"
        if not path.exists():
            return None, None
        data = path.read_bytes()
        return json.loads(data), hashlib.sha256(data).hexdigest()

    def list_records(self) -> list[dict]:
        with self._lock:
            self._sync()
            return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.entries.glob("ast-*.json"))]

    def get(self, asset_id: str) -> tuple[dict | None, str | None]:
        _check_id(asset_id)
        with self._lock:
            self._sync()
            return self._read(asset_id)

    def put(self, record: dict, version: str | None, message: str) -> str:
        _check_id(record["id"])
        rel = f"entries/{record['id']}.json"
        with self._lock:
            self._sync(force=True)
            if self._read(record["id"])[1] != version:
                raise Conflict(record["id"])
            self.entries.mkdir(exist_ok=True)
            data = encode(record)
            (self.checkout / rel).write_bytes(data)
            self._git("add", rel)
            self._git("-c", f"user.name={self.author_name}", "-c", f"user.email={self.author_email}",
                      "commit", "--quiet", "-m", message)
            try:
                self._git("push", "--quiet", "origin", f"HEAD:{self.branch}")
            except StoreError as exc:
                rejected = any(k in str(exc) for k in ("rejected", "fetch first", "non-fast-forward"))
                self._fetched_at = 0.0  # resync (and drop the local commit) on next access
                if rejected:
                    try:
                        self._sync(force=True)
                    except StoreError:
                        pass
                    raise Conflict(record["id"]) from None
                raise
            return hashlib.sha256(data).hexdigest()
