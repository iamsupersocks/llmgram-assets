import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from llmgram_assets import model
from llmgram_assets.linkcheck import LinkResult
from llmgram_assets.mcp_server import Handler, RateLimiter, TokenBook, dispatch, make_http_handler
from llmgram_assets.service import AssetService, ToolError
import subprocess

from llmgram_assets.store import GitHubStore, GitStore, LocalStore, StoreError
from http.server import ThreadingHTTPServer


def op():
    return str(uuid.uuid4())


COMPLETE = {
    "name": "Example Kit",
    "summary": "A free kit of low-poly props.",
    "category": "3d-models",
    "tags": ["Low Poly", "glb"],
    "publisher": {"name": "Example", "url": "https://example.com"},
    "resource_url": "https://www.example.com/kit/?utm_source=x",
    "download_url": "https://example.com/kit/download",
    "access": {"model": "free", "license": "CC0-1.0", "commercial_use": "yes", "signup_required": False},
    "procedure": ["Open the kit page", "Click Download"],
    "stats": {"count": "120 models", "formats": ["GLB", "GLB", "FBX"]},
    "source": {"url": "https://x.com/example/status/1", "author": "@example", "published_at": "2026-10-27T15:05:40Z", "kind": "x_post"},
    "verdict": {"score": 80, "why": "Useful and truly free."},
}


class FakeChecker:
    def __init__(self):
        self.dead = set()
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        if url in self.dead:
            return LinkResult(False, 404, "http error")
        return LinkResult(True, 200, "reachable")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = LocalStore(Path(self.tmp.name))
        self.checker = FakeChecker()
        self.service = AssetService(self.store, checker=self.checker, clock=lambda: "2026-10-27T16:00:00Z")

    def tearDown(self):
        self.tmp.cleanup()


class ModelTests(unittest.TestCase):
    def test_rejects_unsafe_urls(self):
        for bad in ("http://example.com", "https://localhost/x", "https://127.0.0.1/", "https://10.0.0.2/",
                    "https://user:pw@example.com/", "javascript:alert(1)", "https://intranet/"):
            with self.subTest(url=bad), self.assertRaises(model.ValidationError):
                model.clean_url(bad, "url", required=True)

    def test_canonical_key_ignores_www_slash_and_tracking(self):
        a = model.asset_id_for(model.clean_url("https://www.example.com/kit/?utm_source=x&s=20", "u"))
        b = model.asset_id_for(model.clean_url("https://example.com/kit", "u"))
        self.assertEqual(a, b)

    def test_rejects_unknown_keys_and_bad_enums(self):
        with self.assertRaises(model.ValidationError):
            model.normalize_fields({**COMPLETE, "status": "published"}, partial=False)
        with self.assertRaises(model.ValidationError):
            model.normalize_fields({**COMPLETE, "category": "nft"}, partial=False)
        with self.assertRaises(model.ValidationError):
            model.normalize_fields({**COMPLETE, "access": {"model": "free", "secret": 1}}, partial=False)

    def test_strips_control_and_bidi_characters(self):
        out = model.normalize_fields({**COMPLETE, "name": "Kit‮\x00 name"}, partial=False)
        self.assertEqual(out["name"], "Kit name")


class ServiceTests(Base):
    def test_complete_submission_is_published(self):
        receipt = self.service.submit({"operation_id": op(), "asset": COMPLETE}, "grokbot")
        self.assertEqual(receipt["result"], "created")
        self.assertEqual(receipt["status"], "published")
        self.assertEqual(receipt["missing"], [])
        record, _ = self.store.get(receipt["asset_id"])
        self.assertEqual(record["tags"], ["low-poly", "glb"])
        self.assertEqual(record["stats"]["formats"], ["GLB", "FBX"])
        self.assertEqual(record["added_by"], "grokbot")
        self.assertEqual(model.validate_record(record), [])

    def test_incomplete_submission_stays_candidate(self):
        asset = {k: v for k, v in COMPLETE.items() if k not in ("access", "procedure")}
        receipt = self.service.submit({"operation_id": op(), "asset": asset}, "grokbot")
        self.assertEqual(receipt["status"], "candidate")
        self.assertEqual(receipt["missing"], ["access.model", "access.license", "procedure"])

    def test_dead_link_keeps_candidate(self):
        self.checker.dead.add("https://example.com/kit/download")
        receipt = self.service.submit({"operation_id": op(), "asset": COMPLETE}, "grokbot")
        self.assertEqual(receipt["status"], "candidate")
        self.assertIn("verification.download_url", receipt["missing"])

    def test_replay_and_duplicate(self):
        oid = op()
        first = self.service.submit({"operation_id": oid, "asset": COMPLETE}, "grokbot")
        again = self.service.submit({"operation_id": oid, "asset": COMPLETE}, "grokbot")
        self.assertTrue(again["replayed"])
        self.assertEqual(again["asset_id"], first["asset_id"])
        dup = self.service.submit({"operation_id": op(), "asset": {**COMPLETE, "name": "Other"}}, "grokbot")
        self.assertEqual(dup["result"], "duplicate")
        with self.assertRaises(ToolError):
            self.service.submit({"operation_id": oid, "asset": {**COMPLETE, "name": "Changed"}}, "grokbot")

    def test_operation_id_must_be_uuid(self):
        with self.assertRaises(ToolError):
            self.service.submit({"operation_id": "abc", "asset": COMPLETE}, "grokbot")

    def test_update_completes_candidate(self):
        asset = {k: v for k, v in COMPLETE.items() if k != "access"}
        rid = self.service.submit({"operation_id": op(), "asset": asset}, "grokbot")["asset_id"]
        part = self.service.update({"operation_id": op(), "asset_id": rid, "changes": {"access": {"model": "free"}}}, "grokbot")
        self.assertEqual(part["missing"], ["access.license"])
        done = self.service.update({"operation_id": op(), "asset_id": rid, "changes": {"access": {"license": "CC0-1.0"}}}, "grokbot")
        self.assertEqual(done["status"], "published")
        record, _ = self.store.get(rid)
        self.assertEqual(record["access"]["model"], "free")
        with self.assertRaises(ToolError):
            self.service.update({"operation_id": op(), "asset_id": rid, "changes": {"resource_url": "https://other.com"}}, "grokbot")

    def test_flags(self):
        rid = self.service.submit({"operation_id": op(), "asset": COMPLETE}, "grokbot")["asset_id"]
        flagged = self.service.flag({"operation_id": op(), "asset_id": rid, "reason": "now_paid", "note": "Paywalled since today"}, "grokbot")
        self.assertEqual(flagged["status"], "flagged")
        fixed = self.service.update({"operation_id": op(), "asset_id": rid, "changes": {"access": {"model": "paid", "price": "$5"}}}, "grokbot")
        self.assertEqual(fixed["status"], "published")
        self.service.flag({"operation_id": op(), "asset_id": rid, "reason": "unsafe"}, "grokbot")
        still = self.service.update({"operation_id": op(), "asset_id": rid, "changes": {"summary": "Edited"}}, "grokbot")
        self.assertEqual(still["status"], "flagged")
        record, _ = self.store.get(rid)
        self.assertEqual(model.validate_record(record), [])

    def test_search(self):
        self.service.submit({"operation_id": op(), "asset": COMPLETE}, "grokbot")
        other = {**COMPLETE, "name": "Sound pack", "summary": "Foley sounds.", "category": "audio-sfx", "resource_url": "https://sounds.example.org/pack"}
        self.service.submit({"operation_id": op(), "asset": other}, "grokbot")
        self.assertEqual(self.service.search({"query": "kit"})["total"], 1)
        self.assertEqual(self.service.search({"category": "audio-sfx"})["items"][0]["name"], "Sound pack")
        page = self.service.search({"limit": 1})
        self.assertEqual(page["next_cursor"], "1")
        found = self.service.get({"url": "https://example.com/kit"})
        self.assertTrue(found["found"])

    def test_store_failure_is_ambiguous_and_retry_is_safe(self):
        class Flaky(LocalStore):
            fail = True

            def put(self, record, version, message):
                if self.fail:
                    self.fail = False
                    raise StoreError("GitHub unreachable: TimeoutError")
                return super().put(record, version, message)

        service = AssetService(Flaky(Path(self.tmp.name) / "flaky"), checker=self.checker)
        oid = op()
        self.assertEqual(service.submit({"operation_id": oid, "asset": COMPLETE}, "grokbot")["result"], "ambiguous")
        self.assertEqual(service.submit({"operation_id": oid, "asset": COMPLETE}, "grokbot")["result"], "created")


class GitHubStoreTests(unittest.TestCase):
    def test_put_and_get_use_contents_api(self):
        store = GitHubStore("iamsupersocks/llmgram-assets", token="t")
        calls = []

        def fake(method, path, body=None):
            calls.append((method, path, body))
            if method == "PUT":
                return {"content": {"sha": "new"}}
            raise FileNotFoundError(path)

        store._call = fake
        record = {"id": "ast-0123456789ab", "name": "x"}
        self.assertEqual(store.get("ast-0123456789ab"), (None, None))
        self.assertEqual(store.put(record, None, "msg"), "new")
        method, path, body = calls[-1]
        self.assertEqual(path, "/repos/iamsupersocks/llmgram-assets/contents/entries/ast-0123456789ab.json")
        self.assertNotIn("sha", body)
        with self.assertRaises(ValueError):
            store.get("../../etc")


class GitStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.origin = root / "origin.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True)
        seed = root / "seed"
        subprocess.run(["git", "clone", "-q", str(self.origin), str(seed)], check=True)
        (seed / "entries").mkdir()
        (seed / "entries" / ".keep").write_text("")
        git = ["git", "-C", str(seed), "-c", "user.name=t", "-c", "user.email=t@t"]
        subprocess.run(git + ["add", "."], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "init"], check=True)
        subprocess.run(git + ["push", "-q", "origin", "HEAD:main"], check=True)
        self.clones = []
        for name in ("a", "b"):
            path = root / name
            subprocess.run(["git", "clone", "-q", str(self.origin), str(path)], check=True)
            self.clones.append(GitStore(path, fetch_interval=0))

    def tearDown(self):
        self.tmp.cleanup()

    def test_writes_are_pushed_commits_and_conflicts_detected(self):
        a, b = self.clones
        svc_a = AssetService(a, checker=FakeChecker())
        svc_b = AssetService(b, checker=FakeChecker())
        rid = svc_a.submit({"operation_id": op(), "asset": COMPLETE}, "grokbot")["asset_id"]
        self.assertEqual(svc_b.get({"asset_id": rid})["asset"]["name"], "Example Kit")
        _, version = b.get(rid)
        svc_a.update({"operation_id": op(), "asset_id": rid, "changes": {"summary": "From A"}}, "grokbot")
        record, _ = b.get(rid)
        with self.assertRaises(Exception):
            b.put({**record, "summary": "stale"}, version, "stale write")
        out = svc_b.update({"operation_id": op(), "asset_id": rid, "changes": {"name": "From B"}}, "grokbot")
        self.assertEqual(out["result"], "updated")
        final, _ = a.get(rid)
        self.assertEqual((final["name"], final["summary"]), ("From B", "From A"))
        log = subprocess.run(["git", "--git-dir", str(self.origin), "log", "--format=%s%n%b"], capture_output=True, text=True).stdout
        self.assertIn("Operation-Id:", log)


class TransportTests(Base):
    def setUp(self):
        super().setUp()
        self.handler = Handler(AssetService(self.store, checker=self.checker), RateLimiter(3))

    def test_jsonrpc_flow(self):
        init = dispatch(self.handler, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}, "local")
        self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
        self.assertIsNone(dispatch(self.handler, {"jsonrpc": "2.0", "method": "notifications/initialized"}, "local"))
        tools = dispatch(self.handler, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, "local")["result"]["tools"]
        self.assertEqual({t["name"] for t in tools}, {"asset_search", "asset_get", "asset_submit", "asset_update", "asset_flag"})
        bad = dispatch(self.handler, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "asset_submit", "arguments": {"operation_id": "x"}}}, "local")
        self.assertTrue(bad["result"]["isError"])

    def test_rate_limit(self):
        for i in range(3):
            asset = {**COMPLETE, "resource_url": f"https://example.com/kit{i}"}
            self.handler.call("asset_submit", {"operation_id": op(), "asset": asset}, "grokbot")
        out = self.handler.call("asset_submit", {"operation_id": op(), "asset": COMPLETE}, "grokbot")
        self.assertTrue(out["isError"])

    def test_http_requires_token_and_records_actor(self):
        token = "secret-token"
        tokens = Path(self.tmp.name) / "tokens.json"
        tokens.write_text(json.dumps({hashlib.sha256(token.encode()).hexdigest(): "grokbot"}))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_http_handler(self.handler, TokenBook(tokens), set()))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "asset_submit", "arguments": {"operation_id": op(), "asset": COMPLETE}}}).encode()
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}))
            self.assertEqual(ctx.exception.code, 401)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(urllib.request.Request(url, data=body, headers={"Authorization": f"Bearer {token}", "Origin": "https://evil.example"}))
            self.assertEqual(ctx.exception.code, 403)
            req = urllib.request.Request(url, data=body, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req) as resp:
                out = json.loads(resp.read())
            self.assertEqual(out["result"]["structuredContent"]["status"], "published")
            record = self.store.list_records()[0]
            self.assertEqual(record["added_by"], "grokbot")
        finally:
            server.shutdown()
            server.server_close()


class EntriesTests(unittest.TestCase):
    def test_committed_entries_are_valid(self):
        root = Path(__file__).resolve().parents[1] / "entries"
        for path in root.glob("*.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(entry=path.name):
                self.assertEqual(model.validate_record(record), [])
                self.assertEqual(path.stem, record["id"])


if __name__ == "__main__":
    unittest.main()
