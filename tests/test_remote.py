"""OAuth + Streamable HTTP gateway, end to end (skipped without the mcp SDK)."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

try:
    from starlette.testclient import TestClient

    from llmgram_assets.remote import build_app
except ImportError:  # pragma: no cover - remote extras not installed
    build_app = None

from llmgram_assets.service import AssetService
from llmgram_assets.store import LocalStore
from llmgram_assets.linkcheck import LinkResult

SECRET = "s" * 40
REDIRECT = "https://grok.example/callback"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@unittest.skipIf(build_app is None, "mcp SDK not installed")
class RemoteGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        service = AssetService(LocalStore(root / "data"), checker=lambda url: LinkResult(True, 200, "ok"))
        app, _ = build_app(service, secret=SECRET, public_url="https://assets.example",
                           clients_file=root / "clients.json")
        self.client = TestClient(app, base_url="http://127.0.0.1:8791", follow_redirects=False)
        self.client.__enter__()
        self.clients_file = root / "clients.json"

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.tmp.cleanup()

    def _authorize(self, secret=SECRET):
        reg = self.client.post("/register", json={"redirect_uris": [REDIRECT], "client_name": "Grok Bot",
                                                  "token_endpoint_auth_method": "none",
                                                  "grant_types": ["authorization_code", "refresh_token"]})
        self.assertEqual(reg.status_code, 201, reg.text)
        client_id = reg.json()["client_id"]
        verifier = "v" * 64
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        auth = self.client.get("/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "state": "st",
            "code_challenge": challenge, "code_challenge_method": "S256", "scope": "llmgram-assets"})
        self.assertEqual(auth.status_code, 302, auth.text)
        request_id = parse_qs(urlsplit(auth.headers["location"]).query)["request"][0]
        page = self.client.get("/oauth/approve", params={"request": request_id})
        self.assertIn("Grok Bot", page.text)
        approve = self.client.post("/oauth/approve", data={"request": request_id, "secret": secret, "action": "approve"})
        return client_id, verifier, approve

    def _token(self):
        client_id, verifier, approve = self._authorize()
        self.assertEqual(approve.status_code, 302)
        query = parse_qs(urlsplit(approve.headers["location"]).query)
        self.assertEqual(query["state"], ["st"])
        token = self.client.post("/token", data={"grant_type": "authorization_code", "code": query["code"][0],
                                                 "redirect_uri": REDIRECT, "client_id": client_id,
                                                 "code_verifier": verifier})
        self.assertEqual(token.status_code, 200, token.text)
        return token.json()

    def _rpc(self, token, method, params=None, rid=1):
        headers = dict(MCP_HEADERS, Authorization=f"Bearer {token}")
        return self.client.post("/mcp", headers=headers,
                                json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})

    def test_mcp_requires_token(self):
        response = self.client.post("/mcp", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(response.status_code, 401)
        self.assertIn("resource_metadata", response.headers.get("www-authenticate", ""))

    def test_wrong_owner_secret_is_refused(self):
        _, _, approve = self._authorize(secret="nope")
        self.assertEqual(approve.status_code, 403)

    def test_full_flow_submit_records_oauth_actor(self):
        tokens = self._token()
        access = tokens["access_token"]
        init = self._rpc(access, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                "clientInfo": {"name": "t", "version": "1"}})
        self.assertEqual(init.status_code, 200, init.text)
        listed = self._rpc(access, "tools/list", rid=2).json()["result"]["tools"]
        self.assertEqual({t["name"] for t in listed}, {"asset_search", "asset_get", "asset_submit", "asset_update", "asset_flag"})
        submit = self._rpc(access, "tools/call", {"name": "asset_submit", "arguments": {
            "operation_id": "6f1c1b2e-8d3a-4b8e-9f00-2a1c3d4e5f60", "asset": {
            "resource_url": "https://example.com/pack",
            "name": "Pack", "summary": "A pack of things.", "category": "3d-models",
            "publisher": {"name": "Example"},
            "access": {"model": "free", "license": "CC0", "commercial_use": "yes"},
            "procedure": ["Open the page and download"],
            "source": {"url": "https://x.com/example/status/1", "kind": "x_post"},
        }}}, rid=3).json()["result"]
        self.assertFalse(submit["isError"], submit)
        record = submit["structuredContent"]
        self.assertEqual(record["result"], "created")
        stored = json.loads(next(Path(self.tmp.name, "data", "entries").glob("ast-*.json")).read_text())
        self.assertEqual(stored["history"][-1]["actor"], "oauth:Grok Bot")
        # registered client survives a restart file
        self.assertEqual(oct(self.clients_file.stat().st_mode & 0o777), "0o600")
        refreshed = self.client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                                     "client_id": json.loads(self.clients_file.read_text()).popitem()[0]})
        self.assertEqual(refreshed.status_code, 200, refreshed.text)

    def test_tampered_token_is_refused(self):
        access = self._token()["access_token"]
        response = self._rpc(access[:-2] + "AA", "tools/list")
        self.assertEqual(response.status_code, 401)

    def test_health(self):
        self.assertEqual(self.client.get("/healthz").json(), {"ok": True})


if __name__ == "__main__":
    unittest.main()
