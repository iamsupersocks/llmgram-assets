"""Remote MCP gateway for Grok Bot: Streamable HTTP + OAuth.

Grok Bot connects to remote MCP servers through the standard MCP OAuth flow
(discovery, dynamic client registration, PKCE). The owner approves each new
client once on ``/oauth/approve`` with ``LLMGRAM_ASSETS_OWNER_SECRET``. The
pattern and token format follow the Karen gateway.

Requires the ``mcp`` SDK and ``uvicorn`` (requirements-remote.txt). The
stdio/plain-HTTP server in ``mcp_server`` stays stdlib-only.

    LLMGRAM_ASSETS_OWNER_SECRET=... \\
    LLMGRAM_ASSETS_PUBLIC_URL=https://host.example \\
    python -m llmgram_assets.remote --git-checkout /srv/llmgram-assets --ssh-key /srv/deploy_key
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import anyio
from mcp import types
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .mcp_server import INSTRUCTIONS, MAX_BODY, MUTATING, MUTATIONS_PER_HOUR, TOOLS, Handler, RateLimiter
from .service import AssetService
from .store import GitStore, LocalStore

READ_SCOPE = "assets.read"
WRITE_SCOPE = "assets.write"
SCOPES = [READ_SCOPE, WRITE_SCOPE]
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600
CODE_TTL = 300
PENDING_TTL = 600
MCP_PATH = "/mcp"

logger = logging.getLogger("llmgram_assets.remote")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class OwnerApprovedOAuth:
    """Single-owner OAuth provider: clients register, the owner approves once."""

    def __init__(self, secret: str, base_url: str, clients_file: Path):
        if len(secret) < 32:
            raise ValueError("owner secret must be at least 32 characters")
        self._secret = secret
        self._key = hashlib.sha256(("llmgram-assets-oauth-v1\0" + secret).encode()).digest()
        self._base_url = base_url.rstrip("/")
        self._clients_path = Path(clients_file)
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending: dict[str, tuple[float, OAuthClientInformationFull, AuthorizationParams]] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._load_clients()

    # ---- client registry ---------------------------------------------

    def _load_clients(self) -> None:
        try:
            raw = json.loads(self._clients_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for client_id, value in raw.items() if isinstance(raw, dict) else []:
            client = OAuthClientInformationFull.model_validate(value)
            if client.client_id == client_id:
                self._clients[client_id] = client

    def _save_clients(self) -> None:
        self._clients_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self._clients_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({k: v.model_dump(mode="json") for k, v in self._clients.items()}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self._clients_path)

    def client_name(self, client_id: str) -> str:
        client = self._clients.get(client_id)
        return (client.client_name if client and client.client_name else client_id)[:60]

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id or not client_info.redirect_uris:
            raise RegistrationError("invalid_client_metadata", "client_id and redirect_uris are required")
        if len(self._clients) >= 20 and client_info.client_id not in self._clients:
            raise RegistrationError("invalid_client_metadata", "too many registered clients")
        self._clients[client_info.client_id] = client_info
        self._save_clients()

    # ---- authorization -----------------------------------------------

    def _prune(self) -> None:
        now = time.time()
        self._pending = {k: v for k, v in self._pending.items() if v[0] >= now}
        self._codes = {k: v for k, v in self._codes.items() if v.expires_at >= now}

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        self._prune()
        request_id = secrets.token_urlsafe(32)
        self._pending[request_id] = (time.time() + PENDING_TTL, client, params)
        return f"{self._base_url}/oauth/approve?request={request_id}"

    async def approval(self, request: Request) -> Response:
        self._prune()
        if request.method == "GET":
            request_id = request.query_params.get("request", "")
            pending = self._pending.get(request_id)
            if pending is None:
                return HTMLResponse(_page("Demande expirée", "Relance la connexion depuis Grok Bot."), 400)
            return HTMLResponse(_approval_page(request_id, pending[1].client_name or "Client MCP", _granted(pending[2].scopes)),
                                headers={"Cache-Control": "no-store"})

        body = (await request.body())[:4096].decode("utf-8", "replace")
        form = parse_qs(body, keep_blank_values=True)
        request_id = (form.get("request") or [""])[0]
        owner_secret = (form.get("secret") or [""])[0]
        action = (form.get("action") or ["deny"])[0]
        pending = self._pending.get(request_id)
        if pending is None:
            return HTMLResponse(_page("Demande expirée", "Relance la connexion depuis Grok Bot."), 400)
        _, client, params = pending
        if action != "approve":
            self._pending.pop(request_id, None)
            return RedirectResponse(construct_redirect_uri(str(params.redirect_uri), error="access_denied", state=params.state), 302)
        if not hmac.compare_digest(owner_secret.encode(), self._secret.encode()):
            return HTMLResponse(_approval_page(request_id, client.client_name or "Client MCP", _granted(params.scopes), invalid=True), 403)
        self._pending.pop(request_id, None)
        code_value = secrets.token_urlsafe(32)
        self._codes[code_value] = AuthorizationCode(
            code=code_value,
            scopes=_granted(params.scopes),
            expires_at=time.time() + CODE_TTL,
            client_id=client.client_id or "",
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        logger.info("oauth client approved: %s", client.client_name or client.client_id)
        return RedirectResponse(construct_redirect_uri(str(params.redirect_uri), code=code_value, state=params.state), 302,
                                headers={"Cache-Control": "no-store"})

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        self._prune()
        code = self._codes.get(authorization_code)
        return code if code and code.client_id == client.client_id else None

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)
        return self._issue(client.client_id or "", authorization_code.scopes, authorization_code.resource)

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        payload = self._decode(refresh_token, "refresh")
        if payload is None or payload.get("client_id") != client.client_id:
            return None
        return RefreshToken(token=refresh_token, client_id=payload["client_id"], scopes=_granted(payload.get("scopes")), expires_at=payload["exp"])

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        return self._issue(client.client_id or "", scopes or refresh_token.scopes, None)

    async def load_access_token(self, token: str) -> AccessToken | None:
        payload = self._decode(token, "access")
        if payload is None or payload.get("client_id") not in self._clients:
            return None
        return AccessToken(token=token, client_id=payload["client_id"], scopes=_granted(payload.get("scopes")),
                           expires_at=payload["exp"], resource=payload.get("resource"))

    async def revoke_token(self, token) -> None:
        return None

    # ---- tokens ------------------------------------------------------

    def _issue(self, client_id: str, scopes: list[str], resource) -> OAuthToken:
        return OAuthToken(
            access_token=self._encode("access", client_id, scopes, ACCESS_TTL, resource),
            token_type="Bearer",
            expires_in=ACCESS_TTL,
            scope=" ".join(scopes),
            refresh_token=self._encode("refresh", client_id, scopes, REFRESH_TTL, resource),
        )

    def _encode(self, kind: str, client_id: str, scopes: list[str], ttl: int, resource) -> str:
        now = int(time.time())
        payload = {"kind": kind, "client_id": client_id, "scopes": scopes, "iat": now, "exp": now + ttl,
                   "jti": secrets.token_urlsafe(12), "resource": str(resource) if resource else None}
        encoded = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        return f"la1.{encoded}.{_b64(hmac.new(self._key, encoded.encode(), hashlib.sha256).digest())}"

    def _decode(self, token: str, kind: str) -> dict | None:
        try:
            prefix, encoded, signature = token.split(".", 2)
            if prefix != "la1":
                return None
            expected = _b64(hmac.new(self._key, encoded.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(signature, expected):
                return None
            payload = json.loads(_unb64(encoded))
            if payload.get("kind") != kind or int(payload.get("exp", 0)) < int(time.time()):
                return None
            return payload
        except (ValueError, TypeError):
            return None


def _granted(scopes) -> list[str]:
    """Known scopes only; read is always implied."""
    granted = [s for s in SCOPES if s in (scopes or [])]
    return granted if READ_SCOPE in granted else [READ_SCOPE, *granted]


def _page(title: str, message: str) -> str:
    return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
            "<title>LLMgram assets</title><style>body{font:16px system-ui;max-width:520px;margin:12vh auto;padding:24px}"
            "main{border:1px solid #ddd;border-radius:16px;padding:28px}</style><main><h1>" + html.escape(title) +
            "</h1><p>" + html.escape(message) + "</p></main>")


def _approval_page(request_id: str, client_name: str, scopes: list[str], invalid: bool = False) -> str:
    access = "lire et compléter (ajout, mise à jour, signalement ; aucune suppression)" if WRITE_SCOPE in scopes else "lire"
    warning = "<p style='color:#b42318'>Code incorrect.</p>" if invalid else ""
    return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
            "<title>Autoriser LLMgram assets</title><style>body{font:16px system-ui;max-width:520px;margin:8vh auto;padding:24px}"
            "main{border:1px solid #ddd;border-radius:16px;padding:28px}input,button{box-sizing:border-box;width:100%;"
            "padding:12px;margin-top:12px;border-radius:10px;border:1px solid #bbb}button{background:#111;color:#fff;border:0}"
            ".deny{background:#fff;color:#333;border:1px solid #bbb}</style><main><h1>Autoriser LLMgram assets</h1><p>" +
            html.escape(client_name) + " demande à " + access + " le catalogue Asset Signal.</p>" + warning +
            "<form method=post action='/oauth/approve'><input type=hidden name=request value='" +
            html.escape(request_id, quote=True) + "'><input type=password name=secret autocomplete=off placeholder='Secret propriétaire'>"
            "<button name=action value=approve>Autoriser</button><button class=deny name=action value=deny>Refuser</button></form></main>")


class BodyLimit:
    """Refuse oversized request bodies before the MCP layer reads them."""

    def __init__(self, app, limit: int = MAX_BODY):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            length = dict(scope.get("headers") or []).get(b"content-length")
            if length and length.isdigit() and int(length) > self.limit:
                await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"error":"body too large"}'})
                return
        await self.app(scope, receive, send)


def build_app(service: AssetService, *, secret: str, public_url: str, clients_file: Path):
    parts = urlsplit(public_url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("public URL must be https")
    provider = OwnerApprovedOAuth(secret, public_url, clients_file)
    handler = Handler(service, RateLimiter(MUTATIONS_PER_HOUR))
    host = parts.netloc
    server = FastMCP(
        name="llmgram-assets",
        instructions=INSTRUCTIONS,
        streamable_http_path=MCP_PATH,
        json_response=True,
        stateless_http=True,
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=public_url,
            resource_server_url=f"{public_url.rstrip('/')}{MCP_PATH}",
            client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=SCOPES, default_scopes=[READ_SCOPE]),
            required_scopes=[READ_SCOPE],
        ),
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[host, f"{parts.hostname}:*", "127.0.0.1:*", "localhost:*"],
            allowed_origins=[f"https://{host}"],
        ),
        debug=False,
    )
    low = server._mcp_server

    @low.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"],
                           annotations=types.ToolAnnotations(**t["annotations"])) for t in TOOLS]

    @low.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
        token = get_access_token()
        if name in MUTATING and (token is None or WRITE_SCOPE not in token.scopes):
            message = f"{name} needs the {WRITE_SCOPE} scope; this connection is read-only"
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps({"error": message}))],
                                        structuredContent={"error": message}, isError=True)
        actor = "oauth:" + provider.client_name(token.client_id) if token else "oauth:unknown"
        result = await anyio.to_thread.run_sync(handler.call, name, arguments or {}, actor)
        return types.CallToolResult(content=[types.TextContent(type="text", text=result["content"][0]["text"])],
                                    structuredContent=result["structuredContent"], isError=result["isError"])

    server.custom_route("/oauth/approve", methods=["GET", "POST"])(provider.approval)
    server.custom_route("/healthz", methods=["GET"])(_health)
    return BodyLimit(server.streamable_http_app()), provider


async def _health(request: Request) -> Response:
    return Response('{"ok":true}', media_type="application/json")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="LLMgram assets remote MCP gateway (OAuth)")
    parser.add_argument("--git-checkout", help="clone of the data repository (writes are pushed)")
    parser.add_argument("--ssh-key", help="write deploy key for the data repository")
    parser.add_argument("--local-root", help="plain directory store (tests only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8791)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    secret = os.environ.get("LLMGRAM_ASSETS_OWNER_SECRET", "")
    public_url = os.environ.get("LLMGRAM_ASSETS_PUBLIC_URL", "")
    clients_file = Path(os.environ.get("LLMGRAM_ASSETS_OAUTH_CLIENTS_FILE",
                                       Path.home() / ".config/llmgram-assets-mcp/oauth-clients.json"))
    if len(secret) < 32 or not public_url:
        logger.error("refusing to start: LLMGRAM_ASSETS_OWNER_SECRET (>= 32 chars) and LLMGRAM_ASSETS_PUBLIC_URL are required")
        return 2
    if args.git_checkout:
        store = GitStore(Path(args.git_checkout), ssh_key=args.ssh_key)
    elif args.local_root:
        store = LocalStore(Path(args.local_root))
    else:
        logger.error("refusing to start: --git-checkout is required")
        return 2
    app, _ = build_app(AssetService(store), secret=secret, public_url=public_url, clients_file=clients_file)
    import uvicorn

    logger.info("llmgram-assets remote MCP on http://%s:%s%s (TLS by proxy)", args.host, args.port, MCP_PATH)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
