"""Business operations behind the MCP tools.

Mutations are idempotent by ``operation_id``: the first call records it in
the asset history together with a payload hash, and a replay of the same
operation returns the stored receipt instead of writing again. A backend
failure during a write is reported as ``ambiguous``; the caller must retry
with the same ``operation_id`` and never with a new one.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Callable

from . import media, model
from .linkcheck import check_url, fetch
from .store import Conflict, StoreError

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
FIXED_BY_UPDATE = {"dead_link", "now_paid", "license_changed", "wrong_info"}
HISTORY_KEEP = 50


class ToolError(Exception):
    """Recoverable business error returned with ``isError=true``."""


def _hold(args: dict) -> bool | None:
    value = args.get("hold")
    if value is not None and not isinstance(value, bool):
        raise ToolError("hold must be a boolean")
    return value


def _operation_id(value: Any) -> str:
    if not isinstance(value, str) or not _UUID.match(value.lower()):
        raise ToolError("operation_id must be a fresh UUID; reuse it only to retry the same call")
    return value.lower()


class AssetService:
    def __init__(self, store, *, checker: Callable[[str], Any] = check_url, fetcher: Callable[..., Any] = fetch,
                 clock: Callable[[], str] = model.utc_now):
        self.store = store
        self.checker = checker
        self.fetcher = fetcher
        self.clock = clock

    # ---- reads -------------------------------------------------------

    def search(self, args: dict) -> dict:
        query = model.clean_text(args.get("query"), "query", 120).lower()
        category = args.get("category")
        if category not in (None, "", *model.CATEGORIES):
            raise ToolError("unknown category")
        access = args.get("access_model")
        if access not in (None, "", *model.ACCESS_MODELS):
            raise ToolError("unknown access_model")
        statuses = args.get("status") or ["published", "candidate"]
        if not isinstance(statuses, list) or not set(statuses) <= set(model.STATUSES):
            raise ToolError("status must be a list of " + ", ".join(model.STATUSES))
        limit = args.get("limit", 20)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 50:
            raise ToolError("limit must be 1 to 50")
        cursor = str(args.get("cursor") or "0")
        if not cursor.isdigit():
            raise ToolError("cursor must be the value returned by a previous search")
        offset = int(cursor)

        rows = []
        for rec in self._list():
            if rec.get("status") not in statuses:
                continue
            if category and rec.get("category") != category:
                continue
            if access and (rec.get("access") or {}).get("model") != access:
                continue
            if query:
                hay = " ".join([
                    rec.get("name", ""), rec.get("summary", ""), " ".join(rec.get("tags", [])),
                    (rec.get("publisher") or {}).get("name", ""), rec.get("resource_url", ""),
                ]).lower()
                if not all(term in hay for term in query.split()):
                    continue
            rows.append(rec)
        rows.sort(key=lambda r: (r.get("added_at", ""), r.get("id", "")), reverse=True)
        page = rows[offset:offset + limit]
        nxt = offset + limit
        return {
            "total": len(rows),
            "items": [self._compact(r) for r in page],
            "next_cursor": str(nxt) if nxt < len(rows) else None,
        }

    def get(self, args: dict) -> dict:
        asset_id = args.get("asset_id")
        url = args.get("url")
        if bool(asset_id) == bool(url):
            raise ToolError("give exactly one of asset_id or url")
        if url:
            try:
                asset_id = model.asset_id_for(model.clean_url(url, "url", required=True))
            except model.ValidationError as exc:
                raise ToolError(str(exc)) from None
        record, _ = self._get(asset_id)
        if record is None:
            return {"found": False, "asset_id": asset_id}
        return {"found": True, "asset": record}

    # ---- mutations ---------------------------------------------------

    def submit(self, args: dict, actor: str) -> dict:
        op = _operation_id(args.get("operation_id"))
        raw = args.get("asset")
        try:
            fields = model.normalize_fields(raw, partial=False)
        except model.ValidationError as exc:
            raise ToolError(str(exc)) from None
        hold = _hold(args)
        digest = model.payload_hash({"action": "submit", "asset": raw, "hold": hold})
        asset_id = model.asset_id_for(fields["resource_url"])

        existing, _ = self._get(asset_id)
        if existing is not None:
            replay = self._replay(existing, op, digest)
            if replay:
                return replay
            return {
                "result": "duplicate",
                "asset_id": asset_id,
                "status": existing.get("status"),
                "hint": "This resource is already listed. Use asset_update with a new operation_id to complete it.",
            }

        now = self.clock()
        self._fill_image(fields)
        record = {
            "schema_version": model.SCHEMA_VERSION,
            "id": asset_id,
            **{k: fields.get(k) for k in ("name", "summary", "category", "tags", "publisher", "resource_url", "download_url",
                                          "access", "procedure", "stats", "source", "related_sources", "verdict", "image")},
            "verification": self._verify(fields, now),
            "hold": bool(hold),
            "status": "candidate",
            "flags": [],
            "added_at": now,
            "added_by": actor,
            "updated_at": now,
            "history": [],
        }
        record["status"] = model.compute_status(record)
        receipt = self._receipt("created", record, op)
        record["history"].append(self._history(op, "submit", now, actor, digest, receipt))
        try:
            self.store.put(record, None, self._message("add", record, op, actor))
        except Conflict:
            # Created concurrently; it may be this very operation.
            current, _ = self._get(asset_id)
            replay = current and self._replay(current, op, digest)
            if replay:
                return replay
            return {"result": "duplicate", "asset_id": asset_id, "status": current.get("status") if current else None}
        except StoreError as exc:
            return self._ambiguous(op, asset_id, exc)
        return receipt

    def update(self, args: dict, actor: str) -> dict:
        op = _operation_id(args.get("operation_id"))
        asset_id = self._asset_id(args)
        changes = args.get("changes") or {}
        if not isinstance(changes, dict):
            raise ToolError("changes must be an object")
        if "resource_url" in changes:
            raise ToolError("resource_url identifies the asset and cannot change; flag it as duplicate and submit the new URL")
        hold = _hold(args)
        digest = model.payload_hash({"action": "update", "asset_id": asset_id, "changes": changes, "hold": hold})

        def mutate(record: dict, now: str) -> tuple[str, dict]:
            merged = {}
            for key, value in changes.items():
                old = record.get(key)
                merged[key] = {**old, **value} if isinstance(old, dict) and isinstance(value, dict) else value
            try:
                fields = model.normalize_fields(merged, partial=True)
            except model.ValidationError as exc:
                raise ToolError(str(exc)) from None
            record.update(fields)
            if hold is not None:
                record["hold"] = hold
            self._fill_image(record)
            record["verification"] = self._verify(record, now)
            for flag in record.get("flags", []):
                if flag.get("open") and flag.get("reason") in FIXED_BY_UPDATE:
                    flag["open"] = False
                    flag["closed_at"] = now
                    flag["closed_by_operation"] = op
            if record.get("status") == "flagged" and not any(f.get("open") for f in record.get("flags", [])):
                record["status"] = "candidate"
            record["status"] = model.compute_status(record)
            return "updated", record

        return self._mutate(asset_id, op, digest, actor, "update", mutate)

    def flag(self, args: dict, actor: str) -> dict:
        op = _operation_id(args.get("operation_id"))
        asset_id = self._asset_id(args)
        reason = args.get("reason")
        if reason not in model.FLAG_REASONS:
            raise ToolError("reason must be one of " + ", ".join(model.FLAG_REASONS))
        try:
            note = model.clean_text(args.get("note"), "note", 300)
        except model.ValidationError as exc:
            raise ToolError(str(exc)) from None
        digest = model.payload_hash({"action": "flag", "asset_id": asset_id, "reason": reason, "note": note})

        def mutate(record: dict, now: str) -> tuple[str, dict]:
            record.setdefault("flags", []).append({"reason": reason, "note": note, "at": now, "by": actor, "open": True})
            if record.get("status") != "retired":
                record["status"] = "flagged"
            return "flagged", record

        return self._mutate(asset_id, op, digest, actor, "flag", mutate)

    # ---- helpers -----------------------------------------------------

    def _mutate(self, asset_id: str, op: str, digest: str, actor: str, action: str, mutate) -> dict:
        for _ in range(2):
            record, version = self._get(asset_id)
            if record is None:
                raise ToolError(f"unknown asset {asset_id}")
            replay = self._replay(record, op, digest)
            if replay:
                return replay
            now = self.clock()
            result, record = mutate(copy.deepcopy(record), now)
            record["updated_at"] = now
            receipt = self._receipt(result, record, op)
            record["history"] = (record.get("history", []) + [self._history(op, action, now, actor, digest, receipt)])[-HISTORY_KEEP:]
            try:
                self.store.put(record, version, self._message(action, record, op, actor))
            except Conflict:
                continue
            except StoreError as exc:
                return self._ambiguous(op, asset_id, exc)
            return receipt
        raise ToolError("asset changed concurrently twice; retry with the same operation_id")

    def _fill_image(self, fields: dict) -> None:
        """Find the post or asset picture when the caller gave none."""
        if (fields.get("image") or {}).get("url"):
            return
        try:
            found = media.discover(fields, self.fetcher)
        except Exception:  # noqa: BLE001 - discovery is best effort; the gate reports a missing image
            found = None
        if found:
            fields["image"] = {"url": found["url"], "alt": found.get("alt", ""), "credit": found.get("credit", "")}

    def _verify(self, fields: dict, now: str) -> dict:
        resource = self.checker(fields["resource_url"])
        out = {"checked_at": now, "resource_ok": resource.ok, "resource": resource.as_dict()}
        if fields.get("download_url"):
            download = self.checker(fields["download_url"])
            out.update(download_ok=download.ok, download=download.as_dict())
        image_url = (fields.get("image") or {}).get("url")
        if image_url:
            image = media.check_image(image_url, self.fetcher)
            out.update(image_ok=image.ok, image=image.as_dict())
        return out

    @staticmethod
    def _receipt(result: str, record: dict, op: str) -> dict:
        return {
            "result": result,
            "asset_id": record["id"],
            "status": record["status"],
            "missing": model.missing_for_publication(record),
            "operation_id": op,
        }

    @staticmethod
    def _history(op: str, action: str, now: str, actor: str, digest: str, receipt: dict) -> dict:
        return {"operation_id": op, "action": action, "at": now, "actor": actor, "payload_sha256": digest,
                "result": receipt["result"], "status": receipt["status"]}

    @staticmethod
    def _replay(record: dict, op: str, digest: str) -> dict | None:
        for item in record.get("history", []):
            if item.get("operation_id") != op:
                continue
            if item.get("payload_sha256") != digest:
                raise ToolError("operation_id already used for a different call; use a fresh UUID")
            return {"result": item["result"], "asset_id": record["id"], "status": item["status"],
                    "current_status": record.get("status"), "operation_id": op, "replayed": True}
        return None

    @staticmethod
    def _ambiguous(op: str, asset_id: str, exc: Exception) -> dict:
        return {"result": "ambiguous", "asset_id": asset_id, "operation_id": op, "detail": str(exc),
                "hint": "Outcome unknown. Retry later with the same operation_id; never with a new one."}

    @staticmethod
    def _message(action: str, record: dict, op: str, actor: str) -> str:
        name = record.get("name", "")[:60]
        return f"asset {action}: {name} ({record['id']}, {record['status']})\n\nOperation-Id: {op}\nActor: {actor}\n"

    @staticmethod
    def _asset_id(args: dict) -> str:
        asset_id = args.get("asset_id")
        if not isinstance(asset_id, str) or not re.fullmatch(r"ast-[0-9a-f]{12}", asset_id):
            raise ToolError("asset_id must look like ast-<12 hex>")
        return asset_id

    @staticmethod
    def _compact(rec: dict) -> dict:
        access = rec.get("access") or {}
        return {
            "asset_id": rec.get("id"),
            "name": rec.get("name"),
            "category": rec.get("category"),
            "publisher": (rec.get("publisher") or {}).get("name"),
            "access_model": access.get("model"),
            "license": access.get("license"),
            "status": rec.get("status"),
            "missing": model.missing_for_publication(rec),
            "resource_url": rec.get("resource_url"),
            "added_at": rec.get("added_at"),
        }

    def _list(self) -> list[dict]:
        try:
            return self.store.list_records()
        except StoreError as exc:
            raise ToolError(f"catalog unavailable: {exc}") from None

    def _get(self, asset_id: str):
        try:
            return self.store.get(asset_id)
        except StoreError as exc:
            raise ToolError(f"catalog unavailable: {exc}") from None
