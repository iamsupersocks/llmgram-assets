"""Asset record: normalization, validation and publication gate.

Every value written by an agent goes through ``normalize_submission`` first.
Input is untrusted: unknown keys are refused, strings are bounded, URLs must
be public HTTPS and enums are closed. The publication status is computed here
and never taken from the caller.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SCHEMA_VERSION = "llmgram-asset/v1"

CATEGORIES = (
    "3d-models",
    "textures-materials",
    "hdri-environments",
    "animations-mocap",
    "audio-sfx",
    "music",
    "fonts",
    "icons-ui",
    "images-video",
    "datasets",
    "models-weights",
    "simulation",
    "tools",
    "other",
)
ACCESS_MODELS = (
    "free",
    "free-with-signup",
    "freemium",
    "open-source",
    "paid",
    "research-only",
    "unknown",
)
COMMERCIAL_USE = ("yes", "no", "restricted", "unknown")
SOURCE_KINDS = ("x_post", "article", "github", "huggingface", "website", "other")
FLAG_REASONS = (
    "dead_link",
    "now_paid",
    "license_changed",
    "duplicate",
    "wrong_info",
    "unsafe",
)
STATUSES = ("published", "candidate", "flagged", "retired")

MAX_TAGS = 12
MAX_STEPS = 10
MAX_FORMATS = 12
MAX_RELATED = 5

_LIMITS = {
    "name": 120,
    "summary": 500,
    "tag": 40,
    "publisher.name": 80,
    "license": 80,
    "price": 120,
    "access.notes": 300,
    "step": 300,
    "stat": 80,
    "format": 24,
    "author": 80,
    "why": 400,
    "flag.note": 300,
}

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏ -‮⁦-⁩]")
_TAG = re.compile(r"^[a-z0-9][a-z0-9+.#-]*$")


class ValidationError(ValueError):
    """Business validation failure, reported to the caller as a tool error."""

    def __init__(self, field: str, message: str):
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clean_text(value: Any, field: str, limit: int, *, required: bool = False, multiline: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValidationError(field, "must be a string")
    text = unicodedata.normalize("NFC", value)
    text = _CONTROL.sub("", text)
    if multiline:
        text = "\n".join(re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()).strip()
    else:
        text = re.sub(r"\s+", " ", text).strip()
    if required and not text:
        raise ValidationError(field, "is required")
    if len(text) > limit:
        raise ValidationError(field, f"exceeds {limit} characters")
    return text


def _is_public_host(host: str) -> bool:
    if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        return False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return "." in host
    return ip.is_global


def clean_url(value: Any, field: str, *, required: bool = False) -> str | None:
    if value in (None, ""):
        if required:
            raise ValidationError(field, "is required")
        return None
    if not isinstance(value, str) or len(value) > 2048:
        raise ValidationError(field, "must be a URL string of at most 2048 characters")
    if _CONTROL.search(value) or any(ch.isspace() for ch in value.strip()):
        raise ValidationError(field, "contains whitespace or control characters")
    parts = urlsplit(value.strip())
    if parts.scheme.lower() != "https":
        raise ValidationError(field, "must use https")
    if parts.username or parts.password:
        raise ValidationError(field, "must not embed credentials")
    host = (parts.hostname or "").lower().rstrip(".")
    if not _is_public_host(host):
        raise ValidationError(field, "must point to a public host")
    netloc = host if parts.port in (None, 443) else f"{host}:{parts.port}"
    return urlunsplit(("https", netloc, parts.path or "/", parts.query, ""))


_TRACKING = re.compile(r"^(utm_[a-z]+|s|t|ref|ref_src|fbclid|gclid|si|igshid)$")


def canonical_key(url: str) -> str:
    """Dedup key: host without www, path without trailing slash, no tracking params."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    path = parts.path.rstrip("/") or "/"
    query = "&".join(
        sorted(p for p in parts.query.split("&") if p and not _TRACKING.match(p.split("=", 1)[0].lower()))
    )
    return f"{host}{path}" + (f"?{query}" if query else "")


def asset_id_for(url: str) -> str:
    return "ast-" + hashlib.sha256(canonical_key(url).encode("utf-8")).hexdigest()[:12]


def payload_hash(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _enum(value: Any, field: str, allowed: tuple[str, ...], default: str | None = None) -> str:
    if value in (None, "") and default is not None:
        return default
    if value not in allowed:
        raise ValidationError(field, f"must be one of {', '.join(allowed)}")
    return value


def _reject_unknown(obj: dict, allowed: set[str], field: str) -> None:
    extra = sorted(set(obj) - allowed)
    if extra:
        raise ValidationError(field, f"unknown keys: {', '.join(extra)}")


def _obj(value: Any, field: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(field, "must be an object")
    return value


def _list(value: Any, field: str, limit: int) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError(field, "must be an array")
    if len(value) > limit:
        raise ValidationError(field, f"accepts at most {limit} items")
    return value


def _iso(value: Any, field: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise ValidationError(field, "must be an ISO-8601 date")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(field, "must be an ISO-8601 date") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


SUBMIT_FIELDS = {
    "name", "summary", "category", "tags", "publisher", "resource_url", "download_url",
    "access", "procedure", "stats", "source", "related_sources", "verdict",
}


def normalize_fields(raw: dict, *, partial: bool) -> dict:
    """Normalize caller fields. ``partial`` allows a subset (asset_update)."""
    if not isinstance(raw, dict):
        raise ValidationError("asset", "must be an object")
    _reject_unknown(raw, SUBMIT_FIELDS, "asset")
    out: dict[str, Any] = {}

    def has(key: str) -> bool:
        return not partial or key in raw

    if has("name"):
        out["name"] = clean_text(raw.get("name"), "name", _LIMITS["name"], required=True)
    if has("summary"):
        out["summary"] = clean_text(raw.get("summary"), "summary", _LIMITS["summary"], required=True)
    if has("category"):
        out["category"] = _enum(raw.get("category"), "category", CATEGORIES)
    if has("tags"):
        tags = []
        for i, tag in enumerate(_list(raw.get("tags"), "tags", MAX_TAGS)):
            t = clean_text(tag, f"tags[{i}]", _LIMITS["tag"]).lower().replace(" ", "-")
            if t and not _TAG.match(t):
                raise ValidationError(f"tags[{i}]", "use lowercase letters, digits, + . # -")
            if t and t not in tags:
                tags.append(t)
        out["tags"] = tags
    if has("publisher"):
        pub = _obj(raw.get("publisher"), "publisher")
        _reject_unknown(pub, {"name", "url"}, "publisher")
        out["publisher"] = {
            "name": clean_text(pub.get("name"), "publisher.name", _LIMITS["publisher.name"], required=True),
            "url": clean_url(pub.get("url"), "publisher.url"),
        }
    if has("resource_url"):
        out["resource_url"] = clean_url(raw.get("resource_url"), "resource_url", required=True)
    if has("download_url"):
        out["download_url"] = clean_url(raw.get("download_url"), "download_url")
    if has("access"):
        acc = _obj(raw.get("access"), "access")
        _reject_unknown(acc, {"model", "license", "license_url", "commercial_use", "signup_required", "price", "notes"}, "access")
        signup = acc.get("signup_required")
        if signup is not None and not isinstance(signup, bool):
            raise ValidationError("access.signup_required", "must be true, false or null")
        out["access"] = {
            "model": _enum(acc.get("model"), "access.model", ACCESS_MODELS, "unknown"),
            "license": clean_text(acc.get("license"), "access.license", _LIMITS["license"]) or "unknown",
            "license_url": clean_url(acc.get("license_url"), "access.license_url"),
            "commercial_use": _enum(acc.get("commercial_use"), "access.commercial_use", COMMERCIAL_USE, "unknown"),
            "signup_required": signup,
            "price": clean_text(acc.get("price"), "access.price", _LIMITS["price"]),
            "notes": clean_text(acc.get("notes"), "access.notes", _LIMITS["access.notes"]),
        }
    if has("procedure"):
        steps = [clean_text(s, f"procedure[{i}]", _LIMITS["step"]) for i, s in enumerate(_list(raw.get("procedure"), "procedure", MAX_STEPS))]
        out["procedure"] = [s for s in steps if s]
    if has("stats"):
        st = _obj(raw.get("stats"), "stats")
        _reject_unknown(st, {"count", "size", "formats", "cadence"}, "stats")
        formats = []
        for i, f in enumerate(_list(st.get("formats"), "stats.formats", MAX_FORMATS)):
            f = clean_text(f, f"stats.formats[{i}]", _LIMITS["format"])
            if f and f not in formats:
                formats.append(f)
        out["stats"] = {
            "count": clean_text(st.get("count"), "stats.count", _LIMITS["stat"]),
            "size": clean_text(st.get("size"), "stats.size", _LIMITS["stat"]),
            "formats": formats,
            "cadence": clean_text(st.get("cadence"), "stats.cadence", _LIMITS["stat"]),
        }
    if has("source"):
        out["source"] = _source(raw.get("source"), "source", required=True)
    if has("related_sources"):
        out["related_sources"] = [
            _source(s, f"related_sources[{i}]", required=True)
            for i, s in enumerate(_list(raw.get("related_sources"), "related_sources", MAX_RELATED))
        ]
    if has("verdict"):
        ver = _obj(raw.get("verdict"), "verdict")
        _reject_unknown(ver, {"score", "why"}, "verdict")
        score = ver.get("score")
        if score is not None and (isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100):
            raise ValidationError("verdict.score", "must be an integer from 0 to 100")
        out["verdict"] = {"score": score, "why": clean_text(ver.get("why"), "verdict.why", _LIMITS["why"])}
    return out


def _source(value: Any, field: str, *, required: bool) -> dict:
    src = _obj(value, field)
    _reject_unknown(src, {"url", "author", "published_at", "kind"}, field)
    return {
        "url": clean_url(src.get("url"), f"{field}.url", required=required),
        "author": clean_text(src.get("author"), f"{field}.author", _LIMITS["author"]),
        "published_at": _iso(src.get("published_at"), f"{field}.published_at"),
        "kind": _enum(src.get("kind"), f"{field}.kind", SOURCE_KINDS, "other"),
    }


def missing_for_publication(record: dict) -> list[str]:
    """Fields that keep a record out of the public page."""
    missing = []
    if record.get("hold"):
        missing.append("hold")
    access = record.get("access") or {}
    if access.get("model", "unknown") == "unknown":
        missing.append("access.model")
    if access.get("license", "unknown").lower() in ("", "unknown"):
        missing.append("access.license")
    if not record.get("procedure"):
        missing.append("procedure")
    if not (record.get("source") or {}).get("url"):
        missing.append("source.url")
    check = record.get("verification") or {}
    if not check.get("resource_ok"):
        missing.append("verification.resource_url")
    if record.get("download_url") and not check.get("download_ok"):
        missing.append("verification.download_url")
    return missing


def compute_status(record: dict) -> str:
    if record.get("status") in ("flagged", "retired"):
        return record["status"]
    return "candidate" if missing_for_publication(record) else "published"


def validate_record(record: dict) -> list[str]:
    """Check a stored record (used by CI-less validation and by the site build)."""
    errors: list[str] = []
    try:
        if record.get("schema_version") != SCHEMA_VERSION:
            errors.append("schema_version")
        if not re.fullmatch(r"ast-[0-9a-f]{12}", str(record.get("id", ""))):
            errors.append("id")
        fields = {k: record[k] for k in SUBMIT_FIELDS if k in record}
        normalized = normalize_fields(fields, partial=False)
        if record.get("id") != asset_id_for(normalized["resource_url"]):
            errors.append("id does not match resource_url")
        if record.get("status") not in STATUSES:
            errors.append("status")
        if record.get("status") not in ("flagged", "retired") and record.get("status") != compute_status(record):
            errors.append("status does not match publication gate")
    except ValidationError as exc:
        errors.append(str(exc))
    return errors
