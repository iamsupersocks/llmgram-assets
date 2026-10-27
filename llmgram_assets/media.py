"""Find and check the picture that shows what an asset is.

The first photo (or video thumbnail) of the X post that surfaced the asset
is preferred, then the resource page's og:image / twitter:image. Every
candidate must be a real JPEG, PNG, GIF or WebP file.
"""

from __future__ import annotations

import html
import json
import re
from typing import Callable
from urllib.parse import urljoin

from .linkcheck import FetchResult, LinkResult, fetch

MAX_IMAGE_BYTES = 5_000_000
MAX_PAGE_BYTES = 768_000
_X_STATUS = re.compile(r"^https://(?:www\.|mobile\.)?(?:x|twitter)\.com/([A-Za-z0-9_]{1,15})/status/(\d{1,25})(?:[/?#]|$)")
_META = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(r"""([a-zA-Z:_-]+)\s*=\s*("([^"]*)"|'([^']*)')""")

Fetcher = Callable[..., FetchResult]


def sniff(data: bytes) -> str | None:
    """Image extension from magic bytes, or None."""
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def check_image(url: str, fetcher: Fetcher = fetch) -> LinkResult:
    result = fetcher(url, max_bytes=MAX_IMAGE_BYTES, accept="image/*")
    if not result.ok:
        return LinkResult(False, result.status, result.detail)
    kind = sniff(result.body)
    if kind is None:
        return LinkResult(False, result.status, "not an image")
    return LinkResult(True, result.status, f"image/{kind}, {len(result.body)} bytes")


def post_image(url: str, fetcher: Fetcher = fetch) -> dict | None:
    match = _X_STATUS.match(url or "")
    if not match:
        return None
    result = fetcher(f"https://api.fxtwitter.com/{match.group(1)}/status/{match.group(2)}", max_bytes=MAX_PAGE_BYTES,
                     accept="application/json")
    if not result.ok:
        return None
    try:
        tweet = json.loads(result.body)["tweet"]
    except (ValueError, KeyError, TypeError):
        return None
    media = tweet.get("media") or {}
    for photo in media.get("photos") or []:
        if isinstance(photo, dict) and str(photo.get("url", "")).startswith("https://"):
            return {"url": photo["url"], "alt": str(photo.get("altText") or "")[:200]}
    for video in media.get("videos") or []:
        if isinstance(video, dict) and str(video.get("thumbnail_url", "")).startswith("https://"):
            return {"url": video["thumbnail_url"], "alt": ""}
    return None


def page_image(url: str, fetcher: Fetcher = fetch) -> dict | None:
    result = fetcher(url, max_bytes=MAX_PAGE_BYTES, accept="text/html")
    if not result.ok or "html" not in result.content_type:
        return None
    text = result.body.decode("utf-8", "replace")
    found: dict[str, str] = {}
    for tag in _META.findall(text):
        attrs = {m.group(1).lower(): html.unescape(m.group(3) if m.group(3) is not None else m.group(4)) for m in _ATTR.finditer(tag)}
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key in ("og:image", "og:image:secure_url", "twitter:image", "og:image:alt", "twitter:image:alt") and attrs.get("content"):
            found.setdefault(key, attrs["content"].strip())
    for key in ("og:image:secure_url", "og:image", "twitter:image"):
        if key in found:
            image = urljoin(url, found[key])
            if image.startswith("https://"):
                return {"url": image, "alt": (found.get("og:image:alt") or found.get("twitter:image:alt") or "")[:200]}
    return None


def discover(fields: dict, fetcher: Fetcher = fetch) -> dict | None:
    """Best picture for an asset: the post's media first, then the asset page."""
    sources = [fields.get("source") or {}] + list(fields.get("related_sources") or [])
    for source in sources:
        found = post_image(source.get("url", ""), fetcher)
        if found:
            found["credit"] = source.get("author") or ""
            return found
    for page in (fields.get("resource_url"), fields.get("download_url")):
        if page:
            found = page_image(page, fetcher)
            if found:
                found["credit"] = (fields.get("publisher") or {}).get("name", "")
                return found
    return None
