"""HTTP layer for the urlscan.io API.

Everything that can go wrong with a remote API is handled here so the tool
layer stays readable: auth, rate limits, the scan-still-running case, and
network failure all become clear, actionable messages rather than tracebacks.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

BASE_URL = "https://urlscan.io"
USER_AGENT = "urlscan-mcp/0.1 (+https://github.com/)"
DEFAULT_TIMEOUT = 30.0

#: How long a GET response stays reusable. Scans are immutable once written and
#: the corpus moves slowly, so an hour costs nothing in freshness and spares the
#: free tier: an agent pivoting around one investigation asks the same question
#: repeatedly, and without this every repeat is a request.
DEFAULT_CACHE_TTL = 3600.0

#: Bounded so a long-lived server cannot grow a cache without limit.
MAX_CACHE_ENTRIES = 256


class UrlscanError(Exception):
    """An error worth showing to the model verbatim."""


class ScanPending(UrlscanError):
    """The scan exists but has not finished yet. Retry, do not treat as failure."""


class ImageTooLarge(UrlscanError):
    """The image is past the caller's ceiling. Carries the size so the tool can say."""

    def __init__(self, size_bytes: int) -> None:
        super().__init__(f"Image is {size_bytes} bytes, past the configured ceiling.")
        self.size_bytes = size_bytes


class UrlscanClient:
    """Thin async client.

    The API key is optional on purpose. Search, result retrieval and the
    country list all work unauthenticated; only submission and quota lookup
    require a key. Running without one degrades to read-only rather than
    failing at import time, and `capabilities()` reports exactly what is
    available so the caller never has to guess.
    """

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        cache_ttl: float = DEFAULT_CACHE_TTL,
    ):
        self.api_key = api_key if api_key is not None else os.getenv("URLSCAN_API_KEY")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._cache_ttl = cache_ttl
        self._cache: dict[str, tuple[float, Any]] = {}
        self.cache_stats = {"hits": 0, "misses": 0}

    # -- lifecycle ---------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=BASE_URL,
                timeout=self._timeout,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    # -- introspection -----------------------------------------------------

    @property
    def authenticated(self) -> bool:
        return bool(self.api_key)

    def capabilities(self) -> dict[str, bool]:
        """What actually works with the current configuration."""
        return {
            "search": True,
            "list_countries": True,
            # Verified against the live API: the result and DOM endpoints
            # return 403 without a key, despite the docs implying otherwise.
            # Verdicts appear in result documents but never in search hits,
            # with or without a key — see assess_indicator.
            "read_results": self.authenticated,
            "read_dom": self.authenticated,
            "verdicts_in_results": self.authenticated,
            "verdicts_in_search": False,
            "submit_scans": self.authenticated,
            "read_quotas": self.authenticated,
        }

    def _headers(self, require_key: bool, action: str) -> dict[str, str]:
        if require_key and not self.api_key:
            raise UrlscanError(
                f"{action} requires a urlscan.io API key. Set URLSCAN_API_KEY in the "
                "environment (free key at https://urlscan.io/user/signup). "
                "Search and the country list still work without one."
            )
        return {"API-Key": self.api_key} if self.api_key else {}

    # -- core request ------------------------------------------------------

    async def request(
        self,
        method: str,
        path: str,
        *,
        require_key: bool = False,
        action: str = "This operation",
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        expect_json: bool = True,
    ) -> Any:
        client = await self._get_client()
        headers = self._headers(require_key, action)

        # Only GETs are cached, and only successful ones (an exception exits
        # before the store below). A POST here is a scan submission: replaying
        # a cached response would hand back a scan id for a scan that never
        # ran, which is worse than the request it saves.
        cache_key = (
            self._cache_key(path, params) if method.upper() == "GET" else None
        )
        if cache_key is not None:
            hit = self._cache_read(cache_key)
            if hit is not None:
                return hit

        try:
            response = await client.request(
                method, path, params=params, json=json, headers=headers
            )
        except httpx.TimeoutException as exc:
            raise UrlscanError(
                f"urlscan.io timed out after {self._timeout:.0f}s. The service may be "
                "slow or unreachable; retrying usually resolves it."
            ) from exc
        except httpx.HTTPError as exc:
            raise UrlscanError(f"Could not reach urlscan.io: {exc}") from exc

        self._raise_for_status(response, action)

        if not expect_json:
            if cache_key is not None:
                self._cache_write(cache_key, response.text)
            return response.text

        try:
            payload = response.json()
        except ValueError as exc:
            raise UrlscanError(
                f"urlscan.io returned a non-JSON response (HTTP {response.status_code}) "
                f"for {path}."
            ) from exc
        if cache_key is not None:
            self._cache_write(cache_key, payload)
        return payload

    async def request_bytes(
        self, url: str, *, action: str = "Fetching an image", max_bytes: int | None = None
    ) -> bytes:
        """Fetch raw bytes from an absolute URL — screenshots live off /api.

        Not cached: an image is orders of magnitude larger than the JSON this
        cache is sized for, and one screenshot would evict the whole working set.
        `max_bytes` is checked against Content-Length *before* the body is read,
        so an oversized capture costs a header exchange rather than a download.
        """
        client = await self._get_client()
        headers = {"API-Key": self.api_key} if self.api_key else {}
        try:
            response = await client.get(url, headers=headers)
        except httpx.TimeoutException as exc:
            raise UrlscanError(
                f"urlscan.io timed out after {self._timeout:.0f}s fetching the image."
            ) from exc
        except httpx.HTTPError as exc:
            raise UrlscanError(f"Could not reach urlscan.io: {exc}") from exc

        if response.status_code == 404:
            raise ScanPending(
                "No image at that address. A freshly submitted scan may not have "
                "rendered yet, and a failed scan never produces one."
            )
        self._raise_for_status(response, action)

        if max_bytes is not None:
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise ImageTooLarge(int(declared))
            if len(response.content) > max_bytes:
                raise ImageTooLarge(len(response.content))
        return response.content

    # -- cache ------------------------------------------------------------

    @staticmethod
    def _cache_key(path: str, params: dict[str, Any] | None) -> str:
        # sort_keys so parameter order cannot split one question into two
        # entries; callers build these dicts in whatever order reads well.
        return f"{path}?{json.dumps(params or {}, sort_keys=True, default=str)}"

    def _cache_read(self, key: str) -> Any | None:
        entry = self._cache.get(key)
        if entry is None:
            self.cache_stats["misses"] += 1
            return None
        expires_at, value = entry
        if expires_at <= time.monotonic():
            self._cache.pop(key, None)
            self.cache_stats["misses"] += 1
            return None
        self.cache_stats["hits"] += 1
        return value

    def _cache_write(self, key: str, value: Any) -> None:
        if self._cache_ttl <= 0:
            return
        if len(self._cache) >= MAX_CACHE_ENTRIES:
            oldest = min(self._cache, key=lambda k: self._cache[k][0])
            self._cache.pop(oldest, None)
        self._cache[key] = (time.monotonic() + self._cache_ttl, value)

    def clear_cache(self) -> None:
        self._cache.clear()

    def _raise_for_status(self, response: httpx.Response, action: str) -> None:
        status = response.status_code

        if status == 200:
            return

        if status == 404:
            # For the result endpoint this genuinely means "not finished yet",
            # which is a normal state rather than an error.
            raise ScanPending(
                "Not found. If this was a freshly submitted scan it is probably "
                "still running — wait a few seconds and try again."
            )

        if status == 401 or status == 403:
            raise UrlscanError(
                f"{action} was rejected as unauthorised. Check that URLSCAN_API_KEY is "
                "set and valid, and that your plan covers this endpoint."
            )

        if status == 410:
            raise UrlscanError("That scan has been deleted and is no longer available.")

        if status == 429:
            raise UrlscanError(
                "Rate limited by urlscan.io. " + self._rate_limit_hint(response)
            )

        detail = self._error_detail(response)
        raise UrlscanError(f"{action} failed (HTTP {status}). {detail}")

    @staticmethod
    def _rate_limit_hint(response: httpx.Response) -> str:
        window = response.headers.get("X-Rate-Limit-Window")
        limit = response.headers.get("X-Rate-Limit-Limit")
        reset_after = response.headers.get("X-Rate-Limit-Reset-After")
        parts = []
        if limit and window:
            parts.append(f"Limit is {limit} per {window}.")
        if reset_after:
            parts.append(f"Retry in about {reset_after}s.")
        return " ".join(parts) or "Wait before retrying."

    @staticmethod
    def _error_detail(response: httpx.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            text = response.text.strip()
            return text[:300] if text else "No further detail returned."
        for key in ("message", "description", "error"):
            if isinstance(body, dict) and body.get(key):
                return str(body[key])[:300]
        return str(body)[:300]

    @staticmethod
    def rate_limit_status(response: httpx.Response) -> dict[str, str]:
        """Remaining budget, when the API bothers to tell us."""
        return {
            k.replace("X-Rate-Limit-", "").lower(): v
            for k, v in response.headers.items()
            if k.startswith("X-Rate-Limit-")
        }
