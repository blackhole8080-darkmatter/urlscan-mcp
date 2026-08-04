"""HTTP layer for the urlscan.io API.

Everything that can go wrong with a remote API is handled here so the tool
layer stays readable: auth, rate limits, the scan-still-running case, and
network failure all become clear, actionable messages rather than tracebacks.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

BASE_URL = "https://urlscan.io"
USER_AGENT = "urlscan-mcp/0.1 (+https://github.com/)"
DEFAULT_TIMEOUT = 30.0


class UrlscanError(Exception):
    """An error worth showing to the model verbatim."""


class ScanPending(UrlscanError):
    """The scan exists but has not finished yet. Retry, do not treat as failure."""


class UrlscanClient:
    """Thin async client.

    The API key is optional on purpose. Search, result retrieval and the
    country list all work unauthenticated; only submission and quota lookup
    require a key. Running without one degrades to read-only rather than
    failing at import time, and `capabilities()` reports exactly what is
    available so the caller never has to guess.
    """

    def __init__(self, api_key: str | None = None, timeout: float = DEFAULT_TIMEOUT):
        self.api_key = api_key if api_key is not None else os.getenv("URLSCAN_API_KEY")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

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
            return response.text

        try:
            return response.json()
        except ValueError as exc:
            raise UrlscanError(
                f"urlscan.io returned a non-JSON response (HTTP {response.status_code}) "
                f"for {path}."
            ) from exc

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
