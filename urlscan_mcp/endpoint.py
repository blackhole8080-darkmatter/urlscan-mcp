"""Where the API lives.

One module because two places need it — the JSON client and the screenshot
fetcher — and a host that drifts between them would send credentials to one
service and read images from another.

``URLSCAN_BASE_URL`` overrides the public host. That exists for two reasons:
urlscan sells a self-hosted appliance, whose customers should not have to fork
this to point at it; and an integration test cannot prove that an image
survives a subprocess boundary unless it can serve one. It is read once, at
import, and never written into any file.
"""

from __future__ import annotations

import os

PUBLIC_BASE_URL = "https://urlscan.io"

#: The host every request goes to. Trailing slashes are stripped so callers can
#: set it either way without producing `//api/v1/...`.
BASE_URL = (os.getenv("URLSCAN_BASE_URL") or PUBLIC_BASE_URL).rstrip("/")

#: Screenshots are served off the main host rather than under /api, and need no
#: API key.
SCREENSHOT_URL = BASE_URL + "/screenshots/{uuid}.png"


def is_public() -> bool:
    """False when pointed at a self-hosted instance — worth saying out loud
    before a caller reads a capability report as describing urlscan.io."""
    return BASE_URL == PUBLIC_BASE_URL
