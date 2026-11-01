"""Shared helpers for the taintproof scripts. Standard library only."""
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
REFERENCES_DIR = SKILL_DIR / "references"
RULES_FILE = REFERENCES_DIR / "dynamic-rules.md"
KEV_INDEX_FILE = REFERENCES_DIR / "kev-index.tsv"

USER_AGENT = "taintproof-skill/1.0"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")

# C0/C1 controls plus zero-width and bidi characters, which can hide instructions.
INVISIBLE = re.compile("[\x00-\x1f\x7f-\x9f​-‏ -‮⁠-⁤﻿]")


def use_utf8_stdout():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def clean(value, limit=200):
    """Flatten third-party text so it can only ever be data in a Markdown table."""
    text = " ".join(INVISIBLE.sub(" ", str(value or "")).split())
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("|", "/").replace("`", "'")
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def http_json(url, payload=None, headers=None, timeout=45, retries=2):
    """GET, or POST when payload is given. Retries rate limits and server errors."""
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    for attempt in range(retries + 1):
        request = urllib.request.Request(url, data=data, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError(f"response from {url} exceeds {MAX_RESPONSE_BYTES} bytes")
            return json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code not in (403, 429, 500, 502, 503, 504) or attempt == retries:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries:
                raise
        time.sleep(6 * (attempt + 1))
    raise RuntimeError("unreachable")


def kev_lookup():
    """Map CVE ID to its KEV row, or an empty dict before the first update."""
    if not KEV_INDEX_FILE.exists():
        return {}
    rows = {}
    for line in KEV_INDEX_FILE.read_text(encoding="utf-8").splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) == 7:
            rows[fields[0]] = fields
    return rows
