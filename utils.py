"""
utils.py - Shared helper utilities for TokenSpy.

Contains:
  - Manual Base64URL encode/decode (no JWT library used anywhere in this
    project; decoding and signature verification are implemented from
    scratch using only the standard library).
  - Terminal color codes for the CLI.
  - Small helpers used across modules (JSON pretty-printing, wordlist
    loading, secret redaction, timestamp formatting).
"""

import base64
import json
from datetime import datetime, timezone


# --------------------------------------------------------------------------
# Base64URL (RFC 4648 section 5) - implemented manually.
#
# JWTs use Base64URL *without* padding. Python's base64 module expects
# padding to be present, so we restore it before decoding, and strip it
# after encoding.
# --------------------------------------------------------------------------

def base64url_decode(data: str) -> bytes:
    """
    Decode a Base64URL string (no padding) into raw bytes.

    Steps performed manually:
      1. Replace URL-safe characters back is NOT needed because Python's
         base64.urlsafe_b64decode already understands '-' and '_'.
      2. Base64 requires the input length to be a multiple of 4. JWT
         segments have their '=' padding stripped, so we re-add it here.

    Raises:
        ValueError: if the input contains invalid Base64URL characters
                    or cannot be decoded.
    """
    if data is None:
        raise ValueError("Cannot decode None as Base64URL")

    # Base64URL alphabet check (before padding is added back).
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    if not set(data) <= allowed:
        raise ValueError("Segment contains characters outside the Base64URL alphabet")

    # Restore the padding that JWT strips off.
    padding_needed = (-len(data)) % 4
    padded = data + ("=" * padding_needed)

    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - we want to re-wrap any decode error
        raise ValueError(f"Base64URL decode failed: {exc}") from exc


def base64url_encode(data: bytes) -> str:
    """Encode raw bytes into a Base64URL string with the padding stripped."""
    encoded = base64.urlsafe_b64encode(data).decode("ascii")
    return encoded.rstrip("=")


def decode_json_segment(segment: str, name: str) -> dict:
    """Base64URL-decode a JWT segment and parse it as JSON."""
    try:
        raw_bytes = base64url_decode(segment)
    except ValueError as exc:
        raise ValueError(f"Could not decode {name}: {exc}") from exc

    try:
        return json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{name} is not valid JSON: {exc}") from exc


# --------------------------------------------------------------------------
# Terminal colors / severity styling
# --------------------------------------------------------------------------

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    GRAY = "\033[90m"


SEVERITY_COLOR = {
    "CRITICAL": Colors.RED + Colors.BOLD,
    "HIGH": Colors.RED,
    "MEDIUM": Colors.YELLOW,
    "LOW": Colors.BLUE,
    "CLEAN": Colors.GREEN,
    "INFO": Colors.CYAN,
}


def colorize_severity(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity.upper(), "")
    return f"{color}{severity.upper()}{Colors.RESET}"


# --------------------------------------------------------------------------
# Misc helpers
# --------------------------------------------------------------------------

def pretty_json(obj) -> str:
    """Return a nicely indented JSON string for display purposes."""
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False)


def load_wordlist(path: str) -> list:
    """
    Load a plain-text wordlist file, one candidate secret per line.
    Blank lines and lines starting with '#' are ignored.
    """
    secrets = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            secrets.append(line)
    return secrets


def redact_secret(secret: str) -> str:
    """Never print a real secret. Show only its length and a hash fingerprint."""
    import hashlib

    if secret is None:
        return "N/A"
    fingerprint = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]
    return f"<redacted: {len(secret)} chars, fingerprint {fingerprint}>"


def human_timestamp(ts) -> str:
    """Convert a Unix timestamp (int/float) to a readable UTC string."""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (ValueError, TypeError, OSError):
        return f"<invalid timestamp: {ts!r}>"


def now_utc_string() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
