"""
claims_analyzer.py - Feature 6: Claims Security Analysis

Checks the standard JWT claims (exp, iat, nbf, iss, aud) for common
weaknesses, and scans the payload for likely sensitive data that should
never have been placed in a JWT (JWTs are only Base64URL-encoded, not
encrypted, so anyone can read the payload).
"""

import time

from utils import human_timestamp

# A token lifetime longer than this is flagged as "excessively long".
MAX_REASONABLE_LIFETIME_SECONDS = 24 * 60 * 60  # 24 hours

SENSITIVE_KEY_MARKERS = [
    "password", "passwd", "pwd", "secret", "ssn", "social_security",
    "credit_card", "card_number", "cvv", "pin", "api_key", "apikey",
    "private_key", "access_token", "bank_account", "national_id",
]


def _finding(claim, issue, severity, detail):
    return {"claim": claim, "issue": issue, "severity": severity, "detail": detail}


def analyze_claims(payload: dict) -> list:
    """
    Analyze the payload's registered claims and return a list of finding
    dicts, each with: claim, issue, severity, detail.

    Severities used: HIGH, MEDIUM, LOW, CLEAN.
    """
    findings = []
    now = int(time.time())

    # --- exp (expiry) ---------------------------------------------------
    exp = payload.get("exp")
    if exp is None:
        findings.append(_finding(
            "exp", "missing_expiry", "HIGH",
            "Token has no 'exp' claim — it never expires. A leaked or stolen "
            "token stays valid forever."
        ))
    else:
        try:
            exp = int(exp)
            if exp < now:
                findings.append(_finding(
                    "exp", "expired", "HIGH",
                    f"Token expired at {human_timestamp(exp)} (now: {human_timestamp(now)})."
                ))
            else:
                lifetime_hint = None
                iat = payload.get("iat")
                if iat is not None:
                    try:
                        lifetime_hint = int(exp) - int(iat)
                    except (TypeError, ValueError):
                        lifetime_hint = None
                if lifetime_hint is not None and lifetime_hint > MAX_REASONABLE_LIFETIME_SECONDS:
                    hours = lifetime_hint / 3600
                    findings.append(_finding(
                        "exp", "excessive_lifetime", "MEDIUM",
                        f"Token lifetime is about {hours:.1f} hours, longer than the "
                        f"{MAX_REASONABLE_LIFETIME_SECONDS // 3600}-hour guideline. Long-lived "
                        "tokens increase the damage window if stolen."
                    ))
                else:
                    findings.append(_finding(
                        "exp", "ok", "CLEAN",
                        f"Token is not expired (expires {human_timestamp(exp)})."
                    ))
        except (TypeError, ValueError):
            findings.append(_finding(
                "exp", "malformed", "HIGH", f"'exp' claim is not a valid timestamp: {exp!r}"
            ))

    # --- iat (issued-at) --------------------------------------------------
    iat = payload.get("iat")
    if iat is None:
        findings.append(_finding(
            "iat", "missing", "LOW",
            "No 'iat' claim. Not critical on its own, but makes token age and "
            "lifetime harder to audit."
        ))
    else:
        try:
            iat_int = int(iat)
            if iat_int > now + 60:  # allow small clock skew
                findings.append(_finding(
                    "iat", "future_issued_at", "LOW",
                    f"'iat' is in the future ({human_timestamp(iat_int)}), which is unusual."
                ))
            else:
                findings.append(_finding(
                    "iat", "ok", "CLEAN", f"Token issued at {human_timestamp(iat_int)}."
                ))
        except (TypeError, ValueError):
            findings.append(_finding("iat", "malformed", "LOW", f"'iat' is not a valid timestamp: {iat!r}"))

    # --- nbf (not-before) ---------------------------------------------------
    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            nbf_int = int(nbf)
            if nbf_int > now:
                findings.append(_finding(
                    "nbf", "not_yet_valid", "LOW",
                    f"Token is not valid until {human_timestamp(nbf_int)}."
                ))
            else:
                findings.append(_finding("nbf", "ok", "CLEAN", f"'nbf' satisfied ({human_timestamp(nbf_int)})."))
        except (TypeError, ValueError):
            findings.append(_finding("nbf", "malformed", "LOW", f"'nbf' is not a valid timestamp: {nbf!r}"))

    # --- iss (issuer) -------------------------------------------------------
    iss = payload.get("iss")
    if not iss:
        findings.append(_finding(
            "iss", "missing_issuer", "MEDIUM",
            "No 'iss' claim — a verifier cannot confirm which service issued this token."
        ))
    else:
        findings.append(_finding("iss", "ok", "CLEAN", f"Issuer present: {iss!r}."))

    # --- aud (audience) -------------------------------------------------------
    aud = payload.get("aud")
    if not aud:
        findings.append(_finding(
            "aud", "missing_audience", "MEDIUM",
            "No 'aud' claim — this token could potentially be replayed against "
            "a service it was never meant for."
        ))
    else:
        findings.append(_finding("aud", "ok", "CLEAN", f"Audience present: {aud!r}."))

    # --- sensitive data in payload -----------------------------------------
    sensitive_hits = _find_sensitive_keys(payload)
    if sensitive_hits:
        findings.append(_finding(
            "payload", "sensitive_data_exposed", "HIGH",
            f"Payload appears to contain sensitive field(s): {sensitive_hits}. "
            "JWTs are only Base64URL-encoded, not encrypted — anyone who can "
            "read the token can read these values."
        ))
    else:
        findings.append(_finding(
            "payload", "no_sensitive_keys_detected", "CLEAN",
            "No obviously sensitive field names detected in the payload."
        ))

    return findings


def _find_sensitive_keys(obj, prefix="") -> list:
    """Recursively scan dict keys for names that suggest sensitive data."""
    hits = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            key_lower = str(key).lower()
            if any(marker in key_lower for marker in SENSITIVE_KEY_MARKERS):
                hits.append(path)
            if isinstance(value, (dict, list)):
                hits.extend(_find_sensitive_keys(value, path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            hits.extend(_find_sensitive_keys(item, f"{prefix}[{i}]"))
    return hits
