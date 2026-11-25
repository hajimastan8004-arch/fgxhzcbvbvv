"""
algorithm_check.py - Feature 2: Algorithm Detection

Looks at the JWT header's "alg" field and classifies it. Supported
HMAC algorithms map to hashlib's constructors; anything else is flagged.
"""

import hashlib

SUPPORTED_HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

# Algorithms that are not HMAC but are commonly seen (asymmetric / none).
# TokenSpy only verifies HMAC, so these are reported but not verifiable here.
KNOWN_NON_HMAC_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}


def check_algorithm(header: dict) -> dict:
    """
    Inspect the header's alg (and kid/typ) and return a finding dict:
        {
          "alg": <str>,
          "status": "OK" | "CRITICAL" | "WARNING" | "UNSUPPORTED",
          "severity": "CLEAN" | "CRITICAL" | "MEDIUM" | "LOW",
          "message": <human readable explanation>,
          "hmac_verifiable": bool,
          "hash_func": callable or None,
          "kid": value or None,
          "typ": value or None,
        }
    """
    alg = header.get("alg")
    typ = header.get("typ")
    kid = header.get("kid")

    if alg is None:
        return {
            "alg": None,
            "status": "CRITICAL",
            "severity": "CRITICAL",
            "message": "Header has no 'alg' field at all. Token cannot be trusted.",
            "hmac_verifiable": False,
            "hash_func": None,
            "kid": kid,
            "typ": typ,
        }

    alg_normalized = str(alg).strip()

    # "none" algorithm, case-insensitively, is the classic JWT bypass vector.
    if alg_normalized.lower() == "none":
        return {
            "alg": alg_normalized,
            "status": "CRITICAL",
            "severity": "CRITICAL",
            "message": (
                "alg is set to 'none'. This token claims to require no signature "
                "at all. If any verifier accepts this, authentication is "
                "completely bypassable."
            ),
            "hmac_verifiable": False,
            "hash_func": None,
            "kid": kid,
            "typ": typ,
        }

    if alg_normalized in SUPPORTED_HMAC_ALGORITHMS:
        return {
            "alg": alg_normalized,
            "status": "OK",
            "severity": "CLEAN",
            "message": f"{alg_normalized} is a supported HMAC algorithm. TokenSpy can verify its signature.",
            "hmac_verifiable": True,
            "hash_func": SUPPORTED_HMAC_ALGORITHMS[alg_normalized],
            "kid": kid,
            "typ": typ,
        }

    if alg_normalized in KNOWN_NON_HMAC_ALGORITHMS:
        return {
            "alg": alg_normalized,
            "status": "WARNING",
            "severity": "MEDIUM",
            "message": (
                f"{alg_normalized} is an asymmetric/RSA-PSS/ECDSA algorithm. "
                "TokenSpy only implements HMAC verification, so the signature "
                "cannot be checked here. Also watch for 'algorithm confusion' "
                "attacks where a server expecting this algorithm is tricked "
                "into verifying with HMAC using a public key as the secret."
            ),
            "hmac_verifiable": False,
            "hash_func": None,
            "kid": kid,
            "typ": typ,
        }

    return {
        "alg": alg_normalized,
        "status": "UNSUPPORTED",
        "severity": "MEDIUM",
        "message": f"'{alg_normalized}' is not a recognized/expected algorithm for this verifier.",
        "hmac_verifiable": False,
        "hash_func": None,
        "kid": kid,
        "typ": typ,
    }


def inspect_kid(kid) -> dict:
    """
    Feature (stretch): inspect the 'kid' (Key ID) header for suspicious
    path-traversal or injection-shaped values, a known real-world JWT
    attack vector (e.g. kid pointing outside the intended key directory,
    or kid used to build a SQL/command string).
    """
    if kid is None:
        return {"kid": None, "severity": "INFO", "message": "No 'kid' header present."}

    kid_str = str(kid)
    suspicious_markers = ["../", "..\\", "/etc/", "\\windows\\", "' OR ", "--", ";", "|", "$(", "`"]
    hits = [m for m in suspicious_markers if m.lower() in kid_str.lower()]

    if hits:
        return {
            "kid": kid_str,
            "severity": "HIGH",
            "message": (
                f"'kid' value looks suspicious (matched pattern(s): {hits}). "
                "This can indicate a path-traversal or injection attempt against "
                "key-lookup logic."
            ),
        }

    return {
        "kid": kid_str,
        "severity": "CLEAN",
        "message": "'kid' value does not match any known suspicious pattern.",
    }
