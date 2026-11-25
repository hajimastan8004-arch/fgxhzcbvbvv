"""
signature.py - Feature 3: HMAC Signature Verification

Implements JWT HMAC signature verification from scratch using Python's
standard-library `hmac` and `hashlib` modules. No JWT library is used.
Comparison is done in constant time with hmac.compare_digest().
"""

import hmac as hmac_module

from algorithm_check import SUPPORTED_HMAC_ALGORITHMS
from utils import base64url_decode, base64url_encode


class UnsupportedAlgorithmError(ValueError):
    """Raised when asked to HMAC-verify a token whose alg isn't HS256/384/512."""


def compute_hmac_signature(signing_input: bytes, secret: str, alg: str) -> bytes:
    """
    Recompute the HMAC digest over `signing_input` using `secret`,
    choosing the hash function from `alg` (HS256/HS384/HS512).

    Returns the raw digest bytes.
    """
    alg_normalized = str(alg).strip()
    if alg_normalized not in SUPPORTED_HMAC_ALGORITHMS:
        raise UnsupportedAlgorithmError(
            f"'{alg_normalized}' is not a supported HMAC algorithm (expected HS256/HS384/HS512)"
        )

    hash_func = SUPPORTED_HMAC_ALGORITHMS[alg_normalized]
    digest = hmac_module.new(secret.encode("utf-8"), signing_input, hash_func).digest()
    return digest


def verify_signature(signing_input: bytes, signature_b64: str, secret: str, alg: str) -> dict:
    """
    Verify a JWT's HMAC signature.

    Returns a result dict:
        {
          "valid": bool,
          "alg": str,
          "message": str,
        }

    Uses hmac.compare_digest() for a constant-time comparison so that
    verification timing does not leak information about how many bytes
    matched (defends against timing side-channel attacks).
    """
    try:
        expected_digest = compute_hmac_signature(signing_input, secret, alg)
    except UnsupportedAlgorithmError as exc:
        return {"valid": False, "alg": alg, "message": str(exc)}

    try:
        provided_digest = base64url_decode(signature_b64)
    except ValueError as exc:
        return {
            "valid": False,
            "alg": alg,
            "message": f"Could not decode provided signature: {exc}",
        }

    is_valid = hmac_module.compare_digest(expected_digest, provided_digest)

    return {
        "valid": is_valid,
        "alg": alg,
        "message": "Signature is VALID — matches the supplied secret." if is_valid
        else "Signature is INVALID — does not match the supplied secret.",
    }


def build_unsigned_variant(header: dict, payload_b64_raw: str) -> str:
    """
    Build the classic 'alg: none' attack variant of a token:
    rewrite the header with alg=None, keep the original payload bytes,
    and leave the signature segment empty.

    Used only by vulnerability_tests.test_alg_none() against a token's
    OWN lab verification endpoint, never a third-party system.
    """
    import json

    forged_header = dict(header)
    forged_header["alg"] = "none"
    header_json = json.dumps(forged_header, separators=(",", ":"))
    header_b64 = base64url_encode(header_json.encode("utf-8"))
    return f"{header_b64}.{payload_b64_raw}."
