"""
decoder.py - Feature 1: JWT Decoder

Splits a raw JWT string into its three dot-separated segments and decodes
the header and payload manually using Base64URL (see utils.py). No JWT
library is used anywhere in this process.
"""

from utils import decode_json_segment


class MalformedTokenError(ValueError):
    """Raised when a string is not a structurally valid JWT."""


class DecodedToken:
    """Container for a decoded JWT's pieces."""

    def __init__(self, raw_token, header, payload, header_b64, payload_b64, signature_b64):
        self.raw_token = raw_token
        self.header = header
        self.payload = payload
        self.header_b64 = header_b64
        self.payload_b64 = payload_b64
        self.signature_b64 = signature_b64

    @property
    def signing_input(self) -> bytes:
        """The exact bytes that were signed: '<header_b64>.<payload_b64>'."""
        return f"{self.header_b64}.{self.payload_b64}".encode("ascii")


def decode_jwt(token: str) -> DecodedToken:
    """
    Decode a JWT into header, payload and raw signature segment.

    Raises:
        MalformedTokenError: if the token does not have exactly three
            dot-separated parts, or either the header or payload cannot
            be Base64URL-decoded and parsed as JSON.
    """
    if not token or not isinstance(token, str):
        raise MalformedTokenError("Token is empty or not a string")

    token = token.strip()
    parts = token.split(".")

    if len(parts) != 3:
        raise MalformedTokenError(
            f"A JWT must have exactly 3 parts separated by '.', found {len(parts)}"
        )

    header_b64, payload_b64, signature_b64 = parts

    if not header_b64 or not payload_b64:
        raise MalformedTokenError("Header or payload segment is empty")

    header = decode_json_segment(header_b64, "header")
    payload = decode_json_segment(payload_b64, "payload")

    if not isinstance(header, dict):
        raise MalformedTokenError("Decoded header is not a JSON object")
    if not isinstance(payload, dict):
        raise MalformedTokenError("Decoded payload is not a JSON object")

    return DecodedToken(token, header, payload, header_b64, payload_b64, signature_b64)


def load_token_from_file(path: str) -> str:
    """Read a single token from a file (first non-empty line)."""
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                return line
    raise MalformedTokenError(f"No token found in file: {path}")


def load_tokens_from_file(path: str) -> list:
    """Read multiple tokens from a file, one per non-empty/non-comment line (batch mode)."""
    tokens = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                tokens.append(line)
    if not tokens:
        raise MalformedTokenError(f"No tokens found in file: {path}")
    return tokens
