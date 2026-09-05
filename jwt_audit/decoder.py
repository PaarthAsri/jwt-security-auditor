"""
decoder.py - Safe, non-verifying JWT structural decoder.

This module NEVER trusts the token. It only splits, base64url-decodes,
and JSON-parses the three segments, recording every structural anomaly
it finds along the way instead of raising and losing that evidence.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field

_B64URL_RE = re.compile(r'^[A-Za-z0-9_-]*$')


@dataclass
class DecodeResult:
    raw_token: str
    parts: list = field(default_factory=list)          # raw segment strings
    header_raw: bytes | None = None
    payload_raw: bytes | None = None
    signature_raw: bytes | None = None
    header: dict | None = None
    payload: dict | None = None
    structure_errors: list = field(default_factory=list)  # list[str]
    is_well_formed: bool = True

    def add_error(self, msg: str):
        self.structure_errors.append(msg)
        self.is_well_formed = False


def _b64url_decode(segment: str, name: str, result: DecodeResult) -> bytes | None:
    if segment == "":
        result.add_error(f"{name} segment is empty")
        return None
    if not _B64URL_RE.match(segment):
        result.add_error(
            f"{name} segment contains characters outside the Base64URL "
            f"alphabet (found non [A-Za-z0-9_-] characters)"
        )
        # still attempt best-effort decode below

    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        result.add_error(f"{name} segment failed Base64URL decoding: {exc}")
        return None


def _json_parse(raw: bytes | None, name: str, result: DecodeResult) -> dict | None:
    if raw is None:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        result.add_error(f"{name} segment is not valid UTF-8: {exc}")
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.add_error(f"{name} segment is not valid JSON: {exc}")
        return None
    if not isinstance(data, dict):
        result.add_error(f"{name} segment JSON is not an object (got {type(data).__name__})")
        return None
    return data


def decode(token: str) -> DecodeResult:
    """Parse a JWT string into its structural components without any
    trust decisions. Every anomaly is recorded rather than raised."""
    result = DecodeResult(raw_token=token.strip())
    token = result.raw_token

    if token == "":
        result.add_error("Token is empty")
        return result

    parts = token.split(".")
    result.parts = parts

    if len(parts) != 3:
        result.add_error(
            f"Token does not have the required 3 dot-separated segments "
            f"(found {len(parts)}). This may not be a JWT (e.g. it could be "
            f"a JWE with 5 segments, or an opaque/reference token)."
        )
        # Still attempt to decode whatever segments exist, best-effort.
        while len(parts) < 3:
            parts.append("")

    header_seg, payload_seg, sig_seg = parts[0], parts[1], parts[2]

    result.header_raw = _b64url_decode(header_seg, "Header", result)
    result.payload_raw = _b64url_decode(payload_seg, "Payload", result)

    if sig_seg == "":
        result.add_error("Signature segment is empty (unsigned or 'alg:none' token)")
    else:
        result.signature_raw = _b64url_decode(sig_seg, "Signature", result)

    result.header = _json_parse(result.header_raw, "Header", result)
    result.payload = _json_parse(result.payload_raw, "Payload", result)

    return result


def signing_input(token: str) -> bytes:
    """Return the exact bytes that were signed (header.payload), used for
    offline HMAC secret verification. Raises ValueError if malformed."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Token does not have enough segments to reconstruct signing input")
    return f"{parts[0]}.{parts[1]}".encode("ascii")
