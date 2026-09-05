"""
token_factory.py - Minimal, dependency-free JWT construction helpers used
ONLY to generate deliberately vulnerable sample tokens for the test suite.
This is intentionally not exported by the jwt_audit package: it is test
fixture tooling, not part of the audited product.
"""
import base64
import hashlib
import hmac
import json
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header: dict, payload: dict, secret: str | None = None, alg: str | None = None,
               raw_signature: bytes | None = None, corrupt_signature: bool = False) -> str:
    alg = alg if alg is not None else header.get("alg")
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if raw_signature is not None:
        sig = raw_signature
    elif alg in ("none", None):
        sig = b""
    elif alg == "HS256":
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    elif alg == "HS384":
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha384).digest()
    elif alg == "HS512":
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
    else:
        sig = b"unsupported-alg-placeholder"

    if corrupt_signature:
        sig = b"\x00" + sig[1:] if sig else b"\x00"

    sig_b64 = b64url(sig) if sig != b"" else ""
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def now() -> int:
    return int(time.time())
