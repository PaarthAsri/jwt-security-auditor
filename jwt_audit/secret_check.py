"""
secret_check.py - OPTIONAL, offline, dictionary-based weak-secret test
for HMAC-signed (HS256/384/512) tokens.

Scope and safety constraints (by design, not configurable away):
  * This module NEVER contacts a network or the token's issuer.
  * It ONLY tries candidate strings drawn from a wordlist file the
    caller supplies (or the small built-in common-weak-secret list).
  * It performs no incremental brute forcing, mutation, or generation
    of candidates - only a fixed, finite, user-provided dictionary.
  * Callers (see cli.py) MUST pass an explicit --i-am-authorized flag
    before this function is ever invoked, confirming the operator is
    authorized to test the system/token in question.

This is a defensive auditing helper (e.g. "is our HS256 secret
'changeme'?"), not an offensive cracking tool.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .decoder import signing_input

_HASH_FOR_ALG = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

# Small, well-known, illustrative set of weak secrets. This is deliberately
# tiny - it is a convenience default, not a cracking wordlist. Real audits
# should supply their own authorized wordlist via --wordlist.
BUILTIN_COMMON_WEAK_SECRETS = (
    "secret", "password", "123456", "changeme", "your-256-bit-secret",
    "jwt_secret", "secretkey", "test", "supersecret", "qwerty",
    "letmein", "admin", "key", "your-secret-key",
)


@dataclass
class SecretCheckResult:
    attempted: int
    match: str | None
    algorithm: str
    truncated: bool = False


def check_weak_secret(token: str, alg: str, wordlist: list, max_candidates: int = 200_000) -> SecretCheckResult:
    """Try each candidate secret in `wordlist` against the token's HMAC
    signature using constant-time comparison. Returns as soon as a match
    is found. Caller is responsible for enforcing authorization before
    calling this function."""
    alg = alg.upper()
    if alg not in _HASH_FOR_ALG:
        raise ValueError(f"check_weak_secret only supports HMAC algorithms {list(_HASH_FOR_ALG)}, got {alg!r}")

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Token must have 3 segments to check its signature")

    import base64
    sig_b64 = parts[2]
    padded = sig_b64 + "=" * (-len(sig_b64) % 4)
    try:
        expected_sig = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise ValueError(f"Could not decode signature segment: {exc}")

    msg = signing_input(token)
    hash_fn = _HASH_FOR_ALG[alg]

    truncated = False
    if len(wordlist) > max_candidates:
        wordlist = wordlist[:max_candidates]
        truncated = True

    attempted = 0
    for candidate in wordlist:
        attempted += 1
        candidate_bytes = candidate.encode("utf-8") if isinstance(candidate, str) else candidate
        computed = hmac.new(candidate_bytes, msg, hash_fn).digest()
        if hmac.compare_digest(computed, expected_sig):
            return SecretCheckResult(attempted=attempted, match=candidate,
                                       algorithm=alg, truncated=truncated)

    return SecretCheckResult(attempted=attempted, match=None, algorithm=alg,
                               truncated=truncated)


def load_wordlist(path: str) -> list:
    candidates = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.rstrip("\n\r")
            if line:
                candidates.append(line)
    return candidates
