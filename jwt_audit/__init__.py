"""jwt_audit - a small, focused JWT security auditing tool.

Passive-first: decode + analyze a JWT for common security misconfigurations
(alg:none, weak/missing claims, sensitive data exposure, suspicious headers).
Optional authorized offline dictionary check for weak HMAC secrets.
"""
from .analyzer import AuditResult, Finding, Severity, analyze
from .decoder import DecodeResult, decode

__all__ = ["decode", "analyze", "DecodeResult", "AuditResult", "Finding", "Severity"]
__version__ = "1.0.0"
