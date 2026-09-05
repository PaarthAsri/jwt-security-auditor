"""
analyzer.py - Passive JWT security analysis.

Everything here is READ-ONLY / non-intrusive: it inspects the decoded
header and payload and reasons about them. Nothing in this module makes
a network call, mutates a remote system, or attempts to forge a token.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import IntEnum

from .decoder import DecodeResult

# ----------------------------------------------------------------------
# Severity model
# ----------------------------------------------------------------------

class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self) -> str:
        return self.name


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}


@dataclass
class Finding:
    id: str
    severity: Severity
    title: str
    evidence: str
    explanation: str
    remediation: str

    def to_dict(self):
        return {
            "id": self.id,
            "severity": self.severity.label(),
            "title": self.title,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "remediation": self.remediation,
        }


@dataclass
class AuditResult:
    decode: DecodeResult
    findings: list = field(default_factory=list)   # list[Finding]
    risk_score: int = 0
    max_severity: Severity = Severity.INFO

    def to_dict(self):
        return {
            "well_formed": self.decode.is_well_formed,
            "structure_errors": self.decode.structure_errors,
            "header": self.decode.header,
            "payload": self.decode.payload,
            "signature_present": bool(self.decode.signature_raw)
            or (self.decode.parts and self.decode.parts[-1] not in ("", None)),
            "risk_score": self.risk_score,
            "max_severity": self.max_severity.label(),
            "findings": [f.to_dict() for f in self.findings],
        }


# ----------------------------------------------------------------------
# Constants / heuristics
# ----------------------------------------------------------------------

# Algorithms considered acceptable baseline choices. Anything outside this
# set (or explicitly dangerous) gets flagged.
SECURE_ALGS = {
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
}
HMAC_ALGS = {"HS256", "HS384", "HS512"}
ASYMMETRIC_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

DANGEROUS_ALGS = {"none", "None", "NONE", "nOnE"}

MAX_REASONABLE_LIFETIME_SECONDS = 60 * 60 * 24 * 365  # 1 year
LONG_LIFETIME_WARN_SECONDS = 60 * 60 * 24 * 30        # 30 days
CLOCK_SKEW_LEEWAY_SECONDS = 300                        # 5 minutes grace

SENSITIVE_KEY_PATTERNS = [
    (re.compile(r'pass(word)?$', re.I), "password"),
    (re.compile(r'secret', re.I), "secret"),
    (re.compile(r'token$', re.I), "embedded token/credential"),
    (re.compile(r'api[_-]?key', re.I), "API key"),
    (re.compile(r'private[_-]?key', re.I), "private key material"),
    (re.compile(r'ssn|social[_-]?security', re.I), "national ID / SSN"),
    (re.compile(r'credit[_-]?card|card[_-]?number|ccn', re.I), "payment card data"),
    (re.compile(r'dob|date[_-]?of[_-]?birth', re.I), "date of birth"),
    (re.compile(r'^pin$', re.I), "PIN code"),
]

# Very rough patterns for values that *look* sensitive even under an
# innocuous key name.
CREDIT_CARD_VALUE_RE = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
EMAIL_VALUE_RE = re.compile(r'[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}')

SUSPICIOUS_KID_RE = re.compile(r'(\.\./|\.\.\\|[;|&$`]|\bSELECT\b|\bUNION\b|\bDROP\b|\x00)', re.I)

STANDARD_TIME_CLAIMS = ("exp", "nbf", "iat")
STANDARD_STRING_CLAIMS = ("iss", "aud", "sub")


def _f(id_, sev, title, evidence, explanation, remediation) -> Finding:
    return Finding(id=id_, severity=sev, title=title, evidence=evidence,
                    explanation=explanation, remediation=remediation)


# ----------------------------------------------------------------------
# Individual check functions - each returns a list[Finding]
# ----------------------------------------------------------------------

def check_structure(d: DecodeResult) -> list:
    findings = []
    if not d.is_well_formed:
        findings.append(_f(
            "STRUCT-001", Severity.CRITICAL,
            "Malformed JWT structure",
            "; ".join(d.structure_errors),
            "The token does not conform to the expected header.payload.signature "
            "Base64URL/JSON structure defined in RFC 7519. Parsers with lenient "
            "or inconsistent handling of malformed tokens are a common source "
            "of authentication bypass bugs.",
            "Reject any token that fails strict structural validation before "
            "attempting any further processing or verification.",
        ))
    return findings


def check_algorithm(header: dict) -> list:
    findings = []
    if header is None:
        return findings
    alg = header.get("alg")

    if alg is None:
        findings.append(_f(
            "ALG-001", Severity.HIGH,
            "Missing 'alg' header claim",
            "header.alg is absent",
            "The 'alg' field declares which algorithm the server should use to "
            "verify the signature. Its absence often indicates a non-standard "
            "or misconfigured issuer and can enable algorithm-confusion attacks "
            "in lenient verifiers.",
            "Always issue tokens with an explicit, expected 'alg' value and "
            "reject tokens where it is missing.",
        ))
        return findings

    if str(alg).strip() in DANGEROUS_ALGS or str(alg).strip().lower() == "none":
        findings.append(_f(
            "ALG-002", Severity.CRITICAL,
            "'alg:none' signature bypass",
            f"header.alg = {alg!r}",
            "The 'none' algorithm indicates an unsigned token. If a relying "
            "party is tricked into honoring this token, authentication and "
            "integrity protections are completely bypassed. This is one of "
            "the most well-known JWT vulnerabilities (CVE-class 'alg:none').",
            "Verifiers must maintain an allow-list of acceptable algorithms "
            "and unconditionally reject 'none'. Never derive the verification "
            "algorithm from the token itself.",
        ))
        return findings

    if alg not in SECURE_ALGS:
        findings.append(_f(
            "ALG-003", Severity.HIGH,
            "Unrecognized or non-standard signing algorithm",
            f"header.alg = {alg!r}",
            "The algorithm is outside the common, well-vetted JWS algorithm "
            "set. This may indicate a custom/experimental implementation, a "
            "deprecated algorithm, or a crafted value intended to confuse a "
            "poorly-implemented verifier.",
            "Restrict accepted algorithms to a small explicit allow-list "
            "matching your key type, and reject anything else.",
        ))
    elif alg in ASYMMETRIC_ALGS:
        findings.append(_f(
            "ALG-004", Severity.INFO,
            "Asymmetric signing algorithm in use",
            f"header.alg = {alg!r}",
            "Asymmetric algorithms (RSA/ECDSA/RSA-PSS) are generally "
            "preferable to shared-secret HMAC when tokens are verified by "
            "multiple/untrusted parties, since verifiers only need the "
            "public key. Confirm the verifier pins the expected public key "
            "and does not accept a public key supplied by the token itself.",
            "No action required if the verifier hardcodes/pins the correct "
            "public key per issuer and enforces the algorithm allow-list "
            "(prevents RS256->HS256 confusion attacks).",
        ))

    # jku / x5u / jwk in header = server is told to fetch/trust an
    # attacker-influenceable key source.
    for key, desc in (("jku", "JWK Set URL"), ("x5u", "X.509 URL"), ("jwk", "embedded JWK")):
        if key in header:
            findings.append(_f(
                f"ALG-HDR-{key.upper()}", Severity.HIGH,
                f"'{key}' header present ({desc})",
                f"header.{key} = {header[key]!r}",
                f"The '{key}' header lets the token itself point to (or embed) "
                "the key material used for verification. If a verifier trusts "
                "this value without strict allow-listing, an attacker can "
                "supply their own key and self-sign arbitrary tokens.",
                f"Ignore '{key}' from untrusted tokens; verifiers should use a "
                "pre-configured, pinned key/JWKS source resolved server-side, "
                "never one supplied by the token.",
            ))

    if "kid" in header:
        kid = str(header.get("kid"))
        if SUSPICIOUS_KID_RE.search(kid):
            findings.append(_f(
                "ALG-KID-001", Severity.HIGH,
                "Suspicious 'kid' header value",
                f"header.kid = {kid!r}",
                "The 'kid' (Key ID) header is often used unsafely by "
                "verifiers to build a file path or SQL query to look up the "
                "verification key. This value contains characters consistent "
                "with path traversal or injection payloads.",
                "Treat 'kid' as untrusted input: validate it against a strict "
                "allow-list/format (e.g. UUID) before using it in any lookup, "
                "and never interpolate it directly into file paths or queries.",
            ))
        elif len(kid) > 128:
            findings.append(_f(
                "ALG-KID-002", Severity.MEDIUM,
                "Unusually long 'kid' header value",
                f"header.kid length = {len(kid)}",
                "An excessively long key identifier is atypical and may be an "
                "attempt to exploit a poorly-bounded key lookup or cause "
                "resource exhaustion.",
                "Enforce a sane maximum length and character set for 'kid' "
                "before using it.",
            ))

    if header.get("crit"):
        findings.append(_f(
            "ALG-CRIT-001", Severity.MEDIUM,
            "'crit' (critical headers) extension present",
            f"header.crit = {header.get('crit')!r}",
            "RFC 7515 'crit' lists extension headers the verifier MUST "
            "understand and enforce, or else reject the token. Verifiers "
            "that ignore unrecognized 'crit' entries silently undermine "
            "whatever protection those extensions were meant to add.",
            "Confirm the verifier implements and enforces every header name "
            "listed in 'crit', and rejects the token if any are unrecognized.",
        ))

    return findings


def _fmt_ts(ts) -> str:
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return str(ts)
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) + f" (epoch {ts:g})"
    except (OverflowError, OSError, ValueError):
        return f"epoch {ts:g} (out of range)"


def check_claims(payload: dict, now: float | None = None) -> list:
    findings = []
    if payload is None:
        return findings
    now = time.time() if now is None else now

    # --- type sanity for time claims ---
    numeric_times = {}
    for claim in STANDARD_TIME_CLAIMS:
        if claim in payload:
            val = payload[claim]
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                findings.append(_f(
                    f"CLAIM-{claim.upper()}-TYPE", Severity.MEDIUM,
                    f"'{claim}' claim has an invalid type",
                    f"payload.{claim} = {val!r} (type {type(val).__name__})",
                    f"The '{claim}' claim must be a NumericDate (seconds since "
                    "the Unix epoch) per RFC 7519. A non-numeric value likely "
                    "indicates a broken issuer or a verifier that silently "
                    "fails open when parsing fails.",
                    f"Ensure '{claim}' is always emitted and validated as an "
                    "integer NumericDate, and reject tokens where it is not.",
                ))
            else:
                numeric_times[claim] = float(val)

    # --- exp ---
    if "exp" not in payload:
        findings.append(_f(
            "CLAIM-EXP-001", Severity.HIGH,
            "Missing 'exp' (expiration) claim",
            "payload.exp is absent",
            "Without an expiration, a captured/leaked token remains valid "
            "indefinitely, dramatically increasing the impact of any token "
            "theft (e.g. via XSS, logs, referrer leakage, or a compromised "
            "client).",
            "Always set a short, purpose-appropriate 'exp' and enforce it "
            "strictly during verification.",
        ))
    elif "exp" in numeric_times:
        exp = numeric_times["exp"]
        if exp < now - CLOCK_SKEW_LEEWAY_SECONDS:
            age = now - exp
            findings.append(_f(
                "CLAIM-EXP-002", Severity.HIGH,
                "Token is expired",
                f"exp = {_fmt_ts(exp)}; expired {age:.0f}s ago (now = {_fmt_ts(now)})",
                "The token's expiration timestamp is in the past. A correct "
                "verifier must reject this token outright.",
                "Confirm the verification path rejects expired tokens and "
                "does not fall back to accepting them (e.g. on clock-parsing "
                "errors).",
            ))

    # --- nbf ---
    if "nbf" in numeric_times:
        nbf = numeric_times["nbf"]
        if nbf > now + CLOCK_SKEW_LEEWAY_SECONDS:
            findings.append(_f(
                "CLAIM-NBF-001", Severity.MEDIUM,
                "Token is not yet valid ('nbf' in the future)",
                f"nbf = {_fmt_ts(nbf)} (now = {_fmt_ts(now)})",
                "The 'not before' timestamp has not yet elapsed; a "
                "spec-compliant verifier should currently reject this token.",
                "Confirm 'nbf' is enforced by the verifier and is intentional "
                "(e.g. pre-issued tokens for scheduled activation).",
            ))

    # --- iat ---
    if "iat" in numeric_times:
        iat = numeric_times["iat"]
        if iat > now + CLOCK_SKEW_LEEWAY_SECONDS:
            findings.append(_f(
                "CLAIM-IAT-001", Severity.MEDIUM,
                "'iat' (issued-at) is in the future",
                f"iat = {_fmt_ts(iat)} (now = {_fmt_ts(now)})",
                "An issued-at timestamp in the future is inconsistent and "
                "may indicate clock skew on the issuer, a forged token, or "
                "a testing artifact.",
                "Investigate issuer clock configuration; consider rejecting "
                "tokens with implausible 'iat' values.",
            ))
    else:
        findings.append(_f(
            "CLAIM-IAT-002", Severity.LOW,
            "Missing 'iat' (issued-at) claim",
            "payload.iat is absent",
            "Without 'iat', token age cannot be determined, which weakens "
            "auditing, revocation-by-age strategies, and anomaly detection.",
            "Include 'iat' on every issued token.",
        ))

    # --- lifetime ---
    if "exp" in numeric_times and "iat" in numeric_times:
        lifetime = numeric_times["exp"] - numeric_times["iat"]
        if lifetime > MAX_REASONABLE_LIFETIME_SECONDS:
            findings.append(_f(
                "CLAIM-LIFETIME-001", Severity.HIGH,
                "Excessively long-lived token",
                f"lifetime = {lifetime / 86400:.1f} days (iat={_fmt_ts(numeric_times['iat'])}, "
                f"exp={_fmt_ts(numeric_times['exp'])})",
                "A validity window longer than a year is atypical for "
                "bearer tokens and greatly increases the blast radius of a "
                "single leaked token.",
                "Shorten token lifetime and rely on a refresh-token flow for "
                "long-lived sessions instead of a single long-lived access "
                "token.",
            ))
        elif lifetime > LONG_LIFETIME_WARN_SECONDS:
            findings.append(_f(
                "CLAIM-LIFETIME-002", Severity.MEDIUM,
                "Long-lived token",
                f"lifetime = {lifetime / 86400:.1f} days",
                "Bearer tokens valid for more than 30 days increase exposure "
                "if leaked, since there is a wide window for misuse before "
                "natural expiry.",
                "Consider shortening the access-token lifetime and using "
                "refresh tokens for extended sessions.",
            ))
        elif lifetime < 0:
            findings.append(_f(
                "CLAIM-LIFETIME-003", Severity.MEDIUM,
                "Token expires before it was issued",
                f"iat={_fmt_ts(numeric_times['iat'])} is after exp={_fmt_ts(numeric_times['exp'])}",
                "This is logically inconsistent and indicates either a "
                "broken issuer or a tampered/hand-crafted token.",
                "Investigate the issuing system; reject tokens failing this "
                "sanity check.",
            ))

    # --- iss / aud / sub presence ---
    for claim, sev in (("iss", Severity.LOW), ("aud", Severity.LOW), ("sub", Severity.LOW)):
        if claim not in payload:
            findings.append(_f(
                f"CLAIM-{claim.upper()}-MISSING", sev,
                f"Missing '{claim}' claim",
                f"payload.{claim} is absent",
                {
                    "iss": "Without 'iss', a verifier cannot confirm which "
                           "authority issued the token, which is important "
                           "when multiple issuers/environments share "
                           "verification infrastructure.",
                    "aud": "Without 'aud', a token legitimately issued for "
                           "one service could potentially be replayed against "
                           "a different service that shares the same signing "
                           "key/issuer (a common cross-service confusion "
                           "attack).",
                    "sub": "Without 'sub', the token does not clearly bind to "
                           "a specific subject/principal, which can complicate "
                           "authorization decisions and auditing.",
                }[claim],
                {
                    "iss": "Set 'iss' and verify it against an expected "
                           "value/allow-list.",
                    "aud": "Set 'aud' to the intended recipient service and "
                           "verify it strictly on every relying party.",
                    "sub": "Always set 'sub' to a stable, unique subject "
                           "identifier.",
                }[claim],
            ))

    return findings


def check_sensitive_data(payload: dict) -> list:
    findings = []
    if payload is None:
        return findings

    def walk(obj, path):
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_path = f"{path}.{k}" if path else str(k)
                for pattern, label in SENSITIVE_KEY_PATTERNS:
                    if pattern.search(str(k)):
                        findings.append(_f(
                            "SENS-KEY-001", Severity.HIGH,
                            "Potentially sensitive data in payload",
                            f"payload key '{new_path}' suggests {label}",
                            "JWT payloads are only Base64URL-encoded, NOT "
                            "encrypted, and are trivially readable by anyone "
                            "who obtains the token (browser devtools, proxy "
                            "logs, referrers, etc.). Storing secrets or PII "
                            "in a signed-but-unencrypted token exposes that "
                            "data to the token bearer and any intermediary.",
                            "Remove sensitive data from the payload, or "
                            "switch to an encrypted token format (JWE) if it "
                            "must be carried in the token.",
                        ))
                        break
                if isinstance(v, str) and EMAIL_VALUE_RE.search(v) and k not in ("email", "sub", "upn"):
                    findings.append(_f(
                        "SENS-VAL-EMAIL", Severity.LOW,
                        "Email-like value found under an unrelated claim",
                        f"payload key '{new_path}' contains an email-like value",
                        "Personally identifiable information embedded under "
                        "a non-obvious claim name is easy to overlook during "
                        "privacy/security review but is just as exposed as "
                        "any other payload data.",
                        "Confirm this is intentional; minimize PII in the "
                        "token to what each relying party strictly needs.",
                    ))
                if isinstance(v, str) and CREDIT_CARD_VALUE_RE.search(v):
                    findings.append(_f(
                        "SENS-VAL-PAN", Severity.CRITICAL,
                        "Value resembling a payment card number found",
                        f"payload key '{new_path}' contains a digit sequence "
                        "matching payment-card-number length/format",
                        "A value shaped like a PAN (Primary Account Number) "
                        "in a plaintext-readable token is a severe data "
                        "exposure risk and may violate PCI-DSS.",
                        "Never place cardholder data in a JWT payload. "
                        "Use a tokenized reference from your payment "
                        "processor instead.",
                    ))
                walk(v, new_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")

    walk(payload, "")
    return findings


def compute_risk_score(findings: list) -> tuple:
    """Returns (score 0-100, max_severity)."""
    if not findings:
        return 0, Severity.INFO
    total = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    score = min(100, total)
    max_sev = max(f.severity for f in findings)
    return score, max_sev


def analyze(decode_result: DecodeResult, now: float | None = None) -> AuditResult:
    findings = []
    findings += check_structure(decode_result)
    findings += check_algorithm(decode_result.header)
    findings += check_claims(decode_result.payload, now=now)
    findings += check_sensitive_data(decode_result.payload)

    # Stable order: most severe first, then by id for determinism.
    findings.sort(key=lambda f: (-f.severity, f.id))

    score, max_sev = compute_risk_score(findings)
    return AuditResult(decode=decode_result, findings=findings,
                        risk_score=score, max_severity=max_sev)
