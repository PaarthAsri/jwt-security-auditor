"""
cli.py - jwt-audit command-line interface.

    jwt-audit --token <jwt>
    jwt-audit --file token.txt
    jwt-audit --token <jwt> --format html --output report.html
    jwt-audit --token <jwt> --check-secret --wordlist rockyou-sample.txt --i-am-authorized

Exit codes (for CI gating):
    0  - analysis completed, highest finding severity < HIGH (or no findings)
    1  - analysis completed, highest finding severity == HIGH
    2  - analysis completed, highest finding severity == CRITICAL
    3  - usage / input error (bad args, unreadable file, unparsable token)

Use --fail-on to change the severity threshold that maps to a non-zero
CI-relevant exit code.
"""
from __future__ import annotations

import argparse
import sys

from .analyzer import Severity, analyze
from .decoder import decode
from .report import to_html, to_json, to_text
from .secret_check import (BUILTIN_COMMON_WEAK_SECRETS, check_weak_secret,
                            load_wordlist)

_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jwt-audit",
        description="Passive JWT security auditor: decode, inspect, and "
                    "flag risky configurations in a JWT. Not a general "
                    "JWT toolkit — audits authorized tokens only.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--token", "-t", help="JWT string to audit")
    src.add_argument("--file", "-f", help="Path to a file containing the JWT (first line/whitespace-trimmed)")

    p.add_argument("--format", choices=["text", "json", "html"], default="text",
                    help="Report output format (default: text)")
    p.add_argument("--output", "-o", help="Write report to this file instead of stdout")

    p.add_argument("--fail-on", choices=_SEVERITY_ORDER, default="HIGH",
                    help="Minimum finding severity that produces a non-zero "
                        "CI exit code (default: HIGH)")

    secret = p.add_argument_group(
        "authorized weak-secret check (HMAC only, offline dictionary, no brute forcing)"
    )
    secret.add_argument("--check-secret", action="store_true",
                        help="Attempt to identify a weak HS256/384/512 secret "
                            "using an offline dictionary. Requires --i-am-authorized.")
    secret.add_argument("--wordlist", help="Path to a newline-delimited wordlist file")
    secret.add_argument("--use-builtin-list", action="store_true",
                        help="Also/only try a small built-in list of common weak secrets")
    secret.add_argument("--i-am-authorized", action="store_true",
                        help="Required flag confirming you are authorized to test "
                            "the secret of the system that issued this token")
    secret.add_argument("--max-candidates", type=int, default=200_000,
                        help="Hard cap on dictionary entries tried (default: 200000)")

    return p


def _read_token(args) -> str:
    if args.token:
        return args.token.strip()
    with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
        content = fh.read().strip()
    # Be forgiving of files containing "Authorization: Bearer <jwt>" or
    # surrounding quotes/whitespace/newlines.
    content = content.strip().strip('"').strip("'")
    if content.lower().startswith("bearer "):
        content = content[7:].strip()
    return content.split()[0] if content else content


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        token = _read_token(args)
    except OSError as exc:
        print(f"error: could not read token file: {exc}", file=sys.stderr)
        return 3

    if not token:
        print("error: no token content found", file=sys.stderr)
        return 3

    decoded = decode(token)
    result = analyze(decoded)

    secret_check_dict = None
    if args.check_secret:
        if not args.i_am_authorized:
            print(
                "error: --check-secret requires --i-am-authorized to confirm "
                "you have permission to test this token's issuing system. "
                "Refusing to proceed.",
                file=sys.stderr,
            )
            return 3
        alg = (decoded.header or {}).get("alg", "")
        if str(alg).upper() not in ("HS256", "HS384", "HS512"):
            print(
                f"error: --check-secret only applies to HMAC algorithms "
                f"(HS256/384/512); token uses alg={alg!r}",
                file=sys.stderr,
            )
            return 3

        candidates = []
        if args.wordlist:
            try:
                candidates.extend(load_wordlist(args.wordlist))
            except OSError as exc:
                print(f"error: could not read wordlist: {exc}", file=sys.stderr)
                return 3
        if args.use_builtin_list or not args.wordlist:
            candidates.extend(BUILTIN_COMMON_WEAK_SECRETS)
        # de-duplicate, preserve order
        seen = set()
        deduped = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                deduped.append(c)

        try:
            sc = check_weak_secret(token, alg, deduped, max_candidates=args.max_candidates)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3

        secret_check_dict = {
            "algorithm": sc.algorithm,
            "attempted": sc.attempted,
            "truncated": sc.truncated,
            "match": sc.match,
        }
        if sc.match is not None:
            from .analyzer import Finding
            result.findings.insert(0, Finding(
                id="SECRET-001",
                severity=Severity.CRITICAL,
                title="Weak HMAC signing secret confirmed",
                evidence=f"Signature matches candidate {sc.match!r} from supplied dictionary",
                explanation="The token's HMAC signature validates against a "
                            "common/weak secret. Anyone with this secret can "
                            "forge arbitrary valid tokens for this issuer.",
                remediation="Rotate the signing secret immediately to a "
                            "high-entropy random value (>= 256 bits), store "
                            "it in a secrets manager, and audit for any "
                            "tokens forged while the weak secret was active.",
            ))
            result.findings.sort(key=lambda f: (-f.severity, f.id))
            result.risk_score, result.max_severity = _recompute(result.findings)

    rendered = _render(args.format, result, secret_check_dict, token_label=_label(token))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        print(rendered)

    return _exit_code(result.max_severity, args.fail_on, result.decode.is_well_formed)


def _label(token: str) -> str:
    return token if len(token) <= 60 else token[:30] + "..." + token[-15:]


def _recompute(findings):
    from .analyzer import compute_risk_score
    return compute_risk_score(findings)


def _render(fmt, result, secret_check, token_label):
    if fmt == "json":
        return to_json(result, secret_check=secret_check)
    if fmt == "html":
        return to_html(result, secret_check=secret_check, token_label=token_label)
    return to_text(result, secret_check=secret_check)


def _exit_code(max_severity: Severity, fail_on: str, well_formed: bool) -> int:
    threshold = Severity[fail_on]
    if max_severity < threshold:
        return 0
    return 2 if max_severity >= Severity.CRITICAL else 1


if __name__ == "__main__":
    sys.exit(main())
