"""
report.py - Renders an AuditResult as JSON, plain text, or a self-contained
HTML report.
"""
from __future__ import annotations

import html
import json

from .analyzer import AuditResult, Severity

_SEVERITY_COLOR = {
    Severity.INFO: "#6b7280",
    Severity.LOW: "#2563eb",
    Severity.MEDIUM: "#d97706",
    Severity.HIGH: "#dc2626",
    Severity.CRITICAL: "#7f1d1d",
}


def to_json(result: AuditResult, secret_check=None, indent: int = 2) -> str:
    data = result.to_dict()
    if secret_check is not None:
        data["secret_check"] = secret_check
    return json.dumps(data, indent=indent, default=str)


def to_text(result: AuditResult, secret_check=None) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append("JWT SECURITY AUDIT REPORT")
    lines.append("=" * 72)
    lines.append(f"Well-formed structure : {result.decode.is_well_formed}")
    if result.decode.structure_errors:
        for e in result.decode.structure_errors:
            lines.append(f"  ! {e}")
    lines.append(f"Risk score            : {result.risk_score}/100")
    lines.append(f"Highest severity       : {result.max_severity.label()}")
    lines.append("")

    if result.decode.header is not None:
        lines.append("-- Header --")
        lines.append(json.dumps(result.decode.header, indent=2))
        lines.append("")
    if result.decode.payload is not None:
        lines.append("-- Payload --")
        lines.append(json.dumps(result.decode.payload, indent=2))
        lines.append("")

    lines.append(f"-- Findings ({len(result.findings)}) --")
    if not result.findings:
        lines.append("No issues identified by passive analysis.")
    for f in result.findings:
        lines.append("")
        lines.append(f"[{f.severity.label()}] {f.id}: {f.title}")
        lines.append(f"  Evidence     : {f.evidence}")
        lines.append(f"  Explanation  : {f.explanation}")
        lines.append(f"  Remediation  : {f.remediation}")

    if secret_check is not None:
        lines.append("")
        lines.append("-- Weak Secret Dictionary Check (authorized, offline) --")
        lines.append(f"  Algorithm       : {secret_check['algorithm']}")
        lines.append(f"  Candidates tried: {secret_check['attempted']}"
                      + (" (wordlist truncated)" if secret_check.get("truncated") else ""))
        if secret_check["match"] is not None:
            lines.append(f"  RESULT          : WEAK SECRET FOUND -> {secret_check['match']!r}")
        else:
            lines.append("  RESULT          : no match in supplied wordlist")

    lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines)


def to_html(result: AuditResult, secret_check=None, token_label: str = "") -> str:
    def esc(s):
        return html.escape(str(s), quote=True)

    rows = []
    for f in result.findings:
        color = _SEVERITY_COLOR[f.severity]
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{color}">{esc(f.severity.label())}</span></td>
          <td><code>{esc(f.id)}</code></td>
          <td>
            <div class="finding-title">{esc(f.title)}</div>
            <div class="finding-block"><b>Evidence:</b> {esc(f.evidence)}</div>
            <div class="finding-block"><b>Why it matters:</b> {esc(f.explanation)}</div>
            <div class="finding-block"><b>Remediation:</b> {esc(f.remediation)}</div>
          </td>
        </tr>""")

    findings_html = "\n".join(rows) if rows else (
        '<tr><td colspan="3">No issues identified by passive analysis.</td></tr>'
    )

    struct_errors_html = ""
    if result.decode.structure_errors:
        items = "".join(f"<li>{esc(e)}</li>" for e in result.decode.structure_errors)
        struct_errors_html = f"<ul class='struct-errors'>{items}</ul>"

    header_json = esc(json.dumps(result.decode.header, indent=2)) if result.decode.header is not None else "(unavailable)"
    payload_json = esc(json.dumps(result.decode.payload, indent=2)) if result.decode.payload is not None else "(unavailable)"

    secret_html = ""
    if secret_check is not None:
        if secret_check["match"] is not None:
            verdict = f'<span class="badge" style="background:#7f1d1d">WEAK SECRET FOUND</span> &rarr; <code>{esc(secret_check["match"])}</code>'
        else:
            verdict = '<span class="badge" style="background:#15803d">no match</span>'
        secret_html = f"""
        <h2>Weak Secret Dictionary Check <small>(authorized, offline only)</small></h2>
        <p>Algorithm: <code>{esc(secret_check['algorithm'])}</code> &middot;
           Candidates tried: {esc(secret_check['attempted'])}
           {' (wordlist truncated)' if secret_check.get('truncated') else ''}</p>
        <p>{verdict}</p>
        """

    risk_color = _SEVERITY_COLOR[result.max_severity]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>JWT Security Audit Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
          background:#0b0d12; color:#e5e7eb; margin:0; padding:2rem; }}
  h1 {{ margin-top:0; }}
  h2 {{ border-bottom:1px solid #2a2f3a; padding-bottom:.4rem; margin-top:2.5rem;}}
  .summary {{ display:flex; gap:2rem; flex-wrap:wrap; margin:1.5rem 0; }}
  .card {{ background:#151821; border:1px solid #2a2f3a; border-radius:10px; padding:1rem 1.4rem; }}
  .score {{ font-size:2.2rem; font-weight:700; }}
  table {{ width:100%; border-collapse:collapse; margin-top:1rem; }}
  td, th {{ text-align:left; vertical-align:top; padding:.6rem .7rem; border-bottom:1px solid #2a2f3a; }}
  .badge {{ color:white; border-radius:6px; padding:.15rem .55rem; font-size:.78rem; font-weight:600; letter-spacing:.03em; }}
  .finding-title {{ font-weight:600; margin-bottom:.35rem; }}
  .finding-block {{ font-size:.92rem; color:#c7cad1; margin:.2rem 0; }}
  pre {{ background:#0f1117; border:1px solid #2a2f3a; border-radius:8px; padding:1rem; overflow-x:auto; font-size:.85rem;}}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  .struct-errors li {{ color:#fca5a5; }}
  small {{ color:#9ca3af; font-weight:400; }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:1rem; }}
  @media (max-width:800px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
  <h1>JWT Security Audit Report</h1>
  {f'<p><code>{esc(token_label)}</code></p>' if token_label else ''}
  <div class="summary">
    <div class="card"><div>Risk score</div><div class="score" style="color:{risk_color}">{result.risk_score}/100</div></div>
    <div class="card"><div>Highest severity</div><div class="score" style="color:{risk_color}">{esc(result.max_severity.label())}</div></div>
    <div class="card"><div>Well-formed structure</div><div class="score">{'YES' if result.decode.is_well_formed else 'NO'}</div></div>
    <div class="card"><div>Findings</div><div class="score">{len(result.findings)}</div></div>
  </div>
  {struct_errors_html}

  <h2>Decoded Token</h2>
  <div class="grid2">
    <div><h3>Header</h3><pre>{header_json}</pre></div>
    <div><h3>Payload</h3><pre>{payload_json}</pre></div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>ID</th><th>Details</th></tr></thead>
    <tbody>
      {findings_html}
    </tbody>
  </table>

  {secret_html}

  <p style="margin-top:3rem;color:#6b7280;font-size:.8rem;">
    Generated by jwt-audit — passive analysis only. This report reflects
    structural and best-practice checks; it does not constitute cryptographic
    verification of the token against a live issuer.
  </p>
</body>
</html>"""
