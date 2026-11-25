"""
report_generator.py - Feature 7: Security Report Generation

Collects the results of every check into one structured report, computes
an overall severity assessment, and saves the report as both a .txt file
and a .json file. Secrets are always redacted before they are written.
"""

import json
import os

from utils import now_utc_string, pretty_json, redact_secret, colorize_severity

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0, "INFO": 0}

REMEDIATION_HINTS = {
    "alg_none": "Reject tokens with alg=none server-side; always pin the expected algorithm(s) explicitly.",
    "alg_unverifiable": "Confirm the verifier enforces an explicit allow-list of algorithms (avoid trusting the header's alg blindly).",
    "signature_invalid": "Treat an invalid signature as a hard authentication failure; do not fall back to trusting claims.",
    "weak_secret": "Replace the HMAC secret with a long, random, high-entropy value (32+ bytes) and rotate it.",
    "missing_expiry": "Always set a short, enforced 'exp' claim.",
    "expired": "Reject expired tokens; ensure client/server clocks and verifier logic enforce 'exp'.",
    "excessive_lifetime": "Shorten token lifetime and use refresh tokens for long sessions instead.",
    "missing_issuer": "Set and validate the 'iss' claim against an expected value.",
    "missing_audience": "Set and validate the 'aud' claim to the intended recipient service.",
    "sensitive_data_exposed": "Never place sensitive data in a JWT payload; it is encoded, not encrypted.",
    "suspicious_kid": "Validate 'kid' against an allow-list of known key IDs; never use it to build file paths or queries.",
    "alg_none_accepted": "CRITICAL: fix the verification endpoint immediately — it accepts unsigned tokens.",
}


def _overall_assessment(all_findings) -> str:
    if not all_findings:
        return "CLEAN"
    worst = max(all_findings, key=lambda f: SEVERITY_RANK.get(f.get("severity", "INFO"), 0))
    return worst.get("severity", "INFO")


def build_report(
    token_source: str,
    decoded_token,
    alg_result: dict,
    kid_result: dict,
    signature_result: dict,
    alg_none_result: dict,
    weak_secret_result: dict,
    claims_findings: list,
) -> dict:
    """
    Assemble every check's output into one structured report dict.
    Secrets are redacted here before anything is stored or written.
    """
    all_findings = []

    # Algorithm finding
    alg_remediation = None
    if alg_result["severity"] not in ("CLEAN", "INFO"):
        alg_remediation = REMEDIATION_HINTS.get(
            "alg_none" if alg_result["alg"] and str(alg_result["alg"]).lower() == "none" else "alg_unverifiable"
        )
    all_findings.append({
        "category": "algorithm",
        "claim": "alg",
        "issue": alg_result["status"],
        "severity": alg_result["severity"],
        "detail": alg_result["message"],
        "remediation": alg_remediation,
    })

    # kid finding (only include if not trivially clean/absent, but we show it either way for completeness)
    if kid_result:
        all_findings.append({
            "category": "header",
            "claim": "kid",
            "issue": "kid_inspection",
            "severity": kid_result.get("severity", "INFO"),
            "detail": kid_result.get("message", ""),
            "remediation": REMEDIATION_HINTS.get("suspicious_kid") if kid_result.get("severity") == "HIGH" else None,
        })

    # Signature finding
    if signature_result:
        all_findings.append({
            "category": "signature",
            "claim": "signature",
            "issue": "valid" if signature_result.get("valid") else "invalid",
            "severity": "CLEAN" if signature_result.get("valid") else "HIGH",
            "detail": signature_result.get("message", ""),
            "remediation": None if signature_result.get("valid") else REMEDIATION_HINTS.get("signature_invalid"),
        })

    # alg:none active test finding
    if alg_none_result and alg_none_result.get("ran"):
        severity = "CRITICAL" if alg_none_result.get("accepted") else "CLEAN"
        all_findings.append({
            "category": "active_test",
            "claim": "alg_none_endpoint_test",
            "issue": "accepted" if alg_none_result.get("accepted") else "rejected",
            "severity": severity,
            "detail": alg_none_result.get("message", ""),
            "remediation": REMEDIATION_HINTS.get("alg_none_accepted") if alg_none_result.get("accepted") else None,
        })

    # Weak secret finding
    if weak_secret_result:
        if weak_secret_result.get("found"):
            all_findings.append({
                "category": "active_test",
                "claim": "weak_secret",
                "issue": "weak_secret_found",
                "severity": "HIGH",
                "detail": weak_secret_result.get("message", ""),
                "remediation": REMEDIATION_HINTS.get("weak_secret"),
            })
        else:
            all_findings.append({
                "category": "active_test",
                "claim": "weak_secret",
                "issue": "no_weak_secret_found",
                "severity": "CLEAN",
                "detail": weak_secret_result.get("message", ""),
                "remediation": None,
            })

    # Claims findings
    issue_to_hint_key = {
        "missing_expiry": "missing_expiry",
        "expired": "expired",
        "excessive_lifetime": "excessive_lifetime",
        "missing_issuer": "missing_issuer",
        "missing_audience": "missing_audience",
        "sensitive_data_exposed": "sensitive_data_exposed",
    }
    for finding in claims_findings:
        hint_key = issue_to_hint_key.get(finding["issue"])
        all_findings.append({
            "category": "claims",
            "claim": finding["claim"],
            "issue": finding["issue"],
            "severity": finding["severity"],
            "detail": finding["detail"],
            "remediation": REMEDIATION_HINTS.get(hint_key) if hint_key else None,
        })

    report = {
        "tool": "TokenSpy",
        "version": "1.0.0",
        "analysis_timestamp": now_utc_string(),
        "token_source": token_source,
        "algorithm": alg_result.get("alg"),
        "header": decoded_token.header,
        "payload": decoded_token.payload,
        "signature_verification": signature_result,
        "alg_none_test": {
            **(alg_none_result or {}),
            # forged_token is safe to show (it's unsigned/useless), keep as-is
        },
        "weak_secret_test": (
            {**weak_secret_result, "secret": redact_secret(weak_secret_result.get("secret"))}
            if weak_secret_result and weak_secret_result.get("found")
            else weak_secret_result
        ),
        "claims_analysis": claims_findings,
        "findings": all_findings,
        "overall_assessment": _overall_assessment(all_findings),
    }
    return report


def render_text_report(report: dict) -> str:
    """Render the report dict as a human-readable plain-text report."""
    lines = []
    sep = "=" * 70
    lines.append(sep)
    lines.append("  TOKENSPY — JWT SECURITY ANALYSIS REPORT")
    lines.append(sep)
    lines.append(f"Analysis date/time : {report['analysis_timestamp']}")
    lines.append(f"Token source       : {report['token_source']}")
    lines.append(f"Algorithm (alg)    : {report['algorithm']}")
    lines.append("")

    lines.append("-- HEADER --")
    lines.append(pretty_json(report["header"]))
    lines.append("")

    lines.append("-- PAYLOAD --")
    lines.append(pretty_json(report["payload"]))
    lines.append("")

    sig = report.get("signature_verification")
    lines.append("-- SIGNATURE VERIFICATION --")
    lines.append(sig.get("message", "Not performed (no secret supplied).") if sig else "Not performed (no secret supplied).")
    lines.append("")

    alg_none = report.get("alg_none_test") or {}
    lines.append("-- ALG:NONE ENDPOINT TEST --")
    lines.append(alg_none.get("message", "Not performed."))
    lines.append("")

    weak = report.get("weak_secret_test") or {}
    lines.append("-- WEAK SECRET TEST --")
    lines.append(weak.get("message", "Not performed (no wordlist supplied)."))
    lines.append("")

    lines.append("-- CLAIMS ANALYSIS --")
    for f in report.get("claims_analysis", []):
        lines.append(f"  [{f['severity']:<8}] {f['claim']:<6} - {f['detail']}")
    lines.append("")

    lines.append("-- ALL FINDINGS (with remediation) --")
    lines.append(f"{'SEVERITY':<10} {'CATEGORY':<14} {'CLAIM':<16} DETAIL")
    lines.append("-" * 70)
    for f in sorted(report["findings"], key=lambda x: -SEVERITY_RANK.get(x["severity"], 0)):
        lines.append(f"{f['severity']:<10} {f['category']:<14} {f['claim']:<16} {f['detail']}")
        if f.get("remediation"):
            lines.append(f"{'':<10} {'':<14} {'':<16} -> Remediation: {f['remediation']}")
    lines.append("")

    lines.append(sep)
    lines.append(f"OVERALL SECURITY ASSESSMENT: {report['overall_assessment']}")
    lines.append(sep)

    return "\n".join(lines)


def render_text_report_colored(report: dict) -> str:
    """Same as render_text_report but with ANSI color codes, for terminal display."""
    plain = render_text_report(report)
    # Re-render the findings table with color for terminal display only
    # (kept simple: color the overall assessment and per-finding severity words)
    colored = plain
    for sev in SEVERITY_RANK:
        colored = colored.replace(f"[{sev:<8}]", f"[{colorize_severity(sev):<8}]".replace(
            colorize_severity(sev), colorize_severity(sev)
        ))
    colored = colored.replace(
        f"OVERALL SECURITY ASSESSMENT: {report['overall_assessment']}",
        f"OVERALL SECURITY ASSESSMENT: {colorize_severity(report['overall_assessment'])}",
    )
    return colored


def save_text_report(report: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_text_report(report))


def save_json_report(report: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, sort_keys=False)


def build_batch_summary_table(reports: list) -> str:
    """Build a short summary table across several analyzed tokens (batch mode)."""
    lines = []
    lines.append(f"{'#':<4}{'SOURCE':<20}{'ALG':<10}{'SIG':<10}{'OVERALL':<12}")
    lines.append("-" * 56)
    for i, r in enumerate(reports, start=1):
        sig = r.get("signature_verification") or {}
        sig_str = "VALID" if sig.get("valid") else ("INVALID" if sig else "N/A")
        src = os.path.basename(str(r.get("token_source", "")))[:18]
        lines.append(f"{i:<4}{src:<20}{str(r.get('algorithm')):<10}{sig_str:<10}{r.get('overall_assessment'):<12}")
    return "\n".join(lines)
