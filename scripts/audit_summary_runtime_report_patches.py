#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from pathlib import Path
import re
import py_compile


ROOT = Path(__file__).resolve().parents[1]
STAGE1 = ROOT / "scripts" / "audit_summary_stage1_build_analysis_pack.py"
STAGE2 = ROOT / "scripts" / "audit_summary_stage2_generate_docx.py"

STAGE1_MATCH_PATTERN = 'def _match_pattern(desc: str, flags: str) -> str:\n    """Map a non-compliant control to the most defensible weakness pattern.\n\n    The previous first-match strategy could over-classify controls as\n    hardcoded-secret issues when a description mentioned credentials but the\n    flags actually described storage, signing, manifest, IPC, or governance.\n    This scoring approach keeps the mapping deterministic while giving the\n    workbook flags stronger influence than incidental words in prose.\n    """\n    text = f"{desc or \'\'} {flags or \'\'}".lower()\n    flag_ids = _split_flags_cell(flags)\n    flag_text = " ".join(flag_ids).lower()\n\n    order = [p["name"] for p in PATTERNS] + ["Other control gaps"]\n    scores: Dict[str, int] = {name: 0 for name in order}\n\n    for p in PATTERNS:\n        for kw in p["keywords"]:\n            if re.search(kw, text, flags=re.IGNORECASE):\n                scores[p["name"]] += 2\n\n    def boost(pattern_name: str, points: int) -> None:\n        scores[pattern_name] = scores.get(pattern_name, 0) + points\n\n    if re.search(r"\\bhas_sca_|dependency|dependencies|component_vulnerab|patch|sbom|security_update", flag_text):\n        boost("Supply chain governance & outdated components", 10)\n\n    if re.search(r"encrypted|keystore|key_storage|secure_key|shared_preferences|database|sqlite|filesystem|external_storage|ephi|screenshot|local_storage|stores_sensitive|stores_keys|data_minimization", flag_text):\n        boost("Insecure local storage / key management gaps", 10)\n\n    if re.search(r"tls|ssl|cert|certificate|pinning|cleartext|sha1|v1_signature|janus|trust|hostname|code_signing", flag_text):\n        boost("Transport security / certificate validation weaknesses", 10)\n\n    if re.search(r"tamper|reverse|debuggable|debug_|binary_protection|integrity|root|dynamic_code_loading|kill_switch|safe_mode|temporary_compiled", flag_text):\n        boost("Tampering / reverse engineering protections missing", 9)\n\n    if re.search(r"permission|signature_level|ipc|bindservice|exported|explicit_accessibility|manifest_exports|intent", flag_text):\n        boost("Authorization / RBAC / least privilege gaps", 8)\n        boost("Security misconfiguration / insecure defaults", 4)\n\n    if re.search(r"rbac|authorization|privilege|endpoint_requires_user_authentication|server_side_authz|authz|access_control", flag_text):\n        boost("Authorization / RBAC / least privilege gaps", 10)\n\n    if re.search(r"hardcoded|api_keys_in_version_control|secrets_count|secrets_generic|password_literal|credential", flag_text):\n        boost("Hardcoded credentials / embedded secrets", 10)\n\n    if re.search(r"brute|lockout|captcha|reauth|session_timeout|session_invalidation|password_policy|authentication", flag_text):\n        boost("Weak authentication lifecycle / brute-force protections", 9)\n\n    if re.search(r"input|injection|xss|sqli|sanitize|schema|format|deserialization|webview|path_traversal|log_injection", flag_text):\n        boost("Input validation & injection weaknesses (XSS/SQLi/command/log injection)", 9)\n\n    if re.search(r"audit|logging|log_|siem|retention|alert|telemetry|forensic", flag_text):\n        boost("Audit logging completeness / retention / alerting gaps", 8)\n\n    if re.search(r"privacy|consent|notification|deprecation|communication_plan|pii|patient_data", flag_text):\n        boost("Privacy notice / consent / governance gaps", 8)\n\n    if re.search(r"default|cookie|httponly|secure_flag|configuration|misconfig|allow_backup", flag_text):\n        boost("Security misconfiguration / insecure defaults", 8)\n\n    explicit_secret = bool(re.search(r"hardcoded|api_keys_in_version_control|secrets_count|secrets_generic|password_literal|credential", flag_text))\n    non_secret_domain = any(\n        scores.get(name, 0) >= 8\n        for name in [\n            "Insecure local storage / key management gaps",\n            "Transport security / certificate validation weaknesses",\n            "Supply chain governance & outdated components",\n            "Tampering / reverse engineering protections missing",\n            "Authorization / RBAC / least privilege gaps",\n            "Security misconfiguration / insecure defaults",\n        ]\n    )\n    if non_secret_domain and not explicit_secret:\n        scores["Hardcoded credentials / embedded secrets"] = min(scores.get("Hardcoded credentials / embedded secrets", 0), 3)\n\n    best = max(order, key=lambda name: (scores.get(name, 0), -order.index(name)))\n    return best if scores.get(best, 0) > 0 else "Other control gaps"'
STAGE2_HELPERS = 'def _expected_state_fallback(pattern: str) -> str:\n    """Return a report-safe expected state when AI output describes the deficiency."""\n    pat = _clean_text(pattern).lower()\n    if "hardcoded credentials" in pat or "embedded secrets" in pat:\n        return "The application should externalize secrets and credentials so that no hardcoded passwords, API keys, tokens, signing credentials, or reusable shared secrets are present in the application binary or source-controlled application code."\n    if "authorization" in pat or "rbac" in pat or "least privilege" in pat:\n        return "The application should enforce server-side authorization, role-based access control, and least-privilege access consistently across sensitive workflows, APIs, and Android components."\n    if "local storage" in pat or "key management" in pat:\n        return "The application should minimize client-side sensitive data storage and protect any required local secrets, tokens, keys, preferences, databases, or files using appropriate platform-backed encryption and lifecycle controls."\n    if "authentication" in pat or "brute-force" in pat:\n        return "The application should enforce a secure authentication lifecycle, including appropriate session handling, reauthentication, account protection, and server-side controls against unauthorized or repeated access attempts."\n    if "transport" in pat or "certificate" in pat:\n        return "The application should use production signing, secure transport configuration, and documented certificate-validation or pinning decisions aligned with the threat model and operational constraints."\n    if "supply chain" in pat or "outdated components" in pat:\n        return "The application delivery process should maintain an inventory of dependencies, track known vulnerabilities, and remediate or formally accept vulnerable components according to severity and available fixes."\n    if "input validation" in pat or "injection" in pat:\n        return "The application should validate and encode untrusted input at appropriate client and server boundaries to prevent injection, unsafe deserialization, path manipulation, and log-forging risks."\n    if "audit logging" in pat:\n        return "The application and supporting services should produce complete, protected, reviewable audit evidence for relevant security and session events without exposing sensitive information."\n    if "tampering" in pat or "reverse engineering" in pat:\n        return "The application should apply appropriate release-build hardening, integrity controls, and tamper-response mechanisms for the assessed risk profile."\n    if "privacy" in pat or "consent" in pat:\n        return "The application should provide clear privacy, consent, deprecation, and user-notification controls consistent with the assessed health-data processing context."\n    return "The application should implement the mapped controls for this weakness pattern and provide sufficient workbook, scanner, test, or risk-acceptance evidence for the assessed scope."\n\n\ndef _sanitize_expected_state(pattern: str, value: Any) -> str:\n    """Keep AI-authored expected-state prose from describing the observed defect."""\n    text = _clean_text(value)\n    fallback = _expected_state_fallback(pattern)\n    if not text:\n        return fallback\n\n    lower = text.lower()\n    defect_markers = [\n        "contains numerous",\n        "contains hardcoded",\n        "exhibits several weaknesses",\n        "lacks sufficient",\n        "lacks comprehensive",\n        "deficiencies exist",\n        "lack sufficient",\n        "missing",\n        "weaknesses related",\n        "vulnerabilities related",\n        "fails to",\n        "does not ",\n        "is not ",\n        "are not ",\n    ]\n    if any(marker in lower for marker in defect_markers):\n        return fallback\n\n    if not re.search(r"\\b(should|must|shall|expected to|is expected to|are expected to)\\b", lower):\n        return fallback\n\n    text = re.sub(r"\\s+", " ", text).strip()\n    if text and not text.endswith((".", ";", ":")):\n        text += "."\n    return text\n\n\ndef _vision360_correlation_paragraph(technical: Dict[str, Any]) -> str:\n    """Render Vision360 as the correlation layer, not as a standalone scanner."""\n    vision = _as_dict(technical.get("vision360"))\n    if not _block_available(vision):\n        return (\n            "Vision360 evidence was not available to the report generator. Requirement-level judgments remain grounded in the workbook, "\n            "and scanner findings should be interpreted directly from the available Trivy, MobSF, and SAST artifacts."\n        )\n\n    flags_count = _deep_int(vision, ["flags_count"])\n    state_counts = _deep_dict(vision, ["state_counts"])\n    top_groups = _deep_list(vision, ["top_active_groups"])\n    source_counts = _deep_dict(vision, ["evidence_source_counts"])\n\n    fragments = [\n        "Vision360 is used in this report as the normalized evidence-correlation layer linking workbook adjudication, scanner-derived flags, technical artifacts, and treatment-plan generation; it is not treated as an independent vulnerability scanner."\n    ]\n\n    if flags_count:\n        fragments.append(f"The normalized fingerprint contains {flags_count} flag record(s).")\n    if state_counts:\n        state_text = ", ".join(f"{k}: {v}" for k, v in sorted(state_counts.items()))\n        fragments.append(f"Flag state distribution is {state_text}.")\n    if top_groups:\n        group_bits = []\n        for item in top_groups[:4]:\n            if isinstance(item, dict):\n                group = _clean_text(item.get("group"))\n                count = _safe_int(item.get("active_flag_count"), 0)\n                if group and count:\n                    group_bits.append(f"{group} ({count})")\n        if group_bits:\n            fragments.append("The most active evidence groups include " + ", ".join(group_bits) + ".")\n    if source_counts:\n        source_text = ", ".join(f"{k}: {v}" for k, v in sorted(source_counts.items())[:6])\n        if source_text:\n            fragments.append(f"Evidence-source distribution is {source_text}.")\n\n    return " ".join(fragments)'


def replace_between(text: str, start_pattern: str, end_pattern: str, replacement: str, label: str) -> str:
    m = re.search(start_pattern, text, flags=re.MULTILINE)
    if not m:
        raise SystemExit(f"[ERROR] Could not find start for {label}")
    n = re.search(end_pattern, text[m.start():], flags=re.MULTILINE)
    if not n:
        raise SystemExit(f"[ERROR] Could not find end for {label}")
    end = m.start() + n.start()
    return text[:m.start()] + replacement + "\n\n" + text[end:]


def patch_stage1() -> bool:
    text = STAGE1.read_text(encoding="utf-8")
    if "Map a non-compliant control to the most defensible weakness pattern" in text:
        return False
    new_text = replace_between(
        text,
        r"^def _match_pattern\(desc: str, flags: str\) -> str:\n",
        r"^def _likelihood_from_count\(cnt: int\) -> str:\n",
        STAGE1_MATCH_PATTERN,
        "Stage 1 _match_pattern",
    )
    STAGE1.write_text(new_text, encoding="utf-8")
    return True


def patch_stage2() -> bool:
    text = STAGE2.read_text(encoding="utf-8")
    changed = False

    if "def _expected_state_fallback(pattern: str) -> str:" not in text:
        text = text.replace("\ndef _sanitize_recommendation_text(value: Any) -> str:\n", "\n" + STAGE2_HELPERS + "\n\ndef _sanitize_recommendation_text(value: Any) -> str:\n")
        changed = True

    if "secret_store_guardrails = [" not in text:
        marker = "    for pattern, repl in replacements:\n        text = re.sub(pattern, repl, text, flags=re.IGNORECASE)\n"
        insert = marker + """\n    secret_store_guardrails = [
        (
            r"\bMigrate all secrets and signing credentials from environment variables or external files into a secure, hardware-backed keystore[^.]*\.",
            "Keep CI/CD, build-time, and signing credentials in the pipeline secret manager or signing infrastructure; use Android Keystore only for runtime device-resident keys or secrets that must persist on the device.",
        ),
        (
            r"\bMigrate all sensitive secrets currently stored or referenced insecurely to use Android Keystore system for cryptographic key storage\.",
            "Move runtime device-resident secrets or cryptographic keys to Android Keystore where persistence is required; keep build-time, CI/CD, and signing credentials in the pipeline secret-management layer.",
        ),
        (
            r"\bMigrate all secrets and signing credentials from environment variables into Android Keystore[^.]*\.",
            "Keep CI/CD, build-time, and signing credentials in the pipeline secret manager or signing infrastructure; use Android Keystore only for runtime device-resident keys or secrets that must persist on the device.",
        ),
        (
            r"\bMigrate all secrets from environment variables to Android Keystore[^.]*\.",
            "Use the appropriate secret-management layer for each secret type: pipeline secret storage for CI/CD and build-time values, backend-side configuration for server secrets, and Android Keystore for runtime device-resident keys.",
        ),
    ]
    for pattern, repl in secret_store_guardrails:
        text = re.sub(pattern, repl, text, flags=re.IGNORECASE)
"""
        text = text.replace(marker, insert, 1)
        changed = True

    if "The remediation of all\\s+\\d+\\s+noncompliant instances" not in text:
        marker = '    text = re.sub(\n        r"\\bzero-vulnerability state\\b",\n'
        insert = """    text = re.sub(
        r"The remediation of all\s+\d+\s+noncompliant instances of '([^']+)' must be verified by a subsequent security scan, resulting in zero findings for this pattern\.",
        r"Mapped controls for '\\1' are remediated or formally risk-accepted, supported by updated workbook scoring, relevant scan evidence, and documented compensating controls where applicable.",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\bzero findings for this pattern\b",
        "no unresolved scanner-detectable findings for this pattern unless formally risk-accepted",
        text,
        flags=re.IGNORECASE,
    )
"""
        text = text.replace(marker, insert + marker, 1)
        changed = True

    replacements = [
        (
            '"expected": "1 sentence.",',
            '"expected": "1 sentence describing the desired target/control state, not the deficiency. Do not write that the application contains, exhibits, lacks, or has weaknesses as the expected state.",',
        ),
        (
            "Treat TLS pinning as threat-model dependent, not a universal absolute. Prefer documenting certificate validation and pinning decisions over mandating pinning across all communications. Translate raw flag names into operational actions;",
            "Treat TLS pinning as threat-model dependent, not a universal absolute. Prefer documenting certificate validation and pinning decisions over mandating pinning across all communications. Do not recommend Android Keystore for CI/CD secrets, signing credentials, or build-time environment variables; use Android Keystore only for runtime device-resident keys or secrets. Translate raw flag names into operational actions;",
        ),
        (
            'return max(1, _safe_int(os.getenv("AUDIT_SUMMARY_MAX_CONTROL_TREATMENT_ROWS", "250"), 250))',
            'return max(1, _safe_int(os.getenv("AUDIT_SUMMARY_MAX_CONTROL_TREATMENT_ROWS", "500"), 500))',
        ),
        (
            "Treat certificate pinning as threat-model dependent, not mandatory for every application. Return exactly one valid JSON object and nothing else.",
            "Treat certificate pinning as threat-model dependent, not mandatory for every application. Do not recommend Android Keystore for CI/CD secrets, signing credentials, or build-time environment variables; use Android Keystore only for runtime device-resident keys or secrets. Return exactly one valid JSON object and nothing else.",
        ),
        (
            "Verification traceability is provided in Appendix B.",
            "Verification traceability is provided in Appendix D.",
        ),
        (
            'expected = _ai_field_for_pattern(pat, writeups, "expected") or "AI-generated expected-state narrative was not returned for this pattern."',
            'expected = _sanitize_expected_state(pat, _ai_field_for_pattern(pat, writeups, "expected"))',
        ),
    ]
    for old, new in replacements:
        if old in text:
            text = text.replace(old, new)
            changed = True

    coverage_marker = '    _add_table(doc, ["Evidence source", "Available", "Summary"], _source_status_rows(technical), max_rows=10)\n'
    vision_line = '    _add_body_paragraph(doc, _vision360_correlation_paragraph(technical))\n'
    if coverage_marker in text and vision_line not in text:
        text = text.replace(coverage_marker, vision_line + coverage_marker, 1)
        changed = True

    if changed:
        STAGE2.write_text(text, encoding="utf-8")
    return changed


def main() -> int:
    changed1 = patch_stage1()
    changed2 = patch_stage2()
    py_compile.compile(str(STAGE1), doraise=True)
    py_compile.compile(str(STAGE2), doraise=True)
    print(f"[OK] audit summary runtime report patches applied. stage1_changed={changed1} stage2_changed={changed2}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
