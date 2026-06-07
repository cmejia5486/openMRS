#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import fnmatch
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Iterable

import pandas as pd


DEFAULT_SHEET = "audit"

DEFAULT_CONFIG_ENV = "AUDIT_CONFIG_JSON_PATH"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _runtime_data_dir() -> Path:
    # Prefer explicit, cross-platform data-directory variables.
    # If none are provided, use GitHub Actions RUNNER_TEMP when available.
    # As a final local fallback, use a repository-local hidden directory.
    for name in ("VISION360_DATA_DIR", "AUDIT_DATA_DIR", "SECURITY_AUDIT_DATA_DIR"):
        raw = os.getenv(name, "").strip()
        if raw:
            base = Path(raw)
            base.mkdir(parents=True, exist_ok=True)
            return base

    runner_temp = os.getenv("RUNNER_TEMP", "").strip()
    if runner_temp:
        base = Path(runner_temp) / "vision360-data"
        base.mkdir(parents=True, exist_ok=True)
        return base

    base = _repo_root() / ".vision360-data"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _env_path(env_name: str, default_filename: str) -> Path:
    raw = os.getenv(env_name, "").strip()
    if raw:
        return Path(raw)
    return _runtime_data_dir() / default_filename


DEFAULT_EXCEL = str(_env_path("AUDIT_EXCEL_PATH", "security_audit_requirements.xlsx"))
DEFAULT_OUT = str(_env_path("AUDIT_ANALYSIS_JSON_PATH", "audit_summary_analysis_pack.json"))


def _candidate_config_paths() -> List[str]:
    candidates: List[str] = []

    env_path = os.getenv(DEFAULT_CONFIG_ENV, "").strip()
    if env_path:
        candidates.append(env_path)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    candidates.append(os.path.join(repo_root, "parameters", "audit_summary_literals.json"))
    candidates.append(os.path.join(os.getcwd(), "parameters", "audit_summary_literals.json"))
    candidates.append(str(_runtime_data_dir() / "audit_summary_literals.json"))

    out: List[str] = []
    seen = set()
    for p in candidates:
        ap = os.path.abspath(p)
        if ap not in seen:
            seen.add(ap)
            out.append(ap)
    return out


def _load_runtime_config() -> Dict[str, Any]:
    tried_paths = _candidate_config_paths()
    existing = next((p for p in tried_paths if os.path.isfile(p)), None)
    if not existing:
        raise SystemExit("[ERROR] audit_summary_literals.json not found. Tried: " + " | ".join(tried_paths))

    try:
        with open(existing, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        raise SystemExit(f"[ERROR] Failed to read audit_summary_literals.json at {existing}: {e}")

    if not isinstance(cfg, dict):
        raise SystemExit(f"[ERROR] Invalid audit_summary_literals.json at {existing}: top-level JSON must be an object.")

    app_metadata = cfg.get("app_metadata")
    actors = cfg.get("actors")

    if not isinstance(app_metadata, dict):
        raise SystemExit(f"[ERROR] Invalid audit_summary_literals.json at {existing}: key 'app_metadata' must be an object.")

    if not isinstance(actors, dict):
        raise SystemExit(f"[ERROR] Invalid audit_summary_literals.json at {existing}: key 'actors' must be an object.")

    if "Engineering Group (EN)" not in actors:
        raise SystemExit(f"[ERROR] Invalid audit_summary_literals.json at {existing}: missing actors['Engineering Group (EN)'].")

    return {
        "config_path": existing,
        "app_metadata": app_metadata,
        "actors": actors,
    }


CAT_MAP = {
    "ICU": "Improper Credential Usage",
    "ISU": "Inadequate Supply Chain Security",
    "IAA": "Insecure Authentication/Authorization",
    "IOV": "Insufficient Input/Output Validation",
    "ICO": "Insecure Communication",
    "IPC": "Inadequate Privacy Controls",
    "IBP": "Insufficient Binary Protections",
    "SMC": "Security Misconfiguration",
    "IDS": "Insecure Data Storage",
    "ICR": "Insufficient Cryptography",
}

# Deterministic weakness-pattern mapping (reproducible; defensible; fast)
PATTERNS = [
    {
        "name": "Hardcoded credentials / embedded secrets",
        "keywords": [r"hardcoded", r"embedded", r"secret", r"api\s*key", r"token", r"credential", r"password.*code"],
        "severity": "High",
        "owner": "Mobile Engineering / Security Engineering",
    },
    {
        "name": "Weak authentication lifecycle / brute-force protections",
        "keywords": [r"brute", r"lockout", r"throttl", r"captcha", r"password", r"reauth", r"concurrent", r"session timeout", r"authentication"],
        "severity": "High",
        "owner": "Mobile Engineering",
    },
    {
        "name": "Authorization / RBAC / least privilege gaps",
        "keywords": [r"authorization", r"access control", r"role", r"rbac", r"least privilege", r"privilege", r"dual access", r"separation of duties", r"workgroup"],
        "severity": "High",
        "owner": "Mobile Engineering / Governance",
    },
    {
        "name": "Input validation & injection weaknesses (XSS/SQLi/command/log injection)",
        "keywords": [r"input validation", r"injection", r"xss", r"cross[-\s]?site scripting", r"sql", r"command injection", r"log injection", r"sanitize", r"encoding"],
        "severity": "High",
        "owner": "Mobile Engineering",
    },
    {
        "name": "Transport security / certificate validation weaknesses",
        "keywords": [r"tls", r"https", r"certificate", r"pinning", r"cleartext", r"mitm", r"trust manager", r"hostnameverifier", r"ssl"],
        "severity": "High",
        "owner": "Mobile Engineering / DevOps",
    },
    {
        "name": "Insecure local storage / key management gaps",
        "keywords": [r"data storage", r"storage", r"encrypt", r"keystore", r"sharedpreferences", r"database", r"cache", r"key management", r"data at rest"],
        "severity": "High",
        "owner": "Mobile Engineering",
    },
    {
        "name": "Supply chain governance & outdated components",
        "keywords": [r"outdated", r"dependency", r"library", r"vulnerab", r"supply chain", r"patch", r"sbom", r"cicd", r"official sources"],
        "severity": "High",
        "owner": "DevOps / Security Engineering",
    },
    {
        "name": "Tampering / reverse engineering protections missing",
        "keywords": [r"tamper", r"reverse", r"obfusc", r"debuggable", r"anti[-\s]?debug", r"repackag", r"binary protection", r"integrity check", r"root"],
        "severity": "Medium",
        "owner": "Mobile Engineering",
    },
    {
        "name": "Audit logging completeness / retention / alerting gaps",
        "keywords": [r"audit", r"log", r"retention", r"backup", r"central", r"alert", r"ISSO", r"forensic", r"override"],
        "severity": "Medium",
        "owner": "Governance / DevOps",
    },
    {
        "name": "Privacy notice / consent / governance gaps",
        "keywords": [r"privacy", r"consent", r"terms", r"notification", r"mask", r"blocked record", r"decision-maker", r"privacy policy"],
        "severity": "Medium",
        "owner": "Governance / Product",
    },
    {
        "name": "Security misconfiguration / insecure defaults",
        "keywords": [r"misconfig", r"default", r"cookie", r"httponly", r"secure flag", r"ddos", r"error.*reveal", r"server", r"configuration"],
        "severity": "Medium",
        "owner": "DevOps / Mobile Engineering",
    },
]

LIKELIHOOD_RUBRIC = {
    "High": "≥50",
    "Medium–High": "20–49",
    "Medium": "10–19",
    "Low–Medium": "<10",
}


def _find_col(columns: List[str], patterns: List[str]) -> Optional[str]:
    for p in patterns:
        rx = re.compile(p, re.IGNORECASE)
        for c in columns:
            if rx.search(str(c)):
                return c
    return None


def _norm_status(x: Any) -> str:
  
    if x is None:
        return "Not applicable"
    s = str(x).strip()
    if not s or s.lower() == "nan":
        return "Not applicable"

    s_low = s.lower().strip()

    # Upstream "Result" column (yes/no/n/a)
    if s_low in {"yes", "y"}:
        return "Compliant"
    if s_low in {"no", "n"}:
        return "Non-compliant"
    if s_low in {"n/a", "na", "not applicable"}:
        return "Not applicable"

    # Explicit compliance labels
    if s_low in {"compliant", "ok", "pass", "passed"}:
        return "Compliant"
    if s_low in {"non-compliant", "noncompliant", "fail", "failed"}:
        return "Non-compliant"

    # Spanish variants (legacy)
    if s_low in {"si", "sí", "cumple", "verdadero", "true"}:
        return "Compliant"
    if s_low in {"no cumple", "falso", "false"}:
        return "Non-compliant"
    if s_low in {"no aplica"}:
        return "Not applicable"

    # Conservative default
    return "Not applicable"


def _cat_from_puid(puid: str) -> Dict[str, str]:
    m = re.search(r"SECM-CAT-([A-Z]{3})-", puid or "")
    code = m.group(1) if m else "UNK"
    return {"code": code, "name": CAT_MAP.get(code, "Other")}


def _clean_text(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text or text.lower() == "nan":
        return ""
    return text


def _excerpt(s: Any, limit: int = 260) -> str:
    """Return a report-safe excerpt without dangling ellipses.

    The Stage 2 report should not render truncated text with three dots or
    Python/JSON debugging fragments. This helper prefers complete sentences and
    otherwise cuts at a word boundary without adding ellipsis marks.
    """
    t = _clean_text(s)
    if not t:
        return ""
    if limit <= 0 or len(t) <= limit:
        return t

    candidate = t[:limit].rstrip()
    sentence_cut = max(candidate.rfind(". "), candidate.rfind("; "), candidate.rfind(": "))
    if sentence_cut >= max(80, int(limit * 0.45)):
        return candidate[: sentence_cut + 1].strip()

    word_cut = candidate.rfind(" ")
    if word_cut >= max(60, int(limit * 0.35)):
        candidate = candidate[:word_cut]
    return candidate.rstrip(" ,;:-")


def _present_tense_after_subject(text: str) -> str:
    replacements = [
        (r"^(The (?:mobile )?application) not ([a-zA-Z]+)", r"\1 does not \2"),
        (r"^(The (?:mobile )?application) ensure\b", r"\1 ensures"),
        (r"^(The (?:mobile )?application) configure\b", r"\1 configures"),
        (r"^(The (?:mobile )?application) request\b", r"\1 requests"),
        (r"^(The (?:mobile )?application) minimize\b", r"\1 minimizes"),
        (r"^(The (?:mobile )?application) securely handle\b", r"\1 securely handles"),
        (r"^(The (?:mobile )?application) provide\b", r"\1 provides"),
        (r"^(The (?:mobile )?application) implement\b", r"\1 implements"),
        (r"^(The (?:mobile )?application) maintain\b", r"\1 maintains"),
        (r"^(The (?:mobile )?application) remove\b", r"\1 removes"),
        (r"^(The (?:mobile )?application) use\b", r"\1 uses"),
        (r"^(The (?:mobile )?application) validate\b", r"\1 validates"),
        (r"^(The (?:mobile )?application) prevent\b", r"\1 prevents"),
        (r"^(The (?:mobile )?application) disallow\b", r"\1 disallows"),
        (r"^(The (?:mobile )?application) retain\b", r"\1 retains"),
        (r"^(The (?:mobile )?application) store\b", r"\1 stores"),
    ]
    out = text
    for pattern, repl in replacements:
        out = re.sub(pattern, repl, out, flags=re.IGNORECASE)
    return out


def _to_declarative(desc: str) -> str:
    """Convert a requirement sentence into a concise positive-control statement.

    The statement is used as a candidate only; Stage 2 may ask the configured AI
    model to rewrite it. This helper therefore keeps the sentence conservative,
    grammatical, and grounded in the workbook text.
    """
    t = _clean_text(desc)
    if not t:
        return "The application implements the control described in the workbook."

    t = re.sub(r"^\d+[\.\)]\s*", "", t)
    t = re.sub(r"\(e\.g\.,.*?\)", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\b(is|are) required to\b", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\b(needs? to|must|shall|should)\b", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\bwould\s+", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\s+", " ", t).strip()

    if not t:
        return "The application implements the control described in the workbook."

    if not re.match(r"^the\s+(mobile\s+)?application\b", t, flags=re.IGNORECASE):
        t = "The application " + (t[0].lower() + t[1:] if t else "implements security controls")
    else:
        t = re.sub(r"^the mobile application\b", "The mobile application", t, flags=re.IGNORECASE)
        t = re.sub(r"^the application\b", "The application", t, flags=re.IGNORECASE)

    t = _present_tense_after_subject(t)

    grammar_fixes = [
        (r"\bremovess\b", "removes"),
        (r"\brequestss\b", "requests"),
        (r"\bprovidess\b", "provides"),
        (r"\bensuress\b", "ensures"),
        (r"\bconfiguress\b", "configures"),
        (r"\bminimize its usage\b", "minimizes its usage"),
        (r"\bsecurely handle\b", "securely handles"),
        (r"\band prevent\b", "and prevents"),
        (r"\bas well as disallow the\b", "as well as disallowing the"),
        (r"\bCertificate Authority \(CA\) be used\b", "Certificate Authority (CA) is used"),
        (r"\bSelf-signed certificates or a local Certificate Authority \(CA\) be used\b", "Self-signed certificates or a local Certificate Authority (CA) are used"),
    ]
    for pattern, repl in grammar_fixes:
        t = re.sub(pattern, repl, t, flags=re.IGNORECASE)

    t = re.sub(r"\s+", " ", t).strip()
    t = _excerpt(t, 340).strip().rstrip(".;:") + "."
    return t


def _match_pattern(desc: str, flags: str) -> str:
    text = f"{desc or ''} {flags or ''}".lower()
    for p in PATTERNS:
        for kw in p["keywords"]:
            if re.search(kw, text, flags=re.IGNORECASE):
                return p["name"]
    return "Other control gaps"


def _likelihood_from_count(cnt: int) -> str:
    if cnt >= 50:
        return "High"
    if cnt >= 20:
        return "Medium–High"
    if cnt >= 10:
        return "Medium"
    return "Low–Medium"


def _split_flags_cell(value: Any) -> List[str]:
    """Split a workbook Flags cell into stable, deduplicated flag identifiers."""
    text = _clean_text(value)
    if not text:
        return []
    raw_parts = re.split(r"[,;\n|]+", text)
    return _unique_keep_order([p.strip() for p in raw_parts if p.strip()], limit=80)


def _flag_family(flag_id: str) -> str:
    f = str(flag_id or "").strip().lower()
    if f.startswith("has_sca_"):
        return "SCA"
    if f.startswith("has_mobsf_dynamic_") or "dynamic" in f and "mobsf" in f:
        return "MobSF dynamic"
    if f.startswith("has_mobsf_") or "mobsf" in f:
        return "MobSF static"
    if f.startswith("has_sast_") or "sast" in f or "codeql" in f or "semgrep" in f or "detekt" in f:
        return "SAST"
    if f.startswith("has_org_") or f.startswith("org_"):
        return "Organizational"
    if f.startswith("has_manifest_") or "manifest" in f:
        return "Android manifest"
    if "permission" in f:
        return "Android permissions"
    if "crypto" in f or "tls" in f or "ssl" in f or "certificate" in f:
        return "Cryptography / transport"
    return "Workbook"


def _flags_by_family(flags: List[str]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    for flag in flags:
        family = _flag_family(flag)
        grouped.setdefault(family, []).append(flag)
    return {k: _unique_keep_order(v, limit=30) for k, v in sorted(grouped.items())}


def _pick_dict_fields(obj: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not isinstance(obj, dict):
        return out
    for field in fields:
        value = obj.get(field)
        if value not in (None, "", [], {}):
            out[field] = value
    return out


def _sast_retained_count(sast: Dict[str, Any]) -> int:
    if not isinstance(sast, dict):
        return 0
    for key in ("retained_app_code_findings", "total_findings"):
        if key in sast:
            return _safe_int(sast.get(key), 0)
    summary = sast.get("summary") if isinstance(sast.get("summary"), dict) else {}
    return _safe_int(summary.get("retained_app_code_findings") or summary.get("app_code_results"), 0)


def _scanner_context_for_pattern(pattern: str, technical: Dict[str, Any]) -> Dict[str, Any]:
    """Create pattern-specific scanner context for AI-authored recommendations.

    The objective is not to adjudicate requirements here. It is to expose the
    most relevant normalized evidence snippets so Stage 2 can ask the AI model to
    write recommendations grounded in actual scanner outputs.
    """
    pat = str(pattern or "").lower()
    technical = technical if isinstance(technical, dict) else {}
    trivy = technical.get("trivy_sca") if isinstance(technical.get("trivy_sca"), dict) else {}
    mobsf_static = technical.get("mobsf_static") if isinstance(technical.get("mobsf_static"), dict) else {}
    mobsf_dynamic = technical.get("mobsf_dynamic") if isinstance(technical.get("mobsf_dynamic"), dict) else {}
    sast = technical.get("sast_app_code") if isinstance(technical.get("sast_app_code"), dict) else {}
    vision = technical.get("vision360") if isinstance(technical.get("vision360"), dict) else {}

    context: Dict[str, Any] = {
        "relevant_sources": [],
        "evidence": {},
        "guardrails": [],
    }

    def add_source(name: str) -> None:
        if name not in context["relevant_sources"]:
            context["relevant_sources"].append(name)

    if any(tok in pat for tok in ["supply chain", "outdated", "dependency", "components"]):
        add_source("Trivy SCA")
        context["evidence"]["trivy_sca"] = {
            "summary": _pick_dict_fields(trivy.get("summary") if isinstance(trivy.get("summary"), dict) else {}, [
                "total_vulnerabilities",
                "by_severity",
                "fixable_total",
                "unfixed_total",
                "packages_affected",
            ]),
            "affected_packages_top": (trivy.get("affected_packages_top") or [])[:8],
            "top_findings": (trivy.get("top_findings") or [])[:10],
            "licenses": trivy.get("licenses") if isinstance(trivy.get("licenses"), dict) else {},
        }

    if any(tok in pat for tok in ["local storage", "key management", "data at rest", "storage"]):
        add_source("MobSF dynamic")
        add_source("MobSF static")
        context["evidence"]["mobsf_dynamic"] = {
            "local_storage_artifacts_count": mobsf_dynamic.get("local_storage_artifacts_count"),
            "shared_preferences_artifacts": mobsf_dynamic.get("shared_preferences_artifacts", [])[:12],
            "sqlite_database_artifacts": mobsf_dynamic.get("sqlite_database_artifacts", [])[:12],
            "local_storage_artifacts_sample": mobsf_dynamic.get("local_storage_artifacts_sample", [])[:12],
            "runtime_evidence_categories": mobsf_dynamic.get("runtime_evidence_categories", [])[:5],
        }
        context["evidence"]["mobsf_static"] = _pick_dict_fields(mobsf_static, [
            "allow_backup",
            "dangerous_permissions_count",
            "exported_components_count",
        ])

    if any(tok in pat for tok in ["transport", "certificate", "tls", "communication"]):
        add_source("MobSF static")
        context["evidence"]["mobsf_static"] = {
            **_pick_dict_fields(mobsf_static, [
                "cleartext_traffic_signal",
                "sha1",
                "debug_certificate",
                "v1_signature",
                "min_sdk",
                "target_sdk",
            ]),
            "certificate_findings_sample": mobsf_static.get("certificate_findings_sample", [])[:8],
            "certificate_info_excerpt": mobsf_static.get("certificate_info_excerpt", ""),
        }

    if any(tok in pat for tok in ["tampering", "reverse", "binary", "debug", "repackag"]):
        add_source("MobSF static")
        context["evidence"]["mobsf_static"] = _pick_dict_fields(mobsf_static, [
            "debuggable",
            "debug_certificate",
            "v1_signature",
            "sha1",
            "min_sdk",
            "target_sdk",
            "vulnerable_min_sdk_signal",
        ])

    if any(tok in pat for tok in ["misconfiguration", "defaults", "configuration"]):
        add_source("MobSF static")
        context["evidence"]["mobsf_static"] = _pick_dict_fields(mobsf_static, [
            "allow_backup",
            "exported_components_count",
            "cleartext_traffic_signal",
            "debuggable",
            "dangerous_permissions_count",
        ])

    if any(tok in pat for tok in ["input validation", "injection", "xss", "sqli", "command"]):
        add_source("SAST app-code")
        retained = _sast_retained_count(sast)
        retained_security = _safe_int(sast.get("retained_security_findings"), 0)
        hardening_total = _safe_int(sast.get("hardening_or_maintainability_signals"), 0)
        context["evidence"]["sast_app_code"] = {
            "retained_app_code_signals": retained,
            "retained_security_findings": retained_security,
            "hardening_or_maintainability_signals": hardening_total,
            "raw_sarif_results": _safe_int(sast.get("raw_sarif_results"), 0),
            "security_findings_sample": (sast.get("security_findings_sample") or [])[:8] if retained_security > 0 else [],
            "top_security_rules": (sast.get("top_security_rules") or [])[:8],
            "top_hardening_rules": (sast.get("top_hardening_rules") or [])[:8],
            "scope_filter": sast.get("scope_filter") if isinstance(sast.get("scope_filter"), dict) else {},
        }
        if retained_security <= 0:
            context["guardrails"].append(
                "SAST raw SARIF counts and app-scope hardening/quality signals are traceability only; do not describe them as security vulnerabilities."
            )

    if any(tok in pat for tok in ["authorization", "rbac", "authentication", "privacy", "audit logging"]):
        add_source("Vision360")
        context["evidence"]["vision360"] = {
            "state_counts": vision.get("state_counts", {}),
            "top_active_groups": vision.get("top_active_groups", [])[:6],
            "active_flags_sample": vision.get("active_flags_sample", [])[:20],
            "evidence_source_counts": vision.get("evidence_source_counts", {}),
        }

    if not context["relevant_sources"]:
        add_source("Audit workbook")
        if isinstance(vision, dict) and vision.get("available"):
            add_source("Vision360")
            context["evidence"]["vision360"] = {
                "state_counts": vision.get("state_counts", {}),
                "top_active_groups": vision.get("top_active_groups", [])[:4],
            }

    return context


def _enrich_weakness_patterns_for_ai(patterns: List[Dict[str, Any]], non_df: Any, technical: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Attach workbook and scanner context to each weakness pattern.

    Stage 2 can pass this compact context to the AI model so recommendations,
    expected states, impact statements, and closure criteria are generated from
    concrete evidence rather than static text.
    """
    enriched: List[Dict[str, Any]] = []
    for pattern in patterns:
        item = dict(pattern)
        pat = str(item.get("pattern") or "")
        rows = non_df[non_df["Pattern"] == pat].copy() if hasattr(non_df, "__getitem__") and "Pattern" in getattr(non_df, "columns", []) else None

        related_flags: List[str] = []
        evidence_samples: List[str] = []
        category_codes: List[str] = []
        category_names: List[str] = []
        workbook_examples: List[Dict[str, Any]] = []

        if rows is not None:
            for _, row in rows.head(12).iterrows():
                row_flags = _split_flags_cell(row.get("Flags", ""))
                related_flags.extend(row_flags)
                evidence_excerpt = _excerpt(row.get("Evidence", ""), 240)
                description_anchor = _excerpt(row.get("Description", ""), 220)
                if evidence_excerpt:
                    evidence_samples.append(evidence_excerpt)
                category_codes.append(str(row.get("CategoryCode", "")))
                category_names.append(str(row.get("CategoryName", "")))
                workbook_examples.append({
                    "puid": row.get("PUID", ""),
                    "category_code": row.get("CategoryCode", ""),
                    "category_name": row.get("CategoryName", ""),
                    "flags": row_flags[:10],
                    "description_anchor": description_anchor,
                    "evidence_excerpt": evidence_excerpt,
                })

        related_flags = _unique_keep_order(related_flags, limit=60)
        item["related_flags_sample"] = related_flags[:30]
        item["related_flags_by_family"] = _flags_by_family(related_flags)
        item["workbook_evidence_samples"] = _unique_keep_order(evidence_samples, limit=8)
        item["category_codes"] = _unique_keep_order(category_codes, limit=12)
        item["category_names"] = _unique_keep_order(category_names, limit=12)
        item["workbook_examples_for_ai"] = workbook_examples[:8]
        item["scanner_context_for_ai"] = _scanner_context_for_pattern(pat, technical)
        item["ai_instruction"] = (
            "Use workbook prevalence, PUID examples, related flags, evidence excerpts, and scanner_context_for_ai. "
            "Do not invent scanner findings. If scanner context is absent, state that recommendations are workbook-grounded."
        )
        enriched.append(item)
    return enriched


def _build_ai_reporting_context(metrics: Dict[str, Any], patterns: List[Dict[str, Any]], technical: Dict[str, Any]) -> Dict[str, Any]:
    sast = technical.get("sast_app_code") if isinstance(technical.get("sast_app_code"), dict) else {}
    mobsf_dynamic = technical.get("mobsf_dynamic") if isinstance(technical.get("mobsf_dynamic"), dict) else {}
    vision = technical.get("vision360") if isinstance(technical.get("vision360"), dict) else {}

    return {
        "purpose": "Compact evidence map for AI-authored audit-summary prose, recommendations, and MAP closure criteria.",
        "metrics": metrics,
        "top_patterns": [
            {
                "pattern": p.get("pattern"),
                "count": p.get("mapped_noncompliant_count"),
                "severity": p.get("severity"),
                "related_flags_sample": p.get("related_flags_sample", [])[:12],
                "scanner_sources": p.get("scanner_context_for_ai", {}).get("relevant_sources", []),
            }
            for p in patterns[:10]
        ],
        "sast_guardrail": {
            "retained_app_code_signals": _sast_retained_count(sast),
            "retained_security_findings": _safe_int(sast.get("retained_security_findings"), 0),
            "hardening_or_maintainability_signals": _safe_int(sast.get("hardening_or_maintainability_signals"), 0),
            "raw_sarif_results": _safe_int(sast.get("raw_sarif_results"), 0),
            "instruction": "Use retained_security_findings as the authoritative SAST security count. retained_app_code_signals may include hardening/quality findings. Raw SARIF results are traceability only.",
        },
        "mobsf_dynamic_summary": {
            "local_storage_artifacts_count": mobsf_dynamic.get("local_storage_artifacts_count"),
            "shared_preferences_artifacts": mobsf_dynamic.get("shared_preferences_artifacts", [])[:12],
            "sqlite_database_artifacts": mobsf_dynamic.get("sqlite_database_artifacts", [])[:12],
        },
        "vision360_summary": {
            "flags_count": vision.get("flags_count"),
            "state_counts": vision.get("state_counts", {}),
            "top_active_groups": vision.get("top_active_groups", [])[:8],
        },
        "global_guardrails": [
            "Use only evidence present in this analysis pack.",
            "Do not treat absence of a parsed MobSF field as absence of risk.",
            "Do not transform raw SAST counts into retained app-code findings.",
            "Recommendations must be generated from workbook and scanner context, not static templates.",
        ],
    }



# ------------------------------------------------------------
# Treatment plan evidence model
# ------------------------------------------------------------

def _owner_for_pattern(pattern: str, patterns: List[Dict[str, Any]]) -> str:
    for item in patterns:
        if str(item.get("pattern") or "") == str(pattern or ""):
            return str(item.get("recommended_owner") or "Engineering")
    meta = next((p for p in PATTERNS if p["name"] == pattern), None)
    return meta["owner"] if meta else "Engineering"


def _severity_for_pattern(pattern: str, patterns: List[Dict[str, Any]]) -> str:
    for item in patterns:
        if str(item.get("pattern") or "") == str(pattern or ""):
            return str(item.get("severity") or "Medium")
    meta = next((p for p in PATTERNS if p["name"] == pattern), None)
    return meta["severity"] if meta else "Medium"


def _pattern_puids(non_df: Any, pattern: str, limit: int = 12) -> List[str]:
    if not hasattr(non_df, "columns") or "Pattern" not in getattr(non_df, "columns", []):
        return []
    try:
        rows = non_df[non_df["Pattern"] == pattern]
        return _unique_keep_order(rows["PUID"].astype(str).tolist(), limit=limit)
    except Exception:
        return []


def _make_control_treatment_items(non_df: Any, patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Create requirement-level treatment items from non-compliant controls.

    This function deliberately does not prescribe remediation text. It exposes
    normalized evidence so Stage 2 can ask the configured AI model to write the
    treatment action, verification method, and closure evidence dynamically for
    the actual application under assessment.
    """
    if not hasattr(non_df, "iterrows"):
        return []

    items: List[Dict[str, Any]] = []
    for idx, (_, row) in enumerate(non_df.iterrows(), start=1):
        pattern = str(row.get("Pattern") or _match_pattern(row.get("Description", ""), row.get("Flags", "")))
        flags = _split_flags_cell(row.get("Flags", ""))
        item_id = f"CTRL-{idx:04d}"
        severity = _severity_for_pattern(pattern, patterns)
        likelihood = _likelihood_from_count(_safe_int(len(non_df[non_df["Pattern"] == pattern]) if "Pattern" in non_df.columns else 0, 0))
        items.append({
            "item_id": item_id,
            "item_type": "SECM-CAT control",
            "puid": str(row.get("PUID") or ""),
            "category_code": str(row.get("CategoryCode") or ""),
            "category_name": str(row.get("CategoryName") or ""),
            "current_status": "Non-compliant",
            "weakness_pattern": pattern,
            "severity": severity,
            "likelihood": likelihood,
            "recommended_owner": _owner_for_pattern(pattern, patterns),
            "description": _excerpt(row.get("Description", ""), 360),
            "evidence_excerpt": _excerpt(row.get("Evidence", ""), 260),
            "flags": flags[:40],
            "flags_by_family": _flags_by_family(flags),
            "ai_instruction": (
                "Generate treatment_action, verification_method, closure_evidence, and residual_risk from this control, "
                "its flags, evidence excerpt, weakness pattern, and any correlated scanner evidence. Do not invent PUIDs, flags, files, CVEs, or scanner findings."
            ),
        })
    return items


def _technical_patterns_for_finding(source: str, finding_id: str, message: str, component: str = "") -> List[str]:
    haystack = f"{source} {finding_id} {message} {component}".lower()
    patterns: List[str] = []
    if any(t in haystack for t in ["trivy", "cve", "dependency", "package", "library", "sca"]):
        patterns.append("Supply chain governance & outdated components")
    if any(t in haystack for t in ["sharedpreferences", "shared_prefs", "database", ".db", "sqlite", "storage", "keystore", "cache"]):
        patterns.append("Insecure local storage / key management gaps")
    if any(t in haystack for t in ["cleartext", "tls", "ssl", "certificate", "pinning", "trustmanager", "hostnameverifier", "sha1"]):
        patterns.append("Transport security / certificate validation weaknesses")
    if any(t in haystack for t in ["debug", "debuggable", "v1 signature", "janus", "reverse", "tamper", "root"]):
        patterns.append("Tampering / reverse engineering protections missing")
    if any(t in haystack for t in ["exported", "intent", "permission", "backup", "allowbackup", "manifest"]):
        patterns.append("Security misconfiguration / insecure defaults")
    if any(t in haystack for t in ["injection", "xss", "sql", "command", "validation", "webview"]):
        patterns.append("Input validation & injection weaknesses (XSS/SQLi/command/log injection)")
    if any(t in haystack for t in ["authorization", "auth", "rbac", "privilege", "role"]):
        patterns.append("Authorization / RBAC / least privilege gaps")
    return _unique_keep_order(patterns, limit=6) or ["Other control gaps"]


def _linked_puids_for_patterns(non_df: Any, patterns: List[str], limit: int = 12) -> List[str]:
    out: List[str] = []
    for pat in patterns:
        out.extend(_pattern_puids(non_df, pat, limit=limit))
    return _unique_keep_order(out, limit=limit)


def _make_trivy_treatment_items(technical: Dict[str, Any], non_df: Any, start_idx: int = 1) -> List[Dict[str, Any]]:
    trivy = technical.get("trivy_sca") if isinstance(technical.get("trivy_sca"), dict) else {}
    findings = trivy.get("top_findings") if isinstance(trivy.get("top_findings"), list) else []
    items: List[Dict[str, Any]] = []
    for offset, finding in enumerate(findings, start=start_idx):
        if not isinstance(finding, dict):
            continue
        fid = str(finding.get("id") or "")
        pkg = str(finding.get("package") or finding.get("pkg") or "")
        title = _excerpt(finding.get("title") or finding.get("description") or "", 260)
        patterns = _technical_patterns_for_finding("Trivy SCA", fid, title, pkg)
        items.append({
            "item_id": f"TECH-TRIVY-{offset:03d}",
            "item_type": "Dependency vulnerability",
            "source": "Trivy SCA",
            "severity": _severity_norm(finding.get("severity")),
            "finding_id": fid,
            "affected_component": pkg,
            "location": str(finding.get("target") or ""),
            "installed_version": str(finding.get("installed") or ""),
            "fixed_version": str(finding.get("fixed") or ""),
            "fix_available": bool(finding.get("fix_available") or finding.get("fixed")),
            "observed_issue": title,
            "linked_patterns": patterns,
            "linked_puids": _linked_puids_for_patterns(non_df, patterns, limit=12),
            "ai_instruction": "Generate a finding-specific dependency remediation action, validation method, and closure evidence from the CVE, package, installed version, fixed version, and severity. Do not invent package versions.",
        })
    return items


def _make_sast_treatment_items(technical: Dict[str, Any], non_df: Any, start_idx: int = 1) -> List[Dict[str, Any]]:
    sast = technical.get("sast_app_code") if isinstance(technical.get("sast_app_code"), dict) else {}
    findings = sast.get("security_findings_sample") if isinstance(sast.get("security_findings_sample"), list) else []
    items: List[Dict[str, Any]] = []
    for offset, finding in enumerate(findings, start=start_idx):
        if not isinstance(finding, dict):
            continue
        rule = str(finding.get("rule_id") or finding.get("ruleId") or finding.get("id") or "")
        msg = _excerpt(finding.get("message") or finding.get("title") or finding.get("description") or "", 260)
        component = str(finding.get("file") or finding.get("path") or finding.get("uri") or "")
        patterns = _technical_patterns_for_finding(str(finding.get("tool") or "SAST"), rule, msg, component)
        items.append({
            "item_id": f"TECH-SAST-{offset:03d}",
            "item_type": "Application-code SAST finding",
            "source": str(finding.get("tool") or "SAST app-code"),
            "severity": str(finding.get("level") or finding.get("severity") or "warning"),
            "finding_id": rule,
            "affected_component": component,
            "file": component,
            "line": finding.get("line") or finding.get("start_line") or finding.get("startLine") or "",
            "observed_issue": msg,
            "linked_patterns": patterns,
            "linked_puids": _linked_puids_for_patterns(non_df, patterns, limit=12),
            "ai_instruction": "Generate a code-level remediation action and verification method from the SAST rule, message, file, and line. Do not invent additional files or line numbers.",
        })
    return items


def _make_mobsf_treatment_items(technical: Dict[str, Any], non_df: Any, start_idx: int = 1) -> List[Dict[str, Any]]:
    mobsf_static = technical.get("mobsf_static") if isinstance(technical.get("mobsf_static"), dict) else {}
    mobsf_dynamic = technical.get("mobsf_dynamic") if isinstance(technical.get("mobsf_dynamic"), dict) else {}
    items: List[Dict[str, Any]] = []
    idx = start_idx

    def add_item(kind: str, severity: str, finding_id: str, component: str, issue: str, source: str = "MobSF") -> None:
        nonlocal idx
        if not _clean_text(issue) and not _clean_text(finding_id):
            return
        patterns = _technical_patterns_for_finding(source, finding_id, issue, component)
        items.append({
            "item_id": f"TECH-MOBSF-{idx:03d}",
            "item_type": kind,
            "source": source,
            "severity": severity or "Medium",
            "finding_id": finding_id,
            "affected_component": component,
            "location": component,
            "observed_issue": _excerpt(issue, 300),
            "linked_patterns": patterns,
            "linked_puids": _linked_puids_for_patterns(non_df, patterns, limit=12),
            "ai_instruction": "Generate a MobSF-grounded remediation action and verification method. Do not claim absence of risk from missing fields.",
        })
        idx += 1

    flags = mobsf_static.get("flags") if isinstance(mobsf_static.get("flags"), dict) else {}
    indicator_map = [
        ("debug_certificate_detected", "Release signing / debug certificate", "High", "debug-certificate", "Debug certificate evidence was detected in the assessed APK signing material."),
        ("v1_signature_or_janus_detected", "APK signing scheme / Janus exposure", "High", "v1-signature-or-janus", "APK v1 signature or Janus-related exposure evidence was detected."),
        ("sha1_certificate_detected", "Certificate / weak signature algorithm", "Medium", "sha1-certificate", "SHA1 certificate or signature evidence was detected."),
        ("allow_backup_detected", "Android backup configuration", "Medium", "allow-backup", "Android backup appears enabled or requires review in parsed MobSF evidence."),
        ("exported_components_detected", "Android exported component exposure", "High", "exported-components", "Exported Android components were detected and require authorization and intent-safety review."),
        ("vulnerable_min_sdk_signal", "Android platform baseline", "Medium", "vulnerable-min-sdk", "Minimum SDK is below a hardened Android baseline and requires compatibility/risk review."),
    ]
    for key, kind, sev, finding_id, issue in indicator_map:
        if flags.get(key) is True:
            add_item(kind, sev, finding_id, "Android manifest / APK signing evidence", issue, "MobSF static")

    for finding in (mobsf_static.get("manifest_findings_sample") or [])[:12]:
        if isinstance(finding, dict):
            add_item(
                "MobSF static manifest finding",
                str(finding.get("severity") or finding.get("level") or "Medium"),
                str(finding.get("title") or finding.get("id") or finding.get("rule") or "manifest-finding"),
                str(finding.get("component") or "AndroidManifest.xml"),
                str(finding.get("description") or finding.get("message") or finding.get("title") or ""),
                "MobSF static",
            )
    for finding in (mobsf_static.get("certificate_findings_sample") or [])[:8]:
        if isinstance(finding, dict):
            add_item(
                "MobSF certificate finding",
                str(finding.get("severity") or finding.get("level") or "Medium"),
                str(finding.get("title") or finding.get("id") or finding.get("rule") or "certificate-finding"),
                str(finding.get("component") or "APK certificate"),
                str(finding.get("description") or finding.get("message") or finding.get("title") or ""),
                "MobSF static",
            )

    dyn_sources = [
        ("SharedPreferences runtime artifact", "shared-preferences-artifacts", mobsf_dynamic.get("shared_preferences_artifacts") or []),
        ("SQLite/database runtime artifact", "sqlite-database-artifacts", mobsf_dynamic.get("sqlite_database_artifacts") or []),
        ("Local storage runtime artifact", "local-storage-artifacts", mobsf_dynamic.get("local_storage_artifacts_sample") or mobsf_dynamic.get("local_storage_artifacts") or []),
    ]
    for kind, finding_id, values in dyn_sources:
        values = values if isinstance(values, list) else []
        for artifact in _unique_keep_order(values, limit=8):
            add_item(
                kind,
                "Medium",
                finding_id,
                _normalize_android_storage_artifact(artifact),
                f"Runtime storage artifact observed: {_normalize_android_storage_artifact(artifact)}",
                "MobSF dynamic",
            )

    return items


def _owner_summary_from_controls(control_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    high_counts: Dict[str, int] = {}
    for item in control_items:
        owner = str(item.get("recommended_owner") or "Engineering")
        counts[owner] = counts.get(owner, 0) + 1
        if str(item.get("severity") or "").lower() == "high":
            high_counts[owner] = high_counts.get(owner, 0) + 1
    return [
        {"owner": owner, "control_items": count, "high_severity_items": high_counts.get(owner, 0)}
        for owner, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)
    ]


def _priority_summary_from_patterns(patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for pattern in patterns[:15]:
        count = _safe_int(pattern.get("mapped_noncompliant_count"), 0)
        severity = str(pattern.get("severity") or "Medium")
        likelihood = str(pattern.get("likelihood") or _likelihood_from_count(count))
        severity_score = {"High": 3, "Medium": 2, "Low": 1}.get(severity, 1)
        likelihood_score = {"High": 4, "Medium–High": 3, "Medium-High": 3, "Medium": 2, "Low–Medium": 1, "Low-Medium": 1}.get(likelihood, 1)
        rows.append({
            "pattern": pattern.get("pattern"),
            "severity": severity,
            "likelihood": likelihood,
            "mapped_noncompliant_count": count,
            "recommended_owner": pattern.get("recommended_owner"),
            "severity_score": severity_score,
            "likelihood_score": likelihood_score,
            "priority_score": severity_score * likelihood_score,
        })
    return rows


def _make_correlation_items(control_items: List[Dict[str, Any]], technical_items: List[Dict[str, Any]], limit: int = 500) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    control_by_puid = {str(c.get("puid")): c for c in control_items}
    for tech in technical_items:
        linked_puids = tech.get("linked_puids") if isinstance(tech.get("linked_puids"), list) else []
        for puid in linked_puids[:12]:
            ctrl = control_by_puid.get(str(puid), {})
            rows.append({
                "weakness_pattern": ctrl.get("weakness_pattern") or (tech.get("linked_patterns") or [""])[0],
                "puid": puid,
                "flags_sample": (ctrl.get("flags") or [])[:8],
                "technical_source": tech.get("source"),
                "technical_finding_id": tech.get("finding_id"),
                "technical_item_id": tech.get("item_id"),
                "evidence_summary": _excerpt(tech.get("observed_issue") or tech.get("affected_component"), 220),
            })
            if len(rows) >= limit:
                return rows
    return rows


def _build_treatment_plan(non_df: Any, patterns: List[Dict[str, Any]], technical: Dict[str, Any]) -> Dict[str, Any]:
    """Build a dynamic, evidence-only treatment-plan model for Stage 2.

    Stage 1 must not write static remediation recommendations. It only builds
    normalized treatment items from the workbook and scanner findings. Stage 2
    then asks the configured AI model to generate treatment actions, verification
    methods, closure evidence, and residual-risk wording for each item.
    """
    control_items = _make_control_treatment_items(non_df, patterns)
    technical_items: List[Dict[str, Any]] = []
    technical_items.extend(_make_trivy_treatment_items(technical, non_df, start_idx=1))
    technical_items.extend(_make_sast_treatment_items(technical, non_df, start_idx=1))
    technical_items.extend(_make_mobsf_treatment_items(technical, non_df, start_idx=1))

    # Deterministic ordering keeps report diffs stable across runs.
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1, "ERROR": 3, "WARNING": 2, "NOTE": 1}
    technical_items.sort(key=lambda x: (severity_rank.get(str(x.get("severity") or "").upper(), 1), str(x.get("source") or ""), str(x.get("item_id") or "")), reverse=True)

    correlation_items = _make_correlation_items(control_items, technical_items)
    owner_summary = _owner_summary_from_controls(control_items)
    priority_summary = _priority_summary_from_patterns(patterns)

    return {
        "purpose": "Evidence-only treatment-plan input for AI-authored remediation actions inside the Audit Summary DOCX.",
        "generation_rule": "Stage 1 normalizes facts only. Stage 2 must use the configured AI model to write treatment actions, verification methods, closure evidence, and residual-risk notes from these items.",
        "summary": {
            "control_items_total": len(control_items),
            "technical_items_total": len(technical_items),
            "correlation_items_total": len(correlation_items),
            "owner_groups_total": len(owner_summary),
            "priority_patterns_total": len(priority_summary),
        },
        "control_items": control_items,
        "technical_items": technical_items,
        "correlation_items": correlation_items,
        "owner_summary": owner_summary,
        "priority_summary": priority_summary,
        "chart_data": {
            "weakness_pattern_volume": [
                {
                    "pattern": p.get("pattern"),
                    "count": _safe_int(p.get("mapped_noncompliant_count"), 0),
                    "severity": p.get("severity"),
                    "owner": p.get("recommended_owner"),
                }
                for p in patterns[:15]
            ],
            "owner_workload": owner_summary,
            "priority_matrix": priority_summary,
        },
        "ai_guardrails": [
            "Use only treatment_plan.control_items, treatment_plan.technical_items, treatment_plan.correlation_items, and scanner evidence present in this analysis pack.",
            "Do not invent CVEs, packages, versions, files, lines, PUIDs, flags, or scanner findings.",
            "If evidence is insufficient for a direct fix, write a verification action instead of asserting a fix.",
            "Do not use static boilerplate recommendations; generate actions from the actual findings in this run.",
        ],
    }


# ------------------------------------------------------------
# Technical evidence ingestion
# ------------------------------------------------------------

def _safe_read_json(path: Path, default: Any = None) -> Any:
    if default is None:
        default = {}
    try:
        if not path or not path.is_file():
            return default
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return default


def _norm_path_text(path: Any) -> str:
    return str(path or "").replace("\\", "/").lstrip("./")


def _lower_path(path: Any) -> str:
    return _norm_path_text(path).lower()


def _unique_keep_order(values: Iterable[Any], limit: int = 100) -> List[str]:
    out: List[str] = []
    seen = set()
    for value in values:
        s = str(value or "").strip()
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= limit:
            break
    return out


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        if isinstance(value, bool):
            return int(value)
        return int(float(str(value).strip()))
    except Exception:
        return default


def _severity_norm(value: Any) -> str:
    s = str(value or "UNKNOWN").strip().upper()
    return s if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "ERROR", "WARNING", "NOTE", "NONE"} else "UNKNOWN"


def _severity_counter() -> Dict[str, int]:
    return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}


def _env_dir(name: str) -> Optional[Path]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    return Path(raw)


def _technical_root_candidates() -> List[Path]:
    candidates: List[Path] = []
    raw = os.getenv("AUDIT_TECHNICAL_INPUTS_DIR", "").strip()
    if raw:
        candidates.append(Path(raw))

    runner_temp = os.getenv("RUNNER_TEMP", "").strip()
    if runner_temp:
        candidates.append(Path(runner_temp) / "audit-technical-inputs")

    data_dir = _runtime_data_dir()
    candidates.append(data_dir / "audit-technical-inputs")
    candidates.append(data_dir.parent / "audit-technical-inputs")

    out: List[Path] = []
    seen = set()
    for p in candidates:
        key = str(p.resolve()) if p.exists() else str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _artifact_dir_candidates(env_name: str, subdirs: List[str]) -> List[Path]:
    candidates: List[Path] = []
    explicit = _env_dir(env_name)
    if explicit is not None:
        candidates.append(explicit)

    for root in _technical_root_candidates():
        for subdir in subdirs:
            candidates.append(root / subdir)

    runner_temp = os.getenv("RUNNER_TEMP", "").strip()
    if runner_temp:
        for subdir in subdirs:
            candidates.append(Path(runner_temp) / subdir)

    data_dir = _runtime_data_dir()
    for subdir in subdirs:
        candidates.append(data_dir / subdir)
        candidates.append(data_dir.parent / subdir)

    out: List[Path] = []
    seen = set()
    for p in candidates:
        key = str(p.resolve()) if p.exists() else str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _find_file(dirs: List[Path], names: List[str]) -> Optional[Path]:
    wanted = {n.lower(): n for n in names}
    for d in dirs:
        if not d.exists():
            continue
        for name in names:
            p = d / name
            if p.is_file():
                return p
        try:
            for p in d.rglob("*"):
                if p.is_file() and p.name.lower() in wanted:
                    return p
        except Exception:
            continue
    return None


def _dir_debug(dirs: List[Path]) -> List[str]:
    return [str(p) for p in dirs]


def _compact_finding_text(parts: List[Any], limit: int = 220) -> str:
    text = " | ".join(str(x).strip() for x in parts if str(x or "").strip())
    text = re.sub(r"\s+", " ", text).strip()
    return _excerpt(text, limit)


def _flatten_text(obj: Any, limit: int = 1200000) -> str:
    try:
        text = json.dumps(obj, ensure_ascii=False)
    except Exception:
        text = str(obj)
    return text.lower()[:limit]


def _walk_values(obj: Any, path: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{path}.{key}" if path else str(key)
            yield from _walk_values(value, child)
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            child = f"{path}[{idx}]"
            yield from _walk_values(value, child)
    else:
        yield path, obj


def _collect_strings_matching(obj: Any, patterns: List[str], limit: int = 200) -> List[str]:
    regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
    out: List[str] = []
    seen = set()
    for path, value in _walk_values(obj):
        candidates = []
        if isinstance(value, str):
            candidates.append(value)
        # Some tools place useful path-like evidence in keys rather than values.
        if isinstance(path, str):
            candidates.append(path)
        for raw in candidates:
            text = str(raw or "").strip()
            if not text:
                continue
            if any(rx.search(text) for rx in regexes):
                item = _extract_storage_artifact(text) or _excerpt(text, 260)
                if item and item not in seen:
                    seen.add(item)
                    out.append(item)
                if len(out) >= limit:
                    return out
    return out


def _extract_storage_artifact(text: str) -> str:
    text = _clean_text(text)
    if not text:
        return ""
    path_rx = re.compile(
        r"(/data/data/[^\s\"'<>;,]+|[^\s\"'<>;,]+\.(?:db|sqlite|sqlite3|xml|properties))",
        re.IGNORECASE,
    )
    match = path_rx.search(text)
    if match:
        return match.group(1).rstrip(".,;:)")
    return _excerpt(text, 220)


def _deep_find_values(obj: Any, key_patterns: List[str], limit: int = 40) -> List[Any]:
    regexes = [re.compile(p, re.IGNORECASE) for p in key_patterns]
    out: List[Any] = []
    for path, value in _walk_values(obj):
        last_key = re.split(r"[.\[]", str(path or ""))[-1].rstrip("]")
        if any(rx.search(last_key) or rx.search(str(path)) for rx in regexes):
            out.append(value)
            if len(out) >= limit:
                break
    return out


def _first_deep_value(obj: Any, key_patterns: List[str]) -> Any:
    values = _deep_find_values(obj, key_patterns, limit=1)
    return values[0] if values else None


def _bool_from_any(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "yes", "y", "1", "enabled", "detected", "present", "found"}:
        return True
    if text in {"false", "no", "n", "0", "disabled", "not detected", "absent", "none"}:
        return False
    if re.search(r"\btrue\b|enabled|detected|present|found", text):
        return True
    if re.search(r"\bfalse\b|disabled|not detected|absent", text):
        return False
    return None


def _indicator_value(value: Any, detected: Optional[bool] = None) -> str:
    parsed = _bool_from_any(value)
    if parsed is True or detected is True:
        return "Detected"
    if parsed is False or detected is False:
        return "Not detected"
    if value not in (None, ""):
        return _excerpt(value, 120)
    return "Not available in parsed evidence"

def _summarize_vision360(vision360_dir: Path, files: Dict[str, Optional[Path]]) -> Dict[str, Any]:
    fingerprint = _safe_read_json(files.get("vision360_fingerprint") or Path(), {})
    output = _safe_read_json(files.get("vision360_output") or Path(), {})
    trace = _safe_read_json(files.get("vision360_trace") or Path(), {})
    effective = _safe_read_json(files.get("vision360_effective_config") or Path(), {})

    flags = fingerprint.get("flags") if isinstance(fingerprint, dict) else []
    if not isinstance(flags, list):
        flags = []

    state_counts: Dict[str, int] = {}
    group_counts: Dict[str, int] = {}
    evidence_source_counts: Dict[str, int] = {}
    active_flags: List[str] = []
    negative_flags: List[str] = []
    active_flags_by_group: Dict[str, List[str]] = {}
    negative_flags_by_group: Dict[str, List[str]] = {}
    flag_state_index: List[Dict[str, str]] = []

    for flag in flags:
        if not isinstance(flag, dict):
            continue
        flag_id = str(flag.get("id") or flag.get("flag") or flag.get("name") or "").strip()
        verdict = flag.get("app_verdict") or flag.get("verdict") or {}
        if not isinstance(verdict, dict):
            verdict = {}
        state = str(verdict.get("state") or flag.get("state") or "unknown").lower()
        group = str(flag.get("group") or flag.get("category") or "UNKNOWN")
        state_counts[state] = state_counts.get(state, 0) + 1
        group_counts[group] = group_counts.get(group, 0) + 1

        if flag_id:
            flag_state_index.append({"id": flag_id, "group": group, "state": state})

        if state in {"true", "present", "detected", "yes", "positive"} and flag_id:
            active_flags.append(flag_id)
            active_flags_by_group.setdefault(group, []).append(flag_id)
        if state in {"false", "absent", "not_detected", "no", "negative"} and flag_id:
            negative_flags.append(flag_id)
            negative_flags_by_group.setdefault(group, []).append(flag_id)

        for source_key in ("source", "source_tool", "evidence_source", "origin"):
            src = flag.get(source_key)
            if src:
                src_s = str(src)
                evidence_source_counts[src_s] = evidence_source_counts.get(src_s, 0) + 1

    effective_features = trace.get("effective_features") if isinstance(trace, dict) else {}
    if not isinstance(effective_features, dict):
        effective_features = {}

    loaded_files = trace.get("loaded_files") if isinstance(trace, dict) else {}
    if not isinstance(loaded_files, dict):
        loaded_files = {}

    top_active_groups = [
        {
            "group": group,
            "active_flag_count": len(values),
            "active_flags_sample": _unique_keep_order(values, limit=12),
        }
        for group, values in sorted(active_flags_by_group.items(), key=lambda x: len(x[1]), reverse=True)[:12]
    ]

    return {
        "available": bool(fingerprint or output or trace or effective),
        "source_dir": str(vision360_dir),
        "files": {k: str(v) for k, v in files.items() if v},
        "project": (fingerprint.get("project") if isinstance(fingerprint, dict) else {}) or (output.get("project") if isinstance(output, dict) else {}),
        "flags_count": len(flags),
        "state_counts": state_counts,
        "group_counts": group_counts,
        "top_groups": [
            {"group": group, "count": count}
            for group, count in sorted(group_counts.items(), key=lambda x: x[1], reverse=True)[:12]
        ],
        "active_flags_sample": _unique_keep_order(active_flags, limit=40),
        "negative_flags_sample": _unique_keep_order(negative_flags, limit=40),
        "active_flags_by_group": {group: _unique_keep_order(values, limit=40) for group, values in active_flags_by_group.items()},
        "negative_flags_by_group": {group: _unique_keep_order(values, limit=40) for group, values in negative_flags_by_group.items()},
        "top_active_groups": top_active_groups,
        "flag_state_index_sample": flag_state_index[:80],
        "evidence_source_counts": evidence_source_counts,
        "feature_keys": sorted(effective_features.keys()),
        "has_sca_trace": bool(effective_features.get("sca")),
        "has_mobsf_trace": bool(effective_features.get("mobsf") or effective_features.get("mobsf_static") or effective_features.get("mobsf_dynamic")),
        "has_sast_trace": bool(effective_features.get("sast") or effective_features.get("codeql") or effective_features.get("semgrep")),
        "loaded_files": loaded_files,
        "coverage_summary": {
            "flags_total": len(flags),
            "groups_total": len(group_counts),
            "loaded_files_total": len(loaded_files),
            "features_total": len(effective_features),
            "active_flags_total": len(active_flags),
            "negative_flags_total": len(negative_flags),
            "evidence_sources_total": len(evidence_source_counts),
        },
        "ai_summary": {
            "instruction": "Use Vision360 as traceability and feature-coverage evidence. Do not treat a flag as a vulnerability unless it is mapped to a non-compliant requirement or corroborated by scanner evidence.",
            "top_active_groups": top_active_groups,
            "state_counts": state_counts,
            "evidence_source_counts": evidence_source_counts,
        },
    }


def _trivy_findings_from_raw(trivy: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    findings: List[Dict[str, Any]] = []
    packages: List[Dict[str, Any]] = []
    licenses: List[Dict[str, Any]] = []
    targets: List[Dict[str, Any]] = []

    results = trivy.get("Results") if isinstance(trivy, dict) else []
    if not isinstance(results, list):
        results = []

    for result in results:
        if not isinstance(result, dict):
            continue

        target = {
            "target": result.get("Target"),
            "class": result.get("Class"),
            "type": result.get("Type"),
            "packages": len(result.get("Packages") or []),
            "vulnerabilities": len(result.get("Vulnerabilities") or []),
            "licenses": len(result.get("Licenses") or []),
            "secrets": len(result.get("Secrets") or []),
            "misconfigurations": len(result.get("Misconfigurations") or []),
        }
        targets.append(target)

        raw_packages = result.get("Packages") or []
        if isinstance(raw_packages, list):
            packages.extend([x for x in raw_packages if isinstance(x, dict)])

        raw_licenses = result.get("Licenses") or []
        if isinstance(raw_licenses, list):
            licenses.extend([x for x in raw_licenses if isinstance(x, dict)])

        raw_vulns = result.get("Vulnerabilities") or []
        if isinstance(raw_vulns, list):
            for vuln in raw_vulns:
                if not isinstance(vuln, dict):
                    continue
                findings.append({
                    "target": result.get("Target"),
                    "class": result.get("Class"),
                    "type": result.get("Type"),
                    "id": vuln.get("VulnerabilityID"),
                    "pkg": vuln.get("PkgName"),
                    "pkg_id": vuln.get("PkgID"),
                    "installed": vuln.get("InstalledVersion"),
                    "fixed": vuln.get("FixedVersion"),
                    "fix_available": bool(vuln.get("FixedVersion")),
                    "severity": _severity_norm(vuln.get("Severity")),
                    "title": vuln.get("Title"),
                    "description": vuln.get("Description"),
                    "references": vuln.get("References") or [],
                    "primary_url": vuln.get("PrimaryURL"),
                    "cwe": vuln.get("CweIDs") or vuln.get("CWEIDs") or [],
                })

    return findings, packages, licenses, targets


def _summarize_trivy(trivy_dir: Path, files: Dict[str, Optional[Path]]) -> Dict[str, Any]:
    agent_payload = _safe_read_json(files.get("agent_payload") or Path(), {})
    trivy = _safe_read_json(files.get("trivy_json") or Path(), {})

    findings: List[Dict[str, Any]] = []
    packages: List[Dict[str, Any]] = []
    licenses: List[Dict[str, Any]] = []
    targets: List[Dict[str, Any]] = []

    if isinstance(agent_payload, dict):
        raw_findings = agent_payload.get("findings") or []
        if isinstance(raw_findings, list):
            findings = [x for x in raw_findings if isinstance(x, dict)]

        raw_licenses = agent_payload.get("licenses") or []
        if isinstance(raw_licenses, list):
            licenses = [x for x in raw_licenses if isinstance(x, dict)]

        coverage = agent_payload.get("coverage") or {}
        if isinstance(coverage, dict):
            raw_targets = coverage.get("targets") or []
            if isinstance(raw_targets, list):
                targets = [x for x in raw_targets if isinstance(x, dict)]

    raw_findings, raw_packages, raw_licenses, raw_targets = _trivy_findings_from_raw(trivy if isinstance(trivy, dict) else {})
    if not findings:
        findings = raw_findings
    packages = raw_packages
    if not licenses:
        licenses = raw_licenses
    if not targets:
        targets = raw_targets

    coverage = agent_payload.get("coverage") if isinstance(agent_payload, dict) else {}
    if not isinstance(coverage, dict):
        coverage = {}

    summary = agent_payload.get("summary") if isinstance(agent_payload, dict) else {}
    if not isinstance(summary, dict):
        summary = {}

    packages_detected = _safe_int(coverage.get("packages_detected"), len(packages))
    license_entries = _safe_int(coverage.get("license_entries_detected"), len(licenses))
    total = _safe_int(summary.get("total"), len(findings))

    by_severity = _severity_counter()
    for finding in findings:
        sev = _severity_norm(finding.get("severity"))
        if sev in by_severity:
            by_severity[sev] += 1

    if isinstance(summary.get("by_severity"), dict):
        by_severity.update({
            _severity_norm(k): _safe_int(v)
            for k, v in summary.get("by_severity", {}).items()
            if _severity_norm(k) in by_severity
        })

    fixable_summary = summary.get("fixable") if isinstance(summary.get("fixable"), dict) else {}
    fixable_total = _safe_int(fixable_summary.get("total"), sum(1 for f in findings if f.get("fix_available") or f.get("fixed")))
    unfixed_total = max(0, total - fixable_total)

    affected_packages = {}
    for finding in findings:
        pkg = str(finding.get("pkg") or finding.get("PkgName") or "unknown")
        affected_packages.setdefault(pkg, 0)
        affected_packages[pkg] += 1

    def sort_key(f: Dict[str, Any]) -> Tuple[int, str]:
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        return (rank.get(_severity_norm(f.get("severity")), 0), str(f.get("id") or ""))

    top_findings = []
    for finding in sorted(findings, key=sort_key, reverse=True)[:25]:
        top_findings.append({
            "id": finding.get("id"),
            "severity": _severity_norm(finding.get("severity")),
            "package": finding.get("pkg"),
            "installed": finding.get("installed"),
            "fixed": finding.get("fixed"),
            "fix_available": bool(finding.get("fix_available") or finding.get("fixed")),
            "title": _excerpt(finding.get("title") or finding.get("description"), 220),
            "target": finding.get("target"),
        })

    license_names = []
    for item in licenses:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("Name") or item.get("License") or item.get("Category")
        if name:
            license_names.append(str(name))

    return {
        "available": bool(agent_payload or trivy),
        "source_dir": str(trivy_dir),
        "files": {k: str(v) for k, v in files.items() if v},
        "scan": agent_payload.get("scan") if isinstance(agent_payload, dict) else {},
        "coverage": {
            "packages_detected": packages_detected,
            "license_entries_detected": license_entries,
            "targets": targets[:20],
        },
        "summary": {
            "total_vulnerabilities": total,
            "by_severity": by_severity,
            "fixable_total": fixable_total,
            "unfixed_total": unfixed_total,
            "unique_vulns": len(set(str(f.get("id")) for f in findings if f.get("id"))),
            "packages_affected": len(affected_packages),
        },
        "affected_packages_top": [
            {"package": pkg, "count": count}
            for pkg, count in sorted(affected_packages.items(), key=lambda x: x[1], reverse=True)[:15]
        ],
        "top_findings": top_findings,
        "licenses": {
            "total": license_entries,
            "unique_names": _unique_keep_order(license_names, limit=50),
        },
    }


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    if value is None:
        return []
    return [value]


def _collect_mobsf_findings(container: Any, limit: int = 80) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item in _as_list(container):
        if isinstance(item, dict):
            title = item.get("title") or item.get("name") or item.get("rule") or item.get("id") or ""
            desc = item.get("description") or item.get("desc") or item.get("message") or item.get("info") or ""
            sev = item.get("severity") or item.get("level") or item.get("status") or ""
            component = item.get("component") or item.get("file") or item.get("path") or ""
            if title or desc or sev:
                findings.append({
                    "severity": str(sev or "").strip(),
                    "title": _excerpt(title, 160),
                    "description": _excerpt(desc, 260),
                    "component": str(component or "").strip(),
                })
        elif isinstance(item, (list, tuple)) and item:
            findings.append({
                "severity": str(item[0]) if len(item) > 0 else "",
                "title": str(item[2]) if len(item) > 2 else "",
                "description": _excerpt(str(item[1]) if len(item) > 1 else str(item), 260),
                "component": "",
            })
        elif isinstance(item, str) and item.strip():
            findings.append({
                "severity": "",
                "title": "",
                "description": _excerpt(item, 260),
                "component": "",
            })
        if len(findings) >= limit:
            break
    return findings


def _mobsf_permissions(mobsf: Dict[str, Any]) -> Tuple[List[Dict[str, str]], List[str]]:
    raw = mobsf.get("permissions") or mobsf.get("app_permissions") or {}
    permissions: List[Dict[str, str]] = []
    dangerous: List[str] = []

    if isinstance(raw, dict):
        for name, info in raw.items():
            level = ""
            desc = ""
            if isinstance(info, dict):
                level = str(info.get("status") or info.get("protection_level") or info.get("protectionLevel") or info.get("level") or "")
                desc = str(info.get("description") or info.get("info") or "")
            else:
                level = str(info or "")
            item = {"name": str(name), "level": level, "description": _excerpt(desc, 160)}
            permissions.append(item)
            blob = f"{name} {level} {desc}".lower()
            if "dangerous" in blob:
                dangerous.append(str(name))
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("permission") or "")
                level = str(item.get("status") or item.get("protection_level") or item.get("level") or "")
                permissions.append({"name": name, "level": level, "description": _excerpt(item.get("description") or "", 160)})
                if "dangerous" in f"{name} {level} {item}".lower():
                    dangerous.append(name)
            elif isinstance(item, str):
                permissions.append({"name": item, "level": "", "description": ""})
                if any(tok in item for tok in ["WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "CAMERA", "ACCESS_FINE_LOCATION"]):
                    dangerous.append(item)

    known_dangerous = [
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
    ]
    names = {p.get("name") for p in permissions}
    dangerous.extend([p for p in known_dangerous if p in names])
    return permissions[:80], _unique_keep_order(dangerous, limit=80)


def _summarize_mobsf_static(mobsf_dir: Path, files: Dict[str, Optional[Path]]) -> Dict[str, Any]:
    mobsf = _safe_read_json(files.get("mobsf_results") or Path(), {})
    flat = _flatten_text(mobsf)

    manifest = mobsf.get("manifest_analysis") if isinstance(mobsf, dict) else {}
    if not isinstance(manifest, dict):
        manifest = {}

    manifest_findings = _collect_mobsf_findings(manifest.get("manifest_findings") or manifest.get("findings") or [], limit=80)

    cert = mobsf.get("certificate_analysis") if isinstance(mobsf, dict) else {}
    if not isinstance(cert, dict):
        cert = {}
    cert_findings = _collect_mobsf_findings(cert.get("certificate_findings") or cert.get("findings") or [], limit=40)
    cert_info = str(cert.get("certificate_info") or "")

    permissions, dangerous_permissions = _mobsf_permissions(mobsf if isinstance(mobsf, dict) else {})

    trackers = mobsf.get("trackers") if isinstance(mobsf, dict) else None
    detected_trackers = 0
    if isinstance(trackers, dict):
        detected_trackers = _safe_int(trackers.get("detected_trackers"), 0)
    elif isinstance(trackers, list):
        detected_trackers = len(trackers)
    elif isinstance(mobsf, dict) and "detected_trackers" in mobsf:
        detected_trackers = _safe_int(mobsf.get("detected_trackers"), 0)

    app_info = {}
    if isinstance(mobsf, dict):
        for key in ["app_name", "file_name", "package_name", "version_name", "version_code", "min_sdk", "target_sdk", "max_sdk"]:
            if key in mobsf:
                app_info[key] = mobsf.get(key)

    debug_value = _first_deep_value(mobsf, [r"^debuggable$", r"android_debuggable", r"is_debuggable"])
    backup_value = _first_deep_value(mobsf, [r"allow_?backup", r"android_allow_backup", r"backup_enabled"])
    min_sdk = _first_deep_value(mobsf, [r"^min_?sdk$", r"minsdk", r"minSdk"])
    target_sdk = _first_deep_value(mobsf, [r"^target_?sdk$", r"targetSdk"])
    exported_value = _first_deep_value(mobsf, [r"exported_components?_count", r"exported_count", r"exported_components?"])

    debug_cert_detected = ("debug certificate" in flat or "cn=android debug" in flat)
    v1_or_janus_detected = ("janus" in flat or "v1 signature" in flat or "v1 signature scheme" in flat)
    sha1_detected = ("sha1withrsa" in flat or " sha1 " in flat or "hash algorithm: sha1" in flat)
    cleartext_detected = ("cleartext" in flat and ("true" in flat or "enabled" in flat or "traffic" in flat))

    if isinstance(exported_value, list):
        exported_count: Any = len(exported_value)
    elif isinstance(exported_value, dict):
        exported_count = len(exported_value)
    elif exported_value not in (None, ""):
        exported_count = _safe_int(exported_value, 0)
    else:
        exported_count = "Not available in parsed evidence"

    min_sdk_value = _safe_int(min_sdk, 0) if min_sdk not in (None, "") else None
    vulnerable_min_sdk = bool(min_sdk_value and min_sdk_value < 23)

    indicators = {
        "debuggable": _indicator_value(debug_value, None),
        "debug_certificate": _indicator_value(None, debug_cert_detected if debug_cert_detected else None),
        "v1_signature": _indicator_value(None, v1_or_janus_detected if v1_or_janus_detected else None),
        "sha1": _indicator_value(None, sha1_detected if sha1_detected else None),
        "allow_backup": _indicator_value(backup_value, None),
        "min_sdk": min_sdk_value if min_sdk_value is not None else "Not available in parsed evidence",
        "target_sdk": _safe_int(target_sdk, 0) if target_sdk not in (None, "") else "Not available in parsed evidence",
        "dangerous_permissions_count": len(dangerous_permissions),
        "exported_components_count": exported_count,
        "trackers_detected": detected_trackers,
        "cleartext_traffic_signal": "Detected" if cleartext_detected else "Not available in parsed evidence",
        "vulnerable_min_sdk_signal": "Detected" if vulnerable_min_sdk else "Not detected" if min_sdk_value is not None else "Not available in parsed evidence",
    }

    flags = {
        "debuggable_detected": indicators["debuggable"] == "Detected",
        "allow_backup_detected": indicators["allow_backup"] == "Detected",
        "debug_certificate_detected": debug_cert_detected,
        "v1_signature_or_janus_detected": v1_or_janus_detected,
        "sha1_certificate_detected": sha1_detected,
        "cleartext_detected": cleartext_detected,
        "exported_components_detected": isinstance(exported_count, int) and exported_count > 0,
        "vulnerable_min_sdk_signal": vulnerable_min_sdk,
    }

    normalized_indicators = [
        {"indicator": "Debuggable", "value": indicators["debuggable"]},
        {"indicator": "Debug certificate", "value": indicators["debug_certificate"]},
        {"indicator": "v1 signature / Janus exposure", "value": indicators["v1_signature"]},
        {"indicator": "SHA1 certificate/signature evidence", "value": indicators["sha1"]},
        {"indicator": "Backup enabled", "value": indicators["allow_backup"]},
        {"indicator": "Minimum SDK", "value": indicators["min_sdk"]},
        {"indicator": "Target SDK", "value": indicators["target_sdk"]},
        {"indicator": "Dangerous permissions", "value": indicators["dangerous_permissions_count"]},
        {"indicator": "Exported components", "value": indicators["exported_components_count"]},
        {"indicator": "Trackers detected", "value": indicators["trackers_detected"]},
    ]

    return {
        "available": bool(mobsf),
        "source_dir": str(mobsf_dir),
        "files": {k: str(v) for k, v in files.items() if v},
        "app_info": app_info,
        "flags": flags,
        **indicators,
        "normalized_indicators": normalized_indicators,
        "dangerous_permissions": dangerous_permissions,
        "permissions_count": len(permissions),
        "permissions_sample": permissions[:25],
        "manifest_findings_count": len(manifest_findings),
        "manifest_findings_sample": manifest_findings[:20],
        "certificate_findings_count": len(cert_findings),
        "certificate_findings_sample": cert_findings[:15],
        "certificate_info_excerpt": _excerpt(cert_info, 500),
        "detected_trackers": detected_trackers,
    }

def _normalize_android_storage_artifact(item: Any) -> str:
    """Normalize MobSF dynamic storage artifacts for report readability.

    Some MobSF JSON exports and intermediate parsers collapse Android paths such
    as /data/data/org.openmrs.mobile/shared_prefs/OpenMRSPrefFile.xml into
    strings like datadataorg.openmrs.mobileshared_prefsOpenMRSPrefFile.xml.
    This helper reconstructs readable Android storage paths when possible and
    otherwise returns a clean file name or compact value.
    """
    raw = _clean_text(item)
    if not raw:
        return ""

    s = raw.replace("\\", "/")
    s = re.sub(r"^(file:/*)", "", s, flags=re.IGNORECASE)
    s = s.strip().strip("'\"`")

    # Already normalized or near-normalized Android app-private path.
    if "/data/data/" in s:
        idx = s.find("/data/data/")
        candidate = s[idx:]
        candidate = re.split(r"[\s\"'<>;,)]", candidate)[0]
        candidate = re.sub(r"/+", "/", candidate)
        return candidate.rstrip(".,;:")

    # Collapse forms such as data/data/org.openmrs.mobile/shared_prefs/x.xml.
    if s.lower().startswith("data/data/"):
        candidate = "/" + s
        candidate = re.sub(r"/+", "/", candidate)
        return candidate.rstrip(".,;:")

    collapsed = re.sub(r"[^A-Za-z0-9_./-]+", "", s)
    collapsed = collapsed.replace("//", "/")

    # Forms observed in MobSF dynamic text:
    # datadataorg.openmrs.mobileshared_prefsOpenMRSPrefFile.xml
    # datadataorg.openmrs.mobiledatabasesopenmrs.db
    if collapsed.lower().startswith("datadata"):
        tail = collapsed[len("datadata"):]
        for folder in ("shared_prefs", "databases", "no_backup", "cache", "files"):
            idx = tail.lower().find(folder)
            if idx > 0:
                package_name = tail[:idx].strip("./")
                rest = tail[idx + len(folder):].lstrip("/._-")
                if package_name and rest:
                    return f"/data/data/{package_name}/{folder}/{rest}"
                if package_name:
                    return f"/data/data/{package_name}/{folder}"
        # If folder was not found, keep the most useful app-private tail.
        if tail:
            return f"/data/data/{tail}"

    # Handle package + folder without the leading datadata prefix.
    for folder in ("shared_prefs", "databases", "no_backup", "cache", "files"):
        idx = collapsed.lower().find(folder)
        if idx > 0:
            package_name = collapsed[:idx].strip("./")
            rest = collapsed[idx + len(folder):].lstrip("/._-")
            if package_name.startswith("org.") and rest:
                return f"/data/data/{package_name}/{folder}/{rest}"

    # Fall back to the file-like artifact name when present.
    path_match = re.search(r"([A-Za-z0-9_.-]+\.(?:xml|db|sqlite|sqlite3|properties))$", collapsed, re.IGNORECASE)
    if path_match:
        return path_match.group(1)

    return _excerpt(raw, 220)


def _summarize_mobsf_dynamic(dynamic_dir: Path, files: Dict[str, Optional[Path]]) -> Dict[str, Any]:
    dyn = _safe_read_json(files.get("mobsf_dynamic_results") or Path(), {})
    storage_patterns = [
        r"/data/data/",
        r"data[/\\]?data",
        r"shared[_-]?prefs",
        r"sharedpreferences",
        r"preferences.*\.xml",
        r"pref.*\.xml",
        r"\.db(\b|$|-)",
        r"\.sqlite(\b|$)",
        r"\.sqlite3(\b|$)",
        r"/cache/",
        r"/files/",
        r"no[_-]?backup",
    ]

    artifacts = _collect_strings_matching(dyn, storage_patterns, limit=300)

    explicit_values: List[str] = []
    for value in _deep_find_values(
        dyn,
        [
            r"shared.*pref",
            r"preferences",
            r"sqlite",
            r"database",
            r"db_files?",
            r"local.*storage",
            r"app.*files?",
            r"cache",
            r"files",
            r"no[_-]?backup",
        ],
        limit=160,
    ):
        explicit_values.extend(_collect_strings_matching(value, storage_patterns, limit=100))
        if isinstance(value, str):
            maybe = _extract_storage_artifact(value)
            if maybe:
                explicit_values.append(maybe)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    maybe = _extract_storage_artifact(item)
                    if maybe:
                        explicit_values.append(maybe)
                elif isinstance(item, dict):
                    explicit_values.extend(_collect_strings_matching(item, storage_patterns, limit=30))

    raw_artifacts = _unique_keep_order(list(artifacts) + explicit_values, limit=300)
    normalized = _unique_keep_order([_normalize_android_storage_artifact(x) for x in raw_artifacts], limit=160)
    normalized = [x for x in normalized if x]

    def artifact_name(item: str) -> str:
        item = _normalize_android_storage_artifact(item)
        if not item:
            return ""
        return Path(item.replace("\\", "/")).name or item

    names = _unique_keep_order([artifact_name(x) for x in normalized], limit=120)

    shared_prefs = [
        x for x in normalized
        if re.search(r"/shared_prefs/|shared[_-]?prefs|sharedpreferences|pref.*\.xml|preferences.*\.xml", x, re.IGNORECASE)
    ]
    sqlite = [
        x for x in normalized
        if re.search(r"/databases/|\.db(\b|$|-)|\.sqlite(\b|$)|\.sqlite3(\b|$)", x, re.IGNORECASE)
    ]
    cache_files = [x for x in normalized if re.search(r"/cache/|cache", x, re.IGNORECASE)]
    backup_files = [x for x in normalized if re.search(r"/no_backup/|no[_-]?backup|workdb", x, re.IGNORECASE)]
    local_files = [x for x in normalized if re.search(r"/files/|/data/data/", x, re.IGNORECASE)]

    flat = _flatten_text(dyn, limit=500000)
    trackers = 0
    m = re.search(r'"detected_trackers"\s*:\s*(\d+)', flat)
    if m:
        trackers = _safe_int(m.group(1), 0)

    categories = [
        {
            "type": "SharedPreferences artifacts",
            "count": len(shared_prefs),
            "examples": _unique_keep_order(shared_prefs, limit=12),
            "example_names": _unique_keep_order([artifact_name(x) for x in shared_prefs], limit=12),
        },
        {
            "type": "SQLite/database artifacts",
            "count": len(sqlite),
            "examples": _unique_keep_order(sqlite, limit=12),
            "example_names": _unique_keep_order([artifact_name(x) for x in sqlite], limit=12),
        },
        {
            "type": "Local storage artifacts",
            "count": len(normalized),
            "examples": _unique_keep_order(normalized, limit=12),
            "example_names": names[:12],
        },
        {
            "type": "Cache / no-backup artifacts",
            "count": len(cache_files) + len(backup_files),
            "examples": _unique_keep_order(cache_files + backup_files, limit=12),
            "example_names": _unique_keep_order([artifact_name(x) for x in cache_files + backup_files], limit=12),
        },
        {
            "type": "Trackers",
            "count": trackers,
            "examples": [],
            "example_names": [],
        },
    ]

    return {
        "available": bool(dyn),
        "source_dir": str(dynamic_dir),
        "files": {k: str(v) for k, v in files.items() if v},
        "local_storage_artifacts_count": len(normalized),
        "local_storage_artifacts_sample": _unique_keep_order(normalized, limit=40),
        "local_storage_artifacts": _unique_keep_order(normalized, limit=80),
        "local_storage_artifact_names": names[:80],
        "shared_preferences_artifacts_count": len(shared_prefs),
        "shared_preferences_artifacts": _unique_keep_order(shared_prefs, limit=40),
        "shared_preferences_artifact_names": _unique_keep_order([artifact_name(x) for x in shared_prefs], limit=40),
        "shared_preferences": _unique_keep_order(shared_prefs, limit=40),
        "sqlite_database_artifacts_count": len(sqlite),
        "sqlite_database_artifacts": _unique_keep_order(sqlite, limit=40),
        "sqlite_database_artifact_names": _unique_keep_order([artifact_name(x) for x in sqlite], limit=40),
        "sqlite_databases": _unique_keep_order(sqlite, limit=40),
        "cache_artifacts": _unique_keep_order(cache_files, limit=30),
        "backup_artifacts": _unique_keep_order(backup_files, limit=30),
        "local_files_artifacts": _unique_keep_order(local_files, limit=40),
        "detected_trackers": trackers,
        "runtime_evidence_categories": categories,
        "parser_note": "Runtime storage examples are normalized from MobSF dynamic strings, path-like values, and common runtime artifact keys when present. Full readable Android paths are reconstructed when parsable; artifact names are also preserved for executive readability.",
    }


def _sarif_runs(sarif: Dict[str, Any]) -> List[Dict[str, Any]]:
    runs = sarif.get("runs") if isinstance(sarif, dict) else []
    return runs if isinstance(runs, list) else []


def _sarif_rule_map(run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run, dict) else {}
    raw_rules = driver.get("rules") or []
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(raw_rules, list):
        for rule in raw_rules:
            if isinstance(rule, dict) and rule.get("id"):
                out[str(rule.get("id"))] = rule
    return out


def _sarif_tool_name(run: Dict[str, Any]) -> str:
    driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run, dict) else {}
    return str(driver.get("name") or "unknown")


def _sarif_message_text(obj: Any) -> str:
    if isinstance(obj, dict):
        return str(obj.get("text") or obj.get("markdown") or "")
    return str(obj or "")


def _sarif_location(result: Dict[str, Any]) -> Tuple[str, int]:
    locations = result.get("locations") or []
    if not isinstance(locations, list) or not locations:
        return "", 0
    phys = (locations[0].get("physicalLocation") or {}) if isinstance(locations[0], dict) else {}
    artifact = phys.get("artifactLocation") or {}
    region = phys.get("region") or {}
    uri = str(artifact.get("uri") or "")
    line = _safe_int(region.get("startLine"), 0)
    return _norm_path_text(uri), line


DEFAULT_SAST_INCLUDE_PATTERNS = [
    "**/src/main/**",
    "**/AndroidManifest.xml",
    "AndroidManifest.xml",
    "**/*.java",
    "**/*.kt",
    "**/build.gradle",
    "**/build.gradle.kts",
]

DEFAULT_SAST_EXCLUDE_PATTERNS = [
    ".github/**",
    "**/.github/**",
    "scripts/**",
    "**/scripts/**",
    "requirements/**",
    "**/requirements/**",
    "parameters/**",
    "**/parameters/**",
    "tools/**",
    "**/tools/**",
    "report/**",
    "reports/**",
    "**/report/**",
    "**/reports/**",
    "build/**",
    "**/build/**",
    ".gradle/**",
    "**/.gradle/**",
    "gradle/wrapper/**",
    "**/gradle/wrapper/**",
    "docs/**",
    "**/docs/**",
    "**/src/test/**",
    "**/src/androidTest/**",
    "**/test/**",
    "**/tests/**",
    "**/generated/**",
]


def _split_patterns(value: str) -> List[str]:
    if not value:
        return []
    parts = re.split(r"[;,]", value)
    return [p.strip().replace("\\", "/") for p in parts if p.strip()]


def _sast_include_patterns() -> List[str]:
    custom = _split_patterns(os.getenv("AUDIT_SAST_INCLUDE_PATTERNS", ""))
    return custom or DEFAULT_SAST_INCLUDE_PATTERNS


def _sast_exclude_patterns() -> List[str]:
    custom = _split_patterns(os.getenv("AUDIT_SAST_EXCLUDE_PATTERNS", ""))
    return DEFAULT_SAST_EXCLUDE_PATTERNS + custom


def _path_matches_any(path: str, patterns: List[str]) -> bool:
    low = _lower_path(path)
    for pattern in patterns:
        pat = pattern.lower().replace("\\", "/")
        if fnmatch.fnmatch(low, pat):
            return True
        if pat.startswith("**/") and fnmatch.fnmatch(low, pat[3:]):
            return True
    return False


def _is_excluded_sast_path(path: str) -> bool:
    return _path_matches_any(path, _sast_exclude_patterns())


def _is_app_code_sast_path(path: str) -> bool:
    low = _lower_path(path)
    if not low or _is_excluded_sast_path(low):
        return False
    return _path_matches_any(low, _sast_include_patterns())

def _sarif_notifications(run: Dict[str, Any], tool_name: str, limit: int = 20) -> List[Dict[str, Any]]:
    notifications: List[Dict[str, Any]] = []
    invocations = run.get("invocations") or []
    if not isinstance(invocations, list):
        return notifications

    for inv in invocations:
        if not isinstance(inv, dict):
            continue
        for key in ("toolExecutionNotifications", "configurationNotifications"):
            raw = inv.get(key) or []
            if not isinstance(raw, list):
                continue
            for note in raw:
                if not isinstance(note, dict):
                    continue
                level = str(note.get("level") or "note")
                message = _sarif_message_text(note.get("message"))
                loc = ""
                line = 0
                locations = note.get("locations") or []
                if isinstance(locations, list) and locations:
                    loc, line = _sarif_location({"locations": locations})
                notifications.append({
                    "tool": tool_name,
                    "level": level,
                    "message": _excerpt(message, 260),
                    "file": loc,
                    "line": line,
                })
                if len(notifications) >= limit:
                    return notifications
    return notifications


def _summarize_sast(sast_dir: Path, files: Dict[str, Optional[Path]]) -> Dict[str, Any]:
    """Summarize SARIF with strict raw/security/hardening separation.

    Raw SARIF results are tool activity and traceability. Retained app-scope
    signals are findings that pass the configured Android application-code path
    filter. Retained security findings are a narrower subset that explicitly
    carry security semantics through rule metadata, tags, severity, CWE, or
    security-specific rule/message terms. Detekt findings are treated as
    hardening/quality signals unless they explicitly match security semantics.
    """
    selected: List[Tuple[str, Path]] = []
    if files.get("merged_sarif"):
        selected = [("merged", files["merged_sarif"])]  # type: ignore[index]
    else:
        for key in ("semgrep_sarif", "detekt_sarif"):
            if files.get(key):
                selected.append((key, files[key]))  # type: ignore[arg-type]

    raw_results = 0
    raw_by_tool: Dict[str, int] = {}
    raw_by_rule: Dict[str, int] = {}
    app_results: List[Dict[str, Any]] = []
    excluded_results = 0
    notifications: List[Dict[str, Any]] = []
    dedupe = set()

    for label, path in selected:
        sarif = _safe_read_json(path, {})
        for run in _sarif_runs(sarif):
            tool = _sarif_tool_name(run)
            rules = _sarif_rule_map(run)
            notifications.extend(_sarif_notifications(run, tool, limit=80))

            results = run.get("results") or []
            if not isinstance(results, list):
                continue

            for result in results:
                if not isinstance(result, dict):
                    continue
                raw_results += 1
                raw_by_tool[tool] = raw_by_tool.get(tool, 0) + 1

                rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "unknown")
                raw_by_rule[rule_id] = raw_by_rule.get(rule_id, 0) + 1

                uri, line = _sarif_location(result)
                if not _is_app_code_sast_path(uri):
                    excluded_results += 1
                    continue

                rule = rules.get(rule_id, {})
                message = _sarif_message_text(result.get("message"))
                level = str(result.get("level") or "warning")
                props = rule.get("properties") if isinstance(rule, dict) else {}
                if not isinstance(props, dict):
                    props = {}

                key = (tool, rule_id, uri, line, message[:120])
                if key in dedupe:
                    continue
                dedupe.add(key)

                tags = props.get("tags") if isinstance(props.get("tags"), list) else []
                cwe = props.get("cwe") or props.get("cwes") or props.get("problem.severity") or []
                app_results.append({
                    "tool": tool,
                    "rule_id": rule_id,
                    "level": level,
                    "file": uri,
                    "line": line,
                    "message": _excerpt(message, 260),
                    "rule_name": rule.get("name") if isinstance(rule, dict) else "",
                    "help_uri": rule.get("helpUri") if isinstance(rule, dict) else "",
                    "security_severity": props.get("security-severity"),
                    "precision": props.get("precision"),
                    "problem_severity": props.get("problem.severity"),
                    "tags": tags,
                    "cwe": cwe if isinstance(cwe, list) else [cwe] if cwe else [],
                })

    retained_by_tool: Dict[str, int] = {}
    retained_by_rule: Dict[str, int] = {}
    for item in app_results:
        tool = str(item.get("tool") or "unknown")
        rule = str(item.get("rule_id") or "unknown")
        retained_by_tool[tool] = retained_by_tool.get(tool, 0) + 1
        retained_by_rule[rule] = retained_by_rule.get(rule, 0) + 1

    security_terms = [
        "security", "vulnerab", "cwe-", "cve-", "injection", "xss", "sqli", "sql injection",
        "command injection", "path traversal", "xxe", "deserialization", "secret", "credential",
        "password", "token", "api key", "hardcoded", "crypto", "cryptograph", "cipher", "hash",
        "tls", "ssl", "cleartext", "mitm", "certificate", "trustmanager", "hostnameverifier",
        "webview", "exported", "allowbackup", "backup", "keystore", "sharedpreferences",
        "permission", "intent", "ipc", "auth", "authorization", "authentication",
    ]

    def is_security(item: Dict[str, Any]) -> bool:
        tool = str(item.get("tool") or "").lower()
        rule = str(item.get("rule_id") or "").lower()
        rule_name = str(item.get("rule_name") or "").lower()
        tags = " ".join(str(t).lower() for t in item.get("tags") or [])
        cwe = " ".join(str(t).lower() for t in item.get("cwe") or [])
        msg = str(item.get("message") or "").lower()
        sec_sev = item.get("security_severity")

        haystack = f"{rule} {rule_name} {tags} {cwe} {msg}"

        # CodeQL security queries normally carry security-severity, security tags,
        # or CWE metadata. Non-security CodeQL diagnostics remain hardening/quality.
        if sec_sev not in (None, ""):
            return True
        if re.search(r"\bcwe-\d+\b", haystack):
            return True
        if any(tok in haystack for tok in security_terms):
            return True

        # Avoid classifying all Detekt and generic Android style rules as
        # vulnerabilities. They may still be retained as maintainability signals.
        if "detekt" in tool:
            return False

        # Semgrep rules without security metadata are not automatically
        # vulnerabilities. They remain app-scope signals unless the rule/message
        # contains security terms.
        return False

    security_findings = [x for x in app_results if is_security(x)]
    hardening_signals = [x for x in app_results if x not in security_findings]

    def count_by_tool(items: List[Dict[str, Any]]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for item in items:
            tool = str(item.get("tool") or "unknown")
            out[tool] = out.get(tool, 0) + 1
        return out

    def count_by_rule(items: List[Dict[str, Any]]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for item in items:
            rule = str(item.get("rule_id") or "unknown")
            out[rule] = out.get(rule, 0) + 1
        return out

    retained_security_by_tool = count_by_tool(security_findings)
    hardening_by_tool = count_by_tool(hardening_signals)
    retained_security_by_rule = count_by_rule(security_findings)
    hardening_by_rule = count_by_rule(hardening_signals)

    top_raw_rules = [
        {"rule_id": rule, "count": count}
        for rule, count in sorted(raw_by_rule.items(), key=lambda x: x[1], reverse=True)[:20]
    ]
    top_retained_rules = [
        {"rule_id": rule, "count": count}
        for rule, count in sorted(retained_by_rule.items(), key=lambda x: x[1], reverse=True)[:20]
    ]
    top_security_rules = [
        {"rule_id": rule, "count": count}
        for rule, count in sorted(retained_security_by_rule.items(), key=lambda x: x[1], reverse=True)[:20]
    ]
    top_hardening_rules = [
        {"rule_id": rule, "count": count}
        for rule, count in sorted(hardening_by_rule.items(), key=lambda x: x[1], reverse=True)[:20]
    ]

    retained_total = len(app_results)
    retained_security_total = len(security_findings)
    hardening_total = len(hardening_signals)

    return {
        "available": bool(selected),
        "source_dir": str(sast_dir),
        "files": {k: str(v) for k, v in files.items() if v},
        "selected_sarif_files": [str(p) for _, p in selected],
        "scope_filter": {
            "included": _sast_include_patterns(),
            "excluded": _sast_exclude_patterns(),
            "note": "SAST evidence is filtered by generic Android application-code patterns. Workflow files, audit tooling, tests, generated files, reports, build output, and wrapper tooling are excluded unless project configuration overrides the defaults.",
        },
        # Stage 2 compatibility aliases. total_findings remains app-scope signals
        # for older code, but retained_security_findings is authoritative for
        # security-relevant SAST findings.
        "total_findings": retained_total,
        "retained_app_code_findings": retained_total,
        "retained_app_code_signals": retained_total,
        "retained_security_findings": retained_security_total,
        "hardening_or_maintainability_signals": hardening_total,
        "raw_results_count": raw_results,
        "raw_sarif_results": raw_results,
        "excluded_non_app_results": excluded_results,
        "tool_counts": retained_by_tool,
        "retained_tool_counts": retained_by_tool,
        "raw_tool_counts": raw_by_tool,
        "retained_security_tool_counts": retained_security_by_tool,
        "hardening_tool_counts": hardening_by_tool,
        "classification_note": (
            "retained_app_code_findings counts all app-scope SARIF signals after path filtering. "
            "retained_security_findings is the authoritative count of security-relevant SAST findings. "
            "hardening_or_maintainability_signals captures Detekt and other non-security app-scope signals."
        ),
        "summary": {
            "raw_results_in_selected_sarif": raw_results,
            "raw_tool_counts": raw_by_tool,
            "app_code_results": retained_total,
            "retained_app_code_findings": retained_total,
            "retained_app_code_signals": retained_total,
            "excluded_non_app_results": excluded_results,
            "security_relevant_app_findings": retained_security_total,
            "retained_security_findings": retained_security_total,
            "hardening_or_maintainability_signals": hardening_total,
            "retained_by_tool": retained_by_tool,
            "retained_security_by_tool": retained_security_by_tool,
            "hardening_by_tool": hardening_by_tool,
            "top_raw_rules": top_raw_rules,
            "top_retained_rules": top_retained_rules,
            "top_security_rules": top_security_rules,
            "top_hardening_rules": top_hardening_rules,
        },
        "ai_guardrails": {
            "raw_sarif_counts_are_traceability_only": True,
            "retained_security_findings_are_authoritative": True,
            "detekt_is_hardening_by_default": True,
            "instruction": (
                "Use retained_security_findings as the authoritative SAST security finding count. "
                "retained_app_code_findings may include hardening, quality, or maintainability signals. "
                "Do not describe Detekt warnings or raw SARIF counts as vulnerabilities unless they are included in retained_security_findings."
            ),
        },
        "security_findings_sample": security_findings[:40],
        "hardening_signals_sample": hardening_signals[:40],
        "top_security_rules": top_security_rules,
        "top_hardening_rules": top_hardening_rules,
        "coverage_notifications_sample": notifications[:30],
    }


def build_technical_evidence() -> Dict[str, Any]:
    vision_dirs = _artifact_dir_candidates("VISION360_BUNDLE_DIR", ["vision360", "vision360-bundle"])
    trivy_dirs = _artifact_dir_candidates("TRIVY_PAYLOAD_DIR", ["trivy", "trivy-payload"])
    mobsf_dirs = _artifact_dir_candidates("MOBSF_REPORT_DIR", ["mobsf", "mobsf-report"])
    dyn_dirs = _artifact_dir_candidates("MOBSF_DYNAMIC_REPORT_DIR", ["mobsf-dynamic", "mobsf-dynamic-report"])
    sast_dirs = _artifact_dir_candidates("SAST_FINDINGS_DIR", ["sast", "sast-findings"])

    vision_files = {
        "vision360_fingerprint": _find_file(vision_dirs, ["vision360_fingerprint.json"]),
        "vision360_output": _find_file(vision_dirs, ["vision360_output.json", "vision_360_output.json"]),
        "vision360_trace": _find_file(vision_dirs, ["vision360_trace.json"]),
        "vision360_effective_config": _find_file(vision_dirs, ["vision360_effective_config.json"]),
    }       
    trivy_files = {
        "agent_payload": _find_file(trivy_dirs, ["agent_payload.json"]),
        "trivy_json": _find_file(trivy_dirs, ["trivy.json"]),
        "trivy_sarif": _find_file(trivy_dirs, ["trivy.sarif"]),
    }
    mobsf_files = {
        "mobsf_results": _find_file(mobsf_dirs, ["mobsf_results.json", "mobsf-report.json"]),
    }
    dyn_files = {
        "mobsf_dynamic_results": _find_file(dyn_dirs, ["mobsf_dynamic_results.json", "mobsf-dynamic-report.json"]),
    }
    sast_files = {
        "merged_sarif": _find_file(sast_dirs, ["merged.sarif"]),
        "semgrep_sarif": _find_file(sast_dirs, ["semgrep.sarif"]),
        "detekt_sarif": _find_file(sast_dirs, ["detekt.sarif"]),
    }

    technical = {
        "schema_version": 1,
        "artifact_dirs": {
            "vision360_candidates": _dir_debug(vision_dirs),
            "trivy_candidates": _dir_debug(trivy_dirs),
            "mobsf_candidates": _dir_debug(mobsf_dirs),
            "mobsf_dynamic_candidates": _dir_debug(dyn_dirs),
            "sast_candidates": _dir_debug(sast_dirs),
        },
        "vision360": _summarize_vision360(vision_dirs[0] if vision_dirs else Path(), vision_files),
        "trivy_sca": _summarize_trivy(trivy_dirs[0] if trivy_dirs else Path(), trivy_files),
        "mobsf_static": _summarize_mobsf_static(mobsf_dirs[0] if mobsf_dirs else Path(), mobsf_files),
        "mobsf_dynamic": _summarize_mobsf_dynamic(dyn_dirs[0] if dyn_dirs else Path(), dyn_files),
        "sast_app_code": _summarize_sast(sast_dirs[0] if sast_dirs else Path(), sast_files),
    }

    sast_notifications = technical["sast_app_code"].get("coverage_notifications_sample", [])
    notif_by_tool: Dict[str, int] = {}
    notif_by_level: Dict[str, int] = {}
    notif_messages: List[str] = []
    if isinstance(sast_notifications, list):
        for item in sast_notifications:
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool") or "unknown")
            level = str(item.get("level") or "note")
            notif_by_tool[tool] = notif_by_tool.get(tool, 0) + 1
            notif_by_level[level] = notif_by_level.get(level, 0) + 1
            msg = _excerpt(item.get("message"), 220)
            if msg:
                notif_messages.append(f"{tool}: {msg}")

    missing_inputs = [
        key
        for key, section in [
            ("vision360", technical["vision360"]),
            ("trivy_sca", technical["trivy_sca"]),
            ("mobsf_static", technical["mobsf_static"]),
            ("mobsf_dynamic", technical["mobsf_dynamic"]),
            ("sast_app_code", technical["sast_app_code"]),
        ]
        if not section.get("available")
    ]

    sast_warning_count = len(sast_notifications) if isinstance(sast_notifications, list) else 0
    by_tool_text = "; ".join(f"{tool}: {count}" for tool, count in sorted(notif_by_tool.items())) if notif_by_tool else ""
    by_level_text = "; ".join(f"{level}: {count}" for level, count in sorted(notif_by_level.items())) if notif_by_level else ""

    technical["coverage_limitations"] = {
        "missing_inputs": missing_inputs,
        "sast_extraction_warning_count": sast_warning_count,
        "sast_extraction_warnings": (
            f"{sast_warning_count} SAST extraction or frontend notification(s) were reported by the toolchain. "
            "These notifications affect coverage interpretation and must not be treated as application findings."
            if sast_warning_count else ""
        ),
        "sast_extraction_warnings_by_tool": by_tool_text,
        "sast_extraction_warnings_by_level": by_level_text,
        "sast_extraction_warnings_summary": _unique_keep_order(notif_messages, limit=8),
    }

    return technical



def main() -> None:
    excel_path = os.getenv("AUDIT_EXCEL_PATH", DEFAULT_EXCEL)
    sheet = os.getenv("AUDIT_SHEET", DEFAULT_SHEET)
    out_path = os.getenv("AUDIT_ANALYSIS_JSON_PATH", DEFAULT_OUT)

    if not os.path.isfile(excel_path):
        raise SystemExit(f"[ERROR] Excel not found: {excel_path}")

    df = pd.read_excel(excel_path, sheet_name=sheet)

    cols = [str(c) for c in df.columns]

    col_puid = _find_col(cols, [r"^id\b", r"\bpuid\b"])
    col_desc = _find_col(cols, [r"description", r"descrip", r"descri", r"descripci", r"descripción"])
    col_result = _find_col(cols, [r"\bresult\b", r"\bstatus\b", r"\bcumple\b"])
    col_flags = _find_col(cols, [r"\bflags\b"])
    col_evid = _find_col(cols, [r"justif", r"evid", r"\bevidence\b"])

    missing = [("id (PUID)", col_puid), ("Description", col_desc), ("Result/Status", col_result), ("Flags", col_flags)]
    missing = [name for name, col in missing if col is None]
    if missing:
        raise SystemExit(f"[ERROR] Missing mandatory columns in sheet '{sheet}': {', '.join(missing)}")

    df = df.copy()
    df["PUID"] = df[col_puid].astype(str)
    df["Description"] = df[col_desc].astype(str)
    df["Flags"] = df[col_flags].astype(str).fillna("").str.strip()
    df["Evidence"] = df[col_evid].astype(str).fillna("").str.strip() if col_evid else ""

    df["Status"] = df[col_result].apply(_norm_status)
    df["CategoryCode"] = df["PUID"].apply(lambda x: _cat_from_puid(x)["code"])
    df["CategoryName"] = df["PUID"].apply(lambda x: _cat_from_puid(x)["name"])

    total_assessed = int(len(df))
    compliant = int((df["Status"] == "Compliant").sum())
    non_compliant = int((df["Status"] == "Non-compliant").sum())
    not_applicable = int((df["Status"] == "Not applicable").sum())
    applicable = int(compliant + non_compliant)
    overall_compliance_pct = float((compliant / applicable * 100.0) if applicable else 0.0)

    # Category metrics for charts (not for narrative dumps)
    grp = df.groupby(["CategoryCode", "CategoryName", "Status"]).size().reset_index(name="count")
    cat_stats: Dict[str, Dict[str, Any]] = {}
    for (code, name), sub in grp.groupby(["CategoryCode", "CategoryName"]):
        counts = {r["Status"]: int(r["count"]) for _, r in sub.iterrows()}
        c = int(counts.get("Compliant", 0))
        n = int(counts.get("Non-compliant", 0))
        na = int(counts.get("Not applicable", 0))
        app = c + n
        pct = float((c / app * 100.0) if app else 0.0)
        cat_stats[code] = {
            "category_name": name,
            "applicable": app,
            "compliant": c,
            "non_compliant": n,
            "not_applicable": na,
            "compliance_pct": pct,
        }

    # Verified positive controls candidates (Compliant + support signals)
    comp = df[df["Status"] == "Compliant"].copy()
    comp["HasSupport"] = comp["Flags"].astype(str).str.strip().ne("") | comp["Evidence"].astype(str).str.strip().ne("")
    comp = comp[comp["HasSupport"]].copy()
    comp["Declarative"] = comp["Description"].apply(_to_declarative)
    comp["EvidenceExcerpt"] = comp["Evidence"].apply(lambda x: _excerpt(x, 180))

    positive_controls = []
    for _, r in comp.iterrows():
        positive_controls.append({
            "puid": r["PUID"],
            "category_code": r["CategoryCode"],
            "category_name": r["CategoryName"],
            "declarative_statement": r["Declarative"],
            "flags_used": r["Flags"],
            "evidence_excerpt": r["EvidenceExcerpt"],
        })

    # Non-compliance mapping to weakness patterns
    non = df[df["Status"] == "Non-compliant"].copy()
    non["Pattern"] = non.apply(lambda rr: _match_pattern(rr["Description"], rr["Flags"]), axis=1)
    non["Anchor"] = non["Description"].apply(lambda x: _excerpt(x, 220))

    pattern_summary = []
    for pat, sub in non.groupby("Pattern"):
        sub = sub.copy()
        cnt = int(len(sub))
        ex = list(dict.fromkeys(sub["PUID"].tolist()))[:5]
        anchors = list(dict.fromkeys(sub["Anchor"].tolist()))[:2]
        meta = next((p for p in PATTERNS if p["name"] == pat), None)
        severity = meta["severity"] if meta else "Low"
        owner = meta["owner"] if meta else "Engineering"
        likelihood = _likelihood_from_count(cnt)
        pattern_summary.append({
            "pattern": pat,
            "mapped_noncompliant_count": cnt,
            "example_puids": ex,
            "description_anchors": anchors,
            "severity": severity,
            "recommended_owner": owner,
            "likelihood": likelihood,
        })

    # Sort by severity then count (deterministic)
    sev_rank = {"High": 3, "Medium": 2, "Low": 1}
    pattern_summary.sort(key=lambda x: (sev_rank.get(x["severity"], 0), x["mapped_noncompliant_count"]), reverse=True)


    runtime_config = _load_runtime_config()
    app_metadata = runtime_config["app_metadata"]
    actors = runtime_config["actors"]
    technical_evidence = build_technical_evidence()

    # Enrich weakness patterns after technical evidence is available. This gives
    # Stage 2 and the configured AI model a grounded context for recommendations,
    # impact, expected-state narrative, and MAP closure criteria.
    pattern_summary = _enrich_weakness_patterns_for_ai(pattern_summary, non, technical_evidence)
    ai_reporting_context = _build_ai_reporting_context(
        {
            "total_assessed": total_assessed,
            "applicable": applicable,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "not_applicable": not_applicable,
            "overall_compliance_pct": overall_compliance_pct,
        },
        pattern_summary,
        technical_evidence,
    )

    treatment_plan = _build_treatment_plan(non, pattern_summary, technical_evidence)

    out: Dict[str, Any] = {
        "generated_at_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "inputs": {
            "excel_path": excel_path,
            "sheet": sheet,
            "evidence_column_present": bool(col_evid),
            "detected_columns": {
                "puid": col_puid,
                "description": col_desc,
                "result_status": col_result,
                "flags": col_flags,
                "evidence": col_evid,
            },
            "config_json_path": runtime_config["config_path"],
            "technical_artifact_dirs": technical_evidence.get("artifact_dirs", {}),
        },
        "app_metadata": app_metadata,
        "actors": actors,
        "normalization": {
            "status_values": ["Compliant", "Non-compliant", "Not applicable"],
            "category_map": CAT_MAP,
            "result_mapping_note": "Upstream 'Result' values yes/no/n/a are normalized to Compliant/Non-compliant/Not applicable.",
        },
        "metrics": {
            "total_assessed": total_assessed,
            "applicable": applicable,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "not_applicable": not_applicable,
            "overall_compliance_pct": overall_compliance_pct,
        },
        "category_metrics": cat_stats,
        "likelihood_rubric": LIKELIHOOD_RUBRIC,
        "positive_controls_candidates": positive_controls[:12],  # cap
        "weakness_patterns": pattern_summary,
        "technical_evidence": technical_evidence,
        "ai_reporting_context": ai_reporting_context,
        "treatment_plan": treatment_plan,
        "notes": {
            "global_replacement": {"SEC-AM": "mSEC-AM"},
            "method_sentence": "The audit was carried out using the mSEC-AM (mobile SECurity Audit Method).",
            "prohibitions": [
                "No category-level bullet dumps in narrative.",
                "No long exhaustive lists of IDs.",
                "No time-window subheadings inside Recommendations."
            ],
        }
    }

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"[OK] analysis pack -> {out_path}")


if __name__ == "__main__":
    main()