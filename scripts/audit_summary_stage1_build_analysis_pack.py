#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    candidates.append(os.path.join(repo_root, "parameters", "config.json"))
    candidates.append(os.path.join(os.getcwd(), "parameters", "config.json"))
    candidates.append(str(_runtime_data_dir() / "config.json"))

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
        raise SystemExit("[ERROR] config.json not found. Tried: " + " | ".join(tried_paths))

    try:
        with open(existing, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        raise SystemExit(f"[ERROR] Failed to read config.json at {existing}: {e}")

    if not isinstance(cfg, dict):
        raise SystemExit(f"[ERROR] Invalid config.json at {existing}: top-level JSON must be an object.")

    app_metadata = cfg.get("app_metadata")
    actors = cfg.get("actors")

    if not isinstance(app_metadata, dict):
        raise SystemExit(f"[ERROR] Invalid config.json at {existing}: key 'app_metadata' must be an object.")

    if not isinstance(actors, dict):
        raise SystemExit(f"[ERROR] Invalid config.json at {existing}: key 'actors' must be an object.")

    if "Engineering Group (EN)" not in actors:
        raise SystemExit(f"[ERROR] Invalid config.json at {existing}: missing actors['Engineering Group (EN)'].")

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


def _excerpt(s: Any, limit: int = 180) -> str:
    t = re.sub(r"\s+", " ", str(s or "")).strip()
    if not t or t.lower() == "nan":
        return ""
    return (t[:limit] + "…") if len(t) > limit else t


def _to_declarative(desc: str) -> str:
    t = re.sub(r"\s+", " ", str(desc or "")).strip()
    # Remove leading numbering
    t = re.sub(r"^\d+[\.\)]\s*", "", t)
    # Remove example parentheses if any
    t = re.sub(r"\(e\.g\.,.*?\)", "", t, flags=re.IGNORECASE)
    # Remove must/shall/should wording
    t = re.sub(r"\b(must|shall|should)\b", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\s+", " ", t).strip()

    if not t.lower().startswith("the application"):
        if t:
            t = "The application " + t[0].lower() + t[1:]
        else:
            t = "The application implements security controls."

    # Basic grammar smoothing
    t = t.replace(" and prevent ", " and prevents ")
    t = t.replace(" as well as disallow the ", " as well as disallowing the ")
    t = t.strip().rstrip(".") + "."
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
        return int(value)
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
    if len(text) > limit:
        return text[:limit] + "..."
    return text


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
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text:
            continue
        if any(rx.search(text) for rx in regexes):
            item = text
            if item not in seen:
                seen.add(item)
                out.append(item)
            if len(out) >= limit:
                break
    return out


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
    for flag in flags:
        if not isinstance(flag, dict):
            continue
        verdict = flag.get("app_verdict") or {}
        state = str(verdict.get("state") or "unknown").lower()
        group = str(flag.get("group") or "UNKNOWN")
        state_counts[state] = state_counts.get(state, 0) + 1
        group_counts[group] = group_counts.get(group, 0) + 1

    effective_features = trace.get("effective_features") if isinstance(trace, dict) else {}
    if not isinstance(effective_features, dict):
        effective_features = {}

    return {
        "available": bool(fingerprint or output or trace or effective),
        "source_dir": str(vision360_dir),
        "files": {k: str(v) for k, v in files.items() if v},
        "project": (fingerprint.get("project") if isinstance(fingerprint, dict) else {}) or (output.get("project") if isinstance(output, dict) else {}),
        "flags_count": len(flags),
        "state_counts": state_counts,
        "group_counts": group_counts,
        "feature_keys": sorted(effective_features.keys()),
        "has_sca_trace": bool(effective_features.get("sca")),
        "loaded_files": trace.get("loaded_files") if isinstance(trace, dict) else {},
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
    elif "detected_trackers" in mobsf if isinstance(mobsf, dict) else False:
        detected_trackers = _safe_int(mobsf.get("detected_trackers"), 0)

    app_info = {}
    if isinstance(mobsf, dict):
        for key in ["app_name", "file_name", "package_name", "version_name", "version_code", "min_sdk", "target_sdk", "max_sdk"]:
            if key in mobsf:
                app_info[key] = mobsf.get(key)

    flags = {
        "debuggable_detected": bool(re.search(r"debuggable.{0,80}(true|high|app is debuggable)", flat, re.IGNORECASE)),
        "allow_backup_detected": bool(re.search(r"allowbackup.{0,80}(true|enabled|backup)", flat, re.IGNORECASE)),
        "debug_certificate_detected": ("debug certificate" in flat or "cn=android debug" in flat),
        "v1_signature_or_janus_detected": ("janus" in flat or "v1 signature" in flat or "v1 signature scheme" in flat),
        "sha1_certificate_detected": ("sha1withrsa" in flat or " sha1 " in flat or "hash algorithm: sha1" in flat),
        "cleartext_detected": ("cleartext" in flat and ("true" in flat or "enabled" in flat or "traffic" in flat)),
        "exported_components_detected": ("exported" in flat and ("activity" in flat or "service" in flat or "receiver" in flat)),
        "vulnerable_min_sdk_signal": bool(re.search(r"min[^a-z0-9_]?sdk.{0,40}(19|android 4\.4|vulnerable)", flat, re.IGNORECASE)),
    }

    return {
        "available": bool(mobsf),
        "source_dir": str(mobsf_dir),
        "files": {k: str(v) for k, v in files.items() if v},
        "app_info": app_info,
        "flags": flags,
        "dangerous_permissions": dangerous_permissions,
        "permissions_count": len(permissions),
        "permissions_sample": permissions[:25],
        "manifest_findings_count": len(manifest_findings),
        "manifest_findings_sample": manifest_findings[:20],
        "certificate_findings_count": len(cert_findings),
        "certificate_findings_sample": cert_findings[:15],
        "certificate_info_excerpt": _excerpt(cert_info, 400),
        "detected_trackers": detected_trackers,
    }


def _summarize_mobsf_dynamic(dynamic_dir: Path, files: Dict[str, Optional[Path]]) -> Dict[str, Any]:
    dyn = _safe_read_json(files.get("mobsf_dynamic_results") or Path(), {})
    storage_patterns = [
        r"/data/data/",
        r"shared[_-]?prefs",
        r"sharedpreferences",
        r"\.db(\b|$|-)",
        r"\.sqlite(\b|$)",
        r"\.xml(\b|$)",
        r"openmrs",
        r"chucker",
    ]
    artifacts = _collect_strings_matching(dyn, storage_patterns, limit=200)
    shared_prefs = [x for x in artifacts if re.search(r"shared[_-]?prefs|sharedpreferences|pref.*\.xml|preferences.*\.xml", x, re.IGNORECASE)]
    sqlite = [x for x in artifacts if re.search(r"\.db(\b|$|-)|\.sqlite(\b|$)", x, re.IGNORECASE)]

    flat = _flatten_text(dyn, limit=500000)
    trackers = 0
    m = re.search(r'"detected_trackers"\s*:\s*(\d+)', flat)
    if m:
        trackers = _safe_int(m.group(1), 0)

    return {
        "available": bool(dyn),
        "source_dir": str(dynamic_dir),
        "files": {k: str(v) for k, v in files.items() if v},
        "local_storage_artifacts_count": len(artifacts),
        "local_storage_artifacts_sample": _unique_keep_order(artifacts, limit=40),
        "shared_preferences_artifacts": _unique_keep_order(shared_prefs, limit=30),
        "sqlite_database_artifacts": _unique_keep_order(sqlite, limit=30),
        "detected_trackers": trackers,
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


def _is_excluded_sast_path(path: str) -> bool:
    low = _lower_path(path)
    excluded_prefixes = (
        ".github/",
        "scripts/",
        "requirements/",
        "parameters/",
        "tools/",
        "report/",
        "build/",
        ".gradle/",
        "gradle/",
    )
    if low.startswith(excluded_prefixes):
        return True
    excluded_tokens = (
        "/.github/",
        "/scripts/",
        "/requirements/",
        "/parameters/",
        "/tools/",
        "/report/",
        "/build/",
        "/.gradle/",
    )
    return any(tok in low for tok in excluded_tokens)


def _is_app_code_sast_path(path: str) -> bool:
    low = _lower_path(path)
    if _is_excluded_sast_path(low):
        return False

    if low.startswith("openmrs-client/") or low.startswith("openmrs-android-sdk/"):
        if "/src/test/" in low or "/src/androidtest/" in low:
            return False
        return low.endswith((".java", ".kt", ".xml", ".gradle", ".gradle.kts")) or "androidmanifest.xml" in low

    if "/src/main/" in low and low.endswith((".java", ".kt", ".xml")):
        return True

    if low.endswith("androidmanifest.xml") and not _is_excluded_sast_path(low):
        return True

    return False


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
    selected: List[Tuple[str, Path]] = []
    if files.get("merged_sarif"):
        selected = [("merged", files["merged_sarif"])]  # type: ignore[index]
    else:
        for key in ("semgrep_sarif", "detekt_sarif"):
            if files.get(key):
                selected.append((key, files[key]))  # type: ignore[arg-type]

    raw_results = 0
    app_results: List[Dict[str, Any]] = []
    excluded_results = 0
    notifications: List[Dict[str, Any]] = []
    dedupe = set()

    for label, path in selected:
        sarif = _safe_read_json(path, {})
        for run in _sarif_runs(sarif):
            tool = _sarif_tool_name(run)
            rules = _sarif_rule_map(run)
            notifications.extend(_sarif_notifications(run, tool, limit=50))

            results = run.get("results") or []
            if not isinstance(results, list):
                continue

            for result in results:
                if not isinstance(result, dict):
                    continue
                raw_results += 1
                uri, line = _sarif_location(result)
                if not _is_app_code_sast_path(uri):
                    excluded_results += 1
                    continue

                rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "unknown")
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
                    "tags": props.get("tags") if isinstance(props.get("tags"), list) else [],
                })

    by_tool: Dict[str, int] = {}
    by_rule: Dict[str, int] = {}
    for item in app_results:
        tool = str(item.get("tool") or "unknown")
        rule = str(item.get("rule_id") or "unknown")
        by_tool[tool] = by_tool.get(tool, 0) + 1
        by_rule[rule] = by_rule.get(rule, 0) + 1

    def is_security(item: Dict[str, Any]) -> bool:
        tool = str(item.get("tool") or "").lower()
        rule = str(item.get("rule_id") or "").lower()
        tags = " ".join(str(t).lower() for t in item.get("tags") or [])
        if "codeql" in tool or "semgrep" in tool:
            return True
        return any(tok in rule or tok in tags for tok in ["security", "vulnerab", "android", "injection", "storage", "exported", "backup"])

    security_findings = [x for x in app_results if is_security(x)]
    hardening_signals = [x for x in app_results if x not in security_findings]

    top_rules = [
        {"rule_id": rule, "count": count}
        for rule, count in sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:20]
    ]

    return {
        "available": bool(selected),
        "source_dir": str(sast_dir),
        "files": {k: str(v) for k, v in files.items() if v},
        "selected_sarif_files": [str(p) for _, p in selected],
        "scope_filter": {
            "included": ["openmrs-client/**", "openmrs-android-sdk/**", "**/src/main/**", "**/AndroidManifest.xml", "**/*.java", "**/*.kt"],
            "excluded": [".github/**", "scripts/**", "requirements/**", "parameters/**", "tools/**", "report/**"],
            "note": "SAST evidence is filtered to application and application SDK code. Workflow and audit tooling findings are excluded from the application audit scope.",
        },
        "summary": {
            "raw_results_in_selected_sarif": raw_results,
            "app_code_results": len(app_results),
            "excluded_non_app_results": excluded_results,
            "security_relevant_app_findings": len(security_findings),
            "hardening_or_maintainability_signals": len(hardening_signals),
            "by_tool": by_tool,
            "top_rules": top_rules,
        },
        "security_findings_sample": security_findings[:40],
        "hardening_signals_sample": hardening_signals[:30],
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
        "vision360_output": _find_file(vision_dirs, ["vision360_output.json"]),
        "vision360_trace": _find_file(vision_dirs, ["vision360_trace.json"]),
        "vision360_effective_config": _find_file(vision_dirs, ["vision360_effective_config.json"]),
    }
    trivy_files = {
        "agent_payload": _find_file(trivy_dirs, ["agent_payload.json"]),
        "trivy_json": _find_file(trivy_dirs, ["trivy.json"]),
        "trivy_sarif": _find_file(trivy_dirs, ["trivy.sarif"]),
    }
    mobsf_files = {
        "mobsf_results": _find_file(mobsf_dirs, ["mobsf_results.json"]),
    }
    dyn_files = {
        "mobsf_dynamic_results": _find_file(dyn_dirs, ["mobsf_dynamic_results.json"]),
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

    technical["coverage_limitations"] = {
        "missing_inputs": [
            key
            for key, section in [
                ("vision360", technical["vision360"]),
                ("trivy_sca", technical["trivy_sca"]),
                ("mobsf_static", technical["mobsf_static"]),
                ("mobsf_dynamic", technical["mobsf_dynamic"]),
                ("sast_app_code", technical["sast_app_code"]),
            ]
            if not section.get("available")
        ],
        "sast_notifications_sample": technical["sast_app_code"].get("coverage_notifications_sample", []),
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
