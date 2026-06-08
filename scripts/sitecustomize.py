#!/usr/bin/env python3
"""Additive VISION360 fingerprint enrichment hook.

Imported automatically by Python only when scripts/ is on sys.path. The hook is
inactive for every script except vision360_generator.py. It enriches only
vision360_fingerprint.json with technical_details and leaves flags, verdicts,
vision360_output.json and Excel audit outputs unchanged.
"""
from __future__ import annotations

import atexit
import copy
import json
import sys
import zipfile
from pathlib import Path
from typing import Any


def _is_enabled() -> bool:
    return Path(sys.argv[0] or "").name.lower() == "vision360_generator.py"


def _arg(name: str, default: str) -> str:
    prefix = name + "="
    args = list(sys.argv[1:])
    for i, value in enumerate(args):
        if value == name and i + 1 < len(args):
            return args[i + 1]
        if value.startswith(prefix):
            return value.split("=", 1)[1]
    return default


def _load_json(path: Path, default: Any) -> Any:
    try:
        if not path.is_file():
            return copy.deepcopy(default)
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return copy.deepcopy(default)


def _load_zip_json(zip_path: Path, member: str, default: Any) -> Any:
    try:
        if not zip_path.is_file():
            return copy.deepcopy(default)
        with zipfile.ZipFile(zip_path, "r") as zf:
            raw = zf.read(member)
        for enc in ("utf-8", "cp1252", "latin-1"):
            try:
                return json.loads(raw.decode(enc))
            except Exception:
                pass
    except Exception:
        pass
    return copy.deepcopy(default)


def _sev(value: Any) -> str:
    value = str(value or "UNKNOWN").strip().upper()
    return value if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} else "UNKNOWN"


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value) if value is not None else default
    except Exception:
        return default


def _counter(items: list[dict[str, Any]]) -> dict[str, int]:
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for item in items:
        out[_sev(item.get("severity"))] += 1
    return out


def _best_cvss(raw: Any) -> dict[str, Any]:
    best = {"source": None, "v3_score": None, "v3_vector": None}
    best_score = -1.0
    if not isinstance(raw, dict):
        return best
    for source, value in raw.items():
        if not isinstance(value, dict):
            continue
        try:
            score = float(value.get("V3Score") or 0)
        except Exception:
            score = 0.0
        if score > best_score:
            best_score = score
            best = {"source": str(source), "v3_score": score, "v3_vector": value.get("V3Vector")}
    return best


def _norm_trace_finding(item: dict[str, Any]) -> dict[str, Any]:
    vuln_id = item.get("id") or item.get("VulnerabilityID")
    fixed = item.get("fixed") or item.get("FixedVersion")
    return {
        "cve": vuln_id,
        "vulnerability_id": vuln_id,
        "type": "dependency_vulnerability",
        "component": item.get("pkg") or item.get("PkgName"),
        "package_id": item.get("pkg_id") or item.get("PkgID"),
        "installed_version": item.get("installed") or item.get("InstalledVersion"),
        "fixed_version": fixed,
        "fix_available": bool(item.get("fix_available") or fixed),
        "severity": _sev(item.get("severity") or item.get("Severity")),
        "severity_source": item.get("severity_source") or item.get("SeveritySource"),
        "status": item.get("status") or item.get("Status"),
        "cwe_ids": item.get("cwe") or item.get("CweIDs") or item.get("CWEIDs") or [],
        "title": item.get("title") or item.get("Title"),
        "description": item.get("description") or item.get("Description"),
        "primary_url": item.get("primary_url") or item.get("PrimaryURL"),
        "references": item.get("references") or item.get("References") or [],
        "published_at": item.get("published") or item.get("PublishedDate"),
        "last_modified_at": item.get("modified") or item.get("LastModifiedDate"),
        "target": item.get("target") or item.get("Target"),
        "source": "TRIVY",
        "artifact_source": "vision360_trace.json:effective_features.sca.findings",
    }


def _norm_trivy_vuln(result: dict[str, Any], vuln: dict[str, Any]) -> dict[str, Any]:
    fixed = vuln.get("FixedVersion")
    return {
        "cve": vuln.get("VulnerabilityID"),
        "vulnerability_id": vuln.get("VulnerabilityID"),
        "type": "dependency_vulnerability",
        "component": vuln.get("PkgName"),
        "package_id": vuln.get("PkgID"),
        "installed_version": vuln.get("InstalledVersion"),
        "fixed_version": fixed,
        "fix_available": bool(fixed),
        "severity": _sev(vuln.get("Severity")),
        "severity_source": vuln.get("SeveritySource"),
        "status": vuln.get("Status"),
        "cwe_ids": vuln.get("CweIDs") or vuln.get("CWEIDs") or [],
        "title": vuln.get("Title"),
        "description": vuln.get("Description"),
        "primary_url": vuln.get("PrimaryURL"),
        "references": vuln.get("References") or [],
        "published_at": vuln.get("PublishedDate"),
        "last_modified_at": vuln.get("LastModifiedDate"),
        "target": result.get("Target"),
        "class": result.get("Class"),
        "scanner_type": result.get("Type"),
        "best_cvss": _best_cvss(vuln.get("CVSS") or {}),
        "data_source": vuln.get("DataSource") or {},
        "source": "TRIVY",
        "artifact_source": "trivy.json:Results[].Vulnerabilities[]",
    }


def _trivy_vulns(input_dir: Path) -> list[dict[str, Any]]:
    data = _load_zip_json(input_dir / "trivy-payload.zip", "trivy.json", {})
    out: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return out
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for vuln in result.get("Vulnerabilities") or []:
            if isinstance(vuln, dict):
                out.append(_norm_trivy_vuln(result, vuln))
    return out


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for item in items:
        key = (
            str(item.get("vulnerability_id") or ""),
            str(item.get("component") or ""),
            str(item.get("installed_version") or ""),
            str(item.get("target") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _sca_details(trace: dict[str, Any], input_dir: Path) -> dict[str, Any]:
    features = trace.get("effective_features") if isinstance(trace, dict) else {}
    sca = (features or {}).get("sca") if isinstance(features, dict) else {}
    sca = sca if isinstance(sca, dict) else {}
    findings = sca.get("findings") if isinstance(sca.get("findings"), list) else []
    vulns = [_norm_trace_finding(x) for x in findings if isinstance(x, dict)] + _trivy_vulns(input_dir)
    vulns = _dedupe(vulns)
    fixable = [x for x in vulns if x.get("fix_available")]
    unfixed = [x for x in vulns if not x.get("fix_available")]
    packages = sca.get("packages") if isinstance(sca.get("packages"), list) else []
    licenses = sca.get("licenses") if isinstance(sca.get("licenses"), list) else []
    return {
        "source": "TRIVY",
        "artifact_sources": ["trivy-payload.zip/trivy.json", "trivy-payload.zip/agent_payload.json", "vision360_trace.json:effective_features.sca"],
        "summary": {
            "total_vulnerabilities": _to_int(sca.get("total_vulnerabilities"), len(vulns)),
            "by_severity": sca.get("by_severity") if isinstance(sca.get("by_severity"), dict) else _counter(vulns),
            "fixable_total": _to_int(sca.get("fixable_total"), len(fixable)),
            "fixable_by_severity": sca.get("fixable_by_severity") if isinstance(sca.get("fixable_by_severity"), dict) else _counter(fixable),
            "unfixed_total": _to_int(sca.get("unfixed_total"), len(unfixed)),
            "packages_detected": _to_int(sca.get("packages_detected"), len(packages)),
            "license_entries_detected": _to_int(sca.get("license_entries_detected"), len(licenses)),
        },
        "vulnerabilities": vulns,
        "packages": packages[:100],
        "licenses": licenses[:100],
    }


def _enrich() -> None:
    try:
        output_dir = Path(_arg("--output-dir", "/mnt/data")).resolve()
        input_dir = Path(_arg("--input-dir", "/mnt/data")).resolve()
        fp_path = output_dir / "vision360_fingerprint.json"
        trace_path = output_dir / "vision360_trace.json"
        fp = _load_json(fp_path, {})
        trace = _load_json(trace_path, {})
        if not isinstance(fp, dict) or not fp:
            return
        if not isinstance(trace, dict):
            trace = {}
        project = fp.get("project") if isinstance(fp.get("project"), dict) else {}
        details = fp.get("technical_details") if isinstance(fp.get("technical_details"), dict) else {}
        details.update({
            "schema_version": 1,
            "enrichment_mode": "additive_non_breaking",
            "execution": {
                "generated_at": project.get("generated_at") or trace.get("generated_at"),
                "source_manifest_path": trace.get("source_manifest_path"),
                "source_zip_name": trace.get("source_zip_name"),
                "source_label": trace.get("source_label"),
                "declared_sources": project.get("sources") or [],
            },
            "sca": _sca_details(trace, input_dir),
        })
        fp["technical_details"] = details
        fp_path.write_text(json.dumps(fp, indent=2, ensure_ascii=False), encoding="utf-8")
        print("[VISION360] fingerprint technical_details enrichment applied.")
    except Exception as exc:
        print(f"[VISION360] fingerprint technical_details enrichment skipped: {exc}")


if _is_enabled():
    atexit.register(_enrich)
