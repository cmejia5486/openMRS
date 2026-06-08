#!/usr/bin/env python3
"""Guarded runtime hook for additive VISION360 fingerprint enrichment.

This module is imported automatically by Python when scripts/ is on sys.path.
It registers an atexit hook only for scripts/vision360_generator.py. The hook
adds technical_details to /mnt/data/vision360_fingerprint.json after the
standard generator writes its outputs. It does not alter flags, verdicts,
vision360_output.json, or the Excel audit path.
"""
from __future__ import annotations

import atexit
import copy
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List


def _is_vision360_generator_invocation() -> bool:
    argv0 = Path(sys.argv[0] or "").name.lower()
    return argv0 == "vision360_generator.py"


def _arg_value(name: str, default: str) -> str:
    prefix = f"{name}="
    args = list(sys.argv[1:])
    for idx, value in enumerate(args):
        if value == name and idx + 1 < len(args):
            return args[idx + 1]
        if value.startswith(prefix):
            return value.split("=", 1)[1]
    return default


def _read_json(path: Path, default: Any) -> Any:
    try:
        if not path.is_file():
            return copy.deepcopy(default)
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return copy.deepcopy(default)


def _read_json_from_zip(zip_path: Path, member: str, default: Any) -> Any:
    try:
        if not zip_path.is_file():
            return copy.deepcopy(default)
        with zipfile.ZipFile(zip_path, "r") as zf:
            raw = zf.read(member)
        for encoding in ("utf-8", "cp1252", "latin-1"):
            try:
                return json.loads(raw.decode(encoding))
            except Exception:
                continue
    except Exception:
        pass
    return copy.deepcopy(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _normalize_severity(value: Any) -> str:
    severity = str(value or "UNKNOWN").strip().upper()
    return severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} else "UNKNOWN"


def _best_cvss(cvss_raw: Any) -> Dict[str, Any]:
    best: Dict[str, Any] = {"source": None, "v3_score": None, "v3_vector": None}
    if not isinstance(cvss_raw, dict):
        return best
    best_score = -1.0
    for source, value in cvss_raw.items():
        if not isinstance(value, dict):
            continue
        score = value.get("V3Score")
        try:
            score_num = float(score or 0)
        except Exception:
            score_num = 0.0
        if score_num > best_score:
            best_score = score_num
            best = {
                "source": str(source),
                "v3_score": score_num if score is not None else None,
                "v3_vector": value.get("V3Vector"),
            }
    return best


def _normalize_vulnerability_from_trace(finding: Dict[str, Any]) -> Dict[str, Any]:
    vuln_id = finding.get("id") or finding.get("VulnerabilityID")
    fixed = finding.get("fixed") or finding.get("FixedVersion")
    return {
        "cve": vuln_id,
        "vulnerability_id": vuln_id,
        "type": "dependency_vulnerability",
        "component": finding.get("pkg") or finding.get("PkgName"),
        "package_id": finding.get("pkg_id") or finding.get("PkgID"),
        "installed_version": finding.get("installed") or finding.get("InstalledVersion"),
        "fixed_version": fixed,
        "fix_available": bool(finding.get("fix_available") or fixed),
        "severity": _normalize_severity(finding.get("severity") or finding.get("Severity")),
        "severity_source": finding.get("severity_source") or finding.get("SeveritySource"),
        "status": finding.get("status") or finding.get("Status"),
        "cwe_ids": finding.get("cwe") or finding.get("CweIDs") or finding.get("CWEIDs") or [],
        "title": finding.get("title") or finding.get("Title"),
        "description": finding.get("description") or finding.get("Description"),
        "primary_url": finding.get("primary_url") or finding.get("PrimaryURL"),
        "references": finding.get("references") or finding.get("References") or [],
        "published_at": finding.get("published") or finding.get("PublishedDate"),
        "last_modified_at": finding.get("modified") or finding.get("LastModifiedDate"),
        "target": finding.get("target") or finding.get("Target"),
        "artifact_source": "vision360_trace.json:effective_features.sca.findings",
        "source": "TRIVY",
    }


def _normalize_vulnerability_from_trivy(result: Dict[str, Any], vuln: Dict[str, Any]) -> Dict[str, Any]:
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
        "severity": _normalize_severity(vuln.get("Severity")),
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
        "artifact_source": "trivy.json:Results[].Vulnerabilities[]",
        "source": "TRIVY",
    }


def _dedupe_vulnerabilities(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
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


def _severity_counter(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for item in vulnerabilities:
        out[_normalize_severity(item.get("severity"))] += 1
    return out


def _extract_vulnerabilities_from_trivy_zip(input_dir: Path) -> List[Dict[str, Any]]:
    trivy_zip = input_dir / "trivy-payload.zip"
    trivy = _read_json_from_zip(trivy_zip, "trivy.json", {})
    vulnerabilities: List[Dict[str, Any]] = []
    if not isinstance(trivy, dict):
        return vulnerabilities
    results = trivy.get("Results") or []
    if not isinstance(results, list):
        return vulnerabilities
    for result in results:
        if not isinstance(result, dict):
            continue
        raw_vulns = result.get("Vulnerabilities") or []
        if not isinstance(raw_vulns, list):
            continue
        for vuln in raw_vulns:
            if isinstance(vuln, dict):
                vulnerabilities.append(_normalize_vulnerability_from_trivy(result, vuln))
    return vulnerabilities


def _build_sca_details(trace: Dict[str, Any], input_dir: Path) -> Dict[str, Any]:
    features = trace.get("effective_features") if isinstance(trace, dict) else {}
    sca = (features or {}).get("sca") if isinstance(features, dict) else {}
    if not isinstance(sca, dict):
        sca = {}

    vulnerabilities: List[Dict[str, Any]] = []
    trace_findings = sca.get("findings") or []
    if isinstance(trace_findings, list):
        vulnerabilities.extend([
            _normalize_vulnerability_from_trace(item)
            for item in trace_findings
            if isinstance(item, dict)
        ])

    vulnerabilities.extend(_extract_vulnerabilities_from_trivy_zip(input_dir))
    vulnerabilities = _dedupe_vulnerabilities(vulnerabilities)

    by_severity = sca.get("by_severity") if isinstance(sca.get("by_severity"), dict) else _severity_counter(vulnerabilities)
    fixable = [item for item in vulnerabilities if item.get("fix_available")]
    unfixed = [item for item in vulnerabilities if not item.get("fix_available")]
    packages = sca.get("packages") if isinstance(sca.get("packages"), list) else []
    licenses = sca.get("licenses") if isinstance(sca.get("licenses"), list) else []

    return {
        "source": "TRIVY",
        "artifact_sources": [
            "trivy-payload.zip/trivy.json",
            "trivy-payload.zip/agent_payload.json",
            "vision360_trace.json:effective_features.sca",
        ],
        "summary": {
            "total_vulnerabilities": _safe_int(sca.get("total_vulnerabilities"), len(vulnerabilities)),
            "by_severity": by_severity,
            "fixable_total": _safe_int(sca.get("fixable_total"), len(fixable)),
            "fixable_by_severity": sca.get("fixable_by_severity") or _severity_counter(fixable),
            "unfixed_total": _safe_int(sca.get("unfixed_total"), len(unfixed)),
            "packages_detected": _safe_int(sca.get("packages_detected"), len(packages)),
            "license_entries_detected": _safe_int(sca.get("license_entries_detected"), len(licenses)),
        },
        "vulnerabilities": vulnerabilities,
        "packages": packages[:100],
        "licenses": licenses[:100],
    }


def _build_execution_details(trace: Dict[str, Any], fingerprint: Dict[str, Any]) -> Dict[str, Any]:
    project = fingerprint.get("project") if isinstance(fingerprint, dict) else {}
    project = project if isinstance(project, dict) else {}
    return {
        "generated_at": project.get("generated_at") or trace.get("generated_at"),
        "source_manifest_path": trace.get("source_manifest_path"),
        "source_zip_name": trace.get("source_zip_name"),
        "source_label": trace.get("source_label"),
        "declared_sources": project.get("sources") or [],
    }


def _enrich_fingerprint() -> None:
    try:
        output_dir = Path(_arg_value("--output-dir", "/mnt/data")).resolve()
        input_dir = Path(_arg_value("--input-dir", "/mnt/data")).resolve()
        fingerprint_path = output_dir / "vision360_fingerprint.json"
        trace_path = output_dir / "vision360_trace.json"
        bundle_path = output_dir / "vision360_bundle.zip"

        fingerprint = _read_json(fingerprint_path, {})
        trace = _read_json(trace_path, {})
        if not isinstance(fingerprint, dict) or not fingerprint:
            return
        if not isinstance(trace, dict):
            trace = {}

        technical_details = fingerprint.get("technical_details")
        if not isinstance(technical_details, dict):
            technical_details = {}

        technical_details["schema_version"] = 1
        technical_details["enrichment_mode"] = "additive_non_breaking"
        technical_details["execution"] = _build_execution_details(trace, fingerprint)
        technical_details["sca"] = _build_sca_details(trace, input_dir)

        fingerprint["technical_details"] = technical_details
        fingerprint_path.write_text(json.dumps(fingerprint, indent=2, ensure_ascii=False), encoding="utf-8")

        if bundle_path.is_file():
            output_path = output_dir / "vision360_output.json"
            trace_out_path = output_dir / "vision360_trace.json"
            effective_cfg_path = output_dir / "vision360_effective_config.json"
            with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.write(fingerprint_path, arcname="vision360_fingerprint.json")
                if output_path.is_file():
                    zf.write(output_path, arcname="vision360_output.json")
                if trace_out_path.is_file():
                    zf.write(trace_out_path, arcname="vision360_trace.json")
                if effective_cfg_path.is_file():
                    zf.write(effective_cfg_path, arcname="vision360_effective_config.json")

        print("[VISION360] fingerprint technical_details enrichment applied.")
    except Exception as exc:
        print(f"[VISION360] fingerprint technical_details enrichment skipped: {exc}")


if _is_vision360_generator_invocation():
    atexit.register(_enrich_fingerprint)
