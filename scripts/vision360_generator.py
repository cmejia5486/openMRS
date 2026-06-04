#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


# ------------------------------------------------------------
# Generic helpers
# ------------------------------------------------------------

def load_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def load_mapping_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    text = load_text_file(path).strip()
    if not text:
        return {}

    # First: JSON. This supports JSON-compatible YAML, which is enough for this repo.
    try:
        obj = json.loads(text)
        if not isinstance(obj, dict):
            raise ValueError(f"Config root must be an object: {path}")
        return obj
    except Exception:
        pass

    # Optional fallback: regular YAML if available.
    try:
        import yaml  # type: ignore
        obj = yaml.safe_load(text) or {}
        if not isinstance(obj, dict):
            raise ValueError(f"Config root must be an object: {path}")
        return obj
    except Exception as exc:
        raise ValueError(
            f"Unable to parse configuration file: {path}. "
            "Use JSON-compatible YAML or install PyYAML."
        ) from exc


def load_json_file(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        out = copy.deepcopy(base)
        for key, value in override.items():
            out[key] = deep_merge(out.get(key), value)
        return out
    if isinstance(base, list) and isinstance(override, list):
        return copy.deepcopy(override)
    return copy.deepcopy(override if override is not None else base)


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").lower()


def excerpt_at(text: str, idx: int, limit: int = 200) -> str:
    if idx < 0:
        idx = 0
    start = text.rfind("\n", 0, idx)
    end = text.find("\n", idx)
    start = 0 if start == -1 else start + 1
    end = len(text) if end == -1 else end
    out = text[start:end].strip()
    if len(out) > limit:
        out = out[:limit] + "..."
    return out


def ev(source: str, path: str, rule_id: str, excerpt: str) -> Dict[str, str]:
    out = (excerpt or "").strip()
    if len(out) > 200:
        out = out[:200] + "..."
    return {
        "source": source,
        "path": path,
        "rule_id": rule_id,
        "excerpt": out,
    }


def flatten_to_text(obj: Any, max_len: int = 500000) -> str:
    try:
        s = json.dumps(obj, ensure_ascii=False)
    except Exception:
        s = str(obj)
    s = s.lower()
    return s[:max_len]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def resolve_path(path_str: str, repo_root: Path) -> Path:
    p = Path(path_str)
    if p.is_absolute():
        return p
    return (repo_root / p).resolve()


def sort_paths_by_hints(paths: List[str], hints: List[str]) -> List[str]:
    if not hints:
        return sorted(paths)
    hints_low = [h.lower() for h in hints]
    preferred = []
    other = []
    for path in paths:
        norm = normalize_path(path)
        if any(h in norm for h in hints_low):
            preferred.append(path)
        else:
            other.append(path)
    return sorted(preferred) + sorted(other)


# ------------------------------------------------------------
# ZIP readers
# ------------------------------------------------------------

def read_json_from_zip(zip_path: Path, member_name: str) -> Any:
    if not zip_path.exists():
        return {}
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            raw = zf.read(member_name)
    except Exception:
        return {}
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return json.loads(raw.decode(enc))
        except Exception:
            continue
    return {}


def read_text_from_zip_member(zip_path: Path, member_name: str) -> str:
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            raw = zf.read(member_name)
    except Exception:
        return ""
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return ""


def read_all_source_texts(zip_path: Path) -> Dict[str, str]:
    texts: Dict[str, str] = {}
    if not zip_path.exists():
        return texts
    suffixes = (
        ".java", ".kt", ".gradle", ".gradle.kts", ".xml", ".yml", ".yaml", ".md", ".txt", ".pro"
    )
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                low = name.lower()
                if low.endswith(suffixes):
                    txt = read_text_from_zip_member(zip_path, name)
                    if txt:
                        texts[name] = txt
    except Exception:
        return {}
    return texts


# ------------------------------------------------------------
# Configuration and metadata loading
# ------------------------------------------------------------

def default_parameters_dir(repo_root: Path) -> Path:
    return repo_root / "parameters"


def load_effective_config(repo_root: Path, args: argparse.Namespace) -> Tuple[Dict[str, Any], Path, Path, Path | None, Dict[str, Any]]:
    params_dir = default_parameters_dir(repo_root)

    defaults_path = resolve_path(
        args.defaults or os.getenv("VISION360_DEFAULTS", "parameters/vision360.defaults.yml"),
        repo_root,
    )
    groups_path = resolve_path(
        args.groups_file or os.getenv("VISION360_GROUPS_FILE", "parameters/vision360.groups.json"),
        repo_root,
    )

    env_project_cfg = os.getenv("VISION360_PROJECT_PARAMS", "").strip()
    cli_project_cfg = (args.project_config or "").strip()
    default_project_cfg = params_dir / "vision360.project.json"

    if cli_project_cfg:
        project_cfg_path = resolve_path(cli_project_cfg, repo_root)
    elif env_project_cfg:
        project_cfg_path = resolve_path(env_project_cfg, repo_root)
    elif default_project_cfg.exists():
        project_cfg_path = default_project_cfg
    else:
        project_cfg_path = None

    defaults_cfg = load_mapping_file(defaults_path)
    project_cfg = load_mapping_file(project_cfg_path) if project_cfg_path else {}
    effective_cfg = deep_merge(defaults_cfg, project_cfg)

    app_metadata = load_json_file(params_dir / "config.json", default={})
    return effective_cfg, defaults_path, groups_path, project_cfg_path, app_metadata


# ------------------------------------------------------------
# Manifest selection
# ------------------------------------------------------------

def choose_source_manifest(texts: Dict[str, str], scoring_cfg: Dict[str, Any]) -> Tuple[str, str]:
    candidates = [p for p in texts if normalize_path(p).endswith("androidmanifest.xml")]
    if not candidates:
        return "", ""

    application_weight = int(scoring_cfg.get("application_weight", 1000))
    service_weight = int(scoring_cfg.get("service_weight", 50))
    activity_weight = int(scoring_cfg.get("activity_weight", 20))
    path_bonus_tokens = scoring_cfg.get("path_bonus_tokens", []) or []

    scored: List[Tuple[int, int, str, str]] = []
    for path in candidates:
        txt = texts.get(path, "")
        low = txt.lower()
        norm = normalize_path(path)
        score = 0
        if "<application" in low:
            score += application_weight
        score += low.count("<service") * service_weight
        score += low.count("<activity") * activity_weight
        for item in path_bonus_tokens:
            if not isinstance(item, dict):
                continue
            token = str(item.get("token", "")).lower()
            weight = int(item.get("weight", 0))
            if token and token in norm:
                score += weight
        scored.append((-score, len(norm), norm, path))

    scored.sort()
    best = scored[0][3]
    return best, texts.get(best, "")


# ------------------------------------------------------------
# Input loading
# ------------------------------------------------------------

def load_inputs(input_dir: Path, cfg: Dict[str, Any]) -> Dict[str, Any]:
    inputs_cfg = cfg.get("inputs", {}) or {}
    source_label = str(cfg.get("source_label", "SOURCE_CODE_REPOSITORY"))

    mobsf_static_zip = input_dir / str(inputs_cfg.get("mobsf_static_zip", "mobsf-report.zip"))
    mobsf_dynamic_zip = input_dir / str(inputs_cfg.get("mobsf_dynamic_zip", "mobsf-dynamic-report.zip"))
    source_zip = input_dir / str(inputs_cfg.get("source_zip", "openMRS.zip"))
    sast_zip = input_dir / str(inputs_cfg.get("sast_zip", "sast-findings.zip"))
    trivy_zip = input_dir / str(inputs_cfg.get("trivy_zip", "trivy-payload.zip"))

    data = {
        "mobsf_static": read_json_from_zip(mobsf_static_zip, "mobsf_results.json") or {},
        "mobsf_dynamic": read_json_from_zip(mobsf_dynamic_zip, "mobsf_dynamic_results.json") or {},
        "sast_merged": read_json_from_zip(sast_zip, "merged.sarif") or {},
        "sast_semgrep": read_json_from_zip(sast_zip, "semgrep.sarif") or {},
        "trivy": read_json_from_zip(trivy_zip, "trivy.json") or {},
        "agent_payload": read_json_from_zip(trivy_zip, "agent_payload.json") or {},
        "source_texts": read_all_source_texts(source_zip),
        "source_zip_name": source_zip.name,
        "source_label": source_label,
    }

    manifest_path, manifest_text = choose_source_manifest(
        data["source_texts"],
        cfg.get("manifest_scoring", {}) or {},
    )
    data["source_manifest_path"] = manifest_path
    data["source_manifest_text"] = manifest_text
    data["source_manifest_lower"] = manifest_text.lower() if manifest_text else ""
    data["combined_code"] = "\n".join(data["source_texts"].values())
    data["code_lower"] = data["combined_code"].lower()
    return data


# ------------------------------------------------------------
# Detectors
# ------------------------------------------------------------

def detect_os_time_source(texts: Dict[str, str], cfg: Dict[str, Any], source_zip_name: str, source_label: str) -> Dict[str, Any]:
    evidence = []
    paths_hit = set()

    preferred = cfg.get("preferred_evidence", []) or []
    for rule in preferred:
        if not isinstance(rule, dict):
            continue
        suffixes = rule.get("path_suffixes") or []
        suffix = str(rule.get("path_suffix", "")).strip()
        if suffix:
            suffixes = list(suffixes) + [suffix]
        regex = str(rule.get("regex", ""))
        rule_id = str(rule.get("rule_id", "preferred_time_source"))
        note = str(rule.get("note", "preferred time source evidence"))
        if not suffixes or not regex:
            continue
        suffixes_norm = [s.lower() for s in suffixes]
        for path, text in texts.items():
            if not any(normalize_path(path).endswith(sfx) for sfx in suffixes_norm):
                continue
            m = re.search(regex, text, flags=re.IGNORECASE)
            if m:
                evidence.append(ev(source_label, f"{source_zip_name}:{path}", rule_id, excerpt_at(text, m.start()) or note))
                paths_hit.add(path)
                break

    patterns = cfg.get("patterns", []) or []
    for path in sort_paths_by_hints(list(texts.keys()), cfg.get("preferred_path_hints", []) or []):
        text = texts.get(path, "")
        for rule in patterns:
            if not isinstance(rule, dict):
                continue
            regex = str(rule.get("regex", ""))
            rule_id = str(rule.get("rule_id", "time_source"))
            if not regex:
                continue
            m = re.search(regex, text, flags=re.IGNORECASE)
            if m:
                evidence.append(ev(source_label, f"{source_zip_name}:{path}", rule_id, excerpt_at(text, m.start())))
                paths_hit.add(path)
                break
        if len(evidence) >= 8:
            break

    return {
        "has_os_time_source": bool(evidence),
        "paths": sorted(paths_hit),
        "evidence": evidence[:8],
    }


def detect_password_hashing(texts: Dict[str, str], cfg: Dict[str, Any], source_zip_name: str, source_label: str) -> Dict[str, Any]:
    scan_paths = sort_paths_by_hints(list(texts.keys()), cfg.get("preferred_path_hints", []) or [])
    evidence = []
    hit_paths = set()
    kdf_algorithms = set()
    uses_salts = False
    uses_kdf = False

    for path in scan_paths:
        text = texts.get(path, "")
        if not text:
            continue
        for item in cfg.get("kdf_patterns", []) or []:
            if not isinstance(item, dict):
                continue
            regex = str(item.get("regex", ""))
            alg = str(item.get("algorithm", "kdf"))
            m = re.search(regex, text, flags=re.IGNORECASE) if regex else None
            if m:
                uses_kdf = True
                kdf_algorithms.add(alg)
                hit_paths.add(path)
                evidence.append(ev(source_label, f"{source_zip_name}:{path}", f"password_kdf_{alg}", excerpt_at(text, m.start())))
                break
        for item in cfg.get("salt_patterns", []) or []:
            if not isinstance(item, dict):
                continue
            regex = str(item.get("regex", ""))
            alg = str(item.get("algorithm", "salt"))
            m = re.search(regex, text, flags=re.IGNORECASE) if regex else None
            if m:
                uses_salts = True
                hit_paths.add(path)
                evidence.append(ev(source_label, f"{source_zip_name}:{path}", f"password_salt_{alg}", excerpt_at(text, m.start())))
                break
        if len(evidence) >= 8:
            break

    return {
        "has_password_hashing_uses_kdf": uses_kdf,
        "has_password_hashing_uses_salts": uses_salts,
        "kdf_algorithms": sorted(kdf_algorithms),
        "paths": sorted(hit_paths),
        "evidence": evidence[:8],
    }


def is_runtime_code_path(path: str) -> bool:
    norm = normalize_path(path)
    if not norm.endswith((".java", ".kt")):
        return False
    excluded_tokens = [
        "/src/test/",
        "/src/androidtest/",
        "/test/",
        "/tests/",
        "/.github/",
        "parameters/",
        "/build/",
        "/generated/",
        "readme",
    ]
    return not any(tok in norm for tok in excluded_tokens)


def filter_runtime_code_paths(paths: List[str], hints: List[str]) -> List[str]:
    runtime_paths = [p for p in paths if is_runtime_code_path(p)]
    return sort_paths_by_hints(runtime_paths, hints)


def detect_logout_session(texts: Dict[str, str], cfg: Dict[str, Any], source_zip_name: str, source_label: str) -> Dict[str, Any]:
    scan_paths = filter_runtime_code_paths(list(texts.keys()), cfg.get("path_hints", []) or [])
    out = {
        "has_manual_logout": False,
        "has_clears_local_prefs_on_logout": False,
        "has_clears_cookies_on_logout": False,
        "has_session_cookie_based_auth": False,
        "has_logout_invalidates_server_session": False,
        "logout_paths": [],
        "cookie_clear_paths": [],
        "session_cookie_paths": [],
        "logout_endpoint_paths": [],
        "evidence": [],
    }

    for path in scan_paths:
        text = texts.get(path, "")
        for pat in cfg.get("logout_method_patterns", []) or []:
            m = re.search(str(pat), text, flags=re.IGNORECASE)
            if m:
                out["has_manual_logout"] = True
                out["logout_paths"].append(path)
                out["evidence"].append(ev(source_label, f"{source_zip_name}:{path}", "logout_method", excerpt_at(text, m.start())))
                break
        for pat in cfg.get("local_cleanup_patterns", []) or []:
            m = re.search(str(pat), text, flags=re.IGNORECASE)
            if m:
                out["has_clears_local_prefs_on_logout"] = True
                out["logout_paths"].append(path)
                out["evidence"].append(ev(source_label, f"{source_zip_name}:{path}", "logout_local_cleanup", excerpt_at(text, m.start())))
                break
        for pat in cfg.get("cookie_cleanup_patterns", []) or []:
            m = re.search(str(pat), text, flags=re.IGNORECASE)
            if m:
                out["has_clears_cookies_on_logout"] = True
                out["cookie_clear_paths"].append(path)
                out["evidence"].append(ev(source_label, f"{source_zip_name}:{path}", "logout_cookie_cleanup", excerpt_at(text, m.start())))
                break
        for pat in cfg.get("session_cookie_patterns", []) or []:
            m = re.search(str(pat), text, flags=re.IGNORECASE)
            if m:
                out["has_session_cookie_based_auth"] = True
                out["session_cookie_paths"].append(path)
                out["evidence"].append(ev(source_label, f"{source_zip_name}:{path}", "session_cookie_indicator", excerpt_at(text, m.start())))
                break
        for pat in cfg.get("logout_endpoint_patterns", []) or []:
            m = re.search(str(pat), text, flags=re.IGNORECASE)
            if m:
                out["logout_endpoint_paths"].append(path)
                out["evidence"].append(ev(source_label, f"{source_zip_name}:{path}", "logout_endpoint", excerpt_at(text, m.start())))
                break

    for key in ("logout_paths", "cookie_clear_paths", "session_cookie_paths", "logout_endpoint_paths"):
        out[key] = sorted(set(out[key]))
    out["has_logout_invalidates_server_session"] = out["has_manual_logout"] and bool(out["logout_endpoint_paths"])
    out["evidence"] = out["evidence"][:12]
    return out


def detect_endpoint_auth(texts: Dict[str, str], cfg: Dict[str, Any], source_zip_name: str, source_label: str) -> Dict[str, Any]:
    scan_paths = filter_runtime_code_paths(list(texts.keys()), cfg.get("path_hints", []) or [])
    out = {
        "rest_service_builder_paths": [],
        "authorization_header_paths": [],
        "has_basic_auth_header_in_rest_service": False,
        "has_any_authorization_header_usage": False,
        "evidence": [],
    }

    def auth_context_ok(body: str, idx: int) -> bool:
        start = max(0, idx - 120)
        end = min(len(body), idx + 120)
        window = body[start:end].lower()
        strong_tokens = [
            "authorization",
            ".header(",
            "header(",
            "basic ",
            "bearer ",
            "set-cookie",
            "cookie:",
            "cookie ",
            "interceptor",
            "authenticator",
        ]
        weak_false_positives = [
            "basic_menu",
            "menuinflater",
            "basic_menu, menu",
        ]
        if any(tok in window for tok in weak_false_positives):
            return False
        return any(tok in window for tok in strong_tokens)

    for path in scan_paths:
        text = texts.get(path, "")
        for pat in cfg.get("basic_auth_patterns", []) or []:
            m = re.search(str(pat), text, flags=re.IGNORECASE)
            if m and auth_context_ok(text, m.start()):
                out["has_basic_auth_header_in_rest_service"] = True
                out["rest_service_builder_paths"].append(path)
                out["evidence"].append(ev(source_label, f"{source_zip_name}:{path}", "basic_auth_header", excerpt_at(text, m.start())))
                break
        for pat in cfg.get("any_authorization_patterns", []) or []:
            m = re.search(str(pat), text, flags=re.IGNORECASE)
            if m and auth_context_ok(text, m.start()):
                out["has_any_authorization_header_usage"] = True
                out["authorization_header_paths"].append(path)
                out["evidence"].append(ev(source_label, f"{source_zip_name}:{path}", "authorization_usage", excerpt_at(text, m.start())))
                break
    out["rest_service_builder_paths"] = sorted(set(out["rest_service_builder_paths"]))
    out["authorization_header_paths"] = sorted(set(out["authorization_header_paths"]))
    out["evidence"] = out["evidence"][:12]
    return out


def detect_keystore_env_paths(texts: Dict[str, str], cfg: Dict[str, Any]) -> List[str]:
    extensions = [str(x).lower() for x in cfg.get("gradle_file_extensions", [".gradle", ".gradle.kts"]) or []]
    env_vars = [str(x).lower() for x in cfg.get("env_var_names", []) or []]
    hits = []
    for path, text in texts.items():
        norm = normalize_path(path)
        if not any(norm.endswith(ext) for ext in extensions):
            continue
        low = text.lower()
        if "signingconfigs" not in low or "system.getenv" not in low:
            continue
        if env_vars and any(var in low for var in env_vars):
            hits.append(path)
        elif any(tok in low for tok in ["keyalias", "storepassword", "keypassword"]):
            hits.append(path)
    return sorted(set(hits))


def detect_signing_creds_hardcoded(texts: Dict[str, str]) -> bool:
    for path, text in texts.items():
        norm = normalize_path(path)
        if not (norm.endswith(".gradle") or norm.endswith(".gradle.kts")):
            continue
        low = text.lower()
        if "signingconfigs" in low and (
            'storepassword "' in low or "storepassword '" in low or
            'keypassword "' in low or "keypassword '" in low
        ):
            return True
    return False


def detect_release_minify_disabled(texts: Dict[str, str]) -> bool:
    for path, text in texts.items():
        norm = normalize_path(path)
        if not (norm.endswith(".gradle") or norm.endswith(".gradle.kts")):
            continue
        low = text.lower()
        if "buildtypes" in low and "release" in low and "minifyenabled false" in low:
            return True
    return False


def detect_release_minify_enabled(texts: Dict[str, str]) -> Dict[str, Any]:
    paths = []
    for path, text in texts.items():
        norm = normalize_path(path)
        if not (norm.endswith(".gradle") or norm.endswith(".gradle.kts")):
            continue
        low = text.lower()
        if "buildtypes" in low and "release" in low and "minifyenabled true" in low:
            paths.append(path)
    return {
        "has_minify_enabled_release": bool(paths),
        "paths": sorted(set(paths)),
    }


def detect_manifest_attr_true(manifest_text: str, attr_name: str) -> bool:
    if not manifest_text:
        return False
    pat = r'android\s*:\s*' + re.escape(attr_name) + r'\s*=\s*"\s*true\s*"'
    return re.search(pat, manifest_text, flags=re.IGNORECASE) is not None


def detect_manifest_insecure_exports_count(manifest_text: str, manifest_path: str, source_zip_name: str, source_label: str) -> Dict[str, Any]:
    if not manifest_text:
        return {"available": False, "count": 0, "evidence": []}
    evidence = []
    count = 0
    for i, line in enumerate(manifest_text.splitlines(), start=1):
        low = line.lower()
        if 'android:exported="true"' in low and 'permission=' not in low and 'android:permission=' not in low:
            count += 1
            evidence.append(ev(source_label, f"{source_zip_name}:{manifest_path}:line{i}", "android:exported", line.strip()))
    return {"available": True, "count": count, "evidence": evidence[:8]}


def detect_manifest_custom_permissions(manifest_text: str, manifest_path: str, source_zip_name: str, source_label: str) -> Dict[str, Any]:
    if not manifest_text:
        return {"available": False, "count": 0, "evidence": []}
    tags = re.findall(r"<permission\b[^>]*(?:/>|>)", manifest_text, flags=re.IGNORECASE | re.DOTALL)
    evidence = []
    for idx, tag in enumerate(tags[:8]):
        excerpt = re.sub(r"\s+", " ", tag.strip())
        evidence.append(ev(source_label, f"{source_zip_name}:{manifest_path}:permission[{idx}]", "manifest_custom_permission", excerpt))
    return {"available": True, "count": len(tags), "evidence": evidence}


def detect_manifest_signature_level_defined(manifest_text: str, manifest_path: str, source_zip_name: str, source_label: str) -> Dict[str, Any]:
    if not manifest_text:
        return {"available": False, "is_true": False, "evidence": []}
    tags = re.findall(r"<permission\b[^>]*(?:/>|>)", manifest_text, flags=re.IGNORECASE | re.DOTALL)
    evidence = []
    is_true = False
    for idx, tag in enumerate(tags):
        m = re.search(r'android:protectionLevel\s*=\s*"([^"]+)"', tag, flags=re.IGNORECASE)
        if not m:
            continue
        val = m.group(1).strip().lower()
        if "signature" in val:
            is_true = True
            excerpt = re.sub(r"\s+", " ", tag.strip())
            evidence.append(ev(source_label, f"{source_zip_name}:{manifest_path}:permission[{idx}]", "manifest_permission_protectionLevel_signature", f"protectionLevel={val} -> {excerpt}"))
            if len(evidence) >= 8:
                break
    return {"available": True, "is_true": is_true, "evidence": evidence}


def detect_manifest_services_explicit_accessibility(manifest_text: str, manifest_path: str, source_zip_name: str, source_label: str) -> Dict[str, Any]:
    if not manifest_text:
        return {"available": False, "total_services": 0, "missing_exported_count": 0, "evidence": []}
    tags = re.findall(r"<service\b[^>]*>", manifest_text, flags=re.IGNORECASE | re.DOTALL)
    evidence = []
    missing = 0
    for idx, tag in enumerate(tags):
        if "android:exported" not in tag.lower():
            missing += 1
            name_m = re.search(r'android\s*:\s*name\s*=\s*"([^"]+)"', tag, flags=re.IGNORECASE)
            svc_name = name_m.group(1) if name_m else "(unknown_service)"
            excerpt = re.sub(r"\s+", " ", tag.strip())
            evidence.append(ev(source_label, f"{source_zip_name}:{manifest_path}:service[{idx}]", "service_missing_android_exported", f"{svc_name} -> {excerpt}"))
            if len(evidence) >= 8:
                break
    return {
        "available": True,
        "total_services": len(tags),
        "missing_exported_count": missing,
        "evidence": evidence,
    }


def detect_exported_receivers_without_permission(manifest_text: str, manifest_path: str, source_zip_name: str, source_label: str) -> Dict[str, Any]:
    if not manifest_text:
        return {
            "available": False,
            "total_receivers": 0,
            "exported_receivers_count": 0,
            "exported_receivers_without_permission_count": 0,
            "receiver_summaries": [],
            "evidence": [],
        }

    blocks = list(re.finditer(r"<receiver\b[^>]*(?:/>|>.*?</receiver\s*>)", manifest_text, flags=re.IGNORECASE | re.DOTALL))
    summaries = []
    evidence = []
    exported_count = 0
    insecure_count = 0

    def start_tag(block_text: str) -> str:
        if ">" in block_text:
            return block_text.split(">", 1)[0] + ">"
        return block_text

    for idx, match in enumerate(blocks, start=1):
        block = match.group(0)
        tag = start_tag(block)
        name_m = re.search(r'android:name\s*=\s*"([^"]+)"', tag, flags=re.IGNORECASE)
        exported_m = re.search(r'android:exported\s*=\s*"([^"]+)"', tag, flags=re.IGNORECASE)
        perm_m = re.search(r'(android:permission|permission)\s*=\s*"([^"]+)"', tag, flags=re.IGNORECASE)
        has_intent_filter = bool(re.search(r"<intent-filter\b", block, flags=re.IGNORECASE))

        exported_attr = exported_m.group(1).strip().lower() if exported_m else None
        if exported_attr == "true":
            exported_effective = True
        elif exported_attr == "false":
            exported_effective = False
        else:
            exported_effective = has_intent_filter

        if exported_effective:
            exported_count += 1
        insecure = exported_effective and not bool(perm_m)
        if insecure:
            insecure_count += 1
            excerpt = re.sub(r"\s+", " ", tag.strip())
            evidence.append(ev(source_label, f"{source_zip_name}:{manifest_path}:receiver[{idx}]", "exported_broadcast_receiver_without_permission", f"{name_m.group(1) if name_m else '(unnamed)'} -> {excerpt}"))

        summaries.append({
            "index": idx,
            "name": name_m.group(1) if name_m else "",
            "exported_attr": exported_attr,
            "exported_effective": exported_effective,
            "has_intent_filter": has_intent_filter,
            "has_permission": bool(perm_m),
            "permission_value": perm_m.group(2) if perm_m else "",
        })

    if insecure_count == 0 and summaries:
        sample = next((s for s in summaries if s.get("exported_attr") == "false"), None) or summaries[0]
        idx = int(sample["index"])
        block = blocks[idx - 1].group(0)
        excerpt = re.sub(r"\s+", " ", start_tag(block).strip())
        evidence.append(ev(source_label, f"{source_zip_name}:{manifest_path}:receiver[{idx}]", "broadcast_receiver_sample_secure", f"{sample.get('name') or '(unnamed)'} -> {excerpt}"))

    return {
        "available": True,
        "total_receivers": len(blocks),
        "exported_receivers_count": exported_count,
        "exported_receivers_without_permission_count": insecure_count,
        "receiver_summaries": summaries,
        "evidence": evidence[:8],
    }


def analyze_permissions(mobsf_static: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    manifest_analysis = mobsf_static.get("manifest_analysis") or {}
    permissions_table = mobsf_static.get("permissions") or {}
    uses_list = manifest_analysis.get("uses_permission_list") or []
    if not isinstance(permissions_table, dict):
        permissions_table = {}
    if not isinstance(uses_list, list):
        uses_list = []

    requested = set()
    for p in permissions_table.keys():
        if isinstance(p, str):
            requested.add(p)
    for p in uses_list:
        if isinstance(p, str):
            requested.add(p)

    dangerous = []
    signature = []
    privileged = []
    statuses: Dict[str, int] = {}

    for perm in sorted(requested):
        meta = permissions_table.get(perm) or {}
        st = str(meta.get("status", "unknown")).lower().strip() if isinstance(meta, dict) else "unknown"
        statuses[st] = statuses.get(st, 0) + 1
        if st == "dangerous":
            dangerous.append(perm)
        elif st == "signature":
            signature.append(perm)
        elif st == "privileged":
            privileged.append(perm)

    privileged_like = set(privileged) | set(signature)
    for perm, meta in permissions_table.items():
        if not isinstance(meta, dict):
            continue
        st = str(meta.get("status", "")).lower()
        if st in {"signature|privileged", "signatureorsystem", "system"}:
            privileged_like.add(perm)

    special_os_set = set(cfg.get("special_os_permissions", []) or [])
    risky_set = set(cfg.get("risky_permissions", []) or [])

    return {
        "requested_permissions": sorted(requested),
        "status_counts": statuses,
        "dangerous_permissions": sorted(set(dangerous)),
        "signature_permissions": sorted(set(signature)),
        "privileged_permissions": sorted(set(privileged)),
        "privileged_like_permissions": sorted(privileged_like),
        "special_os_permissions_requested": sorted([p for p in requested if p in special_os_set]),
        "risky_permissions_requested": sorted([p for p in requested if p in risky_set]),
        "has_dangerous": bool(dangerous),
        "has_privileged_like": bool(privileged_like),
    }


def extract_mobsf_secrets_hits(mobsf_static: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits = []
    findings = ((mobsf_static.get("code_analysis") or {}).get("findings") or {})
    if isinstance(findings, dict):
        for key, value in findings.items():
            blob = flatten_to_text(value)
            if any(tok in blob for tok in ["hardcoded", "apikey", "api key", "password", "secret", "credential"]):
                hits.append({"source": "MobSF_FINDING", "id": key, "data": value})
    secrets_section = mobsf_static.get("secrets") or {}
    if isinstance(secrets_section, dict):
        for key, value in secrets_section.items():
            blob = flatten_to_text(value)
            if any(tok in blob for tok in ["hardcoded", "apikey", "api key", "password", "secret", "credential"]):
                hits.append({"source": "MobSF_SECRETS_SECTION", "id": key, "data": value})
    return hits



def iter_mobsf_manifest_findings(mobsf_static: Dict[str, Any]) -> List[Dict[str, Any]]:
    manifest_analysis = mobsf_static.get("manifest_analysis") or {}
    raw_findings = manifest_analysis.get("manifest_findings") or []
    out: List[Dict[str, Any]] = []

    if isinstance(raw_findings, list):
        for item in raw_findings:
            if isinstance(item, dict):
                out.append(item)
            else:
                out.append({
                    "rule": "",
                    "title": str(item),
                    "name": str(item),
                    "description": str(item),
                    "component": [],
                })
    elif isinstance(raw_findings, dict):
        for key, value in raw_findings.items():
            if isinstance(value, dict):
                item = dict(value)
                item.setdefault("rule", str(key))
                out.append(item)
            else:
                out.append({
                    "rule": str(key),
                    "title": str(value),
                    "name": str(value),
                    "description": str(value),
                    "component": [],
                })
    return out


def detect_mobsf_manifest_attr_signal(
    mobsf_static: Dict[str, Any],
    source_manifest_text: str,
    source_manifest_path: str,
    source_zip_name: str,
    source_label: str,
    attr_name: str,
    mobsf_rule: str,
    evidence_rule_id: str,
) -> Dict[str, Any]:
    source_true = detect_manifest_attr_true(source_manifest_text, attr_name)
    mobsf_match: Dict[str, Any] | None = None

    for item in iter_mobsf_manifest_findings(mobsf_static):
        rule = str(item.get("rule", "")).strip().lower()
        title = str(item.get("title", "")).lower()
        name = str(item.get("name", "")).lower()
        if rule == mobsf_rule.lower():
            mobsf_match = item
            break
        if attr_name == "debuggable" and ("debug enabled for app" in title or "app_is_debuggable" in name):
            mobsf_match = item
            break
        if attr_name == "allowBackup" and ("application data can be backed up" in title or "allowbackup" in name):
            mobsf_match = item
            break

    mobsf_true = mobsf_match is not None
    evidence: List[Dict[str, str]] = []

    if mobsf_true:
        excerpt = str(
            mobsf_match.get("title")
            or mobsf_match.get("name")
            or mobsf_match.get("description")
            or mobsf_rule
        )
        evidence.append(
            ev(
                "MobSF_STATIC",
                "mobsf_results.json:manifest_analysis.manifest_findings",
                mobsf_rule,
                excerpt,
            )
        )

    if source_true and source_manifest_path:
        evidence.append(
            ev(
                source_label,
                f"{source_zip_name}:{source_manifest_path}",
                evidence_rule_id,
                f'android:{attr_name}="true"',
            )
        )

    return {
        "is_true": bool(source_true or mobsf_true),
        "source_true": bool(source_true),
        "mobsf_true": bool(mobsf_true),
        "mismatch": bool(source_true != mobsf_true),
        "evidence": evidence[:8],
    }


def detect_tls_pinning(mobsf_static: Dict[str, Any]) -> Dict[str, Any]:
    code_analysis = mobsf_static.get("code_analysis") or {}
    findings = code_analysis.get("findings") or {}
    if not isinstance(findings, dict):
        findings = {}

    android_ssl_pinning = findings.get("android_ssl_pinning") or {}
    if not isinstance(android_ssl_pinning, dict):
        android_ssl_pinning = {}

    files_raw = android_ssl_pinning.get("files") or {}
    files: List[str] = []
    if isinstance(files_raw, dict):
        files = sorted(str(p) for p in files_raw.keys())
    elif isinstance(files_raw, list):
        files = sorted(str(p) for p in files_raw)

    metadata = android_ssl_pinning.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    appsec = mobsf_static.get("appsec") or {}
    secure_entries = appsec.get("secure") or [] if isinstance(appsec, dict) else []
    if not isinstance(secure_entries, list):
        secure_entries = []

    secure_matches: List[Dict[str, Any]] = []
    for item in secure_entries:
        if not isinstance(item, dict):
            continue
        blob = " ".join(
            [
                str(item.get("title") or ""),
                str(item.get("description") or ""),
                str(item.get("section") or ""),
            ]
        ).lower()
        if "ssl certificate pinning" in blob or "certificate pinning" in blob or "ssl pinning" in blob:
            secure_matches.append(item)

    evidence: List[Dict[str, str]] = []
    if android_ssl_pinning:
        evidence.append(
            ev(
                "MobSF_STATIC",
                "mobsf_results.json:code_analysis.findings.android_ssl_pinning",
                "android_ssl_pinning",
                f"files={len(files)}",
            )
        )
    if secure_matches:
        first = secure_matches[0]
        excerpt = str(first.get("description") or first.get("title") or "SSL certificate pinning reported")
        evidence.append(
            ev(
                "MobSF_STATIC",
                "mobsf_results.json:appsec.secure",
                "appsec_secure_ssl_pinning",
                excerpt,
            )
        )

    severity = str(metadata.get("severity") or "").strip().lower()

    return {
        "has_android_ssl_pinning_block": bool(android_ssl_pinning),
        "has_secure_ssl_pinning_message": bool(secure_matches),
        "has_pinning": bool(android_ssl_pinning or secure_matches),
        "android_ssl_pinning_files": files,
        "android_ssl_pinning_metadata": metadata,
        "severity_good": severity == "good",
        "evidence": evidence[:8],
    }


def detect_certificate_analysis(mobsf_static: Dict[str, Any]) -> Dict[str, Any]:
    cert_analysis = mobsf_static.get("certificate_analysis") or {}
    if not isinstance(cert_analysis, dict) or not cert_analysis:
        return {"available": False}

    info_text = str(cert_analysis.get("certificate_info") or "")
    findings_raw = cert_analysis.get("certificate_findings") or []

    findings_norm: List[Tuple[str, str, str]] = []
    if isinstance(findings_raw, list):
        for item in findings_raw:
            if isinstance(item, (list, tuple)) and len(item) >= 3:
                findings_norm.append((str(item[0]), str(item[1]), str(item[2])))
            elif isinstance(item, dict):
                findings_norm.append((
                    str(item.get("severity") or item.get("level") or ""),
                    str(item.get("description") or ""),
                    str(item.get("title") or item.get("name") or ""),
                ))
            else:
                findings_norm.append(("", str(item), ""))
    elif isinstance(findings_raw, dict):
        for key, value in findings_raw.items():
            findings_norm.append(("", str(value), str(key)))

    info_low = info_text.lower()
    findings_low = " ".join([" ".join(parts).lower() for parts in findings_norm])

    has_code_sign = ("signed application" in findings_low) or ("code signing certificate" in findings_low)
    has_janus = ("janus" in findings_low) or ("v1 signature scheme" in findings_low) or ("v1 signature: true" in info_low)
    has_debug_cert = (
        ("debug certificate" in findings_low)
        or ("application signed with debug certificate" in findings_low)
        or ("cn=android debug" in info_low)
        or ("x.509 subject: cn=android debug" in info_low)
    )
    has_sha1 = (
        ("sha1withrsa" in info_low)
        or ("hash algorithm: sha1" in info_low)
        or ("sha1withrsa" in findings_low)
        or (" sha1 " in findings_low)
    )
    has_android_debug_subject = (
        ("x.509 subject: cn=android debug" in info_low)
        or ("issuer: cn=android debug" in info_low)
    )

    has_long_term = False
    try:
        m_from = re.search(r"valid from:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", info_low)
        m_to = re.search(r"valid to:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", info_low)
        if m_from and m_to:
            d1 = datetime.fromisoformat(m_from.group(1))
            d2 = datetime.fromisoformat(m_to.group(1))
            has_long_term = (d2 - d1).days >= 3650
        else:
            has_long_term = ("valid to:" in info_low and any(y in info_low for y in ["203", "204", "205"]))
    except Exception:
        has_long_term = ("valid to:" in info_low and any(y in info_low for y in ["203", "204", "205"]))

    return {
        "available": True,
        "info_text": info_text,
        "findings_norm": findings_norm,
        "has_code_sign": has_code_sign,
        "has_janus": has_janus,
        "has_debug_cert": has_debug_cert,
        "has_sha1": has_sha1,
        "has_android_debug_subject": has_android_debug_subject,
        "has_long_term": has_long_term,
    }


def build_certificate_flag_verdict(
    flag_id: str,
    cert_info: Dict[str, Any],
) -> Dict[str, Any]:
    if not cert_info.get("available"):
        return {
            "state": "unknown",
            "summary": f"{flag_id} = UNKNOWN",
            "notes": "certificate_analysis was not found in MobSF; cannot determine.",
            "evidence": [],
        }

    info_text = str(cert_info.get("info_text") or "")
    findings_norm = cert_info.get("findings_norm") or []
    info_low = info_text.lower()

    if flag_id == "has_cert_signed_with_code_signing_cert":
        has_feature = bool(cert_info.get("has_code_sign"))
        state = "pass" if has_feature else "fail"
        match_terms = ["signed application", "code signing certificate"]
    elif flag_id == "has_cert_v1_signature_present_janus_risk":
        has_feature = bool(cert_info.get("has_janus"))
        state = "fail" if has_feature else "pass"
        match_terms = ["janus", "v1 signature scheme", "v1 signature"]
    elif flag_id == "has_cert_signed_with_debug_certificate":
        has_feature = bool(cert_info.get("has_debug_cert"))
        state = "fail" if has_feature else "pass"
        match_terms = ["debug certificate", "android debug", "cn=android debug"]
    elif flag_id == "has_cert_uses_sha1_signature_algorithm":
        has_feature = bool(cert_info.get("has_sha1"))
        state = "fail" if has_feature else "pass"
        match_terms = ["sha1", "sha1withrsa", "hash collision"]
    elif flag_id == "has_cert_x509_subject_android_debug":
        has_feature = bool(cert_info.get("has_android_debug_subject"))
        state = "fail" if has_feature else "pass"
        match_terms = ["x.509 subject", "android debug", "issuer"]
    elif flag_id == "has_cert_validity_long_term":
        has_feature = bool(cert_info.get("has_long_term"))
        state = "fail" if has_feature else "pass"
        match_terms = ["valid from", "valid to"]
    else:
        return {
            "state": "unknown",
            "summary": f"{flag_id} = UNKNOWN",
            "notes": "No certificate rule is implemented for this flag.",
            "evidence": [],
        }

    evidence: List[Dict[str, str]] = [
        ev(
            "MobSF_STATIC",
            "mobsf_results.json:certificate_analysis.certificate_info",
            "certificate_info",
            info_text[:200].replace("\n", " "),
        )
    ]
    if findings_norm:
        evidence.append(
            ev(
                "MobSF_STATIC",
                "mobsf_results.json:certificate_analysis.certificate_findings",
                "certificate_findings_count",
                f"items={len(findings_norm)}",
            )
        )
    for severity, description, title in findings_norm:
        blob = " ".join([severity, description, title]).lower()
        if any(term in blob for term in match_terms):
            excerpt = " | ".join(x for x in [severity, title, description] if x)
            evidence.append(
                ev(
                    "MobSF_STATIC",
                    "mobsf_results.json:certificate_analysis.certificate_findings",
                    "certificate_finding_match",
                    excerpt,
                )
            )
        if len(evidence) >= 5:
            break

    yn = "YES" if has_feature else "NO"
    notes_parts = []
    if flag_id == "has_cert_signed_with_code_signing_cert":
        notes_parts.append("MobSF certificate analysis indicates whether the APK is signed with a code signing certificate.")
    elif flag_id == "has_cert_v1_signature_present_janus_risk":
        notes_parts.append("MobSF certificate analysis indicates whether v1 signature is present, which implies Janus exposure conditions.")
    elif flag_id == "has_cert_signed_with_debug_certificate":
        notes_parts.append("MobSF certificate analysis indicates whether the APK is signed with a debug certificate.")
    elif flag_id == "has_cert_uses_sha1_signature_algorithm":
        notes_parts.append("MobSF certificate analysis indicates whether SHA1 is used in the certificate or hash algorithm details.")
    elif flag_id == "has_cert_x509_subject_android_debug":
        notes_parts.append("MobSF certificate analysis indicates whether the X.509 subject or issuer is Android Debug.")
    elif flag_id == "has_cert_validity_long_term":
        notes_parts.append("MobSF certificate analysis indicates whether certificate validity is long-term (10 years or more).")

    if flag_id == "has_cert_validity_long_term":
        m_from = re.search(r"valid from:\s*([^\n]+)", info_low)
        m_to = re.search(r"valid to:\s*([^\n]+)", info_low)
        if m_from and m_to:
            notes_parts.append(f"validity window: {m_from.group(1).strip()} -> {m_to.group(1).strip()}.")

    return {
        "state": state,
        "summary": f"{flag_id} = {yn}",
        "notes": " ".join(notes_parts),
        "evidence": evidence[:8],
    }


def build_org_text_index(texts: Dict[str, str]) -> Dict[str, str]:
    docs = []
    for path, text in texts.items():
        low = normalize_path(path)
        if low.endswith((".md", ".txt", ".yml", ".yaml")):
            docs.append(text.lower())
    return {"docs": "\n".join(docs)}


def find_org_evidence_for_flag(flag_id: str, org_index: Dict[str, str], cfg: Dict[str, Any]) -> Tuple[bool, List[str], List[Dict[str, str]]]:
    patterns_cfg = (cfg.get("org_flag_patterns") or {}).get(flag_id) or []
    docs = org_index.get("docs", "")
    sources = []
    evidence = []

    for item in patterns_cfg:
        pattern = str(item)
        pos = docs.find(pattern.lower())
        if pos != -1:
            sources.append("docs")
            evidence.append(ev("ORG_INDEX", "ORG_INDEX:docs", "org_policy_reference", excerpt_at(docs, pos)))
            break

    return bool(sources), sorted(set(sources)), evidence[:4]



# ------------------------------------------------------------
# Software Composition Analysis (Trivy / agent_payload)
# ------------------------------------------------------------

SCA_SECURITY_SENSITIVE_PACKAGE_TOKENS = [
    "retrofit",
    "okhttp",
    "gson",
    "guava",
    "kotlin",
    "jackson",
    "bouncycastle",
    "bcprov",
    "conscrypt",
    "grpc",
    "netty",
    "protobuf",
    "commons-codec",
    "commons-io",
    "xml",
    "kxml",
    "jwt",
    "oauth",
    "security",
    "crypto",
]

SCA_RESTRICTIVE_LICENSE_TOKENS = [
    "agpl",
    "gpl",
    "lgpl",
    "sspl",
    "cpal",
    "epl",
    "mpl",
    "cecill",
]

SCA_UNKNOWN_LICENSE_TOKENS = [
    "unknown",
    "noassertion",
    "none",
    "unclassified",
    "not detected",
    "not_found",
    "not found",
]


def _sca_safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _sca_severity_counter() -> Dict[str, int]:
    return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}


def _sca_normalize_severity(value: Any) -> str:
    sev = str(value or "UNKNOWN").strip().upper()
    return sev if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} else "UNKNOWN"


def _sca_finding_from_trivy_vuln(result: Dict[str, Any], vuln: Dict[str, Any]) -> Dict[str, Any]:
    fixed = vuln.get("FixedVersion")
    cvss_raw = vuln.get("CVSS") or {}
    best = {"source": None, "v3": 0, "v3_vector": None}

    if isinstance(cvss_raw, dict):
        for source, value in cvss_raw.items():
            if not isinstance(value, dict):
                continue
            score = value.get("V3Score") or 0
            try:
                score_num = float(score)
            except Exception:
                score_num = 0
            if score_num > float(best.get("v3") or 0):
                best = {
                    "source": str(source),
                    "v3": score_num,
                    "v3_vector": value.get("V3Vector"),
                }

    return {
        "target": result.get("Target"),
        "class": result.get("Class"),
        "type": result.get("Type"),
        "id": vuln.get("VulnerabilityID"),
        "pkg": vuln.get("PkgName"),
        "pkg_id": vuln.get("PkgID"),
        "installed": vuln.get("InstalledVersion"),
        "fixed": fixed,
        "status": vuln.get("Status"),
        "fix_available": bool(fixed),
        "severity": _sca_normalize_severity(vuln.get("Severity")),
        "severity_source": vuln.get("SeveritySource"),
        "vendor_ids": vuln.get("VendorIDs") or [],
        "vendor_severity": vuln.get("VendorSeverity") or {},
        "best_cvss": best,
        "cwe": vuln.get("CweIDs") or vuln.get("CWEIDs") or [],
        "title": vuln.get("Title"),
        "description": vuln.get("Description"),
        "references": vuln.get("References") or [],
        "primary_url": vuln.get("PrimaryURL"),
        "published": vuln.get("PublishedDate"),
        "modified": vuln.get("LastModifiedDate"),
        "data_source": vuln.get("DataSource") or {},
    }


def _sca_license_name(item: Dict[str, Any]) -> str:
    for key in ("name", "Name", "license", "License", "Category"):
        val = item.get(key)
        if val:
            return str(val)
    return ""


def _sca_license_pkg(item: Dict[str, Any]) -> str:
    for key in ("pkg", "PkgName", "PackageName", "PkgID"):
        val = item.get(key)
        if val:
            return str(val)
    return ""


def _sca_finding_evidence(finding: Dict[str, Any], path_prefix: str = "agent_payload.json:findings") -> Dict[str, str]:
    severity = _sca_normalize_severity(finding.get("severity"))
    vuln_id = str(finding.get("id") or "UNKNOWN-CVE")
    pkg = str(finding.get("pkg") or "unknown-package")
    installed = str(finding.get("installed") or "unknown-version")
    fixed = str(finding.get("fixed") or "no fixed version")
    cvss = ((finding.get("best_cvss") or {}).get("v3") if isinstance(finding.get("best_cvss"), dict) else None)
    cvss_txt = f"; CVSSv3={cvss}" if cvss else ""
    excerpt = f"{severity} {vuln_id}: {pkg} {installed}; fixed={fixed}{cvss_txt}"
    return ev("TRIVY", path_prefix, vuln_id, excerpt)


def detect_sca_trivy(data: Dict[str, Any]) -> Dict[str, Any]:
    agent_payload = data.get("agent_payload") or {}
    trivy = data.get("trivy") or {}

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

    raw_results = []
    if isinstance(trivy, dict):
        raw_results = trivy.get("Results") or []
    if isinstance(raw_results, list):
        for result in raw_results:
            if not isinstance(result, dict):
                continue
            raw_packages = result.get("Packages") or []
            if isinstance(raw_packages, list):
                packages.extend([x for x in raw_packages if isinstance(x, dict)])

            raw_vulns = result.get("Vulnerabilities") or []
            if not findings and isinstance(raw_vulns, list):
                findings.extend([
                    _sca_finding_from_trivy_vuln(result, vuln)
                    for vuln in raw_vulns
                    if isinstance(vuln, dict)
                ])

            raw_licenses = result.get("Licenses") or []
            if not licenses and isinstance(raw_licenses, list):
                licenses.extend([x for x in raw_licenses if isinstance(x, dict)])

    coverage = agent_payload.get("coverage") if isinstance(agent_payload, dict) else {}
    if not isinstance(coverage, dict):
        coverage = {}

    packages_detected = _sca_safe_int(coverage.get("packages_detected"), len(packages))
    license_entries_detected = _sca_safe_int(coverage.get("license_entries_detected"), len(licenses))

    if packages_detected == 0 and packages:
        packages_detected = len(packages)
    if license_entries_detected == 0 and licenses:
        license_entries_detected = len(licenses)

    by_severity = _sca_severity_counter()
    fixable_by_severity = _sca_severity_counter()
    fixable_total = 0
    unfixed_total = 0

    for finding in findings:
        sev = _sca_normalize_severity(finding.get("severity"))
        by_severity[sev] += 1
        if bool(finding.get("fix_available")) or bool(finding.get("fixed")):
            fixable_total += 1
            fixable_by_severity[sev] += 1
        else:
            unfixed_total += 1

    total_vulnerabilities = len(findings)

    summary = agent_payload.get("summary") if isinstance(agent_payload, dict) else {}
    if isinstance(summary, dict):
        total_vulnerabilities = _sca_safe_int(summary.get("total"), total_vulnerabilities)
        by_severity = {
            **_sca_severity_counter(),
            **{
                _sca_normalize_severity(k): _sca_safe_int(v)
                for k, v in (summary.get("by_severity") or {}).items()
            },
        }
        fixable = summary.get("fixable") or {}
        if isinstance(fixable, dict):
            fixable_total = _sca_safe_int(fixable.get("total"), fixable_total)
            fixable_by_severity = {
                **_sca_severity_counter(),
                **{
                    _sca_normalize_severity(k): _sca_safe_int(v)
                    for k, v in (fixable.get("by_severity") or {}).items()
                },
            }
            unfixed_total = max(0, total_vulnerabilities - fixable_total)

    sensitive_findings = []
    for finding in findings:
        pkg = str(finding.get("pkg") or finding.get("PkgName") or "").lower()
        title = str(finding.get("title") or finding.get("Title") or "").lower()
        blob = f"{pkg} {title}"
        if any(token in blob for token in SCA_SECURITY_SENSITIVE_PACKAGE_TOKENS):
            sensitive_findings.append(finding)

    restrictive_licenses = []
    unknown_licenses = []
    for item in licenses:
        name = _sca_license_name(item).strip()
        low = name.lower()
        if not low or any(token in low for token in SCA_UNKNOWN_LICENSE_TOKENS):
            unknown_licenses.append(item)
        elif any(token in low for token in SCA_RESTRICTIVE_LICENSE_TOKENS):
            restrictive_licenses.append(item)

    evidence_all = [_sca_finding_evidence(finding) for finding in findings[:12]]
    coverage_evidence = [
        ev(
            "AGENT_PAYLOAD",
            "agent_payload.json:coverage",
            "sca_dependency_inventory",
            f"packages_detected={packages_detected}; license_entries_detected={license_entries_detected}; targets={len(targets)}",
        )
    ]
    if not targets and packages_detected:
        coverage_evidence.append(
            ev(
                "TRIVY",
                "trivy.json:Results[].Packages",
                "sca_dependency_inventory_raw",
                f"packages_detected={packages_detected}",
            )
        )

    license_evidence = []
    for item in licenses[:8]:
        name = _sca_license_name(item) or "unknown"
        pkg = _sca_license_pkg(item) or "unknown-package"
        license_evidence.append(
            ev(
                "TRIVY",
                "agent_payload.json:licenses",
                "sca_license",
                f"{pkg}: {name}",
            )
        )

    return {
        "available": bool(agent_payload or trivy),
        "packages_detected": packages_detected,
        "license_entries_detected": license_entries_detected,
        "targets": targets,
        "packages": packages[:100],
        "findings": findings,
        "licenses": licenses,
        "total_vulnerabilities": total_vulnerabilities,
        "by_severity": by_severity,
        "fixable_total": fixable_total,
        "fixable_by_severity": fixable_by_severity,
        "unfixed_total": unfixed_total,
        "sensitive_findings": sensitive_findings,
        "restrictive_licenses": restrictive_licenses,
        "unknown_licenses": unknown_licenses,
        "coverage_evidence": coverage_evidence[:4],
        "finding_evidence": evidence_all[:12],
        "license_evidence": license_evidence[:8],
    }


def build_sca_flag_verdict(flag_id: str, sca: Dict[str, Any]) -> Dict[str, Any]:
    if not sca.get("available"):
        return {
            "state": "unknown",
            "summary": f"{flag_id} = UNKNOWN",
            "notes": "Trivy artifacts were not found or could not be parsed; SCA cannot be determined.",
            "evidence": [],
        }

    def bool_verdict(has_feature: bool, negative: bool, notes_yes: str, notes_no: str, evidence: List[Dict[str, str]], evidence_count: int | None = None) -> Dict[str, Any]:
        state = ("fail" if has_feature else "pass") if negative else ("pass" if has_feature else "fail")
        out: Dict[str, Any] = {
            "state": state,
            "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}",
            "notes": notes_yes if has_feature else notes_no,
            "evidence": evidence,
        }
        if evidence_count is not None:
            out["evidence_count_override"] = evidence_count
        return out

    total = int(sca.get("total_vulnerabilities") or 0)
    by_severity = sca.get("by_severity") or {}
    fixable_total = int(sca.get("fixable_total") or 0)
    unfixed_total = int(sca.get("unfixed_total") or 0)
    packages_detected = int(sca.get("packages_detected") or 0)
    license_entries = int(sca.get("license_entries_detected") or 0)

    if flag_id == "has_sca_dependency_inventory":
        has_feature = packages_detected > 0
        evidence = sca.get("coverage_evidence", []) or []
        return bool_verdict(
            has_feature,
            negative=False,
            notes_yes=f"Trivy detected a dependency inventory with {packages_detected} package(s).",
            notes_no="Trivy did not detect a dependency inventory.",
            evidence=evidence,
            evidence_count=packages_detected,
        )

    if flag_id == "has_sca_known_vulnerable_dependencies":
        has_feature = total > 0
        evidence = sca.get("finding_evidence", []) or sca.get("coverage_evidence", []) or []
        return bool_verdict(
            has_feature,
            negative=True,
            notes_yes=f"Trivy detected {total} known vulnerable dependency finding(s).",
            notes_no="Trivy did not report known vulnerable dependencies.",
            evidence=evidence,
            evidence_count=total,
        )

    severity_flag_map = {
        "has_sca_critical_vulnerabilities": "CRITICAL",
        "has_sca_high_vulnerabilities": "HIGH",
        "has_sca_medium_vulnerabilities": "MEDIUM",
        "has_sca_low_vulnerabilities": "LOW",
    }
    if flag_id in severity_flag_map:
        sev = severity_flag_map[flag_id]
        count = int(by_severity.get(sev, 0) or 0)
        evidence = [
            _sca_finding_evidence(finding)
            for finding in (sca.get("findings") or [])
            if _sca_normalize_severity(finding.get("severity")) == sev
        ][:12]
        return bool_verdict(
            count > 0,
            negative=True,
            notes_yes=f"Trivy detected {count} {sev.lower()} dependency vulnerability/vulnerabilities.",
            notes_no=f"Trivy did not report {sev.lower()} dependency vulnerabilities.",
            evidence=evidence or sca.get("coverage_evidence", []) or [],
            evidence_count=count,
        )

    if flag_id == "has_sca_fixable_vulnerabilities":
        evidence = [
            _sca_finding_evidence(finding)
            for finding in (sca.get("findings") or [])
            if bool(finding.get("fix_available")) or bool(finding.get("fixed"))
        ][:12]
        return bool_verdict(
            fixable_total > 0,
            negative=True,
            notes_yes=f"Trivy detected {fixable_total} dependency vulnerability/vulnerabilities with a fixed version available.",
            notes_no="Trivy did not report fixable dependency vulnerabilities.",
            evidence=evidence or sca.get("coverage_evidence", []) or [],
            evidence_count=fixable_total,
        )

    if flag_id == "has_sca_unfixed_vulnerabilities":
        evidence = [
            _sca_finding_evidence(finding)
            for finding in (sca.get("findings") or [])
            if not bool(finding.get("fix_available")) and not bool(finding.get("fixed"))
        ][:12]
        return bool_verdict(
            unfixed_total > 0,
            negative=True,
            notes_yes=f"Trivy detected {unfixed_total} dependency vulnerability/vulnerabilities without a fixed version.",
            notes_no="Trivy did not report unfixed dependency vulnerabilities.",
            evidence=evidence or sca.get("coverage_evidence", []) or [],
            evidence_count=unfixed_total,
        )

    if flag_id == "has_sca_security_sensitive_outdated_libraries":
        sensitive = sca.get("sensitive_findings") or []
        evidence = [_sca_finding_evidence(finding) for finding in sensitive[:12]]
        packages = sorted({str(finding.get("pkg") or "unknown") for finding in sensitive})
        return bool_verdict(
            bool(sensitive),
            negative=True,
            notes_yes=f"Trivy detected vulnerable security-sensitive libraries: {', '.join(packages[:12])}.",
            notes_no="Trivy did not report vulnerable security-sensitive libraries from the configured package list.",
            evidence=evidence or sca.get("coverage_evidence", []) or [],
            evidence_count=len(sensitive),
        )

    if flag_id == "has_sca_license_inventory":
        evidence = sca.get("license_evidence", []) or sca.get("coverage_evidence", []) or []
        return bool_verdict(
            license_entries > 0,
            negative=False,
            notes_yes=f"Trivy detected {license_entries} license entr(y/ies).",
            notes_no="Trivy did not detect dependency license inventory entries.",
            evidence=evidence,
            evidence_count=license_entries,
        )

    if flag_id == "has_sca_restrictive_licenses":
        restrictive = sca.get("restrictive_licenses") or []
        evidence = []
        for item in restrictive[:8]:
            evidence.append(ev("TRIVY", "agent_payload.json:licenses", "sca_restrictive_license", f"{_sca_license_pkg(item) or 'unknown-package'}: {_sca_license_name(item) or 'unknown'}"))
        return bool_verdict(
            bool(restrictive),
            negative=True,
            notes_yes=f"Trivy detected {len(restrictive)} potentially restrictive license entr(y/ies).",
            notes_no="Trivy did not detect licenses matching the restrictive-license token list.",
            evidence=evidence or sca.get("license_evidence", []) or [],
            evidence_count=len(restrictive),
        )

    if flag_id == "has_sca_unknown_licenses":
        unknown = sca.get("unknown_licenses") or []
        evidence = []
        for item in unknown[:8]:
            evidence.append(ev("TRIVY", "agent_payload.json:licenses", "sca_unknown_license", f"{_sca_license_pkg(item) or 'unknown-package'}: {_sca_license_name(item) or 'unknown'}"))
        return bool_verdict(
            bool(unknown),
            negative=True,
            notes_yes=f"Trivy detected {len(unknown)} unknown or unclassified license entr(y/ies).",
            notes_no="Trivy did not detect unknown or unclassified license entries.",
            evidence=evidence or sca.get("license_evidence", []) or [],
            evidence_count=len(unknown),
        )

    return {
        "state": "unknown",
        "summary": f"{flag_id} = UNKNOWN",
        "notes": "No SCA rule is implemented for this flag.",
        "evidence": sca.get("coverage_evidence", []) or [],
    }


# ------------------------------------------------------------
# Verdict engine
# ------------------------------------------------------------

def id_to_title(flag_id: str) -> str:
    if flag_id.startswith("has_"):
        body = flag_id[4:]
        prefix = "Has "
    elif flag_id.startswith("uses_"):
        body = flag_id[5:]
        prefix = "Uses "
    else:
        body = flag_id
        prefix = ""
    return prefix + " ".join(part.capitalize() for part in body.split("_"))


def infer_severity(flag_id: str) -> str:
    low = flag_id.lower()
    if low.startswith("has_sca_"):
        if any(tok in low for tok in ["critical", "high", "known_vulnerable", "fixable", "unfixed", "security_sensitive", "restrictive", "unknown_license"]):
            return "high"
        if any(tok in low for tok in ["medium", "license", "inventory"]):
            return "medium"
        return "low"
    if "exported_broadcast_receivers_without_permission" in low:
        return "high"
    if any(tok in low for tok in ["hardcoded", "malware", "debuggable", "vulnerab", "auth_tokens_in_plaintext", "keys_in_plaintext"]):
        return "high"
    if any(tok in low for tok in ["tls", "pinning", "encrypted", "keystore", "signing", "secure_cicd", "password_hashing"]):
        return "high"
    if any(tok in low for tok in ["manifest", "org_", "defined_", "os_time_source"]):
        return "medium"
    return "low"


DEFAULT_NEGATIVE_FINDING_FLAGS = {
    "has_dos_vulnerabilities",
    "has_log_injection_vulnerabilities",
    "has_malware_detections",
    "has_buffer_overflow_vulnerabilities",
    "has_race_condition_vulnerabilities",
    "has_out_of_bounds_vulnerabilities",
    "has_memory_corruption_vulnerabilities",
    "has_integer_arithmetic_vulnerabilities",
    "has_webview_addjavascriptinterface_present",
    "has_webview_javascript_interface_exposes_sensitive_functionality",
    "has_webview_javascript_interface_leaks_sensitive_data",
    "has_webview_remote_content",
    "has_webview_file_scheme",
    "has_insecure_http_based_webview_communication",
    "has_displays_sensitive_data_unmasked",
    "has_notification_leaks_sensitive_data",
    "has_notification_uses_public_channels",
    "has_stores_pii_in_plaintext",
    "has_stores_auth_tokens_in_plaintext",
    "has_stores_keys_in_plaintext",
    "has_stores_ephi_on_external_storage",
}


def is_negative_finding_flag(flag_id: str) -> bool:
    if flag_id in DEFAULT_NEGATIVE_FINDING_FLAGS:
        return True
    low = flag_id.lower()
    negative_tokens = [
        "_vulnerabilities",
        "_leaks_",
        "_insecure_",
        "_weak_",
        "_plaintext",
        "_malware_",
        "_tampered_",
        "_reused",
    ]
    return any(tok in low for tok in negative_tokens)


def classify_fallback(flag_id: str, cfg: Dict[str, Any]) -> Tuple[bool, str]:
    positive = set((cfg.get("classification") or {}).get("positive_flags", []) or [])
    negative = set((cfg.get("classification") or {}).get("negative_flags", []) or [])
    has_feature = False
    if flag_id in negative or is_negative_finding_flag(flag_id):
        state = "fail" if has_feature else "pass"
    elif flag_id in positive:
        state = "pass" if has_feature else "fail"
    else:
        state = "fail"
    return has_feature, state


def get_flag_override_verdict(flag_id: str, cfg: Dict[str, Any]) -> Dict[str, Any] | None:
    overrides = cfg.get("flag_overrides") or {}
    if not isinstance(overrides, dict):
        return None

    raw = overrides.get(flag_id)
    if not isinstance(raw, dict):
        return None

    evidence = raw.get("evidence")
    if not isinstance(evidence, list):
        evidence = []

    state = str(raw.get("state") or "unknown").strip().lower() or "unknown"
    summary = str(raw.get("summary") or f"{flag_id} = UNKNOWN").strip() or f"{flag_id} = UNKNOWN"
    notes = str(raw.get("notes") or "Manual override from vision360.project.json.").strip() or "Manual override from vision360.project.json."

    raw_count = raw.get("evidence_count_override", raw.get("evidence_count", len(evidence)))
    try:
        evidence_count = int(raw_count)
    except Exception:
        evidence_count = len(evidence)
    if evidence_count < 0:
        evidence_count = len(evidence)

    return {
        "state": state,
        "summary": summary,
        "notes": notes,
        "evidence": evidence,
        "evidence_count_override": evidence_count,
    }


def compute_flag_verdict(flag_id: str, data: Dict[str, Any], features: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    evidence: List[Dict[str, Any]] = []
    mobsf_static = data["mobsf_static"]
    source_zip_name = data["source_zip_name"]
    source_label = data["source_label"]

    override_verdict = get_flag_override_verdict(flag_id, cfg)
    if override_verdict is not None:
        return override_verdict

    if flag_id.startswith("has_sca_"):
        return build_sca_flag_verdict(flag_id, features.get("sca", {}) or {})

    if flag_id in set((cfg.get("classification") or {}).get("org_like_prefix_flags", []) or []):
        pass

    if flag_id in {"has_manifest_debuggable_true", "has_android_debuggable_enabled"}:
        info = features.get("manifest_debuggable_signal") or {}
        has_feature = bool(info.get("is_true"))
        evidence.extend(info.get("evidence", []) or [])
        notes = (
            'android:debuggable="true" detected in the MobSF APK manifest or in the primary AndroidManifest.xml.'
            if has_feature
            else 'No android:debuggable="true" detected in the MobSF APK manifest nor in the primary AndroidManifest.xml.'
        )
        if info.get("mismatch"):
            notes += " Mismatch between MobSF APK evidence and the primary AndroidManifest.xml; possible manifest merging or build variant."
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": notes, "evidence": evidence}

    if flag_id == "has_manifest_backup_enabled":
        has_feature = bool(features["manifest_allow_backup"])
        if data["source_manifest_path"]:
            evidence.append(ev(source_label, f"{source_zip_name}:{data['source_manifest_path']}", "android:allowBackup", 'android:allowBackup="true"' if has_feature else "allowBackup not true"))
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": 'android:allowBackup="true" detected in the primary AndroidManifest.xml.' if has_feature else 'No android:allowBackup="true" detected in the primary AndroidManifest.xml.', "evidence": evidence}

    if flag_id == "has_manifest_allow_clear_text_traffic_true":
        has_feature = bool(features["manifest_cleartext"])
        if data["source_manifest_path"]:
            evidence.append(ev(source_label, f"{source_zip_name}:{data['source_manifest_path']}", "usesCleartextTraffic", 'usesCleartextTraffic="true"' if has_feature else "usesCleartextTraffic not true"))
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": 'usesCleartextTraffic="true" detected in the primary AndroidManifest.xml.' if has_feature else 'No usesCleartextTraffic="true" detected in the primary AndroidManifest.xml.', "evidence": evidence}

    if flag_id == "has_manifest_exports_components_insecurely":
        info = features["manifest_exports"]
        if not info.get("available"):
            return {"state": "unknown", "summary": f"{flag_id} = UNKNOWN", "notes": "AndroidManifest.xml was not found in the source ZIP.", "evidence": []}
        count = int(info.get("count", 0))
        evidence.extend(info.get("evidence", []) or [])
        has_feature = count > 0
        notes = f"Detected {count} exported components without permission in the primary AndroidManifest.xml." if has_feature else "No insecure exported component was detected in the primary AndroidManifest.xml."
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": notes, "evidence": evidence}

    if flag_id == "has_manifest_custom_permission_defined":
        info = features["manifest_custom_permissions"]
        if not info.get("available"):
            return {"state": "unknown", "summary": f"{flag_id} = UNKNOWN", "notes": "AndroidManifest.xml was not found in the source ZIP.", "evidence": []}
        count = int(info.get("count", 0))
        evidence.extend(info.get("evidence", []) or [])
        has_feature = count > 0
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Custom <permission> entries were found in the primary AndroidManifest.xml." if has_feature else "No custom <permission> entry was found in the primary AndroidManifest.xml.", "evidence": evidence}

    if flag_id == "has_permissions_protected_with_signature_level":
        info = features["manifest_signature_level"]
        if not info.get("available"):
            return {"state": "unknown", "summary": f"{flag_id} = UNKNOWN", "notes": "AndroidManifest.xml was not found in the source ZIP.", "evidence": []}
        has_feature = bool(info.get("is_true"))
        evidence.extend(info.get("evidence", []) or [])
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "At least one custom permission uses protectionLevel=signature." if has_feature else "No custom permission with protectionLevel=signature was detected.", "evidence": evidence}

    if flag_id == "has_manifest_services_explicit_accessibility_attributes":
        info = features["manifest_services_explicit_accessibility"]
        if not info.get("available"):
            return {"state": "unknown", "summary": f"{flag_id} = UNKNOWN", "notes": "AndroidManifest.xml was not found in the source ZIP.", "evidence": []}
        total = int(info.get("total_services", 0))
        missing = int(info.get("missing_exported_count", 0))
        evidence.extend(info.get("evidence", []) or [])
        if total == 0:
            return {"state": "not_applicable", "summary": f"{flag_id} = NOT_APPLICABLE", "notes": "No <service> entry was detected in the primary AndroidManifest.xml.", "evidence": evidence}
        has_feature = missing == 0
        notes = "All <service> entries explicitly declare android:exported." if has_feature else f"Detected {missing} of {total} <service> entries without explicit android:exported."
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": notes, "evidence": evidence}

    if flag_id == "has_exported_broadcast_receivers_without_permission":
        info = features["exported_receivers_without_permission"]
        if not info.get("available"):
            return {"state": "unknown", "summary": f"{flag_id} = UNKNOWN", "notes": "AndroidManifest.xml was not found in the source ZIP.", "evidence": []}
        total = int(info.get("total_receivers", 0))
        insecure = int(info.get("exported_receivers_without_permission_count", 0))
        evidence.extend(info.get("evidence", []) or [])
        if total == 0:
            return {"state": "not_applicable", "summary": f"{flag_id} = NOT_APPLICABLE", "notes": "No <receiver> entry was detected in the primary AndroidManifest.xml.", "evidence": evidence}
        has_feature = insecure > 0
        notes = f"Receivers total={total}; exported_without_permission={insecure}. Export logic considers android:exported='false' as non-exported and missing exported + intent-filter as effectively exported."
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": notes, "evidence": evidence}

    if flag_id in {
        "has_tls_ssl_pinning_implemented",
        "has_ssl_cert_pinning_implemented",
        "has_ssl_pinning_findings_severity_good",
        "has_android_ssl_pinning_present",
        "has_android_ssl_pinning_detected",
    }:
        info = features.get("tls_pinning") or {}
        has_feature = bool(info.get("has_pinning"))
        evidence.extend(info.get("evidence", []) or [])
        meta = info.get("android_ssl_pinning_metadata", {}) or {}
        files = info.get("android_ssl_pinning_files", []) or []
        notes_parts = []
        if has_feature:
            notes_parts.append("MobSF reports android_ssl_pinning or appsec.secure, indicating pinning.")
            if meta:
                notes_parts.append(f"metadata: severity={meta.get('severity')}, masvs={meta.get('masvs')}.")
            if files:
                notes_parts.append(f"files: {', '.join(files)}.")
        else:
            notes_parts.append("No evidence of SSL pinning found in MobSF.")
        return {
            "state": "pass" if has_feature else "fail",
            "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}",
            "notes": " ".join(notes_parts),
            "evidence": evidence,
        }

    if flag_id in {
        "has_cert_signed_with_code_signing_cert",
        "has_cert_v1_signature_present_janus_risk",
        "has_cert_signed_with_debug_certificate",
        "has_cert_uses_sha1_signature_algorithm",
        "has_cert_x509_subject_android_debug",
        "has_cert_validity_long_term",
    }:
        return build_certificate_flag_verdict(flag_id, features.get("certificate_analysis") or {})

    if flag_id == "has_os_time_source":
        info = features["os_time_source"]
        has_feature = bool(info.get("has_os_time_source"))
        evidence.extend(info.get("evidence", []) or [])
        notes = "Detected use of an operating-system-provided time source in the source code." if has_feature else "No operating-system-provided time source was detected in the source code."
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": notes, "evidence": evidence}

    if flag_id == "has_password_hashing_uses_salts":
        info = features["password_hashing"]
        has_feature = bool(info.get("has_password_hashing_uses_salts"))
        evidence.extend(info.get("evidence", []) or [])
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Evidence of salt usage in password hashing was detected." if has_feature else "No salt-related password hashing evidence was detected.", "evidence": evidence}

    if flag_id == "has_password_hashing_uses_kdf":
        info = features["password_hashing"]
        has_feature = bool(info.get("has_password_hashing_uses_kdf"))
        evidence.extend(info.get("evidence", []) or [])
        algs = info.get("kdf_algorithms", []) or []
        notes = f"Robust password hashing/KDF evidence detected: {algs}." if has_feature else "No robust password hashing/KDF evidence was detected."
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": notes, "evidence": evidence}

    if flag_id == "has_supports_manual_logout":
        info = features["logout_session"]
        has_feature = bool(info.get("has_manual_logout"))
        evidence.extend(info.get("evidence", []) or [])
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Manual logout method detected." if has_feature else "No manual logout method was detected.", "evidence": evidence}

    if flag_id == "has_clears_local_session_data_on_logout":
        info = features["logout_session"]
        has_feature = bool(info.get("has_clears_local_prefs_on_logout"))
        evidence.extend(info.get("evidence", []) or [])
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Local session cleanup on logout detected." if has_feature else "No local session cleanup on logout was detected.", "evidence": evidence}

    if flag_id == "has_clears_cookies_on_logout":
        info = features["logout_session"]
        has_feature = bool(info.get("has_clears_cookies_on_logout"))
        evidence.extend(info.get("evidence", []) or [])
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Cookie cleanup on logout detected." if has_feature else "No cookie cleanup on logout was detected.", "evidence": evidence}

    if flag_id == "has_session_id_assigned_from_server_cookie":
        info = features["logout_session"]
        has_feature = bool(info.get("has_session_cookie_based_auth"))
        evidence.extend(info.get("evidence", []) or [])
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Cookie-based session indicators were detected." if has_feature else "No cookie-based session indicator was detected.", "evidence": evidence}

    if flag_id == "has_logout_invalidates_server_session":
        info = features["logout_session"]
        has_feature = bool(info.get("has_logout_invalidates_server_session"))
        evidence.extend(info.get("evidence", []) or [])
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Logout appears to invalidate the server session." if has_feature else "No clear server-side logout invalidation signal was detected.", "evidence": evidence}

    if flag_id == "has_endpoint_requires_user_authentication":
        info = features["endpoint_auth"]
        has_feature = bool(info.get("has_basic_auth_header_in_rest_service"))
        evidence.extend(info.get("evidence", []) or [])
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Authorization header usage consistent with endpoint authentication was detected." if has_feature else "No conclusive endpoint-authentication pattern was detected.", "evidence": evidence}

    if flag_id == "has_secrets_secure_keystore_env_vars":
        paths = features["keystore_env_paths"]
        has_feature = bool(paths)
        for p in paths:
            evidence.append(ev(source_label, f"{source_zip_name}:{p}", "gradle_signing_env", "signingConfigs uses environment variables"))
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": f"Signing config reads environment variables in: {', '.join(paths)}." if has_feature else "No environment-variable-based signing config was detected.", "evidence": evidence}

    if flag_id == "has_signing_creds_not_hardcoded":
        has_env = bool(features["keystore_env_paths"])
        has_hardcoded = bool(features["signing_creds_hardcoded"])
        has_feature = has_env and not has_hardcoded
        if has_env:
            evidence.append(ev(source_label, f"{source_zip_name}:gradle", "signing_env", "Environment variables used for signing"))
        if has_hardcoded:
            evidence.append(ev(source_label, f"{source_zip_name}:gradle", "signing_hardcoded", "Literal signing password detected"))
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Signing credentials are externalized and not hardcoded." if has_feature else "Signing credentials are not fully externalized or hardcoded values were detected.", "evidence": evidence}

    if flag_id == "has_secure_cicd_key_management":
        has_env = bool(features["keystore_env_paths"])
        has_hardcoded = bool(features["signing_creds_hardcoded"])
        has_feature = has_env and not has_hardcoded
        if has_env:
            evidence.append(ev(source_label, f"{source_zip_name}:gradle", "signing_env", "System.getenv detected in signingConfigs"))
        if has_hardcoded:
            evidence.append(ev(source_label, f"{source_zip_name}:gradle", "signing_hardcoded", "Literal signing password detected"))
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Signing uses environment variables and no hardcoded secret was detected." if has_feature else "No secure CI/CD signing pattern was confirmed.", "evidence": evidence}

    if flag_id == "has_release_minify_disabled":
        has_feature = bool(features["release_minify_disabled"])
        if has_feature:
            evidence.append(ev(source_label, f"{source_zip_name}:gradle", "minifyEnabled", "minifyEnabled false in release"))
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Release build has minifyEnabled false." if has_feature else "Release build does not expose minifyEnabled false.", "evidence": evidence}

    if flag_id == "has_prevention_against_reverse_engineering":
        info = features["reverse_engineering"]
        has_feature = bool(info.get("has_minify_enabled_release"))
        for p in info.get("paths", []) or []:
            evidence.append(ev(source_label, f"{source_zip_name}:{p}", "minifyEnabled", "minifyEnabled true in release"))
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Release minification/obfuscation is enabled." if has_feature else "No minifyEnabled true detected for release.", "evidence": evidence}

    if flag_id == "has_hardcoded_credentials":
        hits = features["hardcoded_secrets_hits"]
        has_literal = bool(re.search(r'password\s*=\s*"[^"]+"', data["combined_code"], flags=re.IGNORECASE))
        has_feature = bool(hits) or has_literal
        if hits:
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:secrets/findings", "hardcoded_secrets", f"hits={len(hits)}"))
        if has_literal:
            evidence.append(ev(source_label, f"{source_zip_name}:code_scan", "password_literal", 'password = "..." pattern'))
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Hardcoded secrets or password literals were detected." if has_feature else "No hardcoded secret indicator was detected.", "evidence": evidence}

    if flag_id == "has_android_read_write_external_storage":
        perms = features["permissions"]
        targets = {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
        }
        present = [p for p in perms["requested_permissions"] if p in targets]
        has_feature = bool(present)
        for p in present:
            meta = (mobsf_static.get("permissions") or {}).get(p) or {}
            evidence.append(ev("MobSF_STATIC", f"mobsf_results.json:permissions.{p}", "permission_status", f"status={meta.get('status', 'unknown')}"))
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": f"External storage permissions present: {present}." if has_feature else "No external storage permissions detected.", "evidence": evidence}

    if flag_id == "has_android_extra_risky_permissions_present":
        perms = features["permissions"]
        present = sorted(set(perms["dangerous_permissions"] + perms["privileged_like_permissions"] + perms["special_os_permissions_requested"]))
        has_feature = bool(present)
        for p in present:
            meta = (mobsf_static.get("permissions") or {}).get(p) or {}
            evidence.append(ev("MobSF_STATIC", f"mobsf_results.json:permissions.{p}", "permission_status", f"status={meta.get('status', 'unknown')}"))
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": f"Risky permissions present: {present}." if has_feature else "No extra risky permission was detected.", "evidence": evidence}

    if flag_id == "has_requests_only_minimum_permissions":
        perms = features["permissions"]
        has_feature = not perms["has_dangerous"] and not perms["has_privileged_like"] and not perms["special_os_permissions_requested"]
        if has_feature:
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:permissions", "permission_summary", "No dangerous, privileged-like, or special OS permissions detected"))
        else:
            for p in perms["dangerous_permissions"] + perms["privileged_like_permissions"] + perms["special_os_permissions_requested"]:
                meta = (mobsf_static.get("permissions") or {}).get(p) or {}
                evidence.append(ev("MobSF_STATIC", f"mobsf_results.json:permissions.{p}", "permission_status", f"status={meta.get('status', 'unknown')}"))
        return {"state": "pass" if has_feature else "fail", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "Only minimum permissions requested." if has_feature else "Dangerous, privileged-like, or special OS permissions were detected.", "evidence": evidence}

    if flag_id == "has_supports_runtime_permission_management":
        perms = features["permissions"]
        has_dangerous = bool(perms["has_dangerous"])
        patterns = [
            r"\brequestpermissions\s*\(",
            r"\bactivitycompat\.requestpermissions\s*\(",
            r"\bshouldshowrequestpermissionrationale\s*\(",
            r"\bonrequestpermissionsresult\s*\(",
            r"\bregisterforactivityresult\s*\(",
            r"\bactivityresultcontracts\.requestpermission\b",
            r"\bactivityresultcontracts\.requestmultiplepermissions\b",
        ]
        supports = any(re.search(p, data["code_lower"], flags=re.IGNORECASE) for p in patterns)
        if not has_dangerous:
            evidence.append(ev("MobSF_STATIC", "mobsf_results.json:permissions", "permission_summary", "No dangerous permissions detected"))
            return {"state": "not_applicable", "summary": f"{flag_id} = NOT_APPLICABLE", "notes": "No dangerous permissions were detected, so runtime permission handling is not strictly applicable.", "evidence": evidence}
        if supports:
            evidence.append(ev(source_label, f"{source_zip_name}:code_scan", "runtime_permissions_api", "requestPermissions/ActivityCompat/etc detected"))
        return {"state": "pass" if supports else "fail", "summary": f"{flag_id} = {'YES' if supports else 'NO'}", "notes": "Runtime permission management APIs were detected." if supports else "No runtime permission management API was detected despite dangerous permissions.", "evidence": evidence}

    if flag_id == "has_android_insecure_random_rng":
        findings = ((mobsf_static.get("code_analysis") or {}).get("findings") or {})
        air = findings.get("android_insecure_random") or {}
        files = air.get("files") or {}
        total = 0
        if isinstance(files, dict):
            for path, count in files.items():
                try:
                    c = int(str(count).strip())
                except Exception:
                    c = 1
                total += max(0, c)
                for i in range(max(0, c)):
                    evidence.append(ev("MobSF_STATIC", f"mobsf_results.json:code_analysis.findings.android_insecure_random.files.{path}", "android_insecure_random", f"{path} occurrence {i+1}/{c}"))
        has_feature = total > 0
        return {"state": "fail" if has_feature else "pass", "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}", "notes": "MobSF reports android_insecure_random." if has_feature else "MobSF does not report android_insecure_random.", "evidence": evidence, "evidence_count_override": total}

    if flag_id.startswith("has_org_") or flag_id.startswith("has_defined_"):
        found, sources, org_evidence = find_org_evidence_for_flag(flag_id, features["org_index"], cfg)
        evidence.extend(org_evidence)
        return {
            "state": "pass" if found else "fail",
            "summary": f"{flag_id} = {'YES' if found else 'NO'}",
            "notes": f"Explicit organizational evidence found in: {', '.join(sources)}." if found else "No explicit organizational evidence pattern was matched in the analyzed documentation corpus.",
            "evidence": evidence,
        }

    _, state = classify_fallback(flag_id, cfg)
    summary_value = "UNKNOWN" if state == "unknown" else "NO"
    notes = "Fallback verdict: no specific portable detector is implemented for this flag yet. The architecture is ready for project-specific parameters without hardcoding them in Python."
    if state == "unknown":
        notes = "Fallback verdict: no specific portable detector is implemented for this flag yet, so the result is UNKNOWN rather than a forced failure."
    return {
        "state": state,
        "summary": f"{flag_id} = {summary_value}",
        "notes": notes,
        "evidence": [],
    }


# ------------------------------------------------------------
# Output builder
# ------------------------------------------------------------

def build_outputs(cfg: Dict[str, Any], app_metadata: Dict[str, Any], data: Dict[str, Any], features: Dict[str, Any], groups: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    metadata = (app_metadata or {}).get("app_metadata") or {}
    project_cfg = cfg.get("project", {}) or {}
    project_name = str(project_cfg.get("name") or metadata.get("Name") or "Portable Vision360 Project")

    sources_list = [
        "MobSF_STATIC",
        "MobSF_DYNAMIC",
        "SAST_MERGED",
        "SAST_SEMGREP",
        "TRIVY",
        "AGENT_PAYLOAD",
        data["source_label"],
    ]

    fingerprint = {
        "schema_version": 1,
        "project": {
            "name": project_name,
            "generated_at": now_iso(),
            "sources": sources_list,
            "metadata": metadata,
        },
        "groups": groups,
        "flags": [],
    }
    output_flags: Dict[str, Any] = {}

    md = cfg.get("metadata_overrides", {}) or {}
    title_overrides = md.get("titles", {}) or {}
    desc_overrides = md.get("descriptions", {}) or {}
    rationale_overrides = md.get("rationales", {}) or {}
    primary_source_overrides = md.get("primary_sources", {}) or {}

    for group in groups:
        gid = group.get("id", "")
        for flag_id in group.get("flags", []) or []:
            verdict = compute_flag_verdict(flag_id, data, features, cfg)
            evidence = verdict.get("evidence") or []
            evidence_count = int(verdict.get("evidence_count_override", len(evidence)))
            description = desc_overrides.get(
                flag_id,
                f"Evaluates whether the condition '{flag_id}' is met in the application or in associated code, configuration, or scanning artifacts.",
            )
            flag_obj = {
                "id": flag_id,
                "group": gid,
                "title": title_overrides.get(flag_id, id_to_title(flag_id)),
                "description": description,
                "severity": infer_severity(flag_id),
                "expected_state": "good",
                "rationale": rationale_overrides.get(
                    flag_id,
                    "Verdict based on deterministic rules, externalized configuration, and structured evidence from source code and scan artifacts.",
                ),
                "primary_sources": primary_source_overrides.get(
                    flag_id,
                    ["TRIVY", "AGENT_PAYLOAD"] if flag_id.startswith("has_sca_") else ["MobSF_STATIC", data["source_label"]],
                ),
                "app_verdict": {
                    "state": verdict["state"],
                    "summary": verdict["summary"],
                    "notes": verdict["notes"],
                    "evidence": evidence,
                    "evidence_count": evidence_count,
                },
            }
            fingerprint["flags"].append(flag_obj)
            output_flags[flag_id] = {
                "summary": verdict["summary"],
                "state": verdict["state"],
                "notes": verdict["notes"],
                "evidence": evidence,
                "evidence_count": evidence_count,
            }

    output = {
        "schema_version": 1,
        "project": fingerprint["project"],
        "flags": output_flags,
    }

    trace = {
        "schema_version": 1,
        "generated_at": now_iso(),
        "source_manifest_path": data.get("source_manifest_path", ""),
        "source_zip_name": data.get("source_zip_name", ""),
        "source_label": data.get("source_label", ""),
        "effective_features": {
            "os_time_source": features["os_time_source"],
            "password_hashing": features["password_hashing"],
            "logout_session": features["logout_session"],
            "endpoint_auth": features["endpoint_auth"],
            "keystore_env_paths": features["keystore_env_paths"],
            "signing_creds_hardcoded": features["signing_creds_hardcoded"],
            "release_minify_disabled": features["release_minify_disabled"],
            "reverse_engineering": features["reverse_engineering"],
            "permissions": features["permissions"],
            "tls_pinning": features["tls_pinning"],
            "certificate_analysis": features["certificate_analysis"],
            "manifest_debuggable_signal": features["manifest_debuggable_signal"],
            "sca": features["sca"],
        },
        "code_inventory": {
            path: {
                "sha256": sha256_text(text),
                "length": len(text),
            }
            for path, text in data.get("source_texts", {}).items()
        },
    }
    return fingerprint, output, trace


# ------------------------------------------------------------
# Bundle writer
# ------------------------------------------------------------

def write_outputs(output_dir: Path, fingerprint: Dict[str, Any], output: Dict[str, Any], trace: Dict[str, Any], effective_cfg: Dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    fingerprint_path = output_dir / "vision360_fingerprint.json"
    output_path = output_dir / "vision360_output.json"
    bundle_path = output_dir / "vision360_bundle.zip"
    trace_path = output_dir / "vision360_trace.json"
    effective_cfg_path = output_dir / "vision360_effective_config.json"

    fingerprint_path.write_text(json.dumps(fingerprint, indent=2, ensure_ascii=False), encoding="utf-8")
    output_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    trace_path.write_text(json.dumps(trace, indent=2, ensure_ascii=False), encoding="utf-8")
    effective_cfg_path.write_text(json.dumps(effective_cfg, indent=2, ensure_ascii=False), encoding="utf-8")

    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(fingerprint_path, arcname="vision360_fingerprint.json")
        zf.write(output_path, arcname="vision360_output.json")
        zf.write(trace_path, arcname="vision360_trace.json")
        zf.write(effective_cfg_path, arcname="vision360_effective_config.json")


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default="/mnt/data")
    parser.add_argument("--output-dir", default="/mnt/data")
    parser.add_argument("--defaults", default="")
    parser.add_argument("--project-config", default="")
    parser.add_argument("--groups-file", default="")
    args = parser.parse_args()

    script_path = Path(__file__).resolve()
    repo_root = script_path.parent.parent

    effective_cfg, defaults_path, groups_path, project_cfg_path, app_metadata = load_effective_config(repo_root, args)
    groups = load_json_file(groups_path, default=[])
    if not isinstance(groups, list):
        raise SystemExit(f"groups file must be a JSON array: {groups_path}")

    data = load_inputs(Path(args.input_dir), effective_cfg)
    detectors_cfg = effective_cfg.get("detectors", {}) or {}

    features = {
        "os_time_source": detect_os_time_source(data["source_texts"], detectors_cfg.get("os_time_source", {}) or {}, data["source_zip_name"], data["source_label"]),
        "password_hashing": detect_password_hashing(data["source_texts"], detectors_cfg.get("password_hashing", {}) or {}, data["source_zip_name"], data["source_label"]),
        "logout_session": detect_logout_session(data["source_texts"], detectors_cfg.get("logout_session", {}) or {}, data["source_zip_name"], data["source_label"]),
        "endpoint_auth": detect_endpoint_auth(data["source_texts"], detectors_cfg.get("endpoint_auth", {}) or {}, data["source_zip_name"], data["source_label"]),
        "keystore_env_paths": detect_keystore_env_paths(data["source_texts"], detectors_cfg.get("signing", {}) or {}),
        "signing_creds_hardcoded": detect_signing_creds_hardcoded(data["source_texts"]),
        "release_minify_disabled": detect_release_minify_disabled(data["source_texts"]),
        "reverse_engineering": detect_release_minify_enabled(data["source_texts"]),
        "permissions": analyze_permissions(data["mobsf_static"], detectors_cfg.get("permissions", {}) or {}),
        "hardcoded_secrets_hits": extract_mobsf_secrets_hits(data["mobsf_static"]),
        "tls_pinning": detect_tls_pinning(data["mobsf_static"]),
        "certificate_analysis": detect_certificate_analysis(data["mobsf_static"]),
        "manifest_debuggable": detect_manifest_attr_true(data["source_manifest_text"], "debuggable"),
        "manifest_debuggable_signal": detect_mobsf_manifest_attr_signal(
            data["mobsf_static"],
            data["source_manifest_text"],
            data["source_manifest_path"] or "AndroidManifest.xml",
            data["source_zip_name"],
            data["source_label"],
            "debuggable",
            "app_is_debuggable",
            "android:debuggable",
        ),
        "manifest_allow_backup": detect_manifest_attr_true(data["source_manifest_text"], "allowBackup"),
        "manifest_cleartext": detect_manifest_attr_true(data["source_manifest_text"], "usesCleartextTraffic"),
        "manifest_exports": detect_manifest_insecure_exports_count(data["source_manifest_text"], data["source_manifest_path"] or "AndroidManifest.xml", data["source_zip_name"], data["source_label"]),
        "manifest_custom_permissions": detect_manifest_custom_permissions(data["source_manifest_text"], data["source_manifest_path"] or "AndroidManifest.xml", data["source_zip_name"], data["source_label"]),
        "manifest_signature_level": detect_manifest_signature_level_defined(data["source_manifest_text"], data["source_manifest_path"] or "AndroidManifest.xml", data["source_zip_name"], data["source_label"]),
        "manifest_services_explicit_accessibility": detect_manifest_services_explicit_accessibility(data["source_manifest_text"], data["source_manifest_path"] or "AndroidManifest.xml", data["source_zip_name"], data["source_label"]),
        "exported_receivers_without_permission": detect_exported_receivers_without_permission(data["source_manifest_text"], data["source_manifest_path"] or "AndroidManifest.xml", data["source_zip_name"], data["source_label"]),
        "org_index": build_org_text_index(data["source_texts"]),
        "sca": detect_sca_trivy(data),
    }

    fingerprint, output, trace = build_outputs(effective_cfg, app_metadata, data, features, groups)

    trace["loaded_files"] = {
        "defaults": str(defaults_path),
        "groups": str(groups_path),
        "project_config": str(project_cfg_path) if project_cfg_path else "",
    }

    write_outputs(Path(args.output_dir), fingerprint, output, trace, effective_cfg)


if __name__ == "__main__":
    main()
