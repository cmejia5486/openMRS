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

def _member_aliases(member_name: str) -> List[str]:
    aliases = [member_name]
    alias_map = {
        "mobsf_results.json": ["mobsf-report.json", "mobsf_results.json"],
        "mobsf_dynamic_results.json": ["mobsf-dynamic-report.json", "mobsf_dynamic_results.json"],
        "trivy.json": ["trivy.json"],
        "agent_payload.json": ["agent_payload.json"],
        "merged.sarif": ["merged.sarif"],
        "semgrep.sarif": ["semgrep.sarif"],
    }
    for item in alias_map.get(member_name, []):
        if item not in aliases:
            aliases.append(item)
    return aliases


def _read_zip_member_with_aliases(zip_path: Path, member_name: str) -> bytes | None:
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            names_norm = {n.replace("\\", "/").strip("/").lower(): n for n in names}
            names_base = {os.path.basename(n.replace("\\", "/").strip("/").lower()): n for n in names}
            for alias in _member_aliases(member_name):
                key = alias.replace("\\", "/").strip("/").lower()
                chosen = names_norm.get(key) or names_base.get(os.path.basename(key))
                if chosen:
                    return zf.read(chosen)
    except Exception:
        return None
    return None


def read_json_from_zip(zip_path: Path, member_name: str) -> Any:
    if not zip_path.exists():
        return {}
    raw = _read_zip_member_with_aliases(zip_path, member_name)
    if raw is None:
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
        ".java", ".kt", ".kts", ".gradle", ".gradle.kts", ".xml", ".yml", ".yaml",
        ".json", ".properties", ".conf", ".cfg", ".ini", ".md", ".txt", ".pro",
        ".html", ".htm", ".js", ".ts"
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


def list_zip_members(zip_path: Path) -> List[str]:
    if not zip_path.exists():
        return []
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            return sorted(zf.namelist())
    except Exception:
        return []


def artifact_status(zip_path: Path, required_members: List[str] | None = None) -> Dict[str, Any]:
    """Return a compact availability record for a scanner artifact.

    The generator must distinguish absence of evidence from absence of an
    artifact. This helper keeps that distinction visible in the trace and lets
    downstream flag rules return UNKNOWN/NOT_APPLICABLE instead of silently
    converting missing coverage into NO.
    """
    required_members = required_members or []
    status: Dict[str, Any] = {
        "path": str(zip_path),
        "filename": zip_path.name,
        "exists": zip_path.exists(),
        "is_zip": False,
        "members_count": 0,
        "missing_required_members": list(required_members),
    }
    if not zip_path.exists():
        return status
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = zf.namelist()
        members_norm = {m.replace("\\", "/").strip("/").lower() for m in members}
        members_base = {os.path.basename(m.replace("\\", "/").strip("/").lower()) for m in members}
        missing = []
        for required in required_members:
            aliases = _member_aliases(required)
            found = False
            for alias in aliases:
                key = alias.replace("\\", "/").strip("/").lower()
                if key in members_norm or os.path.basename(key) in members_base:
                    found = True
                    break
            if not found:
                missing.append(required)
        status.update({
            "is_zip": True,
            "members_count": len(members),
            "missing_required_members": missing,
        })
    except Exception as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
    return status


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
        "source_zip_members": list_zip_members(source_zip),
        "source_zip_name": source_zip.name,
        "source_label": source_label,
        "artifact_status": {
            "mobsf_static_zip": artifact_status(mobsf_static_zip, ["mobsf_results.json"]),
            "mobsf_dynamic_zip": artifact_status(mobsf_dynamic_zip, ["mobsf_dynamic_results.json"]),
            "source_zip": artifact_status(source_zip, []),
            "sast_zip": artifact_status(sast_zip, ["merged.sarif", "semgrep.sarif"]),
            "trivy_zip": artifact_status(trivy_zip, ["trivy.json", "agent_payload.json"]),
        },
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

    inventory_available = packages_detected > 0 or bool(targets) or bool(packages)
    vulnerability_scan_conclusive = bool(agent_payload or trivy) and inventory_available
    license_inventory_available = license_entries_detected > 0
    scan_status = "complete" if vulnerability_scan_conclusive else ("no_dependency_inventory" if (agent_payload or trivy) else "missing_artifact")

    return {
        "available": bool(agent_payload or trivy),
        "scan_status": scan_status,
        "inventory_available": inventory_available,
        "vulnerability_scan_conclusive": vulnerability_scan_conclusive,
        "license_inventory_available": license_inventory_available,
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
    inventory_available = bool(sca.get("inventory_available"))
    vulnerability_scan_conclusive = bool(sca.get("vulnerability_scan_conclusive"))
    license_inventory_available = bool(sca.get("license_inventory_available"))
    scan_status = str(sca.get("scan_status") or "unknown")

    def inconclusive_verdict(reason: str) -> Dict[str, Any]:
        evidence = sca.get("coverage_evidence", []) or []
        return {
            "state": "unknown",
            "summary": f"{flag_id} = UNKNOWN",
            "notes": f"SCA evidence is inconclusive for this flag: {reason}. scan_status={scan_status}.",
            "evidence": evidence,
            "evidence_count_override": 0,
        }

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
        if not vulnerability_scan_conclusive and total == 0:
            return inconclusive_verdict("no dependency inventory was available, so zero vulnerabilities cannot be interpreted as a clean result")
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
        if not vulnerability_scan_conclusive and count == 0:
            return inconclusive_verdict(f"no dependency inventory was available, so absence of {sev.lower()} vulnerabilities is not conclusive")
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
        if not vulnerability_scan_conclusive and fixable_total == 0:
            return inconclusive_verdict("no dependency inventory was available, so absence of fixable vulnerabilities is not conclusive")
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
        if not vulnerability_scan_conclusive and unfixed_total == 0:
            return inconclusive_verdict("no dependency inventory was available, so absence of unfixed vulnerabilities is not conclusive")
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
        if not vulnerability_scan_conclusive and not sensitive:
            return inconclusive_verdict("no dependency inventory was available, so absence of vulnerable security-sensitive libraries is not conclusive")
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
        if not license_inventory_available and not inventory_available:
            return inconclusive_verdict("no dependency or license inventory was available")
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
        if not license_inventory_available and not restrictive:
            return inconclusive_verdict("no license inventory was available, so absence of restrictive licenses is not conclusive")
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
        if not license_inventory_available and not unknown:
            return inconclusive_verdict("no license inventory was available, so absence of unknown licenses is not conclusive")
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
# Scanner-backed dynamic flag population
# ------------------------------------------------------------

DYNAMIC_NEGATIVE_FLAGS = {
    "has_api_keys_in_version_control",
    "has_exposes_signing_keys_in_source_or_ci",
    "has_secrets_generic_found",
    "has_dos_vulnerabilities",
    "has_log_injection_vulnerabilities",
    "has_malware_detections",
    "has_android_dynamic_code_loading",
    "has_buffer_overflow_vulnerabilities",
    "has_race_condition_vulnerabilities",
    "has_out_of_bounds_vulnerabilities",
    "has_memory_corruption_vulnerabilities",
    "has_integer_arithmetic_vulnerabilities",
    "has_content_provider_actively_exposed",
    "has_webview_addjavascriptinterface_present",
    "has_webview_javascript_interface_exposes_sensitive_functionality",
    "has_webview_javascript_interface_leaks_sensitive_data",
    "has_webview_remote_content",
    "has_webview_file_scheme",
    "has_insecure_http_based_webview_communication",
    "has_displays_sensitive_data_unmasked",
    "has_notification_leaks_sensitive_data",
    "has_notification_uses_public_channels",
    "has_stores_sensitive_data_on_device",
    "has_stores_pii_in_plaintext",
    "has_stores_auth_tokens_in_plaintext",
    "has_stores_keys_in_plaintext",
    "has_local_caching_of_ephi",
    "has_stores_ephi_on_external_storage",
    "has_sends_ephi_to_third_party_services",
    "has_uses_push_notifications_for_ephi",
    "has_access_tokens_weak_or_unpredictable",
    "has_error_messages_disclose_internal_details",
    "has_error_messages_sent_to_unauthorized_destinations",
    "has_third_party_trackers",
    "has_crash_reporting_tracker",
    "has_analytics_tracker",
    "has_privacy_relevant_tracker",
    "has_min_sdk_below_security_baseline",
    "has_target_sdk_below_security_baseline",
    "has_sast_security_findings",
    "has_codeql_security_findings",
    "has_semgrep_security_findings",
    "has_sast_high_confidence_security_findings",
    "has_dynamic_http_traffic_detected",
}

DYNAMIC_APPLICABILITY_FLAGS = {
    "has_webview_components",
    "has_webview_javascript",
    "has_soap_api_usage",
    "has_saml_based_sso",
}


def _iter_json_nodes(obj: Any, path: str = "") -> List[Tuple[str, Any]]:
    """Flatten dict/list JSON-like data into (path, value) nodes."""
    nodes: List[Tuple[str, Any]] = []
    stack: List[Tuple[str, Any]] = [(path, obj)]
    while stack:
        cur_path, cur = stack.pop()
        nodes.append((cur_path, cur))
        if isinstance(cur, dict):
            for key, value in cur.items():
                child_path = f"{cur_path}.{key}" if cur_path else str(key)
                stack.append((child_path, value))
        elif isinstance(cur, list):
            for idx, value in enumerate(cur):
                child_path = f"{cur_path}[{idx}]" if cur_path else f"[{idx}]"
                stack.append((child_path, value))
    return nodes


def _first_numeric_signal(obj: Any, key_tokens: List[str]) -> int | None:
    tokens = [t.lower() for t in key_tokens]
    for path, value in _iter_json_nodes(obj):
        path_low = path.lower()
        if not all(t in path_low for t in tokens):
            continue
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return int(value)
        if isinstance(value, str):
            m = re.search(r"\d+", value)
            if m:
                return int(m.group(0))
    return None


def _collect_json_text_evidence(source: str, obj: Any, tokens: List[str], rule_id: str, max_hits: int = 8) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    tokens_low = [t.lower() for t in tokens if t]
    for path, value in _iter_json_nodes(obj):
        if isinstance(value, (dict, list)):
            continue
        text = str(value)
        blob = f"{path} {text}".lower()
        if any(tok in blob for tok in tokens_low):
            hits.append(ev(source, path or source, rule_id, text))
        if len(hits) >= max_hits:
            break
    return hits


def _sast_security_level(result: Dict[str, Any], rule: Dict[str, Any]) -> str:
    blob = _sarif_result_blob(result, rule)
    level = str(result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "").lower()
    security_tokens = [
        "security", "cwe-", "injection", "xss", "csrf", "ssrf", "crypto", "cryptographic",
        "cleartext", "plaintext", "credential", "secret", "token", "password", "path traversal",
        "deserialization", "redos", "denial of service", "buffer overflow", "sql", "command injection",
        "unsafe", "weak", "certificate", "ssl", "tls", "permission", "webview", "content uri",
    ]
    quality_tokens = ["detekt.style", "detekt.naming", "magicnumber", "formatting", "complexity", "unused", "comment"]
    if any(t in blob for t in security_tokens):
        return "security"
    if any(t in blob for t in quality_tokens):
        return "quality"
    if level in {"error", "warning"}:
        return "unknown"
    return "quality"


def _collect_sast_bucket_evidence(data: Dict[str, Any], bucket: str, max_hits: int = 12) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    for source_name, result, rule in _iter_sarif_results(data.get("sast_merged") or {}, "SAST_MERGED") + _iter_sarif_results(data.get("sast_semgrep") or {}, "SAST_SEMGREP"):
        if _sast_security_level(result, rule) != bucket:
            continue
        hits.append(_sarif_to_evidence(source_name, result, rule, f"sast_{bucket}_finding"))
        if len(hits) >= max_hits:
            break
    return hits


def _tracker_text_matches(item: Dict[str, Any], tokens: List[str]) -> bool:
    blob = " ".join(str(item.get(k, "")) for k in ("name", "categories", "url", "network_signature", "code_signature")).lower()
    return any(tok.lower() in blob for tok in tokens if tok)


def _iter_mobsf_detected_trackers(mobsf_static: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return trackers that MobSF actually detected in the APK.

    MobSF reports both the number of trackers detected in the application and
    the total size of its tracker signature database. The latter commonly
    appears as ``total_trackers = 432`` and must not be interpreted as evidence
    that the app contains trackers. This helper intentionally reads only the
    explicit detected tracker list.
    """
    trackers_block = mobsf_static.get("trackers") if isinstance(mobsf_static, dict) else {}
    if not isinstance(trackers_block, dict):
        return []
    detected_count = trackers_block.get("detected_trackers")
    trackers = trackers_block.get("trackers")
    if not isinstance(trackers, list) or not trackers:
        return []
    try:
        if detected_count is not None and int(detected_count) <= 0:
            return []
    except Exception:
        pass
    out: List[Dict[str, Any]] = []
    for item in trackers:
        if isinstance(item, dict):
            out.append(item)
        elif isinstance(item, str) and item.strip():
            out.append({"name": item.strip()})
    return out


def _collect_tracker_evidence(data: Dict[str, Any], tokens: List[str], rule_id: str, max_hits: int = 8) -> List[Dict[str, str]]:
    """Collect privacy tracker evidence without false positives from MobSF metadata.

    Positive MobSF evidence must come from trackers.trackers[], not from
    total_trackers, appsec.total_trackers, generic log text, or the phrase
    "Detecting Trackers". Optional source-code evidence is restricted to
    known tracker SDK identifiers and is used only when source code is present.
    """
    hits: List[Dict[str, str]] = []
    mobsf_static = data.get("mobsf_static") or {}
    for idx, item in enumerate(_iter_mobsf_detected_trackers(mobsf_static)):
        if not _tracker_text_matches(item, tokens):
            continue
        name = str(item.get("name") or "unknown tracker")
        category = str(item.get("categories") or "")
        url = str(item.get("url") or "")
        excerpt = _compact_text(name, category, url)
        hits.append(ev("MobSF_STATIC", f"mobsf_results.json:trackers.trackers[{idx}]", rule_id, excerpt))
        if len(hits) >= max_hits:
            return hits[:max_hits]

    # Source fallback: use concrete SDK/package identifiers rather than generic words
    # like "tracker" or "analytics", which create false positives in documentation.
    sdk_patterns = []
    for tok in tokens:
        low = tok.lower().strip()
        if low in {"firebase analytics", "google analytics", "analytics"}:
            sdk_patterns.extend([r"FirebaseAnalytics", r"com\.google\.firebase\.analytics", r"google-services\.json"])
        elif low in {"crashlytics", "crash reporting"}:
            sdk_patterns.extend([r"FirebaseCrashlytics", r"com\.google\.firebase\.crashlytics", r"fabric\.io"])
        elif low == "sentry":
            sdk_patterns.extend([r"io\.sentry", r"Sentry\.init"])
        elif low == "mixpanel":
            sdk_patterns.extend([r"com\.mixpanel", r"MixpanelAPI"])
        elif low == "amplitude":
            sdk_patterns.extend([r"com\.amplitude", r"Amplitude"])
        elif low == "facebook":
            sdk_patterns.extend([r"com\.facebook\.appevents", r"AppEventsLogger"])
    if sdk_patterns and len(hits) < max_hits:
        hits.extend(_collect_source_evidence(data, sorted(set(sdk_patterns)), rule_id, max_hits - len(hits), runtime_only=True))
    return hits[:max_hits]


def _sdk_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    mobsf_static = data.get("mobsf_static") or {}
    min_sdk = _first_numeric_signal(mobsf_static, ["min", "sdk"])
    target_sdk = _first_numeric_signal(mobsf_static, ["target", "sdk"])
    manifest_text = data.get("source_manifest_text") or ""
    if min_sdk is None:
        m = re.search(r"minSdkVersion\s*=\s*['\"]?(\d+)", manifest_text, flags=re.IGNORECASE)
        min_sdk = int(m.group(1)) if m else None
    if target_sdk is None:
        m = re.search(r"targetSdkVersion\s*=\s*['\"]?(\d+)", manifest_text, flags=re.IGNORECASE)
        target_sdk = int(m.group(1)) if m else None
    evidence: List[Dict[str, str]] = []
    if min_sdk is not None:
        evidence.append(ev("MobSF_STATIC", "mobsf_results.json:sdk/min_sdk", "android_min_sdk", f"min_sdk={min_sdk}"))
    if target_sdk is not None:
        evidence.append(ev("MobSF_STATIC", "mobsf_results.json:sdk/target_sdk", "android_target_sdk", f"target_sdk={target_sdk}"))
    return {"min_sdk": min_sdk, "target_sdk": target_sdk, "evidence": evidence}


def _artifact_available(data: Dict[str, Any], key: str) -> bool:
    status = ((data.get("artifact_status") or {}).get(key) or {})
    return bool(status.get("exists") and status.get("is_zip") and not status.get("missing_required_members"))


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _safe_lower(value: Any) -> str:
    return str(value or "").lower()


def _compact_text(*parts: Any, max_len: int = 240) -> str:
    out = " ".join(str(p or "").strip() for p in parts if str(p or "").strip())
    out = re.sub(r"\s+", " ", out).strip()
    return out[:max_len] + ("..." if len(out) > max_len else "")


def _path_looks_runtime_source(path: str) -> bool:
    norm = normalize_path(path)
    if any(tok in norm for tok in ["/src/test/", "/src/androidtest/", "/test/", "/tests/", "/build/", "/generated/", "/.github/"]):
        return False
    return True


def _iter_sarif_results(sarif: Dict[str, Any], source_name: str) -> List[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []
    if not isinstance(sarif, dict):
        return out
    for run in sarif.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run.get("tool"), dict) else {}
        for rule in driver.get("rules", []) or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules_by_id[str(rule.get("id"))] = rule
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            rid = str(result.get("ruleId") or result.get("rule_id") or "")
            out.append((source_name, result, rules_by_id.get(rid, {})))
    return out


def _sarif_result_blob(result: Dict[str, Any], rule: Dict[str, Any]) -> str:
    parts = [
        result.get("ruleId"),
        ((result.get("message") or {}).get("text") if isinstance(result.get("message"), dict) else result.get("message")),
        rule.get("id"),
        rule.get("name"),
        ((rule.get("shortDescription") or {}).get("text") if isinstance(rule.get("shortDescription"), dict) else ""),
        ((rule.get("fullDescription") or {}).get("text") if isinstance(rule.get("fullDescription"), dict) else ""),
        rule.get("helpUri"),
    ]
    return _safe_lower(" ".join(str(p or "") for p in parts))


def _sarif_result_path(result: Dict[str, Any]) -> str:
    locs = result.get("locations") or []
    if not locs or not isinstance(locs, list):
        return "sarif:unknown"
    loc = locs[0] if isinstance(locs[0], dict) else {}
    phys = loc.get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    region = phys.get("region") or {}
    uri = str(art.get("uri") or "unknown")
    line = region.get("startLine")
    return f"{uri}:line{line}" if line else uri


def _sarif_to_evidence(source_name: str, result: Dict[str, Any], rule: Dict[str, Any], rule_id: str = "sarif_match") -> Dict[str, str]:
    msg = result.get("message") or {}
    msg_text = msg.get("text") if isinstance(msg, dict) else str(msg or "")
    rid = str(result.get("ruleId") or rule.get("id") or rule_id)
    return ev(source_name, _sarif_result_path(result), rid, _compact_text(msg_text or rule.get("name") or rid))


def _collect_sarif_evidence(data: Dict[str, Any], any_tokens: List[str], all_tokens: List[str] | None = None, max_hits: int = 8) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    all_tokens = all_tokens or []
    any_low = [t.lower() for t in any_tokens if t]
    all_low = [t.lower() for t in all_tokens if t]
    for source_name, sarif in [("SAST_MERGED", data.get("sast_merged") or {}), ("SAST_SEMGREP", data.get("sast_semgrep") or {})]:
        for src, result, rule in _iter_sarif_results(sarif, source_name):
            blob = _sarif_result_blob(result, rule)
            if all_low and not all(t in blob for t in all_low):
                continue
            if any_low and not any(t in blob for t in any_low):
                continue
            hits.append(_sarif_to_evidence(src, result, rule))
            if len(hits) >= max_hits:
                return hits
    return hits


def _collect_source_evidence(data: Dict[str, Any], regexes: List[str], rule_id: str, max_hits: int = 8, runtime_only: bool = True) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    texts = data.get("source_texts") or {}
    source_zip_name = data.get("source_zip_name") or "source.zip"
    source_label = data.get("source_label") or "SOURCE_CODE_REPOSITORY"
    for path in sort_paths_by_hints(list(texts.keys()), ["app/", "src/main/", "java/", "kotlin/", "res/"]):
        if runtime_only and not _path_looks_runtime_source(path):
            continue
        text = texts.get(path, "") or ""
        for regex in regexes:
            try:
                m = re.search(regex, text, flags=re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            if m:
                hits.append(ev(source_label, f"{source_zip_name}:{path}", rule_id, excerpt_at(text, m.start())))
                break
        if len(hits) >= max_hits:
            break
    return hits


def _collect_member_evidence(data: Dict[str, Any], regexes: List[str], rule_id: str, max_hits: int = 8) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    source_zip_name = data.get("source_zip_name") or "source.zip"
    source_label = data.get("source_label") or "SOURCE_CODE_REPOSITORY"
    for member in data.get("source_zip_members") or []:
        norm = normalize_path(member)
        for regex in regexes:
            if re.search(regex, norm, flags=re.IGNORECASE):
                hits.append(ev(source_label, f"{source_zip_name}:{member}", rule_id, member))
                break
        if len(hits) >= max_hits:
            break
    return hits


def _iter_urls(data: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    out: List[Tuple[str, str, str]] = []
    mobsf_static = data.get("mobsf_static") or {}
    mobsf_dynamic = data.get("mobsf_dynamic") or {}

    for idx, item in enumerate(_as_list(mobsf_static.get("urls"))):
        if isinstance(item, dict):
            value = item.get("url") or item.get("URL") or item.get("value") or item.get("path")
        else:
            value = item
        if value:
            out.append(("MobSF_STATIC", f"mobsf_results.json:urls[{idx}]", str(value)))

    for idx, item in enumerate(_as_list(mobsf_dynamic.get("urls"))):
        if isinstance(item, dict):
            value = item.get("url") or item.get("URL") or item.get("value") or item.get("path")
        else:
            value = item
        if value:
            out.append(("MobSF_DYNAMIC", f"mobsf_dynamic_results.json:urls[{idx}]", str(value)))

    for source_name, obj, root in [("MobSF_STATIC", mobsf_static.get("domains"), "mobsf_results.json:domains"), ("MobSF_DYNAMIC", mobsf_dynamic.get("domains"), "mobsf_dynamic_results.json:domains")]:
        if isinstance(obj, dict):
            for key, value in obj.items():
                out.append((source_name, f"{root}.{key}", str(key)))
                if isinstance(value, str):
                    out.append((source_name, f"{root}.{key}", value))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                out.append((source_name, f"{root}[{idx}]", str(item)))
    return out


def _url_evidence(data: Dict[str, Any], predicate, rule_id: str, max_hits: int = 8) -> List[Dict[str, str]]:
    hits = []
    for source, path, value in _iter_urls(data):
        if predicate(str(value)):
            hits.append(ev(source, path, rule_id, str(value)))
        if len(hits) >= max_hits:
            break
    return hits


def _sca_findings_matching(sca: Dict[str, Any], tokens: List[str], cwes: List[str] | None = None, max_hits: int = 8) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    cwes_low = {c.lower() for c in (cwes or [])}
    tokens_low = [t.lower() for t in tokens if t]
    for finding in sca.get("findings") or []:
        cwe_values = [str(x).lower() for x in (finding.get("cwe") or finding.get("CweIDs") or finding.get("CWEIDs") or [])]
        blob = _safe_lower(" ".join([
            str(finding.get("id") or ""),
            str(finding.get("pkg") or ""),
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            " ".join(cwe_values),
        ]))
        if cwes_low and any(c in cwe_values or c in blob for c in cwes_low):
            hits.append(_sca_finding_evidence(finding))
        elif tokens_low and any(t in blob for t in tokens_low):
            hits.append(_sca_finding_evidence(finding))
        if len(hits) >= max_hits:
            break
    return hits


def _mobsf_text_evidence(data: Dict[str, Any], tokens: List[str], rule_id: str, max_hits: int = 8) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    tokens_low = [t.lower() for t in tokens if t]
    def walk(obj: Any, path: str) -> None:
        if len(hits) >= max_hits:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")
        else:
            text = str(obj or "")
            low = text.lower()
            if any(t in low for t in tokens_low):
                hits.append(ev("MobSF_STATIC", f"mobsf_results.json:{path}", rule_id, text))
    for key in ["code_analysis", "manifest_analysis", "niap_analysis", "binary_analysis", "file_analysis", "malware_permissions", "appsec", "network_security", "trackers"]:
        walk((data.get("mobsf_static") or {}).get(key), key)
    return hits


def _dynamic_storage_evidence(data: Dict[str, Any], tokens: List[str], rule_id: str, max_hits: int = 8) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    tokens_low = [t.lower() for t in tokens if t]
    dyn = data.get("mobsf_dynamic") or {}
    for key in ["sqlite", "xml", "others", "clipboard", "base64_strings", "droidmon", "apimon", "frida_logs"]:
        value = dyn.get(key)
        items = value if isinstance(value, list) else [value] if value else []
        for idx, item in enumerate(items):
            text = json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list)) else str(item or "")
            low = text.lower()
            if not tokens_low or any(t in low for t in tokens_low):
                hits.append(ev("MobSF_DYNAMIC", f"mobsf_dynamic_results.json:{key}[{idx}]", rule_id, text))
            if len(hits) >= max_hits:
                return hits
    return hits


def _packages_matching(sca: Dict[str, Any], tokens: List[str], rule_id: str, max_hits: int = 8) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    tokens_low = [t.lower() for t in tokens if t]
    for pkg in sca.get("packages") or []:
        name = " ".join(str(pkg.get(k) or "") for k in ["Name", "PkgName", "ID", "PkgID", "name", "pkg", "pkg_id"])
        if any(t in name.lower() for t in tokens_low):
            hits.append(ev("TRIVY", "trivy.json:Results[].Packages", rule_id, name))
        if len(hits) >= max_hits:
            break
    return hits


def _known_dynamic_flag_ids() -> set[str]:
    return set(DYNAMIC_FLAG_DEFINITIONS.keys())


def _build_dynamic_verdict(flag_id: str, has_feature: bool, evidence: List[Dict[str, str]], kind: str, notes_yes: str, notes_no: str, evidence_count: int | None = None) -> Dict[str, Any]:
    if kind == "negative":
        state = "fail" if has_feature else "pass"
    elif kind == "applicability":
        state = "pass" if has_feature else "not_applicable"
    else:
        state = "pass" if has_feature else "fail"
    out: Dict[str, Any] = {
        "state": state,
        "summary": f"{flag_id} = {'YES' if has_feature else 'NO'}",
        "notes": notes_yes if has_feature else notes_no,
        "evidence": evidence[:12],
    }
    if evidence_count is not None:
        out["evidence_count_override"] = evidence_count
    return out


def detect_dynamic_flags(data: Dict[str, Any], features: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    sca = features.get("sca") or {}
    tls_pinning = features.get("tls_pinning") or {}
    permissions = features.get("permissions") or {}
    out: Dict[str, Dict[str, Any]] = {}

    def put(flag_id: str, has_feature: bool, evidence: List[Dict[str, str]], kind: str | None = None, yes: str = "Scanner-backed evidence was found.", no: str = "Scanner-backed detector executed and did not find matching evidence.", count: int | None = None) -> None:
        k = kind or ("negative" if flag_id in DYNAMIC_NEGATIVE_FLAGS else "applicability" if flag_id in DYNAMIC_APPLICABILITY_FLAGS else "positive")
        out[flag_id] = _build_dynamic_verdict(flag_id, has_feature, evidence, k, yes, no, count)

    # Secrets and signing exposure.
    secret_evidence = []
    secret_evidence.extend(_mobsf_text_evidence(data, ["secret", "api key", "apikey", "password", "token"], "mobsf_secret_indicator", 4))
    secret_evidence.extend(_collect_sarif_evidence(data, ["secret", "api key", "apikey", "password", "credential", "private key"], max_hits=4))
    secret_evidence.extend(_collect_source_evidence(data, [r"(?i)(api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}", r"(?i)AIza[0-9A-Za-z_\-]{20,}", r"(?i)-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"], "source_secret_literal", 4, runtime_only=False))
    signing_member_evidence = _collect_member_evidence(data, [r"\.(jks|keystore|p12|pfx)$", r"release\.keystore", r"signing"], "signing_key_or_config_in_source", 8)
    put("has_secrets_generic_found", bool(secret_evidence), secret_evidence, "negative", "Secrets or credential-like literals were detected by scan artifacts or source scanning.", "No scanner-backed secret indicators were found.", len(secret_evidence))
    put("has_secrets_count", bool(secret_evidence), secret_evidence, "negative", f"Scanner-backed secret indicators found: {len(secret_evidence)}.", "No scanner-backed secret indicators were found.", len(secret_evidence))
    put("has_api_keys_in_version_control", bool(secret_evidence), secret_evidence, "negative", "API key or credential-like evidence was found in repository-scanned artifacts.", "No API key indicator was found in repository-scanned artifacts.", len(secret_evidence))
    put("has_exposes_signing_keys_in_source_or_ci", bool(signing_member_evidence), signing_member_evidence, "negative", "Signing key or signing credential file/config evidence was found in source inventory.", "No signing key file exposure was found in source inventory.", len(signing_member_evidence))

    ci_env = _collect_source_evidence(data, [r"\$\{\{\s*secrets\.", r"System\.getenv\s*\(", r"getenv\s*\("], "ci_or_env_secret_usage", 8, runtime_only=False)
    put("has_env_specific_api_credentials_configured", bool(ci_env), ci_env, "positive", "Environment or CI secret references were found for API credentials.", "No environment-specific API credential reference was found.", len(ci_env))
    put("has_ci_cd_uses_encrypted_keys", bool(ci_env), ci_env, "positive", "CI secret references indicate encrypted key handling through the CI secret store.", "No CI secret-store reference for encrypted key handling was found.", len(ci_env))

    # Network security and TLS.
    nsc_evidence = []
    nsc_evidence.extend(_collect_source_evidence(data, [r"android\s*:\s*networkSecurityConfig\s*=", r"network_security_config"], "network_security_config_reference", 4, runtime_only=False))
    nsc_evidence.extend(_collect_member_evidence(data, [r"res/xml/.+network.*security.*\.xml$", r"network_security_config\.xml$"], "network_security_config_file", 4))
    if (data.get("mobsf_static") or {}).get("network_security"):
        nsc_evidence.append(ev("MobSF_STATIC", "mobsf_results.json:network_security", "network_security_section", "MobSF network_security section is present"))
    put("has_network_security_config_present", bool(nsc_evidence), nsc_evidence, "positive", "Network security configuration evidence was found.", "No network security configuration evidence was found.", len(nsc_evidence))

    https_evidence = _url_evidence(data, lambda u: u.lower().startswith("https://"), "https_endpoint", 8)
    http_bad = _url_evidence(data, lambda u: u.lower().startswith("http://") and "localhost" not in u.lower() and "127.0.0.1" not in u.lower(), "unapproved_http_endpoint", 8)
    pinning_evidence = (tls_pinning.get("evidence") or []) if tls_pinning.get("has_pinning") else []
    put("has_https_with_cert_pinning", bool(https_evidence and pinning_evidence), (https_evidence + pinning_evidence)[:12], "positive", "HTTPS endpoints and certificate pinning evidence were both found.", "HTTPS plus certificate pinning was not confirmed from scan artifacts.", len((https_evidence + pinning_evidence)[:12]))
    put("has_approved_ports_and_protocols", not bool(http_bad) and bool(_iter_urls(data)), http_bad or https_evidence[:4], "positive", "Observed endpoints use approved HTTP(S)-family protocols without unapproved cleartext HTTP findings.", "Unapproved or cleartext protocol evidence was found, or no endpoint evidence was available.", len(http_bad or https_evidence[:4]))

    # Vulnerability semantic flags from Trivy, SARIF, MobSF.
    vuln_specs = {
        "has_dos_vulnerabilities": (["denial of service", "dos", "resource exhaustion"], ["cwe-400", "cwe-770"]),
        "has_log_injection_vulnerabilities": (["log injection", "log forging", "cwe-117"], ["cwe-117"]),
        "has_buffer_overflow_vulnerabilities": (["buffer overflow"], ["cwe-120", "cwe-121", "cwe-122"]),
        "has_race_condition_vulnerabilities": (["race condition", "time-of-check", "time of check"], ["cwe-362", "cwe-367"]),
        "has_out_of_bounds_vulnerabilities": (["out-of-bounds", "out of bounds"], ["cwe-125", "cwe-787"]),
        "has_memory_corruption_vulnerabilities": (["memory corruption", "use after free", "use-after-free", "double free", "double-free"], ["cwe-416", "cwe-415"]),
        "has_integer_arithmetic_vulnerabilities": (["integer overflow", "integer underflow", "wraparound", "numeric overflow"], ["cwe-190", "cwe-191", "cwe-681"]),
    }
    for flag_id, (tokens, cwes) in vuln_specs.items():
        evidence = []
        evidence.extend(_sca_findings_matching(sca, tokens, cwes, 8))
        evidence.extend(_collect_sarif_evidence(data, tokens + cwes, max_hits=max(0, 8 - len(evidence))))
        evidence.extend(_mobsf_text_evidence(data, tokens + cwes, flag_id, max_hits=max(0, 8 - len(evidence))))
        put(flag_id, bool(evidence), evidence, "negative", f"Scanner findings matched {flag_id}.", f"No scanner findings matched {flag_id}.", len(evidence))

    malware_evidence = []
    if (data.get("mobsf_static") or {}).get("malware_permissions"):
        malware_evidence.append(ev("MobSF_STATIC", "mobsf_results.json:malware_permissions", "malware_permissions", json.dumps((data.get("mobsf_static") or {}).get("malware_permissions"), ensure_ascii=False)[:200]))
    malware_evidence.extend(_mobsf_text_evidence(data, ["malware", "trojan", "spyware", "virus", "ransomware", "adware"], "malware_indicator", 8 - len(malware_evidence)))
    malware_evidence.extend(_collect_sarif_evidence(data, ["malware", "trojan", "spyware", "virus", "ransomware", "adware"], max_hits=8 - len(malware_evidence)))
    put("has_malware_detections", bool(malware_evidence), malware_evidence, "negative", "Malware-like indicators were reported by scan artifacts.", "No malware-like indicators were reported by scan artifacts.", len(malware_evidence))

    tamper_evidence = []
    tamper_evidence.extend(_collect_source_evidence(data, [r"SafetyNet", r"PlayIntegrity", r"IntegrityManager", r"isDeviceRooted", r"rootbeer", r"signature.*verify", r"getPackageInfo\s*\("], "tamper_or_integrity_protection", 8))
    tamper_evidence.extend(_collect_sarif_evidence(data, ["tamper", "integrity", "root", "signature verification"], max_hits=4))
    put("has_protection_against_tampered_executables", bool(tamper_evidence), tamper_evidence, "positive", "Tamper, integrity, root, or signature verification evidence was found.", "No tamper or executable integrity protection evidence was found.", len(tamper_evidence))

    dynamic_code_evidence = []
    dynamic_code_evidence.extend(_collect_source_evidence(data, [r"DexClassLoader", r"PathClassLoader", r"loadDex\s*\(", r"dalvik\.system", r"System\.load\s*\(", r"System\.loadLibrary\s*\(", r"Runtime\.getRuntime\s*\(\)\.exec"], "dynamic_code_loading", 8))
    dynamic_code_evidence.extend(_collect_sarif_evidence(data, ["dynamic code", "dexclassloader", "pathclassloader", "loadlibrary"], max_hits=4))
    dynamic_code_evidence.extend(_mobsf_text_evidence(data, ["dynamic code loading", "dexclassloader", "pathclassloader"], "dynamic_code_loading", 4))
    put("has_android_dynamic_code_loading", bool(dynamic_code_evidence), dynamic_code_evidence, "negative", "Dynamic code loading evidence was found.", "No dynamic code loading evidence was found.", len(dynamic_code_evidence))

    native_lib_members = _collect_member_evidence(data, [r"\.so$", r"/jni/", r"/jniLibs/"], "native_library_inventory", 8)
    unsafe_native = [e for e in native_lib_members if "/data/local/tmp" in e.get("path", "").lower() or "download" in e.get("path", "").lower()]
    put("has_libraries_stored_in_secure_app_dir", bool(native_lib_members) and not unsafe_native, native_lib_members[:8], "positive", "Native libraries were found only in packaged application paths.", "Native library secure app-directory placement was not confirmed.", len(native_lib_members[:8]))

    # IPC, providers, WebView.
    provider_evidence = []
    providers = (data.get("mobsf_static") or {}).get("providers") or []
    if providers:
        provider_evidence.append(ev("MobSF_STATIC", "mobsf_results.json:providers", "providers_present", json.dumps(providers, ensure_ascii=False)[:200]))
    provider_evidence.extend(_collect_sarif_evidence(data, ["content provider", "exported provider", "provider exported"], max_hits=4))
    put("has_content_provider_actively_exposed", bool(provider_evidence), provider_evidence, "negative", "Content provider exposure evidence was found.", "No content provider exposure evidence was found.", len(provider_evidence))

    bind_evidence = _collect_source_evidence(data, [r"bindService\s*\(", r"android:permission\s*=", r"BIND_"], "bindservice_or_service_permission", 8)
    put("has_ipc_bindservice_secure", bool(bind_evidence), bind_evidence, "positive", "Service binding or permission protection evidence was found.", "No explicit secure bindService or service permission evidence was found.", len(bind_evidence))

    webview_components = _collect_source_evidence(data, [r"\bWebView\b", r"android\.webkit\.WebView"], "webview_component", 8)
    webview_js = _collect_source_evidence(data, [r"setJavaScriptEnabled\s*\(\s*true\s*\)"], "webview_javascript_enabled", 8)
    webview_bridge = _collect_source_evidence(data, [r"addJavascriptInterface\s*\("], "webview_addjavascriptinterface", 8)
    webview_file = _collect_source_evidence(data, [r"setAllowFileAccess\s*\(\s*true\s*\)", r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)", r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)", r"file://"], "webview_file_scheme", 8)
    webview_remote = _collect_source_evidence(data, [r"\.loadUrl\s*\(\s*['\"]https?://", r"WebViewClient", r"shouldOverrideUrlLoading"], "webview_remote_content", 8)
    webview_http = _collect_source_evidence(data, [r"\.loadUrl\s*\(\s*['\"]http://", r"WebView[^\n]{0,120}http://", r"shouldOverrideUrlLoading[^\n]{0,240}http://"], "webview_http_content", 8)
    put("has_webview_components", bool(webview_components), webview_components, "applicability", "WebView component evidence was found.", "No WebView component evidence was found.", len(webview_components))
    put("has_webview_javascript", bool(webview_js), webview_js, "applicability", "WebView JavaScript enablement evidence was found.", "No WebView JavaScript enablement evidence was found.", len(webview_js))
    put("has_webview_addjavascriptinterface_present", bool(webview_bridge), webview_bridge, "negative", "WebView JavaScript interface bridge evidence was found.", "No WebView JavaScript interface bridge evidence was found.", len(webview_bridge))
    put("has_webview_file_scheme", bool(webview_file), webview_file, "negative", "WebView file-scheme or file-access evidence was found.", "No WebView file-scheme or file-access evidence was found.", len(webview_file))
    put("has_webview_remote_content", bool(webview_remote), webview_remote, "negative", "WebView remote content loading evidence was found.", "No WebView remote content loading evidence was found.", len(webview_remote))
    put("has_insecure_http_based_webview_communication", bool(webview_http), webview_http, "negative", "WebView cleartext HTTP loading evidence was found.", "No WebView cleartext HTTP loading evidence was found.", len(webview_http))
    put("has_webview_javascript_interface_limited_to_trusted_content", bool(webview_bridge) and not bool(webview_http), (webview_bridge + webview_http)[:12], "positive", "JavaScript bridge evidence exists without cleartext HTTP WebView loading evidence.", "Trusted-content restriction for JavaScript interfaces was not confirmed.", len((webview_bridge + webview_http)[:12]))
    sensitive_bridge = webview_bridge and _collect_source_evidence(data, [r"addJavascriptInterface[\s\S]{0,500}(patient|token|password|credential|secret|ephi|phi|medical|obs|encounter)"], "webview_sensitive_bridge", 8)
    put("has_webview_javascript_interface_exposes_sensitive_functionality", bool(sensitive_bridge), sensitive_bridge if isinstance(sensitive_bridge, list) else [], "negative", "WebView JavaScript bridge appears near sensitive functionality tokens.", "No sensitive-functionality WebView bridge evidence was found.", len(sensitive_bridge if isinstance(sensitive_bridge, list) else []))
    put("has_webview_javascript_interface_leaks_sensitive_data", bool(sensitive_bridge and webview_http), ((sensitive_bridge if isinstance(sensitive_bridge, list) else []) + webview_http)[:12], "negative", "Sensitive WebView bridge evidence and cleartext HTTP WebView loading were both found.", "No combined sensitive WebView bridge and cleartext HTTP evidence was found.", len(((sensitive_bridge if isinstance(sensitive_bridge, list) else []) + webview_http)[:12]))

    # Crypto, auth, token, SOAP/SAML/XML.
    key_store = _collect_source_evidence(data, [r"AndroidKeyStore", r"KeyStore\.getInstance\s*\(\s*['\"]AndroidKeyStore", r"MasterKey\b", r"MasterKeys\b"], "android_keystore_usage", 8)
    crypto = _collect_source_evidence(data, [r"Cipher\.getInstance\s*\(", r"AES/GCM", r"EncryptedSharedPreferences", r"EncryptedFile", r"SQLCipher", r"SecretKeySpec", r"KeyGenParameterSpec"], "client_crypto_usage", 8)
    strongbox = _collect_source_evidence(data, [r"setIsStrongBoxBacked\s*\(\s*true\s*\)", r"isInsideSecureHardware", r"StrongBox"], "hardware_backed_key_storage", 8)
    put("has_os_secure_key_storage", bool(key_store), key_store, "positive", "Android Keystore or Jetpack security key storage evidence was found.", "No Android secure key storage evidence was found.", len(key_store))
    put("has_client_side_crypto_for_sensitive_data", bool(crypto), crypto, "positive", "Client-side cryptographic storage or encryption API usage was found.", "No client-side cryptographic storage or encryption API usage was found.", len(crypto))
    put("has_sensitive_data_encrypted_with_os_keystore", bool(key_store and crypto), (key_store + crypto)[:12], "positive", "Android Keystore and encryption API evidence were both found.", "Encryption tied to Android Keystore was not confirmed.", len((key_store + crypto)[:12]))
    put("has_auth_keys_stored_in_secure_hardware", bool(strongbox), strongbox, "positive", "Hardware-backed key storage evidence was found.", "No hardware-backed key storage evidence was found.", len(strongbox))

    oauth = _collect_source_evidence(data, [r"OAuth", r"AuthorizationService", r"AuthorizationRequest", r"AppAuth", r"oauth2"], "oauth2_usage", 8)
    jwt = _collect_source_evidence(data, [r"\bJWT\b", r"JsonWebToken", r"io\.jsonwebtoken", r"com\.auth0\.jwt", r"jose4j"], "jwt_usage", 8)
    token = _collect_source_evidence(data, [r"Bearer\s+", r"access[_-]?token", r"refresh[_-]?token", r"Authorization\"\s*,\s*\"Bearer", r"Authorization\""], "token_auth_usage", 8)
    weak_token = _collect_source_evidence(data, [r"(token|session|nonce)[\s\S]{0,120}(Math\.random|java\.util\.Random|UUID\.randomUUID)", r"Random\s*\([^)]*\)[\s\S]{0,120}(token|session|nonce)"], "weak_token_generation", 8)
    put("has_oauth2_authentication", bool(oauth), oauth, "positive", "OAuth2/AppAuth evidence was found.", "No OAuth2/AppAuth evidence was found.", len(oauth))
    put("has_jwt_tokens", bool(jwt), jwt, "positive", "JWT evidence was found.", "No JWT evidence was found.", len(jwt))
    put("has_token_based_auth", bool(token or jwt or oauth), (token + jwt + oauth)[:12], "positive", "Token-based authentication evidence was found.", "No token-based authentication evidence was found.", len((token + jwt + oauth)[:12]))
    put("has_access_tokens_weak_or_unpredictable", bool(weak_token), weak_token, "negative", "Weak or predictable token generation evidence was found.", "No weak or predictable token generation evidence was found.", len(weak_token))

    soap = _collect_source_evidence(data, [r"\bSOAP\b", r"SoapObject", r"SoapSerializationEnvelope", r"ksoap", r"javax\.xml\.soap"], "soap_usage", 8)
    soap_https = _collect_source_evidence(data, [r"https://[^\s'\"]*(soap|wsdl|saml|service)", r"(soap|wsdl|saml)[^\n]{0,200}https://"], "soap_tls_endpoint", 8)
    soap_http = _collect_source_evidence(data, [r"http://[^\s'\"]*(soap|wsdl|saml|service)", r"(soap|wsdl|saml)[^\n]{0,200}http://"], "soap_cleartext_endpoint", 8)
    mtls = _collect_source_evidence(data, [r"KeyManagerFactory", r"SSLContext\.init\s*\([^,]+,\s*keyManagers", r"client certificate", r"mutual tls", r"mTLS"], "mutual_tls_usage", 8)
    saml = _collect_source_evidence(data, [r"\bSAML\b", r"saml2", r"OpenSAML", r"SecurityAssertion"], "saml_usage", 8)
    xml_sig = _collect_source_evidence(data, [r"XMLSignature", r"javax\.xml\.crypto\.dsig", r"SignedInfo", r"SignatureMethod"], "xml_signature_usage", 8)
    xml_enc = _collect_source_evidence(data, [r"XMLCipher", r"EncryptedData", r"XML Encryption", r"xenc:"], "xml_encryption_usage", 8)
    wssec = _collect_source_evidence(data, [r"WS-Security", r"wsse:", r"WSSec", r"UsernameToken", r"Timestamp"], "ws_security_usage", 8)
    xsd = _collect_source_evidence(data, [r"SchemaFactory", r"XMLConstants\.W3C_XML_SCHEMA_NS_URI", r"setSchema\s*\("], "xml_schema_validation", 8)
    put("has_soap_api_usage", bool(soap), soap, "applicability", "SOAP client evidence was found.", "No SOAP client evidence was found.", len(soap))
    put("has_soap_uses_tls", bool(soap_https) and not bool(soap_http), (soap_https + soap_http)[:12], "positive", "SOAP endpoints appear to use HTTPS and no SOAP cleartext endpoint was found.", "SOAP TLS usage was not confirmed, or a cleartext SOAP endpoint was found.", len((soap_https + soap_http)[:12]))
    put("has_soap_uses_mutual_tls", bool(mtls), mtls, "positive", "Mutual TLS client-certificate evidence was found.", "No mutual TLS client-certificate evidence was found.", len(mtls))
    put("has_saml_based_sso", bool(saml), saml, "applicability", "SAML/SSO evidence was found.", "No SAML/SSO evidence was found.", len(saml))
    put("has_uses_xml_signatures", bool(xml_sig), xml_sig, "positive", "XML digital signature evidence was found.", "No XML digital signature evidence was found.", len(xml_sig))
    put("has_uses_xml_encryption", bool(xml_enc), xml_enc, "positive", "XML encryption evidence was found.", "No XML encryption evidence was found.", len(xml_enc))
    put("has_proper_ws_security_headers", bool(wssec), wssec, "positive", "WS-Security header evidence was found.", "No WS-Security header evidence was found.", len(wssec))
    put("has_soap_message_level_encryption", bool(xml_enc and soap), (xml_enc + soap)[:12], "positive", "SOAP and XML message encryption evidence were both found.", "SOAP message-level encryption was not confirmed.", len((xml_enc + soap)[:12]))
    put("has_soap_message_level_signatures", bool(xml_sig and soap), (xml_sig + soap)[:12], "positive", "SOAP and XML signature evidence were both found.", "SOAP message-level signatures were not confirmed.", len((xml_sig + soap)[:12]))
    put("has_soap_prevents_replay_attacks", bool(wssec and _collect_source_evidence(data, [r"Nonce", r"Timestamp", r"Created", r"Expires"], "soap_replay_prevention", 8)), wssec[:8], "positive", "WS-Security timestamp/nonce evidence was found.", "SOAP replay-prevention evidence was not confirmed.", len(wssec[:8]))
    put("has_soap_validates_saml_token_audience", bool(saml and _collect_source_evidence(data, [r"AudienceRestriction", r"audience"], "saml_audience_validation", 8)), saml[:8], "positive", "SAML audience validation evidence was found.", "SAML audience validation evidence was not confirmed.", len(saml[:8]))
    put("has_soap_validates_saml_token_expiry", bool(saml and _collect_source_evidence(data, [r"NotOnOrAfter", r"Conditions", r"expiry", r"expiration"], "saml_expiry_validation", 8)), saml[:8], "positive", "SAML expiry validation evidence was found.", "SAML expiry validation evidence was not confirmed.", len(saml[:8]))
    put("has_soap_uses_strict_schema_validation", bool(xsd), xsd, "positive", "XML schema validation evidence was found.", "No XML schema validation evidence was found.", len(xsd))
    put("has_soap_masks_sensitive_data_in_logs", bool(soap and _collect_source_evidence(data, [r"mask", r"redact", r"sanitize"], "soap_log_masking", 8)), soap[:8], "positive", "SOAP and masking/redaction evidence were found.", "SOAP log masking evidence was not confirmed.", len(soap[:8]))

    # Logging, resilience, UI and local storage.
    log_sanitize = _collect_source_evidence(data, [r"sanitize.*log", r"mask.*log", r"redact", r"escape.*log", r"Logger"], "log_sanitization_or_logging", 8)
    log_injection = _collect_sarif_evidence(data, ["log injection", "log forging", "cwe-117"], max_hits=8)
    err_internal = _collect_source_evidence(data, [r"printStackTrace\s*\(", r"Log\.(e|w|d|i)\s*\([^\n]{0,160}(exception|stack|Throwable|getMessage\s*\(\))", r"Toast\.[^\n]{0,160}(Exception|getMessage\s*\(\))"], "error_disclosure", 8)
    generic_err = _collect_source_evidence(data, [r"try\s*\{", r"catch\s*\([^)]*Exception", r"show.*error", r"generic.*error"], "generic_error_handling", 8)
    priv_logs = _collect_source_evidence(data, [r"audit", r"privileged", r"timestamp", r"System\.currentTimeMillis", r"Instant\.now"], "audit_or_timestamp_logging", 8)
    put("has_data_format_strictly_controlled", bool(_collect_source_evidence(data, [r"@SerializedName", r"Moshi", r"Gson", r"JsonAdapter", r"SchemaFactory"], "structured_data_format", 8)), _collect_source_evidence(data, [r"@SerializedName", r"Moshi", r"Gson", r"JsonAdapter", r"SchemaFactory"], "structured_data_format", 8), "positive", "Structured serialization or schema validation evidence was found.", "No structured data-format control evidence was found.")
    put("has_log_input_sanitization_present", bool(log_sanitize), log_sanitize, "positive", "Log sanitization/masking evidence was found.", "No log sanitization/masking evidence was found.", len(log_sanitize))
    put("has_log_injection_vulnerabilities", bool(log_injection), log_injection, "negative", "Log injection findings were reported by SAST.", "No log injection findings were reported by SAST.", len(log_injection))
    put("has_logs_privileged_actions_with_timestamp", bool(priv_logs), priv_logs, "positive", "Audit/timestamp logging evidence was found.", "No privileged-action timestamp logging evidence was found.", len(priv_logs))
    put("has_error_messages_disclose_internal_details", bool(err_internal), err_internal, "negative", "Internal exception or stack detail disclosure evidence was found.", "No internal exception or stack detail disclosure evidence was found.", len(err_internal))
    put("has_error_messages_are_generic", bool(generic_err) and not bool(err_internal), (generic_err + err_internal)[:12], "positive", "Generic error-handling evidence was found without direct internal disclosure matches.", "Generic error handling was not confirmed.", len((generic_err + err_internal)[:12]))
    put("has_error_messages_sent_to_unauthorized_destinations", bool(_url_evidence(data, lambda u: any(x in u.lower() for x in ["sentry", "crashlytics", "bugsnag", "datadog"]), "external_error_destination", 8)), _url_evidence(data, lambda u: any(x in u.lower() for x in ["sentry", "crashlytics", "bugsnag", "datadog"]), "external_error_destination", 8), "negative", "External error reporting destination evidence was found.", "No external error reporting destination evidence was found.")

    null_protection = _collect_source_evidence(data, [r"Objects\.requireNonNull", r"requireNotNull", r"checkNotNull", r"Optional<", r"\?\.", r"?:"], "null_safety_or_guard", 8)
    startup_params = _collect_source_evidence(data, [r"onCreate\s*\(", r"init\w*\s*\(", r"initialize\w*\s*\(", r"ApplicationConstants"], "startup_initialization", 8)
    fail_safe = _collect_source_evidence(data, [r"catch\s*\([^)]*Exception", r"fallback", r"failSafe", r"safe mode", r"return false"], "fail_safe_handling", 8)
    killswitch = _collect_source_evidence(data, [r"kill.?switch", r"feature.?flag", r"remote.?config", r"disable.*feature"], "kill_switch_or_feature_flag", 8)
    workmanager = _collect_source_evidence(data, [r"WorkManager", r"OneTimeWorkRequest", r"PeriodicWorkRequest", r"enqueueUniqueWork"], "workmanager_resilience", 8)
    recovery = _collect_source_evidence(data, [r"transaction", r"rollback", r"retry", r"recovery", r"journal"], "transaction_recovery", 8)
    put("has_null_pointer_protection_implemented", bool(null_protection), null_protection, "positive", "Null-safety or null-guard evidence was found.", "No null-safety or null-guard evidence was found.", len(null_protection))
    put("has_initializes_params_on_startup", bool(startup_params), startup_params, "positive", "Startup initialization evidence was found.", "No startup initialization evidence was found.", len(startup_params))
    put("has_fails_safe_on_init_failure", bool(fail_safe), fail_safe, "positive", "Fail-safe or fallback handling evidence was found.", "No fail-safe initialization evidence was found.", len(fail_safe))
    put("has_runtime_global_kill_switch_for_security_incidents", bool(killswitch), killswitch, "positive", "Runtime kill-switch or feature-flag evidence was found.", "No runtime global kill-switch evidence was found.", len(killswitch))
    put("has_safe_mode_degraded_functionality_design", bool(killswitch or fail_safe), (killswitch + fail_safe)[:12], "positive", "Safe-mode, feature-flag, or fallback evidence was found.", "No safe-mode or degraded-functionality evidence was found.", len((killswitch + fail_safe)[:12]))
    put("has_workmanager_for_resilient_network_tasks", bool(workmanager), workmanager, "positive", "WorkManager resilient background task evidence was found.", "No WorkManager resilient task evidence was found.", len(workmanager))
    put("has_transaction_recovery_logs", bool(recovery), recovery, "positive", "Transaction recovery, retry, or rollback evidence was found.", "No transaction recovery evidence was found.", len(recovery))

    flag_secure = _collect_source_evidence(data, [r"FLAG_SECURE", r"setFlags\s*\([^\n]*FLAG_SECURE"], "android_flag_secure", 8)
    masking = _collect_source_evidence(data, [r"PasswordTransformationMethod", r"inputType\s*=\s*['\"][^'\"]*textPassword", r"TYPE_TEXT_VARIATION_PASSWORD", r"mask", r"redact"], "ui_masking", 8)
    clear_background = _collect_source_evidence(data, [r"onPause\s*\(", r"onStop\s*\(", r"onUserLeaveHint\s*\(", r"clear.*screen", r"hide.*sensitive"], "ui_background_clear", 8)
    notification = _collect_source_evidence(data, [r"NotificationCompat", r"NotificationManager", r"FirebaseMessagingService", r"RemoteMessage"], "notification_usage", 8)
    notif_secure = _collect_source_evidence(data, [r"VISIBILITY_SECRET", r"VISIBILITY_PRIVATE", r"setVisibility\s*\(\s*NotificationCompat\.VISIBILITY_(PRIVATE|SECRET)"], "secure_notification_visibility", 8)
    notif_sensitive = _collect_source_evidence(data, [r"Notification[^\n]{0,240}(patient|ephi|phi|medical|diagnosis|encounter|obs|token|password)"], "sensitive_notification_content", 8)
    public_channel = _collect_source_evidence(data, [r"IMPORTANCE_HIGH", r"CATEGORY_MESSAGE", r"setPublicVersion", r"VISIBILITY_PUBLIC"], "public_notification_channel", 8)
    put("has_blocks_screenshots_flag_secure", bool(flag_secure), flag_secure, "positive", "FLAG_SECURE evidence was found.", "No FLAG_SECURE evidence was found.", len(flag_secure))
    put("has_ui_data_masking", bool(masking), masking, "positive", "UI masking or password transformation evidence was found.", "No UI masking evidence was found.", len(masking))
    put("has_displays_sensitive_data_unmasked", bool(_dynamic_storage_evidence(data, ["screenshot", "patient", "password", "token"], "dynamic_sensitive_ui", 4) and not masking), _dynamic_storage_evidence(data, ["screenshot", "patient", "password", "token"], "dynamic_sensitive_ui", 4), "negative", "Sensitive UI display evidence without matching masking evidence was found.", "No unmasked sensitive UI display evidence was found.")
    put("has_clears_ui_on_background", bool(clear_background), clear_background, "positive", "UI clearing or lifecycle hiding evidence was found.", "No UI clearing on background evidence was found.", len(clear_background))
    put("has_secure_notifications", bool(notif_secure), notif_secure, "positive", "Secure notification visibility evidence was found.", "No secure notification visibility evidence was found.", len(notif_secure))
    put("has_notification_leaks_sensitive_data", bool(notif_sensitive), notif_sensitive, "negative", "Sensitive notification content evidence was found.", "No sensitive notification content evidence was found.", len(notif_sensitive))
    put("has_notification_uses_public_channels", bool(public_channel and not notif_secure), (public_channel + notif_secure)[:12], "negative", "Public notification channel or visibility evidence was found without secure visibility evidence.", "No insecure public notification channel evidence was found.", len((public_channel + notif_secure)[:12]))

    clear_storage = []
    clear_storage.extend(_collect_sarif_evidence(data, ["cleartext-storage", "shared-prefs", "shared preferences", "plaintext"], max_hits=8))
    clear_storage.extend(_dynamic_storage_evidence(data, ["password", "token", "patient", "secret", "ephi", "phi", "credential"], "dynamic_sensitive_storage", 8 - len(clear_storage)))
    encrypted_storage = []
    encrypted_storage.extend(_collect_source_evidence(data, [r"EncryptedSharedPreferences", r"EncryptedFile", r"SQLCipher", r"net\.sqlcipher", r"androidx\.security\.crypto"], "encrypted_storage", 8))
    encrypted_storage.extend(_packages_matching(sca, ["sqlcipher", "androidx.security", "security-crypto"], "encrypted_storage_dependency", 4))
    ext_storage = []
    ext_storage.extend(_collect_source_evidence(data, [r"Environment\.getExternalStorage", r"getExternalFilesDir\s*\(", r"WRITE_EXTERNAL_STORAGE", r"READ_EXTERNAL_STORAGE", r"MANAGE_EXTERNAL_STORAGE"], "external_storage_usage", 8))
    if permissions.get("requested_permissions"):
        for p in permissions.get("requested_permissions") or []:
            if p in {"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.MANAGE_EXTERNAL_STORAGE"}:
                ext_storage.append(ev("MobSF_STATIC", f"mobsf_results.json:permissions.{p}", "external_storage_permission", p))
    third_party = _url_evidence(data, lambda u: any(x in u.lower() for x in ["googleapis", "firebase", "sentry", "crashlytics", "analytics", "facebook", "mixpanel", "amplitude"]), "third_party_endpoint", 8)
    push = _collect_source_evidence(data, [r"FirebaseMessagingService", r"RemoteMessage", r"FCM", r"push notification"], "push_notification_usage", 8)
    secure_push = _collect_source_evidence(data, [r"RemoteMessage", r"data\s*\.", r"encrypted", r"decrypt", r"https://"], "secure_push_channel", 8)
    put("has_stores_sensitive_data_on_device", bool(clear_storage or encrypted_storage or ext_storage), (clear_storage + encrypted_storage + ext_storage)[:12], "negative", "Local sensitive data storage evidence was found.", "No local sensitive data storage evidence was found.", len((clear_storage + encrypted_storage + ext_storage)[:12]))
    put("has_stores_pii_in_plaintext", bool(clear_storage), clear_storage, "negative", "Plaintext or cleartext local storage evidence was found.", "No plaintext PII local storage evidence was found.", len(clear_storage))
    put("has_stores_auth_tokens_in_plaintext", bool([e for e in clear_storage if "token" in e.get("excerpt", "").lower() or "credential" in e.get("excerpt", "").lower()]), clear_storage, "negative", "Plaintext token or credential storage evidence was found.", "No plaintext token storage evidence was found.", len(clear_storage))
    put("has_stores_keys_in_plaintext", bool([e for e in clear_storage if "key" in e.get("excerpt", "").lower() or "secret" in e.get("excerpt", "").lower()]), clear_storage, "negative", "Plaintext key or secret storage evidence was found.", "No plaintext key storage evidence was found.", len(clear_storage))
    put("has_uses_encrypted_local_database", bool(_packages_matching(sca, ["sqlcipher"], "sqlcipher_dependency", 4) or _collect_source_evidence(data, [r"SQLCipher", r"net\.sqlcipher"], "sqlcipher_usage", 4)), (_packages_matching(sca, ["sqlcipher"], "sqlcipher_dependency", 4) + _collect_source_evidence(data, [r"SQLCipher", r"net\.sqlcipher"], "sqlcipher_usage", 4))[:8], "positive", "Encrypted local database evidence was found.", "No encrypted local database evidence was found.")
    put("has_uses_encrypted_shared_preferences", bool(_collect_source_evidence(data, [r"EncryptedSharedPreferences"], "encrypted_shared_preferences", 8)), _collect_source_evidence(data, [r"EncryptedSharedPreferences"], "encrypted_shared_preferences", 8), "positive", "EncryptedSharedPreferences evidence was found.", "No EncryptedSharedPreferences evidence was found.")
    put("has_uses_encrypted_filesystem_storage", bool(_collect_source_evidence(data, [r"EncryptedFile", r"androidx\.security\.crypto"], "encrypted_file_storage", 8)), _collect_source_evidence(data, [r"EncryptedFile", r"androidx\.security\.crypto"], "encrypted_file_storage", 8), "positive", "Encrypted filesystem storage evidence was found.", "No encrypted filesystem storage evidence was found.")
    put("has_local_caching_of_ephi", bool(_dynamic_storage_evidence(data, ["patient", "encounter", "obs", "ephi", "phi", "medical"], "ephi_cache", 8)), _dynamic_storage_evidence(data, ["patient", "encounter", "obs", "ephi", "phi", "medical"], "ephi_cache", 8), "negative", "Local clinical/ePHI cache evidence was found.", "No local clinical/ePHI cache evidence was found.")
    put("has_encrypted_local_caching_of_ephi", bool(encrypted_storage and _dynamic_storage_evidence(data, ["patient", "encounter", "obs", "ephi", "phi", "medical"], "ephi_cache", 4)), (encrypted_storage + _dynamic_storage_evidence(data, ["patient", "encounter", "obs", "ephi", "phi", "medical"], "ephi_cache", 4))[:12], "positive", "Encrypted storage and local clinical/ePHI cache evidence were both found.", "Encrypted local ePHI caching was not confirmed.", len((encrypted_storage + _dynamic_storage_evidence(data, ["patient", "encounter", "obs", "ephi", "phi", "medical"], "ephi_cache", 4))[:12]))
    put("has_stores_ephi_on_external_storage", bool(ext_storage and _dynamic_storage_evidence(data, ["patient", "encounter", "obs", "ephi", "phi", "medical"], "ephi_cache", 4)), (ext_storage + _dynamic_storage_evidence(data, ["patient", "encounter", "obs", "ephi", "phi", "medical"], "ephi_cache", 4))[:12], "negative", "External storage and clinical/ePHI cache evidence were both found.", "No ePHI on external storage evidence was found.", len((ext_storage + _dynamic_storage_evidence(data, ["patient", "encounter", "obs", "ephi", "phi", "medical"], "ephi_cache", 4))[:12]))
    put("has_sends_ephi_to_third_party_services", bool(third_party and _collect_source_evidence(data, [r"patient", r"encounter", r"obs", r"ephi", r"medical"], "clinical_data_tokens", 4)), (third_party + _collect_source_evidence(data, [r"patient", r"encounter", r"obs", r"ephi", r"medical"], "clinical_data_tokens", 4))[:12], "negative", "Third-party endpoint and clinical/ePHI token evidence were both found.", "No ePHI third-party transmission evidence was found.", len((third_party + _collect_source_evidence(data, [r"patient", r"encounter", r"obs", r"ephi", r"medical"], "clinical_data_tokens", 4))[:12]))
    put("has_uses_push_notifications_for_ephi", bool(push and _collect_source_evidence(data, [r"patient", r"encounter", r"obs", r"ephi", r"medical"], "clinical_data_tokens", 4)), (push + _collect_source_evidence(data, [r"patient", r"encounter", r"obs", r"ephi", r"medical"], "clinical_data_tokens", 4))[:12], "negative", "Push notification and clinical/ePHI token evidence were both found.", "No push-notification ePHI evidence was found.", len((push + _collect_source_evidence(data, [r"patient", r"encounter", r"obs", r"ephi", r"medical"], "clinical_data_tokens", 4))[:12]))
    put("has_uses_secure_push_channel_for_ephi", bool(secure_push and not notif_sensitive), (secure_push + notif_sensitive)[:12], "positive", "Secure push-channel indicators were found without sensitive notification leak evidence.", "Secure push-channel use for ePHI was not confirmed.", len((secure_push + notif_sensitive)[:12]))
    put("has_secure_sync_for_offline_ephi", bool(workmanager and https_evidence and encrypted_storage), (workmanager + https_evidence + encrypted_storage)[:12], "positive", "Offline sync resilience, HTTPS, and encrypted storage evidence were found.", "Secure offline ePHI sync was not confirmed.", len((workmanager + https_evidence + encrypted_storage)[:12]))
    put("has_collects_telemetry_for_security_events", bool(_collect_source_evidence(data, [r"analytics", r"telemetry", r"audit", r"security event", r"crashlytics"], "security_telemetry", 8)), _collect_source_evidence(data, [r"analytics", r"telemetry", r"audit", r"security event", r"crashlytics"], "security_telemetry", 8), "positive", "Security telemetry or audit event collection evidence was found.", "No security telemetry collection evidence was found.")

    # Tracker and privacy telemetry flags, backed by MobSF tracker output and source evidence.
    tracker_tokens = ["tracker", "firebase analytics", "google analytics", "crashlytics", "sentry", "mixpanel", "amplitude", "facebook"]
    third_party_trackers = _collect_tracker_evidence(data, tracker_tokens, "third_party_tracker", 12)
    crash_trackers = _collect_tracker_evidence(data, ["crashlytics", "sentry", "crash reporting"], "crash_reporting_tracker", 8)
    analytics_trackers = _collect_tracker_evidence(data, ["firebase analytics", "google analytics", "analytics", "mixpanel", "amplitude"], "analytics_tracker", 8)
    put("has_third_party_trackers", bool(third_party_trackers), third_party_trackers, "negative", "Third-party tracker evidence was found in MobSF or source artifacts.", "No third-party tracker evidence was found.", len(third_party_trackers))
    put("has_crash_reporting_tracker", bool(crash_trackers), crash_trackers, "negative", "Crash reporting tracker evidence was found.", "No crash reporting tracker evidence was found.", len(crash_trackers))
    put("has_analytics_tracker", bool(analytics_trackers), analytics_trackers, "negative", "Analytics tracker evidence was found.", "No analytics tracker evidence was found.", len(analytics_trackers))
    put("has_privacy_relevant_tracker", bool(third_party_trackers), third_party_trackers, "negative", "Privacy-relevant third-party telemetry evidence was found.", "No privacy-relevant tracker evidence was found.", len(third_party_trackers))

    # Android SDK baseline flags. These remain dynamic because they come from MobSF or manifest/Gradle metadata.
    sdk = _sdk_metadata(data)
    min_sdk = sdk.get("min_sdk")
    target_sdk = sdk.get("target_sdk")
    sdk_evidence = sdk.get("evidence") or []
    put("has_min_sdk_below_security_baseline", min_sdk is not None and int(min_sdk) < 23, sdk_evidence, "negative", "Minimum SDK is below the configured security baseline.", "Minimum SDK is at or above the configured baseline, or no SDK metadata was available.", len(sdk_evidence))
    put("has_target_sdk_below_security_baseline", target_sdk is not None and int(target_sdk) < 30, sdk_evidence, "negative", "Target SDK is below the configured security baseline.", "Target SDK is at or above the configured baseline, or no SDK metadata was available.", len(sdk_evidence))
    put("has_modern_android_security_baseline", bool(min_sdk is not None and target_sdk is not None and int(min_sdk) >= 23 and int(target_sdk) >= 30), sdk_evidence, "positive", "SDK metadata satisfies the configured Android security baseline.", "SDK metadata does not satisfy the configured Android security baseline or was unavailable.", len(sdk_evidence))

    # SAST coverage flags. These do not make quality/style findings security failures.
    sast_security = _collect_sast_bucket_evidence(data, "security", 12)
    sast_quality = _collect_sast_bucket_evidence(data, "quality", 12)
    codeql_security = [e for e in sast_security if e.get("source") == "SAST_MERGED"]
    semgrep_security = [e for e in sast_security if e.get("source") == "SAST_SEMGREP"]
    put("has_sast_security_findings", bool(sast_security), sast_security, "negative", "SAST findings with security semantics were found.", "No high-confidence security SAST finding was found.", len(sast_security))
    put("has_codeql_security_findings", bool(codeql_security), codeql_security, "negative", "CodeQL/SAST merged security findings were found.", "No CodeQL/SAST merged security finding was found.", len(codeql_security))
    put("has_semgrep_security_findings", bool(semgrep_security), semgrep_security, "negative", "Semgrep security findings were found.", "No Semgrep security finding was found.", len(semgrep_security))
    put("has_sast_high_confidence_security_findings", bool(sast_security), sast_security, "negative", "High-confidence SAST security findings were found.", "No high-confidence SAST security finding was found.", len(sast_security))
    put("has_sast_quality_only_findings", bool(sast_quality and not sast_security), sast_quality, "positive", "Only quality/style SAST examples were found among sampled findings.", "SAST quality-only status was not confirmed.", len(sast_quality))

    # Dynamic coverage flags, to prevent empty dynamic reports from being read as compliance.
    dyn_available = _artifact_available(data, "mobsf_dynamic_zip") and bool(data.get("mobsf_dynamic"))
    dyn_tls = _dynamic_storage_evidence(data, ["tls", "ssl", "https", "certificate", "pinning"], "dynamic_tls_evidence", 8)
    dyn_storage = _dynamic_storage_evidence(data, ["sqlite", "xml", "shared", "preferences", "database", "file"], "dynamic_storage_evidence", 8)
    dyn_session = _dynamic_storage_evidence(data, ["session", "token", "logout", "cookie", "authorization"], "dynamic_session_evidence", 8)
    dyn_http = _dynamic_storage_evidence(data, ["http://", "cleartext"], "dynamic_http_traffic", 8)
    put("has_dynamic_runtime_evidence", bool(dyn_available), [ev("MobSF_DYNAMIC", "mobsf_dynamic_results.json", "dynamic_report_available", "MobSF dynamic report artifact parsed")] if dyn_available else [], "positive", "MobSF dynamic runtime evidence was available.", "MobSF dynamic runtime evidence was unavailable or empty.", 1 if dyn_available else 0)
    put("has_dynamic_tls_evidence", bool(dyn_tls), dyn_tls, "positive", "Dynamic TLS evidence was found.", "No dynamic TLS evidence was found.", len(dyn_tls))
    put("has_dynamic_storage_evidence", bool(dyn_storage), dyn_storage, "positive", "Dynamic storage evidence was found.", "No dynamic storage evidence was found.", len(dyn_storage))
    put("has_dynamic_session_evidence", bool(dyn_session), dyn_session, "positive", "Dynamic session evidence was found.", "No dynamic session evidence was found.", len(dyn_session))
    put("has_dynamic_http_traffic_detected", bool(dyn_http), dyn_http, "negative", "Dynamic HTTP or cleartext traffic evidence was found.", "No dynamic HTTP or cleartext traffic evidence was found.", len(dyn_http))

    return out


def build_dynamic_flag_verdict(flag_id: str, dynamic_flags: Dict[str, Dict[str, Any]]) -> Dict[str, Any] | None:
    verdict = dynamic_flags.get(flag_id)
    if not isinstance(verdict, dict):
        return None
    return verdict


# Flags that are now backed by scanner, SARIF, or source-code detectors instead of fallback.
DYNAMIC_FLAG_DEFINITIONS = {flag_id: True for flag_id in (
    "has_api_keys_in_version_control", "has_exposes_signing_keys_in_source_or_ci", "has_secrets_generic_found", "has_secrets_count",
    "has_env_specific_api_credentials_configured", "has_ci_cd_uses_encrypted_keys", "has_network_security_config_present", "has_https_with_cert_pinning", "has_approved_ports_and_protocols",
    "has_dos_vulnerabilities", "has_log_injection_vulnerabilities", "has_malware_detections", "has_protection_against_tampered_executables", "has_android_dynamic_code_loading", "has_libraries_stored_in_secure_app_dir",
    "has_buffer_overflow_vulnerabilities", "has_race_condition_vulnerabilities", "has_out_of_bounds_vulnerabilities", "has_memory_corruption_vulnerabilities", "has_integer_arithmetic_vulnerabilities", "has_ipc_bindservice_secure", "has_content_provider_actively_exposed",
    "has_webview_components", "has_webview_javascript", "has_webview_addjavascriptinterface_present", "has_webview_javascript_interface_limited_to_trusted_content", "has_webview_javascript_interface_exposes_sensitive_functionality", "has_webview_javascript_interface_leaks_sensitive_data", "has_webview_remote_content", "has_webview_file_scheme", "has_insecure_http_based_webview_communication",
    "has_os_secure_key_storage", "has_client_side_crypto_for_sensitive_data", "has_sensitive_data_encrypted_with_os_keystore", "has_auth_keys_stored_in_secure_hardware", "has_oauth2_authentication", "has_jwt_tokens", "has_token_based_auth", "has_access_tokens_weak_or_unpredictable",
    "has_soap_api_usage", "has_soap_uses_tls", "has_soap_uses_mutual_tls", "has_saml_based_sso", "has_uses_xml_signatures", "has_uses_xml_encryption", "has_proper_ws_security_headers", "has_soap_message_level_encryption", "has_soap_message_level_signatures", "has_soap_prevents_replay_attacks", "has_soap_validates_saml_token_audience", "has_soap_validates_saml_token_expiry", "has_soap_uses_strict_schema_validation", "has_soap_masks_sensitive_data_in_logs",
    "has_data_format_strictly_controlled", "has_log_input_sanitization_present", "has_logs_privileged_actions_with_timestamp", "has_error_messages_disclose_internal_details", "has_error_messages_are_generic", "has_error_messages_sent_to_unauthorized_destinations", "has_null_pointer_protection_implemented", "has_initializes_params_on_startup", "has_fails_safe_on_init_failure", "has_runtime_global_kill_switch_for_security_incidents", "has_safe_mode_degraded_functionality_design", "has_workmanager_for_resilient_network_tasks", "has_transaction_recovery_logs",
    "has_displays_sensitive_data_unmasked", "has_ui_data_masking", "has_blocks_screenshots_flag_secure", "has_clears_ui_on_background", "has_secure_notifications", "has_notification_leaks_sensitive_data", "has_notification_uses_public_channels", "has_stores_sensitive_data_on_device", "has_uses_encrypted_local_database", "has_uses_encrypted_shared_preferences", "has_uses_encrypted_filesystem_storage", "has_stores_pii_in_plaintext", "has_stores_auth_tokens_in_plaintext", "has_stores_keys_in_plaintext", "has_local_caching_of_ephi", "has_encrypted_local_caching_of_ephi", "has_stores_ephi_on_external_storage", "has_sends_ephi_to_third_party_services", "has_uses_push_notifications_for_ephi", "has_uses_secure_push_channel_for_ephi", "has_secure_sync_for_offline_ephi", "has_collects_telemetry_for_security_events",
    "has_third_party_trackers", "has_crash_reporting_tracker", "has_analytics_tracker", "has_privacy_relevant_tracker",
    "has_min_sdk_below_security_baseline", "has_target_sdk_below_security_baseline", "has_modern_android_security_baseline",
    "has_sast_security_findings", "has_codeql_security_findings", "has_semgrep_security_findings", "has_sast_high_confidence_security_findings", "has_sast_quality_only_findings",
    "has_dynamic_runtime_evidence", "has_dynamic_tls_evidence", "has_dynamic_storage_evidence", "has_dynamic_session_evidence", "has_dynamic_http_traffic_detected",
)}

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
    "has_third_party_trackers",
    "has_crash_reporting_tracker",
    "has_analytics_tracker",
    "has_privacy_relevant_tracker",
    "has_min_sdk_below_security_baseline",
    "has_target_sdk_below_security_baseline",
    "has_sast_security_findings",
    "has_codeql_security_findings",
    "has_semgrep_security_findings",
    "has_sast_high_confidence_security_findings",
    "has_dynamic_http_traffic_detected",
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
        # Evidence-first policy: unmapped flags must not become silent NO/fail.
        # They become UNKNOWN unless explicitly classified through configuration.
        state = "unknown"
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

    dynamic_verdict = build_dynamic_flag_verdict(flag_id, features.get("dynamic_flags") or {})
    if dynamic_verdict is not None:
        return dynamic_verdict

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
        "artifact_status": data.get("artifact_status", {}),
        "scan_quality_summary": {
            "sca_scan_status": (features.get("sca") or {}).get("scan_status", "unknown"),
            "sca_inventory_available": bool((features.get("sca") or {}).get("inventory_available")),
            "sca_license_inventory_available": bool((features.get("sca") or {}).get("license_inventory_available")),
            "source_files_indexed": len(data.get("source_texts", {}) or {}),
            "source_zip_members": len(data.get("source_zip_members", []) or []),
        },
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
            "dynamic_flags": features.get("dynamic_flags", {}),
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
    features["dynamic_flags"] = detect_dynamic_flags(data, features)

    fingerprint, output, trace = build_outputs(effective_cfg, app_metadata, data, features, groups)

    trace["loaded_files"] = {
        "defaults": str(defaults_path),
        "groups": str(groups_path),
        "project_config": str(project_cfg_path) if project_cfg_path else "",
    }

    write_outputs(Path(args.output_dir), fingerprint, output, trace, effective_cfg)


if __name__ == "__main__":
    main()