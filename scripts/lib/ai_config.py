#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def config_path() -> Path:
    env_path = os.getenv("AI_CONFIG_JSON_PATH", "").strip()
    if env_path:
        return Path(env_path)
    return repo_root() / "scripts" / "ai.config.json"


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"AI config file not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"AI config root must be an object: {path}")
    return raw


def deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        out = copy.deepcopy(base)
        for k, v in override.items():
            out[k] = deep_merge(out.get(k), v)
        return out
    if override is None:
        return copy.deepcopy(base)
    return copy.deepcopy(override)


def _env_override(cfg: Dict[str, Any], env_name: str, key: str, cast: Optional[type] = None) -> None:
    value = os.getenv(env_name, "").strip()
    if not value:
        return
    if cast is int:
        try:
            cfg[key] = int(value)
        except ValueError:
            return
    else:
        cfg[key] = value


def _resolve_profile_name(raw: Dict[str, Any], task_name: Optional[str], profile_name: Optional[str]) -> str:
    if profile_name:
        return profile_name
    env_profile = os.getenv("AI_PROFILE", "").strip()
    if env_profile:
        return env_profile
    task_cfg = ((raw.get("tasks") or {}).get(task_name or "") or {}) if task_name else {}
    if isinstance(task_cfg, dict) and task_cfg.get("profile"):
        return str(task_cfg["profile"])
    return str(raw.get("default_profile") or "openai_default")


def resolve_config(task_name: Optional[str] = None, profile_name: Optional[str] = None) -> Dict[str, Any]:
    raw = load_json(config_path())
    profiles = raw.get("profiles") or {}
    if not isinstance(profiles, dict):
        raise ValueError("profiles must be an object in ai.config.json")

    final_profile = _resolve_profile_name(raw, task_name, profile_name)
    if final_profile not in profiles:
        raise KeyError(f"Profile not found in ai.config.json: {final_profile}")

    base = profiles[final_profile]
    if not isinstance(base, dict):
        raise ValueError(f"Profile must be an object: {final_profile}")

    task_cfg = {}
    tasks = raw.get("tasks") or {}
    if task_name and isinstance(tasks, dict):
        task_cfg = tasks.get(task_name) or {}
        if task_cfg and not isinstance(task_cfg, dict):
            raise ValueError(f"Task config must be an object: {task_name}")

    effective = deep_merge(base, task_cfg)
    effective["resolved_profile"] = final_profile
    effective["resolved_task"] = task_name or ""

    _env_override(effective, "AI_PROVIDER", "provider")
    _env_override(effective, "AI_MODEL", "model")
    _env_override(effective, "AI_LITELLM_MODEL", "litellm_model")
    _env_override(effective, "AI_API_BASE", "api_base")
    _env_override(effective, "AI_API_VERSION", "api_version")
    _env_override(effective, "AI_REASONING_EFFORT", "reasoning_effort")
    _env_override(effective, "AI_MAX_OUTPUT_TOKENS", "max_output_tokens", int)
    _env_override(effective, "AI_BATCH_SIZE", "batch_size", int)
    _env_override(effective, "AI_TIMEOUT_S", "timeout_s", int)
    _env_override(effective, "AI_API_KEY_ENV_VAR", "api_key_env_var")

    if not effective.get("provider"):
        effective["provider"] = "openai"
    if not effective.get("api_key_env_var"):
        effective["api_key_env_var"] = "OPENAI_API_KEY"
    return effective


def resolved_api_key(cfg: Dict[str, Any], explicit_api_key: Optional[str] = None) -> str:
    if explicit_api_key:
        return explicit_api_key
    key_env = str(cfg.get("api_key_env_var") or "OPENAI_API_KEY")
    return os.getenv(key_env, "").strip()


def resolved_api_base(cfg: Dict[str, Any]) -> str:
    if str(cfg.get("api_base") or "").strip():
        return str(cfg.get("api_base") or "").strip()
    env_name = str(cfg.get("api_base_env_var") or "").strip()
    return os.getenv(env_name, "").strip() if env_name else ""


def resolved_api_version(cfg: Dict[str, Any]) -> str:
    if str(cfg.get("api_version") or "").strip():
        return str(cfg.get("api_version") or "").strip()
    env_name = str(cfg.get("api_version_env_var") or "").strip()
    return os.getenv(env_name, "").strip() if env_name else ""


def resolved_litellm_model(cfg: Dict[str, Any]) -> str:
    explicit = str(cfg.get("litellm_model") or "").strip()
    if explicit:
        return explicit

    provider = str(cfg.get("provider") or "openai").strip().lower()
    model = str(cfg.get("model") or "").strip()
    if not model:
        raise ValueError("AI model is empty after config resolution")
    if "/" in model:
        return model
    if provider in {"openai", "openai_compatible"}:
        return model
    if provider == "azure":
        return f"azure/{model}"
    if provider == "anthropic":
        return f"anthropic/{model}"
    if provider == "gemini":
        return f"gemini/{model}"
    if provider == "mistral":
        return f"mistral/{model}"
    if provider == "openrouter":
        return f"openrouter/{model}"
    return model
