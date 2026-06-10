#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Central prompt-contract registry for mSEC-AM audit workflows.

The JSON file scripts/prompt_contracts.json is the single source of truth for
LLM prompt identifiers, prompt transcripts, expected output schemas, control
clauses, validation mechanisms, and prompt metadata. Runtime scripts import this
module instead of duplicating prompt text locally.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def registry_path() -> Path:
    explicit = os.getenv("PROMPT_CONTRACTS_JSON_PATH", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return _repo_root() / "scripts" / "prompt_contracts.json"


def stable_json_hash(value: Any) -> str:
    try:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        payload = str(value)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def _pretty_json(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True, indent=2)


def _control_text(clauses: Any) -> str:
    if isinstance(clauses, str):
        return clauses
    if not isinstance(clauses, list):
        return ""
    out: List[str] = []
    for item in clauses:
        if isinstance(item, dict):
            clause = str(item.get("clause") or "").strip()
        else:
            clause = str(item or "").strip()
        if clause:
            out.append(f"- {clause}")
    return "\n".join(out)


def _validation_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "; ".join(str(x) for x in value if str(x).strip())
    return ""


def _normalize_contract(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row or {})
    out.setdefault("prompt_id", "")
    out.setdefault("script_id", "")
    out.setdefault("prompt_name", "")
    out.setdefault("prompt_scope", "")
    out.setdefault("prompt_category", "")
    out.setdefault("is_primary", False)
    out.setdefault("is_auxiliary", False)
    out.setdefault("is_active", True)
    out.setdefault("source_file", "")
    out.setdefault("source_function", "")
    out.setdefault("section_match", "")
    out.setdefault("role_in_workflow", "")
    out.setdefault("system_prompt", "")
    out.setdefault("user_payload_contract", {})
    out.setdefault("required_output_schema", {})
    out.setdefault("control_clauses", [])
    out.setdefault("validation_mechanisms", [])
    out.setdefault("metrics", [])
    out.setdefault("fallback_available", False)
    out.setdefault("retry_available", False)
    out.setdefault("repair_available", False)
    out.setdefault("registration_status", "registered")

    # Backward-compatible names expected by existing telemetry and run-metrics code.
    out["system_prompt_transcript"] = str(out.get("system_prompt") or out.get("system_prompt_transcript") or "")
    out["user_payload_contract"] = _pretty_json(out.get("user_payload_contract"))
    out["required_output_schema"] = _pretty_json(out.get("required_output_schema"))
    out["control_clauses_structured"] = out.get("control_clauses") if isinstance(out.get("control_clauses"), list) else []
    out["control_clauses"] = _control_text(out.get("control_clauses"))
    out["validation_mechanism"] = _validation_text(out.get("validation_mechanisms") or out.get("validation_mechanism"))
    out["required_output_schema_object"] = _try_json(out.get("required_output_schema"))
    out["user_payload_contract_object"] = _try_json(out.get("user_payload_contract"))
    out["prompt_contract_hash"] = stable_json_hash({
        "prompt_id": out.get("prompt_id"),
        "script_id": out.get("script_id"),
        "system_prompt": out.get("system_prompt_transcript"),
        "user_payload_contract": out.get("user_payload_contract"),
        "required_output_schema": out.get("required_output_schema"),
        "control_clauses": out.get("control_clauses"),
        "validation_mechanism": out.get("validation_mechanism"),
    })
    return out


def _try_json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value or ""))
    except Exception:
        return value


def load_registry(path: Optional[Path] = None) -> Dict[str, Any]:
    p = path or registry_path()
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Prompt registry must be a JSON object: {p}")
    contracts = data.get("contracts")
    if not isinstance(contracts, list):
        raise ValueError(f"Prompt registry must contain a contracts array: {p}")
    return data


def registered_prompt_inventory(active_only: bool = False) -> List[Dict[str, Any]]:
    rows = []
    for row in load_registry().get("contracts", []):
        if not isinstance(row, dict):
            continue
        normalized = _normalize_contract(row)
        if active_only and not bool(normalized.get("is_active", True)):
            continue
        rows.append(normalized)
    rows.sort(key=lambda r: str(r.get("prompt_id") or ""))
    return rows


def prompt_contracts_map(active_only: bool = False) -> Dict[str, Dict[str, Any]]:
    return {str(row.get("prompt_id") or ""): row for row in registered_prompt_inventory(active_only=active_only) if row.get("prompt_id")}


def get_prompt_contract(prompt_id: str, *, required: bool = True) -> Dict[str, Any]:
    pid = str(prompt_id or "").strip()
    row = prompt_contracts_map(active_only=False).get(pid)
    if row:
        return dict(row)
    if required:
        raise KeyError(f"Prompt contract not found: {pid}")
    return {}


def contract_for_section(section_name: str, fallback_source_function: str = "_ai_json_chat") -> Dict[str, Any]:
    name = str(section_name or "").strip()
    contracts = sorted(registered_prompt_inventory(active_only=True), key=lambda r: len(str(r.get("section_match") or "")), reverse=True)
    for contract in contracts:
        match = str(contract.get("section_match") or "")
        if match and (name == match or name.startswith(match)):
            return dict(contract)
    auto_key = hashlib.sha256(name.encode("utf-8", errors="replace")).hexdigest()[:12].upper()
    return {
        "prompt_id": "AUTO-" + auto_key,
        "script_id": "S-UNREGISTERED",
        "prompt_name": name or "Unregistered LLM prompt",
        "prompt_scope": "unregistered",
        "prompt_category": "unregistered_candidate",
        "is_primary": False,
        "is_auxiliary": False,
        "is_active": False,
        "source_file": "",
        "source_function": fallback_source_function,
        "registration_status": "unregistered",
        "system_prompt_transcript": "",
        "user_payload_contract": "",
        "required_output_schema": "",
        "control_clauses": "",
        "validation_mechanism": "",
        "prompt_contract_hash": "",
    }


def registry_sha256() -> str:
    p = registry_path()
    if not p.is_file():
        return ""
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def registry_summary() -> Dict[str, Any]:
    rows = registered_prompt_inventory(active_only=False)
    return {
        "registry_path": str(registry_path()),
        "registry_sha256": registry_sha256(),
        "prompt_contract_count": len(rows),
        "active_prompt_contract_count": sum(1 for r in rows if bool(r.get("is_active", True))),
        "primary_prompt_contract_count": sum(1 for r in rows if bool(r.get("is_primary"))),
        "auxiliary_prompt_contract_count": sum(1 for r in rows if bool(r.get("is_auxiliary"))),
        "prompt_inventory_hash": stable_json_hash([
            {
                "prompt_id": r.get("prompt_id"),
                "script_id": r.get("script_id"),
                "prompt_contract_hash": r.get("prompt_contract_hash"),
                "is_active": r.get("is_active"),
            }
            for r in rows
        ]),
    }
