#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prompt-call telemetry helpers for mSEC-AM audit workflows.

Prompt text and contracts are loaded from scripts/prompt_contracts.json through
lib.prompt_registry. Telemetry is file-based and non-blocking: failures in this
module must not change audit adjudication or report generation.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from lib.prompt_registry import (
    contract_for_section,
    get_prompt_contract,
    prompt_contracts_map,
    registered_prompt_inventory,
    stable_json_hash,
)

PROMPT_CONTRACTS: Dict[str, Dict[str, Any]] = prompt_contracts_map(active_only=False)


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def telemetry_path(default_dir: Optional[Path] = None) -> Path:
    raw = os.getenv("PROMPT_TELEMETRY_PATH", "").strip()
    if raw:
        return Path(raw).expanduser()
    base = default_dir or Path(os.getenv("VISION360_DATA_DIR", ".")).expanduser()
    return base / "prompt-telemetry.jsonl"


def _read_existing_call_count(path: Path) -> int:
    try:
        if not path.is_file():
            return 0
        count = 0
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if obj.get("event_type") == "prompt_call":
                    count += 1
        return count
    except Exception:
        return 0


def next_prompt_call_id(path: Optional[Path] = None) -> str:
    p = path or telemetry_path()
    return f"PCALL-{_read_existing_call_count(p) + 1:04d}"


def write_event(event: Dict[str, Any], path: Optional[Path] = None) -> None:
    p = path or telemetry_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(event)
        payload.setdefault("event_generated_at_utc", _now_utc_iso())
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str) + "\n")
    except Exception as exc:
        print(f"[PROMPT][WARN] Could not write prompt telemetry: {exc}", flush=True)


def detect_prompt_controls(system_prompt: Any = "", user_payload: Any = None, expected_schema: Any = None) -> Dict[str, bool]:
    text = " ".join([
        str(system_prompt or ""),
        json.dumps(user_payload, ensure_ascii=False, default=str) if user_payload is not None else "",
        json.dumps(expected_schema, ensure_ascii=False, default=str) if expected_schema is not None else "",
    ]).lower()
    return {
        "json_required_detected": any(x in text for x in ["json", "raw json object", "return exactly one valid json", "return only json"]),
        "schema_required_detected": any(x in text for x in ["required_output_schema", "output_fields", "required_non_empty_fields", "schema", "items", "treatments"]),
        "identifier_preservation_detected": any(x in text for x in ["exact input item_id", "use exact item_id", "use_exact_item_id", "puid", "id"]),
        "grounding_required_detected": any(x in text for x in ["use only", "supplied json", "provided context", "supplied evidence", "observed evidence"]),
        "no_invent_evidence_detected": any(x in text for x in ["do not invent", "no_invent", "do_not_invent"]),
        "no_change_result_detected": any(x in text for x in ["do not change the precomputed result", "precomputed result"]),
        "english_only_detected": any(x in text for x in ["english only", "output english only", "technical english"]),
        "repair_or_retry_detected": any(x in text for x in ["repair", "regenerate", "attempt", "retry", "missing fields"]),
    }


def contract_score(controls: Dict[str, bool]) -> float:
    applicable = [v for v in controls.values() if isinstance(v, bool)]
    return round(sum(1 for v in applicable if v) / len(applicable), 6) if applicable else 0.0


def record_prompt_call(
    *,
    prompt_id: str,
    prompt_name: str = "",
    prompt_scope: str = "",
    prompt_category: str = "",
    source_file: str = "",
    source_function: str = "",
    section_name: str = "",
    system_prompt: Any = "",
    user_payload: Any = None,
    expected_schema: Any = None,
    model: str = "",
    provider: str = "",
    max_output_tokens: int | str = 0,
    reasoning_effort: str = "",
    attempt_count: int = 1,
    retry_count: int = 0,
    expected_items: int = 0,
    received_items: int = 0,
    json_valid: bool = False,
    schema_valid: bool = False,
    traceability_ok: bool | None = None,
    repair_used: bool = False,
    fallback_used: bool = False,
    elapsed_s: float = 0.0,
    error: str = "",
    registration_status: str = "registered",
) -> str:
    path = telemetry_path()
    prompt_call_id = next_prompt_call_id(path)

    try:
        contract = get_prompt_contract(prompt_id, required=False)
    except Exception:
        contract = {}
    if contract:
        prompt_name = prompt_name or str(contract.get("prompt_name") or "")
        prompt_scope = prompt_scope or str(contract.get("prompt_scope") or "")
        prompt_category = prompt_category or str(contract.get("prompt_category") or "")
        source_file = source_file or str(contract.get("source_file") or "")
        source_function = source_function or str(contract.get("source_function") or "")
        system_prompt = system_prompt or contract.get("system_prompt_transcript", "")
        expected_schema = expected_schema or contract.get("required_output_schema_object") or contract.get("required_output_schema")
        registration_status = "registered"
    elif registration_status == "registered":
        registration_status = "unregistered"

    controls = detect_prompt_controls(system_prompt, user_payload, expected_schema)
    event = {
        "event_type": "prompt_call",
        "prompt_call_id": prompt_call_id,
        "prompt_id": prompt_id,
        "prompt_name": prompt_name,
        "prompt_scope": prompt_scope,
        "prompt_category": prompt_category,
        "source_file": source_file,
        "source_function": source_function,
        "section_name": section_name,
        "is_primary": prompt_category.startswith("primary"),
        "is_auxiliary": "auxiliary" in prompt_category or "repair" in prompt_category,
        "registration_status": registration_status,
        "prompt_contract_hash": contract.get("prompt_contract_hash", "") if contract else "",
        "prompt_hash": stable_json_hash({"prompt_id": prompt_id, "system_prompt": system_prompt, "section_name": section_name}),
        "schema_hash": stable_json_hash(expected_schema or {}),
        "payload_hash": stable_json_hash(user_payload or {}),
        "controls_hash": stable_json_hash(controls),
        "contract_score": contract_score(controls),
        "model": model,
        "provider": provider,
        "max_output_tokens": max_output_tokens,
        "reasoning_effort": reasoning_effort,
        "attempt_count": int(attempt_count or 0),
        "retry_count": int(retry_count or 0),
        "expected_items": int(expected_items or 0),
        "received_items": int(received_items or 0),
        "json_valid": bool(json_valid),
        "schema_valid": bool(schema_valid),
        "traceability_ok": traceability_ok if traceability_ok is not None else "",
        "repair_used": bool(repair_used),
        "fallback_used": bool(fallback_used),
        "elapsed_s": round(float(elapsed_s or 0.0), 3),
        "error": str(error or "")[:800],
    }
    event.update(controls)
    write_event(event, path)
    return prompt_call_id
