#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prompt-contract telemetry helpers for mSEC-AM audit workflows.

The module is intentionally lightweight and file-based so it can be used from
independent GitHub Actions workflow steps without a database or service.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="replace")).hexdigest()


def stable_json_hash(value: Any) -> str:
    try:
        payload = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        payload = str(value)
    return _sha256_text(payload)


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
        # Telemetry must never alter audit adjudication or report generation.
        print(f"[PROMPT][WARN] Could not write prompt telemetry: {exc}", flush=True)


PROMPT_CONTRACTS: Dict[str, Dict[str, Any]] = {
    "P-AIX-001": {
        "prompt_name": "Requirement justification",
        "prompt_scope": "audit_matrix",
        "prompt_category": "primary_audit_prompt",
        "is_primary": True,
        "is_auxiliary": False,
        "source_file": "scripts/ai_security_audit_requirements_excel.py",
        "source_function": "generate_justifications_via_openai",
        "section_match": "justification",
    },
    "P-AS2-001": {
        "prompt_name": "Executive summary",
        "prompt_scope": "audit_summary",
        "prompt_category": "primary_audit_summary_prompt",
        "is_primary": True,
        "is_auxiliary": False,
        "source_file": "scripts/audit_summary_stage2_generate_docx.py",
        "source_function": "_ai_json_chat",
        "section_match": "executive_summary",
    },
    "P-AS2-002": {
        "prompt_name": "Positive controls",
        "prompt_scope": "audit_summary",
        "prompt_category": "primary_audit_summary_prompt",
        "is_primary": True,
        "is_auxiliary": False,
        "source_file": "scripts/audit_summary_stage2_generate_docx.py",
        "source_function": "_ai_json_chat",
        "section_match": "positive_controls",
    },
    "P-AS2-003": {
        "prompt_name": "Technical narratives",
        "prompt_scope": "audit_summary",
        "prompt_category": "primary_audit_summary_prompt",
        "is_primary": True,
        "is_auxiliary": False,
        "source_file": "scripts/audit_summary_stage2_generate_docx.py",
        "source_function": "_ai_json_chat",
        "section_match": "technical_narratives",
    },
    "P-AS2-004": {
        "prompt_name": "Pattern writeups",
        "prompt_scope": "audit_summary",
        "prompt_category": "primary_audit_summary_prompt",
        "is_primary": True,
        "is_auxiliary": False,
        "source_file": "scripts/audit_summary_stage2_generate_docx.py",
        "source_function": "_ai_json_chat",
        "section_match": "pattern_writeups",
    },
    "P-AS2-005": {
        "prompt_name": "Control treatment plan",
        "prompt_scope": "audit_summary",
        "prompt_category": "primary_audit_summary_prompt",
        "is_primary": True,
        "is_auxiliary": False,
        "source_file": "scripts/audit_summary_stage2_generate_docx.py",
        "source_function": "_call_llm_for_treatment_plan",
        "section_match": "control_treatment_",
    },
    "P-AS2-006": {
        "prompt_name": "Technical treatment plan",
        "prompt_scope": "audit_summary",
        "prompt_category": "primary_audit_summary_prompt",
        "is_primary": True,
        "is_auxiliary": False,
        "source_file": "scripts/audit_summary_stage2_generate_docx.py",
        "source_function": "_call_llm_for_treatment_plan",
        "section_match": "technical_treatment_",
    },
    "A-AS2-001": {
        "prompt_name": "Control treatment repair",
        "prompt_scope": "audit_summary_repair",
        "prompt_category": "auxiliary_repair_prompt",
        "is_primary": False,
        "is_auxiliary": True,
        "source_file": "scripts/audit_summary_stage2_generate_docx.py",
        "source_function": "_call_llm_for_treatment_repair",
        "section_match": "control_treatment_repair_",
    },
    "A-AS2-002": {
        "prompt_name": "Technical treatment repair",
        "prompt_scope": "audit_summary_repair",
        "prompt_category": "auxiliary_repair_prompt",
        "is_primary": False,
        "is_auxiliary": True,
        "source_file": "scripts/audit_summary_stage2_generate_docx.py",
        "source_function": "_call_llm_for_treatment_repair",
        "section_match": "technical_treatment_repair_",
    },
}


def contract_for_section(section_name: str, fallback_source_function: str = "_ai_json_chat") -> Dict[str, Any]:
    name = str(section_name or "").strip()
    contract_items = sorted(
        PROMPT_CONTRACTS.items(),
        key=lambda item: len(str(item[1].get("section_match") or "")),
        reverse=True,
    )
    for prompt_id, contract in contract_items:
        match = str(contract.get("section_match") or "")
        if not match:
            continue
        if name == match or name.startswith(match):
            out = dict(contract)
            out["prompt_id"] = prompt_id
            return out
    # Deterministic temporary ID for unregistered runtime prompts.
    auto_key = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_") or "unknown"
    return {
        "prompt_id": "AUTO-" + _sha256_text(auto_key)[:12].upper(),
        "prompt_name": name or "Unregistered LLM prompt",
        "prompt_scope": "unregistered",
        "prompt_category": "unregistered_candidate",
        "is_primary": False,
        "is_auxiliary": False,
        "source_file": "",
        "source_function": fallback_source_function,
        "registration_status": "unregistered",
    }


def detect_prompt_controls(system_prompt: Any = "", user_payload: Any = None, expected_schema: Any = None) -> Dict[str, bool]:
    text = " ".join([
        str(system_prompt or ""),
        json.dumps(user_payload, ensure_ascii=False, default=str) if user_payload is not None else "",
        json.dumps(expected_schema, ensure_ascii=False, default=str) if expected_schema is not None else "",
    ]).lower()
    return {
        "json_required_detected": any(x in text for x in ["json", "raw json object", "return exactly one valid json", "return only json"]),
        "schema_required_detected": any(x in text for x in ["required_output_schema", "output_fields", "required_non_empty_fields", "schema"]),
        "identifier_preservation_detected": any(x in text for x in ["exact input item_id", "use exact item_id", "use_exact_item_id", "puid", "id"]),
        "grounding_required_detected": any(x in text for x in ["use only", "supplied json", "provided context", "supplied evidence", "observed evidence"]),
        "no_invent_evidence_detected": any(x in text for x in ["do not invent", "no_invent", "do_not_invent"]),
        "no_change_result_detected": any(x in text for x in ["do not change the precomputed result", "precomputed result"]),
        "english_only_detected": any(x in text for x in ["english only", "output english only"]),
        "repair_or_retry_detected": any(x in text for x in ["repair", "regenerate", "attempt", "retry"]),
    }


def contract_score(controls: Dict[str, bool]) -> float:
    applicable = [v for v in controls.values() if isinstance(v, bool)]
    return round(sum(1 for v in applicable if v) / len(applicable), 6) if applicable else 0.0


def record_prompt_call(
    *,
    prompt_id: str,
    prompt_name: str,
    prompt_scope: str,
    prompt_category: str,
    source_file: str,
    source_function: str,
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
        "prompt_hash": stable_json_hash({"system_prompt": system_prompt, "section_name": section_name}),
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


def registered_prompt_inventory() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for prompt_id, contract in PROMPT_CONTRACTS.items():
        row = dict(contract)
        row["prompt_id"] = prompt_id
        row.setdefault("registration_status", "registered")
        rows.append(row)
    return rows
