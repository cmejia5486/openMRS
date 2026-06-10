#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prompt-contract telemetry helpers for mSEC-AM audit workflows.

The module is file-based and intentionally non-blocking: telemetry failures must
never change audit adjudication or report generation. Prompt contracts include
stable identifiers, plain-language roles, prompt transcripts, output schemas,
control clauses and validation mechanisms so the run-metrics package can show
what was actually controlled and how it was validated.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


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
        print(f"[PROMPT][WARN] Could not write prompt telemetry: {exc}", flush=True)


AIX_SYSTEM_PROMPT = (
    "/no_think\n"
    "You draft very short audit justifications in English for security requirement outcomes.\n"
    "Strict rules:\n"
    "- Do not reason step by step.\n"
    "- Do not produce hidden reasoning.\n"
    "- Return the final JSON immediately.\n"
    "- Output English only.\n"
    "- If any provided notes contain non-English text, paraphrase them into English and do not quote them verbatim.\n"
    "- Do not invent evidence or flags.\n"
    "- Use only the provided context.\n"
    "- Keep exactly 1 short sentence per requirement.\n"
    "- Mention state, normalized summary (YES/NO/NA), relevant note hint, and evidence_count when available.\n"
    "- If a flag is not present in the fingerprint, state: 'flag not present in fingerprint'.\n"
    "- Do not change the precomputed result.\n"
    "- Do not use Markdown, code fences, prose, bullet points, comments, or tool calls.\n"
    "- Return exactly one raw JSON object and nothing else.\n"
    "- Return ONLY JSON in the form: {\"items\": [{\"id\": \"...\", \"justification\": \"...\"}, ...]}.\n"
)

AS2_COMMON_SYSTEM_PROMPT = (
    "You are a senior mobile health security audit reporting specialist. "
    "Write in precise technical English for an executive and engineering audience. "
    "Use only the provided JSON data. Do not invent controls, metrics, vulnerabilities, or evidence. "
    "Use director-facing audit language. Do not discuss discrepancies, contradictions, limitations, missing evidence, unavailable values, failed parsing, or internal pipeline behavior. "
    "Use normalized evidence as authoritative. For SAST, retained_security_findings is authoritative for security-relevant application-code findings. "
    "retained_app_code_signals may include hardening, quality, or maintainability findings and must not be described as vulnerabilities unless also counted in retained_security_findings. "
    "Raw SARIF counts, CodeQL notifications, Detekt warnings, and Semgrep counts must be described as traceability, quality, or execution metadata unless they are explicitly classified as retained_security_findings. "
    "Return exactly one valid JSON object and nothing else."
)

AS2_TREATMENT_SYSTEM_PROMPT = (
    "You are a senior mobile application security remediation planner for mHealth/EMR systems. "
    "Generate treatment-plan text from the supplied JSON only. Do not invent CVEs, packages, versions, files, lines, PUIDs, flags, scanner tools, or evidence. "
    "Use director-facing audit language. Do not discuss discrepancies, contradictions, limitations, missing evidence, unavailable values, failed parsing, or internal pipeline behavior. "
    "For every input item, return exactly one result object using the exact input item_id. "
    "Every result object must contain non-empty treatment_action, verification_method, closure_evidence, and residual_risk fields. "
    "For each item, write concrete but audit-defensible actions and verification steps based on observed evidence. "
    "Keep treatment_action, verification_method, closure_evidence, and residual_risk concise. "
    "Do not use static boilerplate. Do not claim that raw SARIF counts are vulnerabilities. Treat certificate pinning as threat-model dependent, not mandatory for every application. "
    "Return exactly one valid JSON object and nothing else."
)


def _schema(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)


def _control_clauses(*clauses: str) -> str:
    return "\n".join(f"- {c}" for c in clauses)


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
        "role_in_workflow": "Drafts one short English justification for each deterministic requirement result already computed by the audit logic. It does not adjudicate or change yes/no/n/a outcomes.",
        "system_prompt_transcript": AIX_SYSTEM_PROMPT,
        "user_payload_contract": _schema({"batch": ["requirement context objects with id, result, flags and evidence summaries"]}),
        "required_output_schema": _schema({"items": [{"id": "<exact requirement PUID>", "justification": "<one short English sentence>"}]}),
        "control_clauses": _control_clauses(
            "Return exactly one raw JSON object and nothing else.",
            "Output English only.",
            "Do not invent evidence or flags.",
            "Use only the provided context.",
            "Keep exactly one short sentence per requirement.",
            "Do not change the precomputed result.",
            "Return items with exact requirement PUID identifiers."
        ),
        "validation_mechanism": "JSON parsing or structured parse, schema check for items/id/justification, PUID traceability comparison against the requested batch, retry on call failure, deterministic fallback for missing or rejected items.",
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
        "role_in_workflow": "Generates the executive summary paragraph and key takeaways from supplied workbook metrics and technical evidence.",
        "system_prompt_transcript": AS2_COMMON_SYSTEM_PROMPT,
        "user_payload_contract": _schema({"task": "Generate executive summary components", "constraints": {"key_takeaways_count": "5 to 7", "must_reference": ["overall compliance rate", "applicable controls", "non-compliant controls", "top weakness patterns", "technical scanner evidence where available"], "do_not_claim": ["full codebase is clean", "MobSF absence equals no risk", "SAST raw findings are app findings"]}, "context": "application, metrics, likelihood rubric, weakness patterns, technical evidence, positive controls"}),
        "required_output_schema": _schema({"audit_summary_paragraph": "<one concise paragraph>", "key_takeaways": ["<bullet text>"]}),
        "control_clauses": _control_clauses("Use only the provided JSON data.", "Do not invent controls, metrics, vulnerabilities, or evidence.", "Return exactly one valid JSON object and nothing else.", "Do not make claims listed in do_not_claim."),
        "validation_mechanism": "JSON extraction, required field validation, report-language quality guard, retry when output is invalid or rejected.",
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
        "role_in_workflow": "Rewrites verified positive-control statements into report-ready English while preserving exact PUIDs and supplied evidence boundaries.",
        "system_prompt_transcript": AS2_COMMON_SYSTEM_PROMPT,
        "user_payload_contract": _schema({"task": "Rewrite verified positive control statements", "constraints": {"use_exact_puid": True, "do_not_overstate": True, "do_not_invent_evidence": True, "statement_style": "One concise sentence per control"}, "context": "application, positive controls, technical evidence"}),
        "required_output_schema": _schema({"positive_controls": [{"puid": "<exact PUID>", "statement": "<rewritten statement grounded only in flags and evidence>"}]}),
        "control_clauses": _control_clauses("Use exact PUID.", "Do not overstate the evidence.", "Do not invent evidence.", "Return JSON output grounded in supplied positive-control evidence."),
        "validation_mechanism": "JSON extraction, schema validation, PUID preservation check, exclusion of missing or unacceptable statements rather than invented replacement.",
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
        "role_in_workflow": "Generates technical narrative paragraphs from normalized Trivy, MobSF, SAST, Vision360 and workbook context.",
        "system_prompt_transcript": AS2_COMMON_SYSTEM_PROMPT,
        "user_payload_contract": _schema({"task": "Generate report-ready technical narrative paragraphs", "constraints": {"one_paragraph_each": True, "mention_execution_metadata": True, "do_not_overstate_sast": True, "observed_values_only": "Use observed normalized values"}, "context": "application, metrics, technical evidence, weakness patterns"}),
        "required_output_schema": _schema({"technical_coverage_paragraph": "<paragraph>", "technical_evidence_intro": "<paragraph>", "trivy_paragraph": "<paragraph>", "mobsf_static_paragraph": "<paragraph>", "mobsf_dynamic_paragraph": "<paragraph>", "sast_paragraph": "<paragraph>", "technical_execution_metadata_paragraph": "<paragraph>"}),
        "control_clauses": _control_clauses("Use observed normalized values.", "Do not overstate SAST results.", "Do not invent scanner findings, files, CVEs, packages, or metrics.", "Return exactly one valid JSON object."),
        "validation_mechanism": "JSON extraction, schema validation for expected paragraphs, technical-language quality guard, retry when invalid or rejected.",
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
        "role_in_workflow": "Generates weakness-pattern expected states, impacts, recommendations and closure criteria from supplied prevalence, PUID examples and scanner context.",
        "system_prompt_transcript": AS2_COMMON_SYSTEM_PROMPT,
        "user_payload_contract": _schema({"task": "Generate weakness-pattern writeups and recommendations", "constraints": {"patterns": "Use exact pattern names from input", "recommendations": "4 to 6 actionable bullets grounded in evidence", "no_unprovided_metrics": True, "no_static_recommendations": True}, "context": "application, likelihood rubric, top weakness patterns, technical evidence"}),
        "required_output_schema": _schema({"pattern_writeups": [{"pattern": "<exact pattern name>", "expected": "<sentence>", "impact": "<sentence>", "recommendations": ["<AI-generated action grounded in evidence>"], "closure_criteria": "<measurable closure criterion grounded in evidence>"}]}),
        "control_clauses": _control_clauses("Use exact pattern names from input.", "Generate recommendations from supplied workbook prevalence, PUID examples and scanner context.", "Do not use generic boilerplate or static templates.", "Do not use unprovided metrics."),
        "validation_mechanism": "JSON extraction, schema validation, exact pattern-name checks, report-language quality guard and retry when invalid or rejected.",
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
        "role_in_workflow": "Generates treatment actions, verification methods, closure evidence and residual-risk notes for non-compliant requirement-level control items.",
        "system_prompt_transcript": AS2_TREATMENT_SYSTEM_PROMPT,
        "user_payload_contract": _schema({"task": "Generate treatment-plan actions for non-compliant SECM-CAT controls", "constraints": {"one_result_per_input_item": True, "use_exact_item_id_and_puid": True, "do_not_invent_evidence": True, "all_output_fields_must_be_non_empty": True}, "items": "control treatment items with item_id, PUID, flags and evidence excerpt"}),
        "required_output_schema": _schema({"control_treatments": [{"item_id": "<exact input item_id>", "treatment_action": "<non-empty action>", "verification_method": "<non-empty verification method>", "closure_evidence": "<non-empty closure evidence>", "residual_risk": "<residual risk or risk acceptance note>"}]}),
        "control_clauses": _control_clauses("Return exactly one result object using the exact input item_id.", "Do not invent PUIDs, flags, files, CVEs, scanner findings, or package versions.", "Every result object must contain non-empty treatment fields.", "Use supplied evidence only."),
        "validation_mechanism": "JSON extraction, schema validation, exact item_id matching, required non-empty field checks, repair prompt if fields are missing.",
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
        "role_in_workflow": "Generates treatment actions, verification methods, closure evidence and residual-risk notes for technical findings such as dependencies, SAST and MobSF-derived items.",
        "system_prompt_transcript": AS2_TREATMENT_SYSTEM_PROMPT,
        "user_payload_contract": _schema({"task": "Generate treatment-plan actions for technical scanner findings", "constraints": {"one_result_per_input_item": True, "use_exact_item_id_and_finding_id": True, "do_not_invent_evidence": True, "dependency_rule": "Use fixed_version when present; otherwise do not invent a version"}, "items": "technical finding items with item_id, finding_id, source and evidence"}),
        "required_output_schema": _schema({"technical_treatments": [{"item_id": "<exact input item_id>", "treatment_action": "<non-empty action>", "verification_method": "<non-empty verification method>", "closure_evidence": "<non-empty closure evidence>", "residual_risk": "<residual risk or risk acceptance note>"}]}),
        "control_clauses": _control_clauses("Use exact technical item_id values.", "Use only supplied finding metadata.", "Do not invent additional files, line numbers, packages, or versions.", "Every result object must contain non-empty treatment fields."),
        "validation_mechanism": "JSON extraction, schema validation, exact item_id matching, required non-empty field checks, repair prompt if fields are missing.",
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
        "role_in_workflow": "Auxiliary prompt used only when validation detects missing treatment fields for control-treatment items.",
        "system_prompt_transcript": AS2_TREATMENT_SYSTEM_PROMPT,
        "user_payload_contract": _schema({"task": "Repair missing or incomplete treatment-plan fields for non-compliant SECM-CAT controls", "constraints": {"complete_only_missing_or_empty_fields": True, "missing_fields_are_listed_per_item": True, "use_exact_item_id_and_puid": True}, "items": "only incomplete items with missing_ai_fields"}),
        "required_output_schema": _schema({"control_treatments": [{"item_id": "<exact input item_id>", "treatment_action": "<non-empty action>", "verification_method": "<non-empty verification method>", "closure_evidence": "<non-empty closure evidence>", "residual_risk": "<residual risk or risk acceptance note>"}]}),
        "control_clauses": _control_clauses("Runs only after validation detects missing required fields.", "Complete only missing or empty fields.", "Use exact item_id and PUID.", "Do not invent evidence."),
        "validation_mechanism": "Same schema and item_id validation as the treatment plan prompt; merged only into missing fields after validation.",
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
        "role_in_workflow": "Auxiliary prompt used only when validation detects missing treatment fields for technical-treatment items.",
        "system_prompt_transcript": AS2_TREATMENT_SYSTEM_PROMPT,
        "user_payload_contract": _schema({"task": "Repair missing or incomplete treatment-plan fields for technical scanner findings", "constraints": {"complete_only_missing_or_empty_fields": True, "missing_fields_are_listed_per_item": True, "use_exact_item_id_and_finding_id": True}, "items": "only incomplete technical items with missing_ai_fields"}),
        "required_output_schema": _schema({"technical_treatments": [{"item_id": "<exact input item_id>", "treatment_action": "<non-empty action>", "verification_method": "<non-empty verification method>", "closure_evidence": "<non-empty closure evidence>", "residual_risk": "<residual risk or risk acceptance note>"}]}),
        "control_clauses": _control_clauses("Runs only after validation detects missing required fields.", "Complete only missing or empty fields.", "Use exact item_id and finding_id.", "Do not invent evidence, files, CVEs, versions or line numbers."),
        "validation_mechanism": "Same schema and item_id validation as the treatment plan prompt; merged only into missing fields after validation.",
    },
}


def contract_for_section(section_name: str, fallback_source_function: str = "_ai_json_chat") -> Dict[str, Any]:
    name = str(section_name or "").strip()
    contract_items = sorted(PROMPT_CONTRACTS.items(), key=lambda item: len(str(item[1].get("section_match") or "")), reverse=True)
    for prompt_id, contract in contract_items:
        match = str(contract.get("section_match") or "")
        if match and (name == match or name.startswith(match)):
            out = dict(contract)
            out["prompt_id"] = prompt_id
            return out
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
        row["prompt_contract_hash"] = stable_json_hash({
            "system_prompt_transcript": row.get("system_prompt_transcript", ""),
            "user_payload_contract": row.get("user_payload_contract", ""),
            "required_output_schema": row.get("required_output_schema", ""),
            "control_clauses": row.get("control_clauses", ""),
        })
        rows.append(row)
    return rows
