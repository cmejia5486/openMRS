#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import openpyxl
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH


RUN_METRICS_XLSX = "run-metrics.xlsx"
RUN_METRICS_DOCX = "run-metrics-methodology.docx"


def _sha256_file(path: Path) -> str:
    try:
        if not path.is_file():
            return ""
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _read_sheet_as_dicts(wb: Any, sheet_name: str) -> List[Dict[str, Any]]:
    if sheet_name not in wb.sheetnames:
        return []
    ws = wb[sheet_name]
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []
    headers = [str(h or "").strip() for h in rows[0]]
    out: List[Dict[str, Any]] = []
    for row in rows[1:]:
        item = {}
        for idx, header in enumerate(headers):
            if header:
                item[header] = row[idx] if idx < len(row) else None
        if any(v not in (None, "") for v in item.values()):
            out.append(item)
    return out


def _read_kv_sheet(wb: Any, sheet_name: str) -> Dict[str, Any]:
    rows = _read_sheet_as_dicts(wb, sheet_name)
    return {str(r.get("key") or ""): r.get("value") for r in rows if r.get("key") not in (None, "")}


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(float(value))
    except Exception:
        return default


def _rate(numerator: float, denominator: float) -> float:
    return 0.0 if denominator <= 0 else round(float(numerator) / float(denominator), 6)


def _auto_width(ws: Any, max_width: int = 80) -> None:
    for col in ws.columns:
        letter = col[0].column_letter
        max_len = 0
        for cell in col:
            try:
                max_len = max(max_len, len(str(cell.value or "")))
            except Exception:
                pass
        ws.column_dimensions[letter].width = min(max(max_len + 2, 10), max_width)


def _replace_sheet(wb: Any, name: str) -> Any:
    if name in wb.sheetnames:
        del wb[name]
    return wb.create_sheet(name)


def _append_dict_rows(ws: Any, rows: List[Dict[str, Any]], headers: List[str]) -> None:
    ws.append(headers)
    for row in rows:
        ws.append([row.get(h, "") for h in headers])
    _auto_width(ws)


def _compute_metrics(raw_wb: Any) -> Dict[str, Any]:
    summary = _read_kv_sheet(raw_wb, "run_summary")
    compliance = _read_sheet_as_dicts(raw_wb, "compliance_export")
    llm_calls = _read_sheet_as_dicts(raw_wb, "llm_calls")
    llm_items = _read_sheet_as_dicts(raw_wb, "llm_items")

    num_requirements = len(compliance) or _safe_int(summary.get("num_requirements"), 0)
    counts = {"yes": 0, "no": 0, "n/a": 0}
    for row in compliance:
        result = str(row.get("result") or "").strip().lower()
        if result in counts:
            counts[result] += 1

    num_llm_calls = len(llm_calls)
    json_valid_count = sum(1 for r in llm_calls if _to_bool(r.get("json_valid")))
    schema_valid_count = sum(1 for r in llm_calls if _to_bool(r.get("schema_valid")))
    retry_count = sum(_safe_int(r.get("retry_count"), 0) for r in llm_calls)
    expected_items = sum(_safe_int(r.get("expected_items"), 0) for r in llm_calls)
    received_items = sum(_safe_int(r.get("received_items"), 0) for r in llm_calls)
    traceability_expected = sum(1 for r in llm_items if _to_bool(r.get("expected_by_llm")))
    traceability_ok = sum(1 for r in llm_items if _to_bool(r.get("traceability_ok")))
    fallback_count = sum(1 for r in llm_items if _to_bool(r.get("fallback_used")))

    return {
        "summary": summary,
        "counts": counts,
        "num_requirements": num_requirements,
        "num_llm_calls": num_llm_calls,
        "json_valid_count": json_valid_count,
        "schema_valid_count": schema_valid_count,
        "retry_count": retry_count,
        "expected_items": expected_items,
        "received_items": received_items,
        "traceability_expected": traceability_expected,
        "traceability_ok": traceability_ok,
        "fallback_count": fallback_count,
        "json_valid_rate": _rate(json_valid_count, num_llm_calls),
        "schema_valid_rate": _rate(schema_valid_count, num_llm_calls),
        "completion_rate": _rate(received_items, expected_items),
        "traceability_ok_rate": _rate(traceability_ok, traceability_expected),
        "fallback_rate": _rate(fallback_count, num_requirements),
        "retry_rate": _rate(retry_count, num_llm_calls),
    }


def _add_report_quality_sheet(wb: Any, args: argparse.Namespace) -> Dict[str, Any]:
    checks = [
        {"check_name": "raw_metrics_workbook_present", "passed": Path(args.raw_metrics).is_file(), "path": str(args.raw_metrics)},
        {"check_name": "analysis_pack_present", "passed": Path(args.analysis_pack).is_file(), "path": str(args.analysis_pack)},
        {"check_name": "audit_summary_docx_present", "passed": Path(args.audit_summary_docx).is_file(), "path": str(args.audit_summary_docx)},
        {"check_name": "audit_summary_pdf_present", "passed": Path(args.audit_summary_pdf).is_file(), "path": str(args.audit_summary_pdf)},
    ]
    try:
        with Path(args.analysis_pack).open("r", encoding="utf-8", errors="replace") as fh:
            json.load(fh)
        checks.append({"check_name": "analysis_pack_json_parseable", "passed": True, "path": str(args.analysis_pack)})
    except Exception as exc:
        checks.append({"check_name": "analysis_pack_json_parseable", "passed": False, "path": str(args.analysis_pack), "detail": str(exc)[:300]})

    ws = _replace_sheet(wb, "report_quality")
    _append_dict_rows(ws, checks, ["check_name", "passed", "path", "detail"])
    total = len(checks)
    passed = sum(1 for c in checks if c.get("passed"))
    return {"report_checks_total": total, "report_checks_passed": passed, "report_quality_rate": _rate(passed, total), "quality_gate_status": "passed" if passed == total else "failed"}


def _add_package_manifest_sheet(wb: Any, args: argparse.Namespace, output_xlsx: Path) -> None:
    rows = [
        {"artifact": "run-metrics.xlsx", "path": str(output_xlsx), "sha256": _sha256_file(output_xlsx)},
        {"artifact": "raw_metrics_source", "path": str(args.raw_metrics), "sha256": _sha256_file(Path(args.raw_metrics))},
        {"artifact": "analysis_pack", "path": str(args.analysis_pack), "sha256": _sha256_file(Path(args.analysis_pack))},
        {"artifact": "audit_summary_docx", "path": str(args.audit_summary_docx), "sha256": _sha256_file(Path(args.audit_summary_docx))},
        {"artifact": "audit_summary_pdf", "path": str(args.audit_summary_pdf), "sha256": _sha256_file(Path(args.audit_summary_pdf))},
    ]
    ws = _replace_sheet(wb, "package_manifest")
    _append_dict_rows(ws, rows, ["artifact", "path", "sha256"])


def _plot_bar(labels: List[str], values: List[float], title: str, ylabel: str, out_path: Path, percent: bool = False) -> None:
    fig, ax = plt.subplots(figsize=(7.4, 4.4))
    ax.bar(labels, values)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    if percent:
        ax.set_ylim(0, 1.05)
        ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0))
        for i, value in enumerate(values):
            ax.text(i, min(1.02, value + 0.03), f"{value:.1%}", ha="center", fontsize=9)
    else:
        for i, value in enumerate(values):
            ax.text(i, value + max(values + [1]) * 0.02, str(int(value)), ha="center", fontsize=9)
    ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.6)
    fig.tight_layout()
    fig.savefig(out_path, dpi=220)
    plt.close(fig)


def _build_charts(metrics: Dict[str, Any], out_dir: Path) -> Dict[str, Path]:
    chart_dir = out_dir / "_run_metrics_charts"
    chart_dir.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, Path] = {}
    counts = metrics["counts"]
    p = chart_dir / "compliance_distribution.png"
    _plot_bar(["yes", "no", "n/a"], [counts.get("yes", 0), counts.get("no", 0), counts.get("n/a", 0)], "Compliance result distribution", "Requirement count", p)
    paths["compliance_distribution"] = p

    p = chart_dir / "llm_validation_rates.png"
    _plot_bar(
        ["JSON", "schema", "completion", "traceability"],
        [metrics["json_valid_rate"], metrics["schema_valid_rate"], metrics["completion_rate"], metrics["traceability_ok_rate"]],
        "LLM output validation rates",
        "Rate",
        p,
        percent=True,
    )
    paths["llm_validation_rates"] = p

    p = chart_dir / "fallback_retry_rates.png"
    _plot_bar(["fallback", "retry"], [metrics["fallback_rate"], metrics["retry_rate"]], "Fallback and retry rates", "Rate", p, percent=True)
    paths["fallback_retry_rates"] = p
    return paths


def _set_font(doc: Document) -> None:
    for style_name in ["Normal", "Heading 1", "Heading 2", "Heading 3"]:
        try:
            style = doc.styles[style_name]
            style.font.name = "Arial"
            if style_name == "Normal":
                style.font.size = Pt(9.5)
        except Exception:
            pass


def _add_paragraph(doc: Document, text: str) -> None:
    p = doc.add_paragraph(text)
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_after = Pt(6)


def _add_table(doc: Document, headers: List[str], rows: List[List[Any]]) -> None:
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    for idx, header in enumerate(headers):
        cell = table.rows[0].cells[idx]
        cell.text = str(header)
        for run in cell.paragraphs[0].runs:
            run.bold = True
    for row in rows:
        cells = table.add_row().cells
        for idx in range(len(headers)):
            cells[idx].text = str(row[idx] if idx < len(row) else "")
    doc.add_paragraph()


def _generate_methodology_docx(output_docx: Path, metrics: Dict[str, Any], report_quality: Dict[str, Any], charts: Dict[str, Path]) -> None:
    doc = Document()
    _set_font(doc)
    section = doc.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.75)
    section.right_margin = Inches(0.75)

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("Run Metrics Methodology")
    run.bold = True
    run.font.size = Pt(18)
    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.add_run("Per-execution evidence package for audit reproducibility and repeated-run analysis").italic = True

    doc.add_heading("1. Purpose", level=1)
    _add_paragraph(doc, "This document explains the metrics generated during the current audit execution. The companion spreadsheet contains raw exportable data only. The spreadsheet is structured to support subsequent repeated-run analysis when multiple executions are available.")

    doc.add_heading("2. Execution context", level=1)
    summary = metrics.get("summary", {})
    _add_table(doc, ["Field", "Value"], [
        ["Run ID", summary.get("run_id", "")],
        ["Commit SHA", summary.get("commit_sha", "")],
        ["Repository", summary.get("repository", "")],
        ["Model", summary.get("config.OPENAI_MODEL") or summary.get("config.AI_MODEL") or ""],
        ["AI profile", summary.get("config.AI_PROFILE", "")],
        ["LLM configuration hash", summary.get("llm_config_hash", "")],
        ["Compliance matrix hash", summary.get("compliance_matrix_hash", "")],
        ["Generated at", summary.get("generated_at_utc", _now_utc())],
    ])

    doc.add_heading("3. Metrics and formulas", level=1)
    formulas = [
        ["JSON validity rate", "json_valid_count / num_llm_calls", "Formal parseability of LLM responses."],
        ["Schema validity rate", "schema_valid_count / num_llm_calls", "Conformance with the expected response structure."],
        ["Completion rate", "received_items_count / expected_items_count", "Whether the LLM returned all requested PUID-level items."],
        ["Traceability preservation rate", "traceability_ok_count / expected_items_count", "Whether returned PUIDs match the deterministic context."],
        ["Fallback rate", "fallback_count / num_requirements", "Frequency of deterministic fallback usage."],
        ["Retry rate", "retry_count / num_llm_calls", "Operational effort required to obtain valid outputs."],
        ["Report quality rate", "report_checks_passed / report_checks_total", "Result of final artifact checks for this execution."],
    ]
    _add_table(doc, ["Metric", "Formula", "Interpretation"], formulas)

    doc.add_heading("4. Current execution values", level=1)
    _add_table(doc, ["Metric", "Value"], [
        ["Number of requirements", metrics["num_requirements"]],
        ["yes", metrics["counts"].get("yes", 0)],
        ["no", metrics["counts"].get("no", 0)],
        ["n/a", metrics["counts"].get("n/a", 0)],
        ["Number of LLM calls", metrics["num_llm_calls"]],
        ["JSON validity rate", f"{metrics['json_valid_rate']:.1%}"],
        ["Schema validity rate", f"{metrics['schema_valid_rate']:.1%}"],
        ["Completion rate", f"{metrics['completion_rate']:.1%}"],
        ["Traceability preservation rate", f"{metrics['traceability_ok_rate']:.1%}"],
        ["Fallback rate", f"{metrics['fallback_rate']:.1%}"],
        ["Retry rate", f"{metrics['retry_rate']:.1%}"],
        ["Report quality rate", f"{report_quality['report_quality_rate']:.1%}"],
    ])

    doc.add_heading("5. Visual summary", level=1)
    for caption_key, caption in [
        ("compliance_distribution", "Compliance result distribution for the current execution."),
        ("llm_validation_rates", "LLM output validation rates for the current execution."),
        ("fallback_retry_rates", "Deterministic fallback and retry rates for the current execution."),
    ]:
        path = charts.get(caption_key)
        if path and path.is_file():
            doc.add_picture(str(path), width=Inches(6.2))
            p = doc.add_paragraph(caption)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            if p.runs:
                p.runs[0].italic = True

    doc.add_heading("6. Data export structure", level=1)
    _add_paragraph(doc, "The spreadsheet includes one row per requirement in compliance_export, one row per LLM call in llm_calls, one row per expected PUID-level LLM item in llm_items, and artifact checks in report_quality. These tables can be joined across repeated executions using run_id, app_id when available, PUID, result, flags_used, and row_hash.")

    output_docx.parent.mkdir(parents=True, exist_ok=True)
    doc.save(output_docx)


def build(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = Path(args.raw_metrics)
    if not raw_path.is_file():
        raise SystemExit(f"Missing raw run metrics workbook: {raw_path}")

    output_xlsx = out_dir / RUN_METRICS_XLSX
    shutil.copy2(raw_path, output_xlsx)
    wb = openpyxl.load_workbook(output_xlsx)
    report_quality = _add_report_quality_sheet(wb, args)
    _add_package_manifest_sheet(wb, args, output_xlsx)
    wb.save(output_xlsx)

    wb = openpyxl.load_workbook(output_xlsx, data_only=True)
    metrics = _compute_metrics(wb)
    charts = _build_charts(metrics, out_dir)
    output_docx = out_dir / RUN_METRICS_DOCX
    _generate_methodology_docx(output_docx, metrics, report_quality, charts)

    print(f"[OK] Run metrics workbook: {output_xlsx}")
    print(f"[OK] Run metrics methodology DOCX: {output_docx}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build per-run metrics workbook and methodology document.")
    parser.add_argument("--raw-metrics", required=True)
    parser.add_argument("--analysis-pack", required=True)
    parser.add_argument("--audit-summary-docx", required=True)
    parser.add_argument("--audit-summary-pdf", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    build(parse_args())
