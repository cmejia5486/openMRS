#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
from datetime import datetime, date
from pathlib import Path
from typing import Dict, Any, List

import matplotlib.pyplot as plt
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.text.paragraph import Paragraph

try:
    import requests
except Exception:
    requests = None  # type: ignore

def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _runtime_data_dir() -> Path:
    # Prefer explicit, cross-platform data-directory variables.
    # If none are provided, use GitHub Actions RUNNER_TEMP when available.
    # As a final local fallback, use a repository-local hidden directory.
    for name in ("VISION360_DATA_DIR", "AUDIT_DATA_DIR", "SECURITY_AUDIT_DATA_DIR"):
        raw = os.getenv(name, "").strip()
        if raw:
            base = Path(raw)
            base.mkdir(parents=True, exist_ok=True)
            return base

    runner_temp = os.getenv("RUNNER_TEMP", "").strip()
    if runner_temp:
        base = Path(runner_temp) / "vision360-data"
        base.mkdir(parents=True, exist_ok=True)
        return base

    base = _repo_root() / ".vision360-data"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _env_path(env_name: str, default_filename: str) -> Path:
    raw = os.getenv(env_name, "").strip()
    if raw:
        return Path(raw)
    return _runtime_data_dir() / default_filename


DEFAULT_IN = str(_env_path("AUDIT_ANALYSIS_JSON_PATH", "audit_summary_analysis_pack.json"))
DEFAULT_OUT = str(_env_path("AUDIT_SUMMARY_DOCX_PATH", "Audit Summary.docx"))
CHART_DIR = str(_env_path("AUDIT_SUMMARY_CHART_DIR", "_audit_summary_charts"))

HEADER_TEXT = "mSEC-AM Audit Summary - OpenMRS Android Client v3.1.1"


def _wrap_label(s: str, width: int = 30) -> str:
    s = str(s)
    if len(s) <= width:
        return s
    out = []
    while len(s) > width:
        cut = s.rfind(" ", 0, width)
        if cut == -1:
            cut = width
        out.append(s[:cut].strip())
        s = s[cut:].strip()
    if s:
        out.append(s)
    return "\n".join(out)


def _set_cell_shading(cell, fill: str) -> None:
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcPr.append(shd)


def _add_field_run(paragraph, field_instr: str) -> None:
    run = paragraph.add_run()
    fldChar1 = OxmlElement("w:fldChar")
    fldChar1.set(qn("w:fldCharType"), "begin")
    instrText = OxmlElement("w:instrText")
    instrText.set(qn("xml:space"), "preserve")
    instrText.text = field_instr
    fldChar2 = OxmlElement("w:fldChar")
    fldChar2.set(qn("w:fldCharType"), "separate")
    fldChar3 = OxmlElement("w:fldChar")
    fldChar3.set(qn("w:fldCharType"), "end")
    run._r.append(fldChar1)
    run._r.append(instrText)
    run._r.append(fldChar2)
    run._r.append(fldChar3)


def _set_doc_defaults(doc: Document) -> None:
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)
    section = doc.sections[0]
    section.top_margin = Inches(0.75)
    section.bottom_margin = Inches(0.75)
    section.left_margin = Inches(0.85)
    section.right_margin = Inches(0.85)


def _add_header_footer(section, audit_date_str: str, report_title: str = "Mobile Application") -> None:
    header = section.header
    header.is_linked_to_previous = False
    p = header.paragraphs[0]
    p.text = f"mSEC-AM Audit Summary - {report_title}"
    if p.runs:
        p.runs[0].font.size = Pt(9)

    footer = section.footer
    footer.is_linked_to_previous = False
    fp = footer.paragraphs[0]
    fp.text = f"{audit_date_str} | "
    if fp.runs:
        fp.runs[0].font.size = Pt(9)
    fp.add_run("Page ")
    _add_field_run(fp, " PAGE ")
    fp.add_run(" of ")
    _add_field_run(fp, " NUMPAGES ")
    fp.alignment = WD_ALIGN_PARAGRAPH.RIGHT


def _add_cover(doc: Document, audit_date_str: str, auditor: str, report_title: str = "Mobile Application") -> None:
    doc.add_paragraph()
    t = doc.add_paragraph("mSEC-AM Audit Summary")
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    t.runs[0].font.size = Pt(28)
    t.runs[0].bold = True
    s = doc.add_paragraph(report_title)
    s.alignment = WD_ALIGN_PARAGRAPH.CENTER
    s.runs[0].font.size = Pt(16)
    s.runs[0].bold = True
    doc.add_paragraph()
    info = doc.add_paragraph()
    info.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = info.add_run(f"Audit Date: {audit_date_str}\nAuditor: {auditor}\nClassification: Confidential / Internal Use")
    r.font.size = Pt(11)
    doc.add_page_break()


def _enable_update_fields_on_open(doc: Document) -> None:
    settings = doc.settings._element
    existing = settings.xpath('./w:updateFields')
    if not existing:
        node = OxmlElement("w:updateFields")
        node.set(qn("w:val"), "true")
        settings.append(node)


def _make_bookmark_name(text: str, used: set[str]) -> str:
    base = re.sub(r"[^A-Za-z0-9_]+", "_", str(text)).strip("_")
    if not base:
        base = "section"
    if base[0].isdigit():
        base = f"s_{base}"
    name = base[:32]
    seed = name
    i = 2
    while name in used:
        suffix = f"_{i}"
        name = f"{seed[:32-len(suffix)]}{suffix}"
        i += 1
    used.add(name)
    return name


def _add_bookmark(paragraph, bookmark_name: str, bookmark_id: int) -> None:
    p = paragraph._p
    start = OxmlElement("w:bookmarkStart")
    start.set(qn("w:id"), str(bookmark_id))
    start.set(qn("w:name"), bookmark_name)
    end = OxmlElement("w:bookmarkEnd")
    end.set(qn("w:id"), str(bookmark_id))
    p.insert(0, start)
    p.append(end)


def _add_internal_hyperlink(paragraph, text: str, anchor: str) -> None:
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("w:anchor"), anchor)
    hyperlink.set(qn("w:history"), "1")

    run = OxmlElement("w:r")
    rpr = OxmlElement("w:rPr")

    rstyle = OxmlElement("w:rStyle")
    rstyle.set(qn("w:val"), "Hyperlink")
    rpr.append(rstyle)

    color = OxmlElement("w:color")
    color.set(qn("w:val"), "0563C1")
    rpr.append(color)

    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    rpr.append(underline)

    run.append(rpr)
    text_node = OxmlElement("w:t")
    text_node.text = text
    run.append(text_node)
    hyperlink.append(run)
    paragraph._p.append(hyperlink)


def _insert_paragraph_after(paragraph):
    new_p = OxmlElement("w:p")
    paragraph._p.addnext(new_p)
    return Paragraph(new_p, paragraph._parent)


def _render_clickable_toc(after_paragraph, toc_entries: List[tuple[int, str, str]]) -> None:
    current = after_paragraph
    for level, title, anchor in toc_entries:
        p = _insert_paragraph_after(current)
        p.paragraph_format.left_indent = Inches(0.25 * max(level - 1, 0))
        p.paragraph_format.space_after = Pt(2)
        _add_internal_hyperlink(p, title, anchor)
        current = p


def _add_toc(doc: Document):
    doc.add_paragraph("Table of Contents", style="Heading 1")
    p = doc.add_paragraph()
    doc.add_page_break()
    return p


def _add_two_col_table(doc: Document, rows: List[List[str]]) -> None:
    tbl = doc.add_table(rows=0, cols=2)
    tbl.style = "Table Grid"
    for k, v in rows:
        cells = tbl.add_row().cells
        cells[0].text = str(k)
        cells[1].text = str(v)
        for run in cells[0].paragraphs[0].runs:
            run.bold = True
    doc.add_paragraph()


def _add_callout(doc: Document, title: str, bullets: List[str]) -> None:
    tbl = doc.add_table(rows=1, cols=1)
    cell = tbl.cell(0, 0)
    _set_cell_shading(cell, "EDEDED")
    p = cell.paragraphs[0]
    r = p.add_run(title)
    r.bold = True
    r.font.size = Pt(11)
    for b in bullets:
        cell.add_paragraph(b, style="List Bullet")
    doc.add_paragraph()


def _add_figure(doc: Document, img_path: str, caption: str) -> None:
    doc.add_picture(img_path, width=Inches(6.5))
    cap = doc.add_paragraph(caption)
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    if cap.runs:
        cap.runs[0].italic = True
        cap.runs[0].font.size = Pt(9)
    doc.add_paragraph()


def _donut(values: List[int], labels: List[str], title: str, center_text: str, out_path: str) -> None:
    fig, ax = plt.subplots(figsize=(7.4, 4.8))
    wedges, _, _ = ax.pie(values, labels=None, autopct="%1.1f%%", startangle=90, pctdistance=0.82)
    centre = plt.Circle((0, 0), 0.55, fc="white")
    fig.gca().add_artist(centre)
    ax.axis("equal")
    ax.set_title(title)
    ax.legend(wedges, labels, loc="center left", bbox_to_anchor=(1.02, 0.5), frameon=False)
    ax.text(0, 0, center_text, ha="center", va="center", fontsize=11, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def _hbar_share_noncompliances(cat_stats: Dict[str, Any], out_path: str) -> None:
    items = sorted([(d["category_name"], int(d.get("non_compliant", 0))) for _, d in cat_stats.items()], key=lambda x: x[1])
    names = [x[0] for x in items]
    counts = [float(x[1]) for x in items]
    total = float(sum(counts))
    pct = [0.0 for _ in counts] if total <= 0.0 else [(c / total) * 100.0 for c in counts]
    fig, ax = plt.subplots(figsize=(9.2, 5.6))
    y = list(range(len(names)))
    bars = ax.barh(y, pct)
    ax.set_yticks(y)
    ax.set_yticklabels([_wrap_label(n, 30) for n in names])
    ax.set_xlabel("Share of total non-compliances (%)")
    ax.set_title("Share of non-compliances by category (high-level)")
    ax.set_xlim(0, max(5, float(max(pct) if pct else 0.0) + 5))
    ax.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6)
    for b, c, p in zip(bars, counts, pct):
        ax.text(b.get_width() + 0.6, b.get_y() + b.get_height() / 2, f"{p:.1f}%  (n={int(c)})", va="center", fontsize=9)
    fig.text(0.01, 0.01, f"Source: audit workbook. Total non-compliances: {int(total)}.", fontsize=9)
    fig.tight_layout(rect=[0, 0.03, 1, 1])
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def _hbar_compliance_rate(cat_stats: Dict[str, Any], out_path: str) -> None:
    items = []
    for _, d in cat_stats.items():
        app = int(d.get("applicable", 0))
        comp = int(d.get("compliant", 0))
        pct = float(d.get("compliance_pct", 0.0))
        items.append((d["category_name"], pct, comp, app))
    items = sorted(items, key=lambda x: x[1])
    names = [x[0] for x in items]
    pct_vals = [x[1] for x in items]
    comp_vals = [x[2] for x in items]
    app_vals = [x[3] for x in items]
    fig, ax = plt.subplots(figsize=(9.2, 5.6))
    y = list(range(len(names)))
    bars = ax.barh(y, pct_vals)
    ax.set_yticks(y)
    ax.set_yticklabels([_wrap_label(n, 30) for n in names])
    ax.set_xlabel("Compliance rate (%) - applicable controls only")
    ax.set_title("Compliance rate by category (applicable controls only)")
    ax.set_xlim(0, 100)
    ax.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6)
    for b, p, c, a in zip(bars, pct_vals, comp_vals, app_vals):
        ax.text(p + 1, b.get_y() + b.get_height() / 2, f"{p:.1f}%  ({c}/{a})", va="center", fontsize=9)
    fig.text(0.01, 0.01, "Note: (c/a) indicates Compliant / Applicable controls per category. Source: audit workbook.", fontsize=9)
    fig.tight_layout(rect=[0, 0.03, 1, 1])
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def _stacked_counts(cat_stats: Dict[str, Any], out_path: str) -> None:
    items = sorted([(d["category_name"], int(d.get("compliant", 0)), int(d.get("non_compliant", 0)), int(d.get("not_applicable", 0))) for _, d in cat_stats.items()], key=lambda x: (x[1] + x[2] + x[3]), reverse=True)
    names = [x[0] for x in items]
    c = [x[1] for x in items]
    n = [x[2] for x in items]
    na = [x[3] for x in items]
    fig, ax = plt.subplots(figsize=(9.2, 5.6))
    y = list(range(len(names)))
    ax.barh(y, c, label="Compliant")
    ax.barh(y, n, left=c, label="Non-compliant")
    left_cn = [cc + nn for cc, nn in zip(c, n)]
    ax.barh(y, na, left=left_cn, label="Not applicable")
    ax.set_yticks(y)
    ax.set_yticklabels([_wrap_label(nm, 30) for nm in names])
    ax.invert_yaxis()
    ax.set_xlabel("Count")
    ax.set_title("Counts by category and status")
    ax.grid(axis="x", linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(loc="lower right", frameon=False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def _likelihood_from_count(cnt: int) -> str:
    if cnt >= 50:
        return "High"
    if cnt >= 20:
        return "Medium-High"
    if cnt >= 10:
        return "Medium"
    return "Low-Medium"


def _target_timeline(sev: str) -> str:
    return "0-90 days" if sev == "High" else ("0-180 days" if sev == "Medium" else "0-365 days")


def _target_date_str(audit_dt: date, sev: str) -> str:
    days = 90 if sev == "High" else (180 if sev == "Medium" else 365)
    due = audit_dt.toordinal() + days
    return date.fromordinal(due).strftime("%d %b %Y")



def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        if isinstance(value, bool):
            return int(value)
        return int(float(str(value).strip()))
    except Exception:
        return default


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _clean_text(value: Any) -> str:
    """Convert arbitrary evidence values into report-safe text."""
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, (int, float, bool)):
        text = str(value)
    elif isinstance(value, dict):
        # Keep dictionaries out of the final report. Prefer meaningful fields.
        preferred = []
        for key in ("message", "title", "description", "summary", "rule", "rule_id", "tool", "level", "file", "path"):
            val = value.get(key)
            if val not in (None, "", [], {}):
                preferred.append(f"{key}: {_clean_text(val)}")
        text = "; ".join(preferred) if preferred else json.dumps(value, ensure_ascii=False)
    elif isinstance(value, list):
        text = "; ".join(_clean_text(item) for item in value if item not in (None, "", [], {}))
    else:
        text = str(value)
    text = re.sub(r"\s+", " ", text).strip()
    text = text.replace("...", "")
    return text


def _is_emptyish(value: Any) -> bool:
    if value in (None, ""):
        return True
    if isinstance(value, (list, tuple, set)):
        return len([x for x in value if not _is_emptyish(x)]) == 0
    if isinstance(value, dict):
        return len([v for v in value.values() if not _is_emptyish(v)]) == 0
    return False


def _cell_text(value: Any) -> str:
    return _clean_text(value)


def _add_note(doc: Document, text: str) -> None:
    p = doc.add_paragraph(_clean_text(text))
    if p.runs:
        p.runs[0].italic = True


def _sanitize_positive_statement(text: Any) -> str:
    s = _clean_text(text)
    replacements = [
        (r"^The application applications not change", "The application does not change"),
        (r"^The application remove", "The application removes"),
        (r"^The application be free", "The application is free"),
        (r"^The application request", "The application requests"),
        (r"^The application provide", "The application provides"),
        (r"^The application the mobile application", "The mobile application"),
        (r"\bkeep with good SSL practices\b", "align with secure SSL practices"),
        (r"\bpost-development cycle for secure certificate validation\b", "after the development cycle to preserve secure certificate validation"),
    ]
    for pattern, repl in replacements:
        s = re.sub(pattern, repl, s, flags=re.IGNORECASE)
    s = re.sub(r"\s+", " ", s).strip()
    if s and not s.endswith((".", ";", ":")):
        s += "."
    return s


def _qa_doc_text(doc: Document) -> str:
    parts: List[str] = []
    for p in doc.paragraphs:
        parts.append(p.text)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                parts.append(cell.text)
    return "\n".join(parts)


def _quality_gate(doc: Document) -> None:
    text = _qa_doc_text(doc)
    forbidden = [
        "No data available",
        "missing_inputs\n",
        "{'tool':",
        '"tool":',
        "The application applications",
        "The application the mobile application",
        "Not reported",
    ]
    hits = [token for token in forbidden if token in text]
    if hits:
        raise SystemExit("[ERROR] Audit Summary quality gate failed. Forbidden text found: " + ", ".join(hits))


def _short(value: Any, limit: int = 170) -> str:
    """Normalize text for Word cells without using ellipsis.

    The previous implementation appended "...", which made the report look as
    if LLM tokens were missing. This function keeps full text by default when
    limit <= 0 and uses an explicit marker only when a hard limit is requested.
    """
    text = _clean_text(value)
    if limit and limit > 0 and len(text) > limit:
        return text[:limit].rstrip() + " [text shortened]"
    return text

def _first_present(obj: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    for key in keys:
        if isinstance(obj, dict) and key in obj and obj[key] not in (None, ""):
            return obj[key]
    return default


def _deep_find_first(obj: Any, keys: List[str]) -> Any:
    if isinstance(obj, dict):
        for key in keys:
            if key in obj and obj[key] not in (None, ""):
                return obj[key]
        for value in obj.values():
            found = _deep_find_first(value, keys)
            if found not in (None, ""):
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _deep_find_first(item, keys)
            if found not in (None, ""):
                return found
    return None


def _deep_int(obj: Any, keys: List[str], default: int = 0) -> int:
    value = _deep_find_first(obj, keys)
    return _safe_int(value, default)


def _deep_dict(obj: Any, keys: List[str]) -> Dict[str, Any]:
    value = _deep_find_first(obj, keys)
    return value if isinstance(value, dict) else {}


def _deep_list(obj: Any, keys: List[str]) -> List[Any]:
    value = _deep_find_first(obj, keys)
    if isinstance(value, list):
        return value
    return []


def _block_available(block: Any) -> bool:
    if not isinstance(block, dict) or not block:
        return False
    if block.get("available") is True:
        return True
    for key, value in block.items():
        if key in {"available", "paths", "input_paths"}:
            continue
        if isinstance(value, (list, dict)) and len(value) > 0:
            return True
        if isinstance(value, (int, float)) and value > 0:
            return True
        if isinstance(value, str) and value.strip():
            return True
    return False


def _format_bool(value: Any) -> str:
    if value is True:
        return "Detected / Yes"
    if value is False:
        return "Not detected / No"
    if value in (None, ""):
        return "Not available in parsed evidence"
    if isinstance(value, (int, float)):
        return str(value)
    text = _clean_text(value)
    return text if text else "Not available in parsed evidence"

def _add_table(doc: Document, headers: List[str], rows: List[List[Any]], max_rows: int | None = None, empty_message: str | None = None) -> bool:
    """Add a table only when rows exist.

    Returns True when a table was rendered. Empty tables are not emitted because
    they undermine confidence in the final report.
    """
    actual_rows = rows[:max_rows] if max_rows is not None else rows
    actual_rows = [r for r in actual_rows if not _is_emptyish(r)]
    if not actual_rows:
        if empty_message:
            _add_note(doc, empty_message)
        return False

    tbl = doc.add_table(rows=1, cols=len(headers))
    tbl.style = "Table Grid"
    h = tbl.rows[0].cells
    for idx, txt in enumerate(headers):
        h[idx].text = _cell_text(txt)
        _set_cell_shading(h[idx], "D9E1F2")
        for run in h[idx].paragraphs[0].runs:
            run.bold = True
    for row_values in actual_rows:
        r = tbl.add_row().cells
        for idx in range(len(headers)):
            r[idx].text = _cell_text(row_values[idx] if idx < len(row_values) else "")
    doc.add_paragraph()
    return True

def _app_report_title(app: Dict[str, Any]) -> str:
    app = _as_dict(app)
    name = _first_present(app, ["app_name", "application_name", "name", "title", "app", "project", "project_name"])
    version = _first_present(app, ["version", "app_version", "version_name", "release", "app_release"])

    if not name:
        for key, value in app.items():
            if "name" in str(key).lower() and value:
                name = value
                break
    if not version:
        for key, value in app.items():
            if "version" in str(key).lower() and value:
                version = value
                break

    name_s = _safe_str(name, "Mobile Application").strip() or "Mobile Application"
    version_s = _safe_str(version).strip()
    return f"{name_s} - {version_s}" if version_s and version_s not in name_s else name_s


def _technical_evidence(pack: Dict[str, Any]) -> Dict[str, Any]:
    return _as_dict(pack.get("technical_evidence"))


def _source_status_rows(technical: Dict[str, Any]) -> List[List[Any]]:
    labels = [
        ("Vision360 trace", "vision360"),
        ("Trivy SCA", "trivy_sca"),
        ("MobSF static", "mobsf_static"),
        ("MobSF dynamic", "mobsf_dynamic"),
        ("SAST app-code", "sast_app_code"),
    ]
    rows = []
    for label, key in labels:
        block = _as_dict(technical.get(key))
        available = _block_available(block)
        status = "Available" if available else "Not available to report generator"
        summary = "Parsed and available for report correlation." if available else "Artifact was not present, not downloaded, or not normalized into the analysis pack."
        if key == "trivy_sca" and available:
            summary = f"{_deep_int(block, ['total_vulnerabilities', 'vulnerabilities_total', 'total'])} dependency vulnerability finding(s); {_deep_int(block, ['packages_detected', 'package_count', 'packages_total'])} package(s) detected."
        elif key == "sast_app_code" and available:
            total = _deep_int(block, ['total_findings', 'total', 'results_count'])
            raw = _deep_dict(block, ['tool_counts', 'by_tool'])
            raw_text = ", ".join(f"{k}: {v}" for k, v in raw.items()) if raw else "raw tool counts unavailable"
            summary = f"{total} application-scope finding(s) retained after filtering. Raw SARIF counts retained for traceability: {raw_text}."
        elif key == "mobsf_static" and available:
            summary = "Android APK, manifest, certificate, permission, signing, tracker, and hardening indicators were parsed where present."
        elif key == "mobsf_dynamic" and available:
            summary = "Runtime storage, SharedPreferences, database, cache, tracker, and observed artifact evidence was parsed where present."
        rows.append([label, status, summary])
    return rows

def _technical_takeaways(technical: Dict[str, Any]) -> List[str]:
    takeaways: List[str] = []
    trivy = _as_dict(technical.get("trivy_sca"))
    if _block_available(trivy):
        total = _deep_int(trivy, ["total_vulnerabilities", "vulnerabilities_total", "total"])
        by_sev = _deep_dict(trivy, ["by_severity", "severity_counts"])
        critical = _safe_int(by_sev.get("CRITICAL") or by_sev.get("critical"))
        high = _safe_int(by_sev.get("HIGH") or by_sev.get("high"))
        if total > 0:
            takeaways.append(f"Trivy SCA evidence identified {total} known dependency vulnerability finding(s), including {critical} Critical and {high} High finding(s) where reported.")
    mobsf = _as_dict(technical.get("mobsf_static"))
    if _block_available(mobsf):
        indicators = []
        for label, keys in [
            ("debuggable build", ["debuggable", "has_debuggable", "debuggable_true", "android_debuggable"]),
            ("debug certificate", ["debug_certificate", "has_debug_cert", "signed_with_debug_certificate"]),
            ("backup enabled", ["allow_backup", "backup_enabled", "android_allow_backup"]),
            ("exported components", ["exported_components_count", "exported_component_count"]),
        ]:
            value = _deep_find_first(mobsf, keys)
            if value is True or _safe_int(value) > 0:
                indicators.append(label)
        if indicators:
            takeaways.append("MobSF static evidence reported Android hardening indicators requiring review, including " + ", ".join(indicators[:4]) + ".")
    sast = _as_dict(technical.get("sast_app_code"))
    if _block_available(sast):
        total = _deep_int(sast, ["total_findings", "total", "results_count"])
        if total > 0:
            takeaways.append(f"SAST evidence retained {total} application-code finding(s) after excluding CI/CD workflows and audit-generation scripts from scope.")
    return takeaways


def _trivy_findings(trivy: Dict[str, Any]) -> List[Dict[str, Any]]:
    for keys in (["cve_table"], ["findings"], ["vulnerabilities"], ["top_findings"]):
        items = _deep_list(trivy, keys)
        if items:
            return [x for x in items if isinstance(x, dict)]
    return []


def _add_trivy_section(doc: Document, technical: Dict[str, Any]) -> None:
    trivy = _as_dict(technical.get("trivy_sca"))
    if not _block_available(trivy):
        doc.add_paragraph("Trivy SCA evidence was not available in the analysis pack.")
        return
    total = _deep_int(trivy, ["total_vulnerabilities", "vulnerabilities_total", "total"])
    packages = _deep_int(trivy, ["packages_detected", "package_count", "packages_total"])
    fixable = _deep_int(trivy, ["fixable_total", "fixable_vulnerabilities", "fixable"])
    licenses = _deep_int(trivy, ["license_entries_detected", "licenses_detected", "license_count"])
    by_sev = _deep_dict(trivy, ["by_severity", "severity_counts"])
    severity_text = ", ".join(f"{k}: {_safe_int(v)}" for k, v in by_sev.items()) if by_sev else "not reported"

    doc.add_paragraph(
        f"Trivy Software Composition Analysis reported {packages} detected package(s), {total} known dependency vulnerability finding(s), "
        f"{fixable} finding(s) with a fixed version available, and {licenses} license entr(y/ies). Severity distribution: {severity_text}."
    )

    rows = []
    for finding in _trivy_findings(trivy)[:12]:
        rows.append([
            _first_present(finding, ["severity", "Severity"], ""),
            _first_present(finding, ["id", "VulnerabilityID", "cve", "rule_id"], ""),
            _first_present(finding, ["pkg", "PkgName", "package", "package_name"], ""),
            _first_present(finding, ["installed", "InstalledVersion", "installed_version"], ""),
            _first_present(finding, ["fixed", "FixedVersion", "fixed_version"], ""),
            _first_present(finding, ["title", "Title", "description", "Description"], ""),
        ])
    _add_table(doc, ["Severity", "CVE / ID", "Package", "Installed", "Fixed", "Title / description"], rows, max_rows=12)


def _mobsf_signal_rows(mobsf: Dict[str, Any]) -> List[List[Any]]:
    checks = [
        ("Debuggable", ["debuggable", "has_debuggable", "debuggable_true", "android_debuggable"]),
        ("Debug certificate", ["debug_certificate", "has_debug_cert", "signed_with_debug_certificate"]),
        ("v1 signature / Janus exposure", ["v1_signature", "janus", "has_janus", "v1_signature_present"]),
        ("SHA1 certificate/signature evidence", ["sha1", "uses_sha1", "has_sha1"]),
        ("Backup enabled", ["allow_backup", "backup_enabled", "android_allow_backup"]),
        ("Minimum SDK", ["min_sdk", "minsdk", "minSdk"]),
        ("Dangerous permissions", ["dangerous_permissions_count", "dangerous_permission_count"]),
        ("Exported components", ["exported_components_count", "exported_component_count"]),
        ("Trackers detected", ["trackers_detected", "tracker_count", "detected_trackers"]),
    ]
    rows = []
    for label, keys in checks:
        value = _deep_find_first(mobsf, keys)
        rows.append([label, _format_bool(value)])
    return rows


def _add_mobsf_static_section(doc: Document, technical: Dict[str, Any]) -> None:
    mobsf = _as_dict(technical.get("mobsf_static"))
    if not _block_available(mobsf):
        doc.add_paragraph("MobSF static evidence was not available in the analysis pack. Static APK, manifest, signing, certificate, permission, and tracker checks should therefore be treated as not assessed by this report run.")
        return
    doc.add_paragraph("MobSF static evidence was used to summarize Android APK, manifest, certificate, signing, permissions, tracker, and binary hardening indicators. Missing values mean that the parser did not receive or normalize that indicator; they must not be interpreted as absence of risk.")
    _add_table(doc, ["Indicator", "Parsed value"], _mobsf_signal_rows(mobsf), max_rows=20)

    finding_lists = []
    for key in ["manifest_findings", "certificate_findings", "findings", "high_findings", "warnings"]:
        items = _deep_list(mobsf, [key])
        if items:
            finding_lists.extend(items)
    rows = []
    for item in finding_lists[:10]:
        if isinstance(item, dict):
            rows.append([
                _first_present(item, ["severity", "level", "risk"], ""),
                _first_present(item, ["title", "name", "rule", "id"], ""),
                _first_present(item, ["description", "message", "summary"], ""),
            ])
        else:
            rows.append(["", "", item])
    _add_table(doc, ["Severity", "Finding", "Description"], rows, max_rows=10, empty_message="No detailed MobSF static finding rows were available in the normalized evidence block.")

def _add_mobsf_dynamic_section(doc: Document, technical: Dict[str, Any]) -> None:
    dynamic = _as_dict(technical.get("mobsf_dynamic"))
    if not _block_available(dynamic):
        doc.add_paragraph("MobSF dynamic evidence was not available in the analysis pack. If dynamic analysis is not executed for a given application, runtime storage and behavioral observations should be treated as not assessed rather than clean.")
        return
    doc.add_paragraph("MobSF dynamic evidence was used to summarize runtime storage and behavioral observations, including local files, SharedPreferences, SQLite databases, cache artifacts, and trackers where reported.")
    rows = []
    for label, keys in [
        ("SharedPreferences artifacts", ["shared_preferences", "shared_preferences_files", "preferences"]),
        ("SQLite/database artifacts", ["sqlite_databases", "databases", "db_files"]),
        ("Local storage artifacts", ["local_storage_artifacts", "files", "storage_artifacts"]),
        ("Trackers", ["trackers", "detected_trackers"]),
    ]:
        items = _deep_list(dynamic, keys)
        count = len(items) if items else _deep_int(dynamic, [keys[0] + "_count"], 0)
        sample = "; ".join(_clean_text(x) for x in items[:4]) if items else "No examples normalized into analysis pack"
        rows.append([label, count, sample])
    _add_table(doc, ["Runtime evidence type", "Count", "Examples / parser note"], rows, max_rows=20)

def _sast_findings(sast: Dict[str, Any]) -> List[Dict[str, Any]]:
    for key in ["findings", "results", "app_code_findings", "top_findings"]:
        items = _deep_list(sast, [key])
        if items:
            return [x for x in items if isinstance(x, dict)]
    return []


def _add_sast_section(doc: Document, technical: Dict[str, Any]) -> None:
    sast = _as_dict(technical.get("sast_app_code"))
    if not _block_available(sast):
        doc.add_paragraph("SAST app-code evidence was not available in the analysis pack.")
        return

    total = _deep_int(sast, ["total_findings", "total", "results_count"])
    tool_counts = _deep_dict(sast, ["tool_counts", "by_tool"])
    scope_note = _first_present(
        sast,
        ["scope_note", "filter_note"],
        "CI/CD workflows, audit-generation scripts, test paths, tooling, and non-application files are excluded from the application audit scope."
    )

    if total <= 0:
        doc.add_paragraph(
            "SARIF artifacts were parsed, but no application-scope SAST findings were retained after applying the configured scope filter. "
            + _clean_text(scope_note)
        )
        if tool_counts:
            doc.add_paragraph("Raw SARIF result counts are retained for traceability only and are not treated as application-scope findings in this report.")
            _add_table(doc, ["Tool", "Raw SARIF results", "Interpretation"], [[k, v, "Traceability only; not retained as app-code finding"] for k, v in tool_counts.items()], max_rows=10)
        return

    doc.add_paragraph(f"SAST retained {total} application-code finding(s) after scope filtering. {_clean_text(scope_note)}")
    if tool_counts:
        _add_table(doc, ["Tool", "Retained / raw findings"], [[k, v] for k, v in tool_counts.items()], max_rows=10)

    rows = []
    for item in _sast_findings(sast)[:12]:
        rows.append([
            _first_present(item, ["tool", "driver", "source"], ""),
            _first_present(item, ["rule_id", "ruleId", "rule", "id"], ""),
            _first_present(item, ["severity", "level", "kind"], ""),
            _first_present(item, ["file", "path", "uri"], ""),
            _first_present(item, ["line", "start_line", "startLine"], ""),
            _first_present(item, ["message", "title", "description"], ""),
        ])
    _add_table(doc, ["Tool", "Rule", "Severity", "File", "Line", "Message"], rows, max_rows=12, empty_message="No detailed SAST rows were available after normalization.")

def _format_limitation_row(key: str, value: Any) -> List[str] | None:
    if _is_emptyish(value):
        return None
    normalized_key = _clean_text(key)
    if normalized_key == "missing_inputs":
        details = _clean_text(value)
        if not details:
            return None
        return ["Missing technical inputs", details]
    if normalized_key == "sast_notifications_sample":
        count = len(value) if isinstance(value, list) else 1
        tools = []
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and item.get("tool"):
                    tools.append(str(item.get("tool")))
        elif isinstance(value, dict) and value.get("tool"):
            tools.append(str(value.get("tool")))
        tool_text = ", ".join(sorted(set(tools))) if tools else "SAST toolchain"
        return [
            "SAST extraction warnings",
            f"{tool_text} reported {count} extraction or frontend warning(s). Findings detected remain valid for analyzed files, but absence of additional findings must not be interpreted as proof that the full codebase is free of vulnerabilities."
        ]
    if isinstance(value, list):
        details = "; ".join(_clean_text(x) for x in value if not _is_emptyish(x))
    elif isinstance(value, dict):
        details = _clean_text(value)
    else:
        details = _clean_text(value)
    if not details:
        return None
    return [normalized_key.replace("_", " ").title(), details]


def _add_coverage_limitations(doc: Document, technical: Dict[str, Any]) -> None:
    limitations = _as_dict(technical.get("coverage_limitations"))
    rows = []
    if isinstance(limitations, dict):
        for key, value in limitations.items():
            row = _format_limitation_row(str(key), value)
            if row:
                rows.append(row)
    if rows:
        _add_table(doc, ["Limitation", "Report-safe explanation"], rows, max_rows=12)
    else:
        doc.add_paragraph("No additional technical coverage limitations were reported in the analysis pack beyond the workbook-defined scope and tool-specific execution constraints.")


def _fallback_recommendations_for_pattern(pattern: str, technical: Dict[str, Any]) -> List[str]:
    pat = pattern.lower()
    if "hardcoded" in pat or "secret" in pat or "credential" in pat:
        return [
            "Remove credentials, API keys, tokens, and shared secrets from source code, resources, build files, and packaged binaries.",
            "Move secret material to a managed secrets service or secure backend flow; mobile clients should receive only short-lived scoped tokens.",
            "Add automated secret scanning in pull requests and release workflows, and block introduction of new high-confidence secrets.",
            "Rotate any exposed credentials and document revocation evidence before rescoring affected controls.",
        ]
    if "authorization" in pat or "rbac" in pat or "least privilege" in pat:
        return [
            "Define role-to-permission mappings for patient, clinician, administrator, and support workflows.",
            "Enforce authorization server-side for every sensitive API operation; do not rely only on UI-level restrictions.",
            "Add regression tests for horizontal and vertical privilege escalation scenarios.",
            "Review third-party and SDK privileges using least-privilege criteria and document ownership for privileged functions.",
        ]
    if "storage" in pat or "key management" in pat:
        return [
            "Inventory SharedPreferences, SQLite databases, cache directories, files, and logs that may contain PHI, credentials, tokens, or keys.",
            "Encrypt sensitive local data using Android Keystore-backed keys or eliminate client-side persistence where not strictly required.",
            "Disable Android backup for sensitive data or define explicit backup exclusion rules and verify them in the release APK.",
            "Add runtime and static tests that fail when sensitive values are stored in cleartext local storage.",
        ]
    if "authentication" in pat or "brute" in pat:
        return [
            "Implement server-enforced lockout, throttling, and anomaly detection for repeated authentication failures.",
            "Require step-up authentication, such as MFA, FIDO2, TOTP, or Android BiometricPrompt, for sensitive clinical or administrative actions where feasible.",
            "Harden session lifecycle controls, including inactivity timeout, explicit logout, token revocation, and account deletion session invalidation.",
            "Add negative tests for brute-force, credential stuffing, weak session reuse, and missing re-authentication scenarios.",
        ]
    if "transport" in pat or "certificate" in pat or "tls" in pat:
        return [
            "Verify that release builds reject cleartext traffic and do not allow permissive trust managers or hostname verifiers.",
            "Document certificate validation and pinning decisions, including operational rotation procedures when pinning is used.",
            "Remove development-only certificate bypasses from production code and enforce network security configuration checks in CI.",
            "Retest TLS behavior with MobSF or an equivalent mobile network security assessment before closure.",
        ]
    if "supply chain" in pat or "outdated" in pat or "dependency" in pat:
        trivy = _as_dict(technical.get("trivy_sca"))
        findings = _trivy_findings(trivy)
        pkgs = []
        for f in findings:
            pkg = _first_present(f, ["pkg", "PkgName", "package", "package_name"], "")
            fixed = _first_present(f, ["fixed", "FixedVersion", "fixed_version"], "")
            if pkg:
                pkgs.append(f"{pkg}" + (f" to {fixed}" if fixed else ""))
        first = "; ".join(pkgs[:4]) if pkgs else "all vulnerable dependencies with fixed versions"
        return [
            f"Upgrade {first} and regenerate dependency lock or inventory artifacts for the assessed release.",
            "Require Trivy SCA to produce JSON and SARIF artifacts on every release candidate without blocking exploratory scans.",
            "Document accepted-risk decisions for any unfixed CVE, including compensating controls and expiration date.",
            "Maintain an SBOM or dependency inventory and compare it against the previous release before publication.",
        ]
    if "input" in pat or "injection" in pat:
        return [
            "Centralize input validation for external files, network payloads, intents, deep links, logs, and user-controlled fields.",
            "Use parameterized database access and safe serialization/deserialization patterns across the application codebase.",
            "Treat SAST findings for injection, XML parsing, command execution, and log injection as release-blocking unless formally accepted.",
            "Add regression tests for malicious inputs, malformed payloads, and unsafe logging patterns.",
        ]
    if "audit logging" in pat or "retention" in pat or "alerting" in pat:
        return [
            "Define auditable clinical and administrative events, including authentication, access to patient data, privilege changes, and security exceptions.",
            "Protect logs against tampering, injection, excessive PHI disclosure, and unauthorized local persistence.",
            "Configure retention, monitoring, and alerting rules that align with operational and regulatory requirements.",
            "Verify that account deletion, logout, authentication failure, and sensitive data access events are logged consistently.",
        ]
    if "tamper" in pat or "reverse" in pat or "binary" in pat:
        return [
            "Verify that release APKs are not debuggable and are not signed with debug certificates.",
            "Remove debug-only tooling, test endpoints, logging interceptors, and development flags from production builds.",
            "Apply appropriate obfuscation, integrity checks, and anti-tampering controls for the release threat model.",
            "Retest the release APK with MobSF or equivalent tooling and retain evidence for re-scoring.",
        ]
    if "privacy" in pat or "consent" in pat or "permission" in pat:
        return [
            "Map privacy-sensitive data flows to user notices, consent events, and lawful processing purposes.",
            "Minimize dangerous Android permissions and justify each retained permission with a user-facing need.",
            "Ensure privacy notices, deprecation notices, and system-use warnings are visible before relevant access is granted.",
            "Retain evidence of consent, notice acceptance, and permission governance for re-audit.",
        ]
    return [
        "Define specific remediation tasks for each mapped control and assign an accountable owner.",
        "Collect implementation evidence and update the workbook before re-scoring.",
        "Add regression tests or automated checks to prevent recurrence.",
        "Retest the affected controls using the same evidence criteria applied in this audit.",
    ]

def _technical_kpi_for_pattern(pattern: str, technical: Dict[str, Any]) -> str:
    pat = pattern.lower()
    if "supply chain" in pat or "outdated" in pat or "dependency" in pat:
        return "No Critical or High dependency vulnerabilities remain in Trivy; all fixable CVEs have an upgrade, mitigation, or formally accepted-risk decision; dependency inventory/SBOM evidence is retained for the assessed release."
    if "storage" in pat or "key management" in pat:
        return "Local SharedPreferences, SQLite databases, caches, and files are reviewed for PHI, credentials, tokens, and keys; sensitive local data is encrypted or eliminated; backup exposure is explicitly controlled."
    if "tamper" in pat or "reverse" in pat or "binary" in pat:
        return "Release APK is not debuggable, is not signed with a debug certificate, debug-only tooling is absent, and release hardening controls are verified by MobSF or equivalent evidence."
    if "transport" in pat or "certificate" in pat or "tls" in pat:
        return "TLS configuration, certificate validation, and pinning decisions are documented and verified; weak signing or certificate indicators are remediated or formally justified."
    if "input" in pat or "injection" in pat:
        return "Application-code SAST findings for input handling and injection are triaged; exploitable issues are remediated and covered by regression tests."
    if "privacy" in pat or "permission" in pat:
        return "Dangerous permissions and privacy-sensitive data flows are justified, minimized, and covered by user-facing notices and runtime access controls."
    if "misconfiguration" in pat or "default" in pat:
        return "Manifest and runtime configuration findings are triaged; insecure defaults are removed or documented with compensating controls."
    return "Evidence recorded in workbook and technical artifacts; mapped controls can be re-tested and re-scored as compliant after remediation."

def _extract_json_object(text: str) -> str:
    text = (text or "").strip()
    if not text:
        raise ValueError("Model returned empty text.")

    # Direct JSON object.
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return json.dumps(obj, ensure_ascii=False)
    except Exception:
        pass

    # JSON inside Markdown code fence.
    fenced = re.search(
        r"```(?:json)?\s*(\{.*?\})\s*```",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if fenced:
        return fenced.group(1)

    # Remove common fence wrappers if the model used an unterminated fence.
    cleaned = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return json.dumps(obj, ensure_ascii=False)
    except Exception:
        pass

    # Find the first balanced JSON object anywhere in the response.
    start = text.find("{")
    if start < 0:
        preview = text[:500].replace("\n", "\\n")
        raise ValueError(f"No JSON object found in model output. Preview: {preview}")

    depth = 0
    in_string = False
    escape = False

    for i in range(start, len(text)):
        ch = text[i]

        if escape:
            escape = False
            continue

        if ch == "\\":
            escape = True
            continue

        if ch == '"':
            in_string = not in_string
            continue

        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:i + 1]
                obj = json.loads(candidate)
                if isinstance(obj, dict):
                    return candidate

    preview = text[:500].replace("\n", "\\n")
    raise ValueError(f"No complete JSON object found in model output. Preview: {preview}")


def _ai_env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _ai_api_key() -> str:
    for name in ("OPENAI_API_KEY", "LM_API_TOKEN", "AI_API_KEY"):
        value = _ai_env(name)
        if value:
            return value
    return ""


def _ai_enabled() -> bool:
    raw = _ai_env("AUDIT_SUMMARY_AI_ENABLED", "1").lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if requests is None:
        print("[AI] requests is not available; deterministic fallback will be used.")
        return False
    if not _ai_api_key():
        print("[AI] No API key/token found; deterministic fallback will be used.")
        return False
    return True


def _ai_api_base() -> str:
    return (
        _ai_env("AI_API_BASE")
        or _ai_env("OPENAI_API_BASE")
        or _ai_env("LM_STUDIO_API_BASE")
        or "http://localhost:1234/v1"
    ).rstrip("/")


def _ai_model() -> str:
    return _ai_env("AI_MODEL") or _ai_env("OPENAI_MODEL") or "gpt-oss-20b"


def _ai_timeout_s() -> int:
    return _safe_int(_ai_env("AI_TIMEOUT_S", "300"), 300)


def _ai_max_tokens(default: int = 1600) -> int:
    return _safe_int(_ai_env("AI_MAX_OUTPUT_TOKENS", str(default)), default)


def _ai_json_chat(section_name: str, system_prompt: str, user_payload: Dict[str, Any], max_tokens: int = 1600) -> Dict[str, Any]:
    """Call an OpenAI-compatible chat endpoint directly through requests.

    This avoids installing OpenAI SDK, LiteLLM, tokenizers, or HuggingFace packages
    in the audit-summary job. Each call is section-scoped to keep prompts small.
    Failures are non-fatal because deterministic report content remains the fallback.
    """
    if not _ai_enabled():
        return {}

    url = _ai_api_base() + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {_ai_api_key()}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": _ai_model(),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        "temperature": 0.15,
        "max_tokens": max_tokens,
    }

    try:
        print(f"[AI] Calling section={section_name} model={_ai_model()} base={_ai_api_base()}")
        resp = requests.post(url, headers=headers, json=payload, timeout=_ai_timeout_s())  # type: ignore[union-attr]
        if resp.status_code >= 400:
            print(f"[AI][WARN] Section {section_name} failed with HTTP {resp.status_code}: {resp.text[:500]}")
            return {}
        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            print(f"[AI][WARN] Section {section_name} returned no choices.")
            return {}
        content = (((choices[0] or {}).get("message") or {}).get("content") or "").strip()
        if not content:
            print(f"[AI][WARN] Section {section_name} returned empty content.")
            return {}
        obj = json.loads(_extract_json_object(content))
        if isinstance(obj, dict):
            print(f"[AI] Section {section_name} completed.")
            return obj
    except Exception as exc:
        print(f"[AI][WARN] Section {section_name} failed: {exc}")
    return {}


def _compact_patterns_for_ai(patterns: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in patterns[:limit]:
        count = int(p.get("mapped_noncompliant_count", 0))
        out.append({
            "pattern": p.get("pattern"),
            "mapped_noncompliant_count": count,
            "severity": p.get("severity"),
            "likelihood": _likelihood_from_count(count),
            "recommended_owner": p.get("recommended_owner"),
            "example_puids": (p.get("example_puids") or [])[:5],
            "description_anchors": [_clean_text(x) for x in (p.get("description_anchors") or [])[:2]],
        })
    return out


def _compact_technical_for_ai(technical: Dict[str, Any]) -> Dict[str, Any]:
    trivy = _as_dict(technical.get("trivy_sca"))
    mobsf_static = _as_dict(technical.get("mobsf_static"))
    mobsf_dynamic = _as_dict(technical.get("mobsf_dynamic"))
    sast = _as_dict(technical.get("sast_app_code"))
    vision = _as_dict(technical.get("vision360"))
    limitations = _as_dict(technical.get("coverage_limitations"))

    return {
        "vision360": {
            "available": _block_available(vision),
            "flags_count": _deep_int(vision, ["flags_count"]),
            "state_counts": _deep_dict(vision, ["state_counts"]),
            "group_counts": _deep_dict(vision, ["group_counts"]),
            "feature_keys": _deep_list(vision, ["feature_keys"]),
        },
        "trivy_sca": {
            "available": _block_available(trivy),
            "packages_detected": _deep_int(trivy, ["packages_detected", "package_count", "packages_total"]),
            "total_vulnerabilities": _deep_int(trivy, ["total_vulnerabilities", "vulnerabilities_total", "total"]),
            "fixable_total": _deep_int(trivy, ["fixable_total", "fixable_vulnerabilities", "fixable"]),
            "by_severity": _deep_dict(trivy, ["by_severity", "severity_counts"]),
            "top_findings": [
                {
                    "id": _first_present(f, ["id", "VulnerabilityID", "cve", "rule_id"], ""),
                    "severity": _first_present(f, ["severity", "Severity"], ""),
                    "package": _first_present(f, ["pkg", "PkgName", "package", "package_name"], ""),
                    "installed": _first_present(f, ["installed", "InstalledVersion", "installed_version"], ""),
                    "fixed": _first_present(f, ["fixed", "FixedVersion", "fixed_version"], ""),
                    "title": _clean_text(_first_present(f, ["title", "Title", "description", "Description"], "")),
                }
                for f in _trivy_findings(trivy)[:12]
            ],
        },
        "mobsf_static": {
            "available": _block_available(mobsf_static),
            "signals": _mobsf_signal_rows(mobsf_static) if _block_available(mobsf_static) else [],
            "manifest_findings_count": _deep_int(mobsf_static, ["manifest_findings_count"]),
            "certificate_findings_count": _deep_int(mobsf_static, ["certificate_findings_count"]),
            "dangerous_permissions": _deep_list(mobsf_static, ["dangerous_permissions"])[:20],
            "permissions_count": _deep_int(mobsf_static, ["permissions_count"]),
        },
        "mobsf_dynamic": {
            "available": _block_available(mobsf_dynamic),
            "local_storage_artifacts_count": _deep_int(mobsf_dynamic, ["local_storage_artifacts_count", "local_storage_artifacts_count_count"]),
            "local_storage_artifacts_sample": _deep_list(mobsf_dynamic, ["local_storage_artifacts_sample", "local_storage_artifacts"])[:12],
            "shared_preferences_artifacts": _deep_list(mobsf_dynamic, ["shared_preferences_artifacts", "shared_preferences"])[:12],
            "sqlite_database_artifacts": _deep_list(mobsf_dynamic, ["sqlite_database_artifacts", "sqlite_databases"])[:12],
            "detected_trackers": _deep_int(mobsf_dynamic, ["detected_trackers", "trackers_detected"]),
        },
        "sast_app_code": {
            "available": _block_available(sast),
            "summary": _deep_dict(sast, ["summary"]),
            "tool_counts": _deep_dict(sast, ["tool_counts", "by_tool"]),
            "security_findings_sample": _deep_list(sast, ["security_findings_sample", "findings"])[:12],
            "hardening_signals_sample": _deep_list(sast, ["hardening_signals_sample"])[:8],
        },
        "coverage_limitations": {
            "missing_inputs": _deep_list(limitations, ["missing_inputs"]),
            "sast_warning_count": len(_deep_list(limitations, ["sast_notifications_sample", "sast_extraction_warnings"])),
        },
    }


def _call_llm_for_audit_sections(
    metrics: Dict[str, Any],
    app: Dict[str, Any],
    patterns: List[Dict[str, Any]],
    technical: Dict[str, Any],
    likelihood_rubric: Dict[str, str],
) -> Dict[str, Any]:
    if not _ai_enabled():
        return {}

    common_system = (
        "You are a senior mobile health security audit reporting specialist. "
        "Write in precise technical English for an executive and engineering audience. "
        "Use only the provided JSON data. Do not invent controls, metrics, vulnerabilities, or evidence. "
        "If evidence is absent, state the limitation explicitly. "
        "Return exactly one valid JSON object and nothing else."
    )

    compact_patterns = _compact_patterns_for_ai(patterns)
    compact_technical = _compact_technical_for_ai(technical)

    base_context = {
        "application": app,
        "metrics": metrics,
        "likelihood_rubric": likelihood_rubric,
        "top_weakness_patterns": compact_patterns,
        "technical_evidence": compact_technical,
    }

    out: Dict[str, Any] = {}

    executive = _ai_json_chat(
        "executive_summary",
        common_system,
        {
            "task": "Generate executive summary components for an mSEC-AM mobile application audit report.",
            "constraints": {
                "key_takeaways_count": "5 to 7",
                "must_reference": ["overall compliance rate", "applicable controls", "non-compliant controls", "top weakness patterns", "technical scanner evidence where available"],
                "do_not_claim": ["full codebase is clean", "MobSF absence equals no risk", "SAST raw findings are app findings"],
            },
            "context": base_context,
            "required_output_schema": {
                "audit_summary_paragraph": "<one concise paragraph>",
                "key_takeaways": ["<bullet text>"],
            },
        },
        max_tokens=min(_ai_max_tokens(1800), 2200),
    )
    out.update({k: v for k, v in executive.items() if k in {"audit_summary_paragraph", "key_takeaways"}})

    technical_narratives = _ai_json_chat(
        "technical_narratives",
        common_system,
        {
            "task": "Generate report-ready technical narrative paragraphs from scanner evidence.",
            "constraints": {
                "one_paragraph_each": True,
                "mention_limitations": True,
                "do_not_overstate_sast": True,
                "do_not_treat_missing_mobsf_fields_as_clean": True,
            },
            "context": base_context,
            "required_output_schema": {
                "technical_coverage_paragraph": "<paragraph>",
                "technical_evidence_intro": "<paragraph>",
                "trivy_paragraph": "<paragraph>",
                "mobsf_static_paragraph": "<paragraph>",
                "mobsf_dynamic_paragraph": "<paragraph>",
                "sast_paragraph": "<paragraph>",
                "coverage_limitations_paragraph": "<paragraph>",
            },
        },
        max_tokens=min(_ai_max_tokens(2200), 2600),
    )
    if technical_narratives:
        out["technical_narratives"] = technical_narratives

    pattern_writeups = _ai_json_chat(
        "pattern_writeups",
        common_system,
        {
            "task": "Generate concise weakness-pattern writeups and recommendations grounded in workbook prevalence and technical evidence.",
            "constraints": {
                "patterns": "Use exact pattern names from input.",
                "expected": "1 sentence.",
                "impact": "1 sentence mentioning confidentiality, integrity, availability, or health-data regulatory exposure only when supported.",
                "recommendations": "4 to 6 actionable bullets per pattern, specific and non-repetitive.",
                "no_time_window_headings": True,
                "no_unprovided_metrics": True,
            },
            "context": {
                "application": app,
                "likelihood_rubric": likelihood_rubric,
                "top_weakness_patterns": compact_patterns,
                "technical_evidence": compact_technical,
            },
            "required_output_schema": {
                "pattern_writeups": [
                    {
                        "pattern": "<exact pattern name>",
                        "expected": "<sentence>",
                        "impact": "<sentence>",
                        "recommendations": ["<action>"],
                    }
                ]
            },
        },
        max_tokens=min(_ai_max_tokens(3600), 4200),
    )
    if isinstance(pattern_writeups.get("pattern_writeups"), list):
        out["pattern_writeups"] = pattern_writeups["pattern_writeups"]

    return out


def _call_llm_for_style(patterns: List[Dict[str, Any]], likelihood_rubric: Dict[str, str], max_takeaways: int = 7) -> Dict[str, Any]:
    # Backward-compatible wrapper retained for older callers.
    return {}

def main() -> None:
    in_path = os.getenv("AUDIT_ANALYSIS_JSON_PATH", DEFAULT_IN)
    out_path = os.getenv("AUDIT_SUMMARY_DOCX_PATH", DEFAULT_OUT)
    chart_dir = os.getenv("AUDIT_SUMMARY_CHART_DIR", CHART_DIR)

    if not os.path.isfile(in_path):
        raise SystemExit(f"[ERROR] analysis pack not found: {in_path}")

    Path(chart_dir).mkdir(parents=True, exist_ok=True)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    with open(in_path, "r", encoding="utf-8") as f:
        pack = json.load(f)

    metrics = pack["metrics"]
    cat_stats = pack["category_metrics"]
    app = pack["app_metadata"]
    actors = pack["actors"]
    patterns = pack["weakness_patterns"]
    pos_controls = pack.get("positive_controls_candidates", [])[:7]
    likelihood_rubric = pack.get("likelihood_rubric", {})
    technical = _technical_evidence(pack)
    report_title = _app_report_title(app)

    audit_dt = datetime.utcnow().date()
    audit_date_str = audit_dt.strftime("%d %b %Y")

    plt.rcParams.update({"font.size": 10, "figure.titlesize": 12, "axes.titlesize": 12, "axes.labelsize": 10})

    fig1 = os.path.join(chart_dir, "figure1_overall_donut.png")
    fig2 = os.path.join(chart_dir, "figure2_noncompliance_share_hbar.png")
    fig3 = os.path.join(chart_dir, "figure3_compliance_rate_hbar.png")
    fig4 = os.path.join(chart_dir, "figure4_counts_stacked_hbar.png")

    applicable = int(metrics["applicable"])
    compliant = int(metrics["compliant"])
    non_compliant = int(metrics["non_compliant"])
    not_applicable = int(metrics["not_applicable"])
    overall_pct = float(metrics["overall_compliance_pct"])

    _donut([compliant, non_compliant, not_applicable], ["Compliant", "Non-compliant", "Not applicable"], "Overall compliance distribution (workbook-derived)", f"{overall_pct:.2f}%\ncompliant\n(applicable)", fig1)
    _hbar_share_noncompliances(cat_stats, fig2)
    _hbar_compliance_rate(cat_stats, fig3)
    _stacked_counts(cat_stats, fig4)

    prose: Dict[str, Any] = {}
    try:
        prose = _call_llm_for_audit_sections(metrics, app, patterns, technical, likelihood_rubric)
        if prose:
            ai_sections_path = os.getenv("AUDIT_SUMMARY_AI_SECTIONS_PATH", "").strip()
            if not ai_sections_path:
                ai_sections_path = str(_runtime_data_dir() / "audit_summary_ai_sections.json")
            Path(ai_sections_path).parent.mkdir(parents=True, exist_ok=True)
            with open(ai_sections_path, "w", encoding="utf-8") as f:
                json.dump(prose, f, ensure_ascii=False, indent=2)
            print(f"[AI] Section outputs saved -> {ai_sections_path}")
    except Exception as exc:
        print(f"[AI][WARN] Sectioned AI generation failed; deterministic fallback will be used: {exc}")
        prose = {}

    tech_ai = _as_dict(prose.get("technical_narratives"))
    key_takeaways = prose.get("key_takeaways", [])
    writeups = {w["pattern"]: w for w in prose.get("pattern_writeups", []) if isinstance(w, dict) and "pattern" in w}
    if not key_takeaways:
        key_takeaways = [f"{p['pattern']} - {p['severity']} severity; {int(p['mapped_noncompliant_count'])} related non-compliant control(s) in the workbook." for p in patterns[:7]]
    technical_takeaways = _technical_takeaways(technical)
    if technical_takeaways:
        key_takeaways = (technical_takeaways + key_takeaways)[:7]

    doc = Document()
    _set_doc_defaults(doc)
    _add_header_footer(doc.sections[0], audit_date_str, report_title)
    _add_cover(doc, audit_date_str, actors["Auditor"], report_title)
    used_bookmarks: set[str] = set()
    toc_entries: List[tuple[int, str, str]] = []
    bookmark_id = 1000

    def add_nav_heading(text: str, level: int):
        nonlocal bookmark_id
        style = f"Heading {level}"
        p = doc.add_paragraph(text, style=style)
        anchor = _make_bookmark_name(text, used_bookmarks)
        _add_bookmark(p, anchor, bookmark_id)
        toc_entries.append((level, text, anchor))
        bookmark_id += 1
        return p

    toc_placeholder = _add_toc(doc)

    add_nav_heading("1. App information", 1)
    _add_two_col_table(doc, [[k, v] for k, v in app.items()])

    add_nav_heading("2. Actors", 1)
    _add_two_col_table(doc, [["Auditor", actors["Auditor"]], ["Requirement Engineering team", "\n".join(actors["Requirement Engineering team"])], ["Engineering Group (EN)", "\n".join(actors["Engineering Group (EN)"])]])

    add_nav_heading("3. Scope and limitations", 1)
    doc.add_paragraph("This Audit Summary consolidates the compliance determinations recorded in the audit workbook. The results reflect the assessed application version and the workbook-defined scope. Controls not evidenced as implemented in the workbook are reported as non-compliant for summary purposes. Where available, technical evidence from Vision360, Trivy, MobSF, and app-code SAST is used to support and qualify the workbook-derived findings. CI/CD workflows and audit-generation scripts are outside the application audit scope unless explicitly included by project configuration.")

    add_nav_heading("4. Evidence criteria", 1)
    doc.add_paragraph("- Compliant: the workbook provides sufficient evidence that the control is implemented and effective for the assessed scope.\n- Non-compliant: the workbook indicates the control is missing, insufficient, or not evidenced.\n- Not applicable: the control is recorded as out of scope or not relevant for the assessed context.\n- Technical evidence: automated scan artifacts are used as supporting evidence for application code, Android manifest, binary, dependency, runtime, and storage observations. They do not replace requirement-level judgment and are interpreted within the declared audit scope.")

    add_nav_heading("5. Audit summary", 1)
    doc.add_paragraph("The audit was carried out using the mSEC-AM (mobile SECurity Audit Method).")
    doc.add_paragraph(f"Overall, {int(metrics['total_assessed'])} requirements were assessed. {applicable} were applicable controls and {not_applicable} were recorded as not applicable. Of the applicable controls, {compliant} were compliant and {non_compliant} were non-compliant, resulting in an overall compliance rate of {overall_pct:.2f}% (applicable controls only).")
    ai_audit_summary = _clean_text(prose.get("audit_summary_paragraph", ""))
    if ai_audit_summary:
        doc.add_paragraph(ai_audit_summary)
    else:
        doc.add_paragraph("This report summarizes the dominant weakness patterns evidenced by non-compliant requirements and proposes actionable remediations suitable for mHealth/EMR environments handling sensitive health information.")
    if technical:
        doc.add_paragraph("The report also incorporates technical scan evidence where available, including dependency vulnerability evidence from Trivy, Android APK and manifest evidence from MobSF, runtime observations from MobSF dynamic analysis, and SAST findings filtered to application code.")

    add_nav_heading("5.1 Key takeaways (Top findings)", 2)
    _add_callout(doc, "Key takeaways (Top findings)", key_takeaways[:7])

    add_nav_heading("5.2 Positive controls observed", 2)
    doc.add_paragraph("All statements below are derived exclusively from controls recorded as Compliant in the audit workbook and include supporting signals (flags and/or evidence). Verification traceability is provided in Appendix B.")
    if pos_controls:
        for pc in pos_controls:
            doc.add_paragraph(_sanitize_positive_statement(pc.get("declarative_statement", "")), style="List Bullet")
    else:
        doc.add_paragraph("No compliant controls with supporting evidence/flags were available for verification in the workbook.", style="List Bullet")

    add_nav_heading("5.3 Risk scoring approach", 2)
    doc.add_paragraph("Severity and likelihood ratings in this report follow a qualitative rubric grounded in the audit workbook:\n- Severity reflects potential impact on confidentiality, integrity, and availability of health information, including regulatory exposure.\n- Likelihood is derived from workbook prevalence: the count of non-compliant controls mapped to a weakness pattern as a proxy for exposure.\nLikelihood mapping: High (>=50), Medium-High (20-49), Medium (10-19), Low-Medium (<10).")

    add_nav_heading("5.4 Risk triage (prioritized)", 2)
    rt = doc.add_table(rows=1, cols=7)
    rt.style = "Table Grid"
    h = rt.rows[0].cells
    for idx, txt in enumerate(["Weakness pattern", "Severity (rubric)", "Impact", "Likelihood (workbook prevalence)", "Workbook basis", "Recommended owner", "Target timeline"]):
        h[idx].text = txt
        _set_cell_shading(h[idx], "D9E1F2")
        for run in h[idx].paragraphs[0].runs:
            run.bold = True
    for p in patterns[:10]:
        cnt = int(p["mapped_noncompliant_count"])
        lik = _likelihood_from_count(cnt)
        sev = p["severity"]
        owner = p["recommended_owner"]
        impact = writeups.get(p["pattern"], {}).get("impact", "The weakness pattern can compromise confidentiality/integrity/availability of health information and increase regulatory exposure.")
        row = rt.add_row().cells
        row[0].text = p["pattern"]
        row[1].text = sev
        row[2].text = impact
        row[3].text = lik
        row[4].text = f"{cnt} mapped non-compliant control(s) in the workbook."
        row[5].text = owner
        row[6].text = _target_timeline(sev)
    doc.add_paragraph()

    add_nav_heading("5.5 Technical scan coverage", 2)
    ai_technical_coverage = _clean_text(tech_ai.get("technical_coverage_paragraph", ""))
    if ai_technical_coverage:
        doc.add_paragraph(ai_technical_coverage)
    else:
        doc.add_paragraph("The following table summarizes which automated technical evidence sources were available to support the audit summary. Absence of a technical source means that the source was not available to the report generator, not necessarily that the corresponding risk is absent.")
    _add_table(doc, ["Evidence source", "Available", "Summary"], _source_status_rows(technical), max_rows=10)

    add_nav_heading("6. Technical evidence from automated analysis", 1)
    ai_tech_intro = _clean_text(tech_ai.get("technical_evidence_intro", ""))
    if ai_tech_intro:
        doc.add_paragraph(ai_tech_intro)
    else:
        doc.add_paragraph("This section summarizes technical scan evidence relevant to the assessed application and its code. The evidence is used to reinforce and qualify workbook findings while preserving the workbook as the authoritative requirement-level adjudication source.")
    add_nav_heading("6.1 Software Composition Analysis from Trivy", 2)
    if _clean_text(tech_ai.get("trivy_paragraph", "")):
        doc.add_paragraph(_clean_text(tech_ai.get("trivy_paragraph", "")))
    _add_trivy_section(doc, technical)
    add_nav_heading("6.2 Android static evidence from MobSF", 2)
    if _clean_text(tech_ai.get("mobsf_static_paragraph", "")):
        doc.add_paragraph(_clean_text(tech_ai.get("mobsf_static_paragraph", "")))
    _add_mobsf_static_section(doc, technical)
    add_nav_heading("6.3 Runtime evidence from MobSF dynamic analysis", 2)
    if _clean_text(tech_ai.get("mobsf_dynamic_paragraph", "")):
        doc.add_paragraph(_clean_text(tech_ai.get("mobsf_dynamic_paragraph", "")))
    _add_mobsf_dynamic_section(doc, technical)
    add_nav_heading("6.4 Static Application Security Testing evidence", 2)
    if _clean_text(tech_ai.get("sast_paragraph", "")):
        doc.add_paragraph(_clean_text(tech_ai.get("sast_paragraph", "")))
    _add_sast_section(doc, technical)
    add_nav_heading("6.5 Technical coverage limitations", 2)
    if _clean_text(tech_ai.get("coverage_limitations_paragraph", "")):
        doc.add_paragraph(_clean_text(tech_ai.get("coverage_limitations_paragraph", "")))
    _add_coverage_limitations(doc, technical)

    add_nav_heading("7. Main deficiencies", 1)
    doc.add_paragraph("The following deficiencies are synthesized as common weakness patterns based on non-compliant requirements and supported, where available, by technical scan evidence. They are not grouped by category; instead they represent cross-cutting gaps evidenced in the audit workbook and related artifacts.")
    for p in patterns[:10]:
        pat = p["pattern"]
        cnt = int(p["mapped_noncompliant_count"])
        sev = p["severity"]
        owner = p["recommended_owner"]
        ex_ids = p.get("example_puids", [])[:4]
        anchors = p.get("description_anchors", [])[:2]
        doc.add_paragraph(f"{pat} ({sev})", style="Heading 2")
        doc.add_paragraph(f"Workbook basis: {cnt} related non-compliant control(s) mapped to this pattern.")
        expected = writeups.get(pat, {}).get("expected", "Controls in this area should provide robust, consistently enforced safeguards appropriate to health data processing.")
        impact = writeups.get(pat, {}).get("impact", "Deficiencies can increase the likelihood and impact of security incidents affecting confidentiality, integrity, or availability.")
        doc.add_paragraph(f"Expected: {expected}")
        doc.add_paragraph("Observed: The audit workbook indicates the related controls are missing, insufficient, or not evidenced for the assessed scope.")
        doc.add_paragraph(f"Impact: {impact}")
        doc.add_paragraph(f"Recommended owner: {owner}")
        if ex_ids:
            doc.add_paragraph(f"Traceability (examples, non-exhaustive): {', '.join(ex_ids)}.")
        for a in anchors:
            doc.add_paragraph(f"Evidence anchor (from workbook description): {a}", style="List Bullet")

    doc.add_page_break()
    add_nav_heading("8. Recommendations", 1)
    doc.add_paragraph("Recommendations are organized by the same weakness patterns presented in the Main deficiencies section. They target remediation of workbook-evidenced gaps and may include strengthening controls to improve security posture.")
    for p in patterns[:10]:
        pat = p["pattern"]
        doc.add_paragraph(pat, style="Heading 2")
        recs = writeups.get(pat, {}).get("recommendations", [])
        if not recs:
            recs = _fallback_recommendations_for_pattern(pat, technical)
        for r in recs[:12]:
            doc.add_paragraph(str(r).strip(), style="List Bullet")

    doc.add_page_break()
    add_nav_heading("9. Visual Analytics", 1)
    doc.add_paragraph("Figures below summarize workbook-derived outcomes and distributions. All figures: source: audit workbook.")
    _add_figure(doc, fig1, "Figure 1. Overall compliance distribution (donut chart; source: audit workbook).")
    _add_figure(doc, fig2, "Figure 2. Share of non-compliances by category (legible horizontal bars; source: audit workbook).")
    _add_figure(doc, fig3, "Figure 3. Compliance rate by category (applicable controls only; source: audit workbook).")
    _add_figure(doc, fig4, "Figure 4. Counts by category and status (horizontal stacked bars; source: audit workbook).")

    doc.add_page_break()
    add_nav_heading("10. Management Action Plan (MAP)", 1)
    doc.add_paragraph("The MAP below is designed for executive readability. Detailed evidence remains in the workbook and technical artifacts. Priority combines severity and workbook-derived likelihood from Section 5.3.")
    mp = doc.add_table(rows=1, cols=5)
    mp.style = "Table Grid"
    mh = mp.rows[0].cells
    headers = ["Finding / weakness pattern", "Owner", "Priority", "Target date", "Closure criteria"]
    for idx, txt in enumerate(headers):
        mh[idx].text = txt
        _set_cell_shading(mh[idx], "D9E1F2")
        for run in mh[idx].paragraphs[0].runs:
            run.bold = True
    for p in patterns[:10]:
        pat = p["pattern"]
        cnt = int(p["mapped_noncompliant_count"])
        sev = p["severity"]
        lik = _likelihood_from_count(cnt)
        owner = p["recommended_owner"]
        target_date = _target_date_str(audit_dt, sev)
        criteria = _technical_kpi_for_pattern(pat, technical)
        row = mp.add_row().cells
        row[0].text = f"{pat}\nWorkbook basis: {cnt} mapped non-compliant control(s)."
        row[1].text = owner
        row[2].text = f"{sev} / {lik}"
        row[3].text = target_date
        row[4].text = criteria

    doc.add_paragraph("Technical verification evidence expected at closure includes updated workbook scoring, scan artifacts for the remediated release, regression-test evidence where applicable, and formal accepted-risk records for unresolved items.")
    doc.add_page_break()
    add_nav_heading("Appendix A - Traceability index (non-exhaustive)", 1)
    doc.add_paragraph("For complete traceability and evidence, refer to the audit workbook.")
    for p in patterns[:10]:
        ex = p.get("example_puids", [])[:5]
        if ex:
            doc.add_paragraph(f"{p['pattern']}: {', '.join(ex)}", style="List Bullet")

    doc.add_page_break()
    add_nav_heading("Appendix B - Positive controls verification (workbook traceability)", 1)
    doc.add_paragraph("This appendix verifies each Positive controls observed statement by providing the originating PUID, flags used, and an evidence excerpt when available.")
    vb = doc.add_table(rows=1, cols=4)
    vb.style = "Table Grid"
    vh = vb.rows[0].cells
    for idx, txt in enumerate(["Positive control statement (as reported)", "Workbook PUID", "Flags used", "Evidence / justification (excerpt)"]):
        vh[idx].text = txt
        _set_cell_shading(vh[idx], "D9E1F2")
        for run in vh[idx].paragraphs[0].runs:
            run.bold = True
    if pos_controls:
        for pc in pos_controls:
            r = vb.add_row().cells
            r[0].text = _sanitize_positive_statement(pc.get("declarative_statement", ""))
            r[1].text = pc["puid"]
            r[2].text = pc.get("flags_used", "") or ""
            r[3].text = pc.get("evidence_excerpt", "") or ""
    else:
        r = vb.add_row().cells
        r[0].text = "No verified positive controls available."
        r[1].text = ""
        r[2].text = ""
        r[3].text = ""

    doc.add_page_break()
    add_nav_heading("Appendix C - Technical evidence summary", 1)
    doc.add_paragraph("This appendix provides a compact index of the technical evidence parsed from scan artifacts. Detailed raw JSON, SARIF, and tool reports remain in their original pipeline artifacts and are not embedded in the report package.")
    _add_table(doc, ["Evidence source", "Available", "Summary"], _source_status_rows(technical), max_rows=10)

    _render_clickable_toc(toc_placeholder, toc_entries)
    _enable_update_fields_on_open(doc)
    _quality_gate(doc)
    doc.save(out_path)
    print(f"[OK] DOCX generated -> {out_path}")


if __name__ == "__main__":
    main()