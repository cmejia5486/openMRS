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
    from lib.ai_runtime import AIRuntime  # type: ignore
except Exception as exc:
    AIRuntime = None  # type: ignore
    AI_RUNTIME_IMPORT_ERROR = exc
else:
    AI_RUNTIME_IMPORT_ERROR = None

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

HEADER_TEXT_TEMPLATE = "mSEC-AM Audit Summary - {report_title}"


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
    style.paragraph_format.space_after = Pt(6)
    style.paragraph_format.line_spacing = 1.08
    section = doc.sections[0]
    section.top_margin = Inches(0.75)
    section.bottom_margin = Inches(0.75)
    section.left_margin = Inches(0.85)
    section.right_margin = Inches(0.85)


def _is_toc_paragraph(paragraph) -> bool:
    try:
        if paragraph._p.xpath("./w:hyperlink"):
            return True
    except Exception:
        pass
    try:
        left_indent = paragraph.paragraph_format.left_indent
        if left_indent is not None and left_indent.pt and left_indent.pt > 0 and paragraph.text.strip():
            return True
    except Exception:
        pass
    return False


def _should_justify_paragraph(paragraph) -> bool:
    text = (paragraph.text or "").strip()
    if not text:
        return False

    style_name = getattr(getattr(paragraph, "style", None), "name", "") or ""
    if style_name.startswith("Heading"):
        return False
    if style_name in {"Title", "Subtitle", "List Bullet", "List Number", "Caption"}:
        return False
    if paragraph.alignment in {WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.RIGHT}:
        return False
    if _is_toc_paragraph(paragraph):
        return False
    return True


def _format_report_paragraphs(doc: Document) -> None:
    """Apply professional paragraph formatting to narrative body text only.

    Tables, figures, captions, bullets, headings, cover text, TOC links, headers,
    and footers are intentionally excluded. The goal is to fix ragged narrative
    text in the exported PDF without damaging table readability.
    """
    for p in doc.paragraphs:
        if not _should_justify_paragraph(p):
            continue
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.line_spacing = 1.08


def _add_body_paragraph(doc: Document, text: Any):
    p = doc.add_paragraph(_clean_text(text))
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.08
    return p


def _add_header_footer(section, audit_date_str: str, report_title: str = "Mobile Application") -> None:
    header = section.header
    header.is_linked_to_previous = False
    p = header.paragraphs[0]
    p.text = HEADER_TEXT_TEMPLATE.format(report_title=report_title)
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
        (r"^The application applications not change\b", "The application does not change"),
        (r"^The application remove\b", "The application removes"),
        (r"^The application be free\b", "The application is free"),
        (r"^The application request\b", "The application requests"),
        (r"^The application provide\b", "The application provides"),
        (r"^The application the mobile application\b", "The mobile application"),
        (r"\bremovess\b", "removes"),
        (r"\brequestss\b", "requests"),
        (r"\bprovidess\b", "provides"),
        (r"\bCA\) be used\b", "CA) should be used"),
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
    if version_s and version_s not in name_s:
        version_label = version_s if version_s.lower().startswith("v") else f"v{version_s}"
        return f"{name_s} {version_label}"
    return name_s


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
        ("SharedPreferences artifacts", ["shared_preferences_artifacts", "shared_preferences", "shared_preferences_files", "preferences"]),
        ("SQLite/database artifacts", ["sqlite_database_artifacts", "sqlite_databases", "databases", "db_files"]),
        ("Local storage artifacts", ["local_storage_artifacts_sample", "local_storage_artifacts", "files", "storage_artifacts"]),
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



def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _ai_pattern_writeups_required() -> bool:
    """Require AI-generated pattern narratives by default.

    Recommendations and MAP closure criteria are not authored from static
    fallback text. They must be returned by the configured AI task using the
    workbook metrics and scanner context. Set
    AUDIT_SUMMARY_AI_PATTERN_WRITEUPS_REQUIRED=0 only for local debugging.
    """
    if _env_bool("AUDIT_SUMMARY_AI_REQUIRED", False):
        return True
    return _env_bool("AUDIT_SUMMARY_AI_PATTERN_WRITEUPS_REQUIRED", True)


def _ai_recommendations_for_pattern(pattern: str, writeups: Dict[str, Dict[str, Any]]) -> List[str]:
    item = _as_dict(writeups.get(pattern))
    recs = item.get("recommendations")
    if not isinstance(recs, list):
        return []
    return [_clean_text(x) for x in recs if _clean_text(x)]


def _ai_field_for_pattern(pattern: str, writeups: Dict[str, Dict[str, Any]], field: str) -> str:
    return _clean_text(_as_dict(writeups.get(pattern)).get(field, ""))


def _validate_ai_pattern_writeups(patterns: List[Dict[str, Any]], writeups: Dict[str, Dict[str, Any]]) -> None:
    """Validate that AI supplied the report-authored pattern content.

    This prevents static, pre-authored recommendations from silently entering
    the report. The configured model must produce expected state, impact,
    recommendations, and MAP closure criteria for each reported pattern.
    """
    missing: List[str] = []
    for p in patterns[:10]:
        pat = str(p.get("pattern") or "").strip()
        if not pat:
            continue
        item = _as_dict(writeups.get(pat))
        missing_fields = []
        if not _clean_text(item.get("expected")):
            missing_fields.append("expected")
        if not _clean_text(item.get("impact")):
            missing_fields.append("impact")
        if not _ai_recommendations_for_pattern(pat, writeups):
            missing_fields.append("recommendations")
        if not _clean_text(item.get("closure_criteria")):
            missing_fields.append("closure_criteria")
        if missing_fields:
            missing.append(f"{pat}: {', '.join(missing_fields)}")

    if missing and _ai_pattern_writeups_required():
        details = " | ".join(missing[:12])
        raise SystemExit(
            "[ERROR] AI-generated pattern writeups are incomplete. "
            "The report is configured to require AI-authored recommendations, "
            "impact statements, expected-state narratives, and MAP closure "
            f"criteria. Missing: {details}"
        )
    if missing:
        print("[AI][WARN] AI-generated pattern writeups are incomplete: " + " | ".join(missing[:12]))


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


_AI_RUNTIME_CACHE = None


def _audit_ai_task() -> str:
    return _ai_env("AI_TASK", "audit_summary_docx") or "audit_summary_docx"


def _get_ai_runtime():
    """Resolve the configured AI runtime from parameters/ai.config.json.

    The audit-summary workflow exports AI_TASK=audit_summary_docx and may set
    AI_PROFILE or provider/model overrides. AIRuntime delegates resolution to
    scripts/lib/ai_config.py, so the effective model is controlled by
    parameters/ai.config.json first and GitHub Actions variables second.
    """
    global _AI_RUNTIME_CACHE
    if _AI_RUNTIME_CACHE is not None:
        return _AI_RUNTIME_CACHE

    if AIRuntime is None:
        print(f"[AI] AIRuntime is not available; deterministic fallback will be used. Import error: {AI_RUNTIME_IMPORT_ERROR}")
        return None

    try:
        profile = _ai_env("AI_PROFILE") or None
        runtime = AIRuntime(task=_audit_ai_task(), profile=profile)
        _AI_RUNTIME_CACHE = runtime
        cfg = getattr(runtime, "config", {}) or {}
        print(
            "[AI_CONFIG] "
            f"task={cfg.get('resolved_task') or _audit_ai_task()} "
            f"profile={cfg.get('resolved_profile') or profile or ''} "
            f"provider={getattr(runtime, 'provider', '')} "
            f"model={getattr(runtime, 'model', '')} "
            f"litellm_model={getattr(runtime, 'litellm_model', '')} "
            f"api_base={getattr(runtime, 'api_base', '')}"
        )
        return runtime
    except Exception as exc:
        print(f"[AI][WARN] Could not resolve AIRuntime from parameters/ai.config.json: {exc}")
        return None


def _ai_enabled() -> bool:
    raw = _ai_env("AUDIT_SUMMARY_AI_ENABLED", "1").lower()
    if raw in {"0", "false", "no", "off"}:
        return False

    runtime = _get_ai_runtime()
    if runtime is None:
        return False

    try:
        if not runtime.available():
            cfg = getattr(runtime, "config", {}) or {}
            print(
                "[AI] Runtime is not available. AI-authored recommendations will fail if required. "
                f"provider={getattr(runtime, 'provider', '')} "
                f"model={getattr(runtime, 'model', '')} "
                f"api_key_env_var={cfg.get('api_key_env_var', 'OPENAI_API_KEY')}"
            )
            return False
    except Exception as exc:
        print(f"[AI][WARN] Runtime availability check failed: {exc}")
        return False

    return True


def _ai_max_tokens(default: int = 1600) -> int:
    env_value = _ai_env("AI_MAX_OUTPUT_TOKENS")
    if env_value:
        return _safe_int(env_value, default)

    runtime = _get_ai_runtime()
    if runtime is not None:
        cfg = getattr(runtime, "config", {}) or {}
        configured = cfg.get("max_output_tokens")
        if configured not in (None, ""):
            return _safe_int(configured, default)

    return default


def _ai_json_chat(section_name: str, system_prompt: str, user_payload: Dict[str, Any], max_tokens: int = 1600) -> Dict[str, Any]:
    """Call the configured AI runtime through OpenAI SDK or LiteLLM.

    The model, provider, API base, timeout, temperature, and API-key env var are
    resolved by scripts/lib/ai_runtime.py from parameters/ai.config.json for the
    audit_summary_docx task. Each call is section-scoped to keep prompts small.
    Most narrative failures can fall back to non-recommendation report text,
    but weakness-pattern recommendations and MAP closure criteria are required
    from AI by default.
    """
    if not _ai_enabled():
        return {}

    runtime = _get_ai_runtime()
    if runtime is None:
        return {}

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
    ]

    try:
        print(
            "[AI] Calling "
            f"section={section_name} "
            f"task={_audit_ai_task()} "
            f"provider={getattr(runtime, 'provider', '')} "
            f"model={getattr(runtime, 'model', '')}"
        )
        response = runtime.create(
            input=messages,
            max_output_tokens=max_tokens,
            reasoning={"effort": _ai_env("AI_REASONING_EFFORT")},
        )
        content = (getattr(response, "output_text", "") or "").strip()
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


def _compact_positive_controls_for_ai(pos_controls: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for pc in pos_controls[:limit]:
        out.append({
            "puid": pc.get("puid"),
            "original_statement": _clean_text(pc.get("declarative_statement", "")),
            "flags_used": _clean_text(pc.get("flags_used", "")),
            "evidence_excerpt": _clean_text(pc.get("evidence_excerpt", "")),
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
            "local_storage_artifacts_sample": _deep_list(mobsf_dynamic, ["local_storage_artifacts_sample", "local_storage_artifacts", "files", "storage_artifacts"])[:12],
            "shared_preferences_artifacts": _deep_list(mobsf_dynamic, ["shared_preferences_artifacts", "shared_preferences", "shared_preferences_files", "preferences"])[:12],
            "sqlite_database_artifacts": _deep_list(mobsf_dynamic, ["sqlite_database_artifacts", "sqlite_databases", "databases", "db_files"])[:12],
            "detected_trackers": _deep_int(mobsf_dynamic, ["detected_trackers", "trackers_detected"]),
        },
        "sast_app_code": {
            "available": _block_available(sast),
            "retained_app_code_findings": _deep_int(sast, ["total_findings", "total", "results_count"]),
            "raw_sarif_counts_by_tool": _deep_dict(sast, ["tool_counts", "by_tool"]),
            "scope_filter_rule": "Only findings retained after the application-scope filter may be described as application-code findings.",
            "raw_counts_interpretation": "Raw SARIF counts are traceability and coverage signals only; they are not application-code findings unless retained_app_code_findings is greater than zero.",
            "retained_findings_sample": _deep_list(sast, ["findings", "results", "app_code_findings", "top_findings"])[:12],
            "sast_notifications_sample": _deep_list(_as_dict(technical.get("coverage_limitations")), ["sast_notifications_sample", "sast_extraction_warnings"])[:8],
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
    positive_controls: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    if not _ai_enabled():
        return {}

    common_system = (
        "You are a senior mobile health security audit reporting specialist. "
        "Write in precise technical English for an executive and engineering audience. "
        "Use only the provided JSON data. Do not invent controls, metrics, vulnerabilities, or evidence. "
        "If evidence is absent, state the limitation explicitly. "
        "Do not contradict normalized evidence. In particular, the field retained_app_code_findings is authoritative for SAST application-code findings. "
        "If retained_app_code_findings is 0, raw SARIF counts, CodeQL notifications, detekt warnings, and Semgrep counts must be described as traceability or coverage signals only, never as retained application-code findings. "
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
        "positive_controls": _compact_positive_controls_for_ai(positive_controls or []),
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

    positive_controls_ai = _ai_json_chat(
        "positive_controls",
        common_system,
        {
            "task": "Rewrite verified positive control statements into precise, grammatical audit-report English.",
            "constraints": {
                "use_exact_puid": True,
                "do_not_overstate": True,
                "do_not_invent_evidence": True,
                "if_evidence_is_partial": "State the supported observation and the residual limitation in the same sentence.",
                "statement_style": "One concise sentence per control, suitable for an executive report.",
            },
            "context": {
                "application": app,
                "positive_controls": _compact_positive_controls_for_ai(positive_controls or []),
                "technical_evidence": compact_technical,
            },
            "required_output_schema": {
                "positive_controls": [
                    {
                        "puid": "<exact PUID>",
                        "statement": "<rewritten statement grounded only in flags and evidence>"
                    }
                ]
            },
        },
        max_tokens=min(_ai_max_tokens(1400), 1800),
    )
    if isinstance(positive_controls_ai.get("positive_controls"), list):
        out["positive_controls"] = positive_controls_ai["positive_controls"]

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
                "sast_rule": "If technical_evidence.sast_app_code.retained_app_code_findings is 0, say that no application-scope SAST findings were retained. You may mention raw SARIF counts only as traceability or parser coverage signals.",
                "mobsf_dynamic_rule": "Mention runtime artifact examples only when they are present in the normalized MobSF dynamic arrays. If arrays are empty, state that examples were not normalized.",
                "avoid_absolute_claims": "Do not claim the app is clean, fully protected, or fully encrypted unless the supplied data directly supports that exact statement.",
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
                "recommendations": "4 to 6 actionable bullets per pattern. Each recommendation must be generated from the supplied workbook prevalence, PUID examples, scanner findings, and limitations. Do not use generic boilerplate or static templates. Do not convert raw SARIF counts into app-code findings when retained_app_code_findings is 0.",
                "closure_criteria": "1 measurable sentence suitable for the MAP, generated from the supplied evidence and scanner context. Prefer evidence-based closure such as updated workbook scoring, updated Trivy/MobSF/SAST artifacts, regression evidence, or formal risk acceptance. Avoid unrealistic permanent phrases such as zero-vulnerability state unless limited to Critical/High fixable findings.",
                "no_time_window_headings": True,
                "no_unprovided_metrics": True,
                "no_static_recommendations": True,
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
                        "recommendations": ["<AI-generated action grounded in evidence>"],
                        "closure_criteria": "<AI-generated measurable closure criterion grounded in evidence>",
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


def _sanitize_ai_technical_narratives(tech_ai: Dict[str, Any], technical: Dict[str, Any]) -> Dict[str, Any]:
    """Remove or replace AI text that contradicts normalized scanner evidence."""
    tech_ai = dict(tech_ai or {})
    sast = _as_dict(technical.get("sast_app_code"))
    retained = _deep_int(sast, ["total_findings", "total", "results_count"])
    if retained <= 0:
        raw_counts = _deep_dict(sast, ["tool_counts", "by_tool"])
        raw_text = ", ".join(f"{k}: {v}" for k, v in raw_counts.items()) if raw_counts else "raw SARIF counts unavailable"
        tech_ai["sast_paragraph"] = (
            "SARIF artifacts were parsed, but no application-scope SAST findings were retained after the configured scope filter. "
            f"Raw SARIF counts are retained only for traceability and coverage interpretation ({raw_text}); they are not treated as application-code findings in this report."
        )
    return tech_ai

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
        prose = _call_llm_for_audit_sections(metrics, app, patterns, technical, likelihood_rubric, pos_controls)
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

    tech_ai = _sanitize_ai_technical_narratives(_as_dict(prose.get("technical_narratives")), technical)
    key_takeaways = prose.get("key_takeaways", [])
    positive_control_writeups = {
        _clean_text(w.get("puid")): _clean_text(w.get("statement"))
        for w in prose.get("positive_controls", [])
        if isinstance(w, dict) and _clean_text(w.get("puid")) and _clean_text(w.get("statement"))
    }
    writeups = {w["pattern"]: w for w in prose.get("pattern_writeups", []) if isinstance(w, dict) and "pattern" in w}
    _validate_ai_pattern_writeups(patterns, writeups)
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
            puid = _clean_text(pc.get("puid"))
            statement = positive_control_writeups.get(puid) or _sanitize_positive_statement(pc.get("declarative_statement", ""))
            doc.add_paragraph(statement, style="List Bullet")
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
        impact = _ai_field_for_pattern(p["pattern"], writeups, "impact") or "AI-generated impact narrative was not returned for this pattern."
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
        expected = _ai_field_for_pattern(pat, writeups, "expected") or "AI-generated expected-state narrative was not returned for this pattern."
        impact = _ai_field_for_pattern(pat, writeups, "impact") or "AI-generated impact narrative was not returned for this pattern."
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
    doc.add_paragraph("Recommendations are generated by the configured AI model using the audit workbook, weakness-pattern prevalence, PUID examples, Vision360, Trivy, MobSF, SAST, and coverage limitations. Static fallback recommendations are intentionally not used.")
    for p in patterns[:10]:
        pat = p["pattern"]
        doc.add_paragraph(pat, style="Heading 2")
        recs = _ai_recommendations_for_pattern(pat, writeups)
        if not recs:
            doc.add_paragraph("AI-generated recommendations were not returned for this pattern; rerun the pipeline with a valid AI configuration or review the AI section artifact.", style="List Bullet")
            continue
        for r in recs[:12]:
            doc.add_paragraph(_clean_text(r), style="List Bullet")

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
        criteria = _ai_field_for_pattern(pat, writeups, "closure_criteria") or "AI-generated closure criteria were not returned for this pattern."
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
            puid = _clean_text(pc.get("puid"))
            r[0].text = positive_control_writeups.get(puid) or _sanitize_positive_statement(pc.get("declarative_statement", ""))
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
    _format_report_paragraphs(doc)
    _quality_gate(doc)
    doc.save(out_path)
    print(f"[OK] DOCX generated -> {out_path}")


if __name__ == "__main__":
    main()