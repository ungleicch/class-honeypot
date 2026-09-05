#!/usr/bin/env python3
"""Render docs/class-guide.md (or any markdown) to a simple PDF.

Prefers fpdf2 if installed; otherwise uses a minimal stdlib PDF writer
good enough for class handouts (headings, paragraphs, tables-as-text).

Usage:
  python3 scripts/make_report_pdf.py
  python3 scripts/make_report_pdf.py --md docs/class-guide.md --out docs/class-guide.pdf
  # with optional venv:
  #   python3 -m venv .venv-pdf && .venv-pdf/bin/pip install fpdf2
  #   .venv-pdf/bin/python scripts/make_report_pdf.py
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MD = ROOT / "docs" / "class-guide.md"
DEFAULT_OUT = ROOT / "docs" / "class-guide.pdf"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Markdown → PDF for class guide / reports")
    p.add_argument("--md", type=Path, default=DEFAULT_MD)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--title", default="Class Honeypot Guide")
    return p.parse_args()


def strip_md_inline(text: str) -> str:
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text


def ascii_safe(text: str) -> str:
    """Map common Unicode punctuation to Latin-1-safe equivalents for core fonts."""
    repl = {
        "\u2014": "-",  # em dash
        "\u2013": "-",  # en dash
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u00a0": " ",
        "\u2192": "->",
        "\u2022": "*",
        "\u2713": "[x]",
        "\u2610": "[ ]",
        "\u2611": "[x]",
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    # drop anything else outside latin-1
    return text.encode("latin-1", errors="replace").decode("latin-1")


def parse_blocks(md: str) -> list[tuple[str, str]]:
    """Return list of (kind, text) where kind in h1/h2/h3/p/li/code/table/hr."""
    blocks: list[tuple[str, str]] = []
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.strip() == "---":
            blocks.append(("hr", ""))
            i += 1
            continue
        if line.startswith("```"):
            buf: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1  # closing fence
            blocks.append(("code", "\n".join(buf)))
            continue
        if line.lstrip().startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|?\s*-+", lines[i + 1]):
            table_lines = [line]
            i += 1
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                table_lines.append(lines[i])
                i += 1
            # drop separator row
            rows = []
            for tl in table_lines:
                if re.match(r"^\s*\|?\s*-+", tl):
                    continue
                cells = [c.strip() for c in tl.strip().strip("|").split("|")]
                rows.append(" | ".join(strip_md_inline(c) for c in cells))
            blocks.append(("table", "\n".join(rows)))
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            kind = {1: "h1", 2: "h2", 3: "h3"}[len(m.group(1))]
            blocks.append((kind, strip_md_inline(m.group(2))))
            i += 1
            continue
        if re.match(r"^\s*[-*]\s+", line):
            blocks.append(("li", strip_md_inline(re.sub(r"^\s*[-*]\s+", "", line))))
            i += 1
            continue
        if re.match(r"^\s*\d+\.\s+", line):
            blocks.append(("li", strip_md_inline(re.sub(r"^\s*\d+\.\s+", "", line))))
            i += 1
            continue
        # paragraph: gather until blank
        buf = [line]
        i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].startswith("#") and not lines[i].startswith("```") and not lines[i].lstrip().startswith("|") and lines[i].strip() != "---" and not re.match(r"^\s*[-*]\s+", lines[i]) and not re.match(r"^\s*\d+\.\s+", lines[i]):
            buf.append(lines[i])
            i += 1
        blocks.append(("p", strip_md_inline(" ".join(x.strip() for x in buf))))
    return blocks


def render_fpdf2(blocks: list[tuple[str, str]], out: Path, title: str) -> None:
    from fpdf import FPDF  # type: ignore

    class PDF(FPDF):
        def footer(self) -> None:
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(100, 100, 100)
            self.cell(0, 10, ascii_safe(f"{title} - page {self.page_no()}/{{nb}}"), align="C")

    pdf = PDF(format="Letter")
    pdf.alias_nb_pages()
    pdf.set_margins(18, 18, 18)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    def write(kind_font, style, size, body, h, color=(0, 0, 0), fill=False):
        pdf.set_x(pdf.l_margin)
        pdf.set_font(kind_font, style, size)
        pdf.set_text_color(*color)
        # Truncate extremely long lines (mermaid / tables) to avoid layout blowups
        safe = ascii_safe(body)
        if len(safe) > 200:
            safe = safe[:197] + "..."
        pdf.multi_cell(pdf.epw, h, safe if safe else " ", fill=fill)

    for kind, text in blocks:
        if kind == "hr":
            pdf.ln(2)
            y = pdf.get_y()
            pdf.set_draw_color(180, 180, 180)
            pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
            pdf.ln(4)
            continue
        if kind == "h1":
            write("Helvetica", "B", 16, text, 8, (20, 40, 80))
            pdf.ln(2)
            continue
        if kind == "h2":
            pdf.ln(2)
            write("Helvetica", "B", 13, text, 7, (30, 60, 100))
            pdf.ln(1)
            continue
        if kind == "h3":
            write("Helvetica", "B", 11, text, 6, (40, 40, 40))
            pdf.ln(1)
            continue
        if kind == "li":
            write("Helvetica", "", 10, f"* {text}", 5)
            continue
        if kind == "code":
            pdf.set_fill_color(245, 245, 245)
            for cl in text.splitlines() or [""]:
                write("Courier", "", 7, cl if cl else " ", 4, (20, 20, 20), fill=True)
            pdf.ln(2)
            continue
        if kind == "table":
            for row in text.splitlines():
                write("Courier", "", 7, row, 4)
            pdf.ln(2)
            continue
        write("Helvetica", "", 10, text, 5)
        pdf.ln(1)

    out.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out))


# --- Minimal stdlib PDF fallback (ASCII-ish Helvetica) ---

def _pdf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_stdlib(blocks: list[tuple[str, str]], out: Path, title: str) -> None:
    """Very small PDF writer: one content stream per page, WinAnsi-ish text."""
    page_w, page_h = 612, 792  # Letter
    margin = 50
    y_start = page_h - margin
    line_gap = {"h1": 18, "h2": 15, "h3": 13, "p": 12, "li": 12, "code": 10, "table": 10, "hr": 10}
    font_size = {"h1": 18, "h2": 14, "h3": 12, "p": 10, "li": 10, "code": 8, "table": 8, "hr": 10}
    max_chars = {"h1": 70, "h2": 80, "h3": 90, "p": 95, "li": 90, "code": 100, "table": 100, "hr": 80}

    def wrap(kind: str, text: str) -> list[str]:
        width = max_chars[kind]
        words = text.split()
        if not words:
            return [""]
        rows: list[str] = []
        cur = words[0]
        for w in words[1:]:
            if len(cur) + 1 + len(w) <= width:
                cur += " " + w
            else:
                rows.append(cur)
                cur = w
        rows.append(cur)
        return rows

    pages_cmds: list[list[str]] = []
    cmds: list[str] = []
    y = y_start

    def new_page() -> None:
        nonlocal cmds, y
        if cmds:
            pages_cmds.append(cmds)
        cmds = []
        y = y_start

    def draw_line(kind: str, text: str, x_off: float = 0) -> None:
        nonlocal y
        size = font_size[kind]
        gap = line_gap[kind]
        if y < margin + gap:
            new_page()
        # sanitize to latin-1-ish
        safe = text.encode("latin-1", errors="replace").decode("latin-1")
        cmds.append("BT")
        cmds.append(f"/F1 {size} Tf")
        cmds.append(f"{margin + x_off:.1f} {y:.1f} Td")
        cmds.append(f"({_pdf_escape(safe)}) Tj")
        cmds.append("ET")
        y -= gap

    new_page()
    for kind, text in blocks:
        if kind == "hr":
            if y < margin + 20:
                new_page()
            cmds.append(f"{margin} {y} m {page_w - margin} {y} l S")
            y -= 12
            continue
        if kind == "code":
            for cl in (text.splitlines() or [""]):
                draw_line("code", cl[:100])
            y -= 4
            continue
        if kind == "table":
            for row in text.splitlines():
                draw_line("table", row[:100])
            y -= 4
            continue
        prefix = "• " if kind == "li" else ""
        x_off = 12 if kind == "li" else 0
        for row in wrap(kind if kind in font_size else "p", prefix + text):
            draw_line(kind if kind in font_size else "p", row, x_off=x_off)
        if kind in ("h1", "h2"):
            y -= 4

    if cmds:
        pages_cmds.append(cmds)

    # Build PDF objects
    objects: list[bytes] = []

    def add_obj(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    add_obj(b"<< /Type /Catalog /Pages 2 0 R >>\n")
    kids = []
    # placeholder for pages obj (id 2)
    add_obj(b"")  # filled later

    font_id = add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n")

    page_ids: list[int] = []
    content_ids: list[int] = []
    for page_cmds in pages_cmds:
        stream = ("\n".join(page_cmds) + "\n").encode("latin-1", errors="replace")
        content = (
            f"<< /Length {len(stream)} >>\nstream\n".encode()
            + stream
            + b"endstream\n"
        )
        cid = add_obj(content)
        content_ids.append(cid)
        pid = add_obj(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_w} {page_h}] "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
                f"/Contents {cid} 0 R >>\n"
            ).encode()
        )
        page_ids.append(pid)

    kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_ids)} >>\n".encode()

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as fh:
        fh.write(b"%PDF-1.4\n")
        offsets = [0]
        for i, obj in enumerate(objects, 1):
            offsets.append(fh.tell())
            fh.write(f"{i} 0 obj\n".encode())
            fh.write(obj)
            fh.write(b"endobj\n")
        xref_pos = fh.tell()
        fh.write(f"xref\n0 {len(objects) + 1}\n".encode())
        fh.write(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            fh.write(f"{off:010d} 00000 n \n".encode())
        fh.write(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
        )


def main() -> int:
    args = parse_args()
    if not args.md.exists():
        print(f"Error: markdown not found: {args.md}", file=sys.stderr)
        return 1
    md = args.md.read_text(encoding="utf-8")
    blocks = parse_blocks(md)
    try:
        import fpdf  # noqa: F401

        render_fpdf2(blocks, args.out, args.title)
        engine = "fpdf2"
    except Exception as exc:  # noqa: BLE001
        print(f"<!-- fpdf2 unavailable ({exc}); using stdlib PDF writer -->", file=sys.stderr)
        render_stdlib(blocks, args.out, args.title)
        engine = "stdlib"
    print(f"Wrote {args.out} ({args.out.stat().st_size} bytes) via {engine}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
