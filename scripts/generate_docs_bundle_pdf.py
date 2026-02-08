#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

DOCS = [
    ("Demo Installation Guide", Path("/Users/mozesrahangmetan/Documents/DQ/docs/install-demo-detailed.md")),
    ("Production Installation Guide", Path("/Users/mozesrahangmetan/Documents/DQ/docs/install-production-detailed.md")),
    ("User Manual", Path("/Users/mozesrahangmetan/Documents/DQ/docs/user-manual.md")),
]
OUT = Path("/Users/mozesrahangmetan/Documents/DQ/docs/idqe-docs-bundle.pdf")


def escape_pdf_text(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def wrap_line(line: str, max_chars: int = 95) -> list[str]:
    if len(line) <= max_chars:
        return [line]
    words = line.split(" ")
    out: list[str] = []
    cur = ""
    for w in words:
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= max_chars:
            cur += " " + w
        else:
            out.append(cur)
            cur = w
    if cur:
        out.append(cur)
    return out


def markdown_to_lines(text: str) -> list[str]:
    lines: list[str] = []
    in_code = False
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if line.strip().startswith("```"):
            in_code = not in_code
            continue

        if in_code:
            lines.extend(wrap_line("    " + line, 95))
            continue

        if line.startswith("# "):
            lines.append(line[2:].upper())
            lines.append("")
            continue
        if line.startswith("## "):
            lines.append(line[3:])
            lines.append("")
            continue
        if line.startswith("### "):
            lines.append(line[4:])
            continue
        if line.startswith("- "):
            lines.extend(wrap_line("* " + line[2:], 95))
            continue
        if line[:3].isdigit() and line[1:3] == ". ":
            lines.extend(wrap_line(line, 95))
            continue

        lines.extend(wrap_line(line, 95))
    return lines


def paginate(lines: list[str], lines_per_page: int = 60) -> list[list[str]]:
    pages: list[list[str]] = []
    cur: list[str] = []
    for ln in lines:
        cur.append(ln)
        if len(cur) >= lines_per_page:
            pages.append(cur)
            cur = []
    if cur:
        pages.append(cur)
    return pages


def build_pdf(pages: list[list[str]]) -> bytes:
    objs: list[bytes] = []

    def add_obj(b: bytes) -> int:
        objs.append(b)
        return len(objs)

    font_obj = add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    content_obj_ids: list[int] = []
    page_obj_ids: list[int] = []
    pages_obj_id = add_obj(b"<<>>")

    for page_lines in pages:
        parts = ["BT", "/F1 10 Tf", "50 790 Td", "12 TL"]
        first = True
        for ln in page_lines:
            t = escape_pdf_text(ln)
            if first:
                parts.append(f"({t}) Tj")
                first = False
            else:
                parts.append("T*")
                parts.append(f"({t}) Tj")
        parts.append("ET")
        stream = "\n".join(parts).encode("latin-1", errors="replace")
        content = b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"
        content_obj_ids.append(add_obj(content))

    kids = []
    for content_id in content_obj_ids:
        page_dict = (
            b"<< /Type /Page /Parent "
            + str(pages_obj_id).encode()
            + b" 0 R /MediaBox [0 0 612 792] "
            + b"/Resources << /Font << /F1 "
            + str(font_obj).encode()
            + b" 0 R >> >> /Contents "
            + str(content_id).encode()
            + b" 0 R >>"
        )
        pid = add_obj(page_dict)
        page_obj_ids.append(pid)
        kids.append(f"{pid} 0 R")

    objs[pages_obj_id - 1] = f"<< /Type /Pages /Count {len(page_obj_ids)} /Kids [{' '.join(kids)}] >>".encode("latin-1")
    catalog_obj = add_obj(b"<< /Type /Catalog /Pages " + str(pages_obj_id).encode() + b" 0 R >>")

    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    xref_positions = [0]
    body = bytearray()

    for i, obj in enumerate(objs, start=1):
        pos = len(header) + len(body)
        xref_positions.append(pos)
        body.extend(f"{i} 0 obj\n".encode("latin-1"))
        body.extend(obj)
        body.extend(b"\nendobj\n")

    xref_start = len(header) + len(body)
    xref = bytearray()
    xref.extend(f"xref\n0 {len(objs)+1}\n".encode("latin-1"))
    xref.extend(b"0000000000 65535 f \n")
    for pos in xref_positions[1:]:
        xref.extend(f"{pos:010d} 00000 n \n".encode("latin-1"))

    trailer = (
        f"trailer\n<< /Size {len(objs)+1} /Root {catalog_obj} 0 R >>\nstartxref\n{xref_start}\n%%EOF\n"
    ).encode("latin-1")

    return bytes(header + body + xref + trailer)


def main() -> None:
    all_lines: list[str] = []
    all_lines.append("INTELLIGENT DATA QUALITY ENGINE")
    all_lines.append("Documentation Bundle")
    all_lines.append("")
    for title, path in DOCS:
        if not path.exists():
            raise FileNotFoundError(f"Missing source document: {path}")
        all_lines.append("=" * 70)
        all_lines.append(title.upper())
        all_lines.append(str(path))
        all_lines.append("=" * 70)
        all_lines.append("")
        text = path.read_text(encoding="utf-8")
        all_lines.extend(markdown_to_lines(text))
        all_lines.append("")
        all_lines.append("")

    pages = paginate(all_lines, lines_per_page=60)
    OUT.write_bytes(build_pdf(pages))
    print(f"Generated: {OUT}")


if __name__ == "__main__":
    main()

