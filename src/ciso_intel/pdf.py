"""C-level PDF. The quotation is the finding. Everything else is subordinate to it."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib.colors import HexColor, Color
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from ciso_intel.prompts import CATEGORIES
from ciso_intel.report import CATEGORY_SHORT
from ciso_intel.schema import Brief, FindingRecord
from ciso_intel.window import DETROIT

NAVY = HexColor("#101A2B")
CREAM = HexColor("#F3EEE4")
INK = HexColor("#1C1915")
MUTED = HexColor("#5E584E")
RULE = HexColor("#D9D0C2")
GOLD = HexColor("#C4A36A")
PAPER = HexColor("#FFFCF7")
LINK = HexColor("#1D4E89")

SEVERITY_COLOR = {
    "critical": HexColor("#8E1D1D"),
    "high": HexColor("#9A4514"),
    "medium": HexColor("#8A6A14"),
    "low": HexColor("#1E5A40"),
    "informational": HexColor("#3D5168"),
}

REASON_LABELS = {
    "url_not_in_tool_results": "URL was not in the tool results",
    "excerpt_not_on_page": "Quotation was not on the retrieved page",
    "identifier_not_on_page": "Model id, package, identifier, or author was not on the page",
    "excerpt_too_short": "Quotation was too short to check",
    "not_refetched": "Page could not be re-fetched",
    "outside_window": "Dates fell outside the window",
    "duplicate": "Duplicate of a confirmed item",
    "no_specific_identifier": "No specific model id, package, identifier, or author",
    "no_evidence": "No evidence URL",
    "unknown_category": "Category was not one of the seven briefed here",
    "blocked_non_public": "URL was not a public web address",
    "dns_failed": "Host did not resolve",
    "unsupported_content": "Page was not readable text or PDF",
    "empty_page": "Page had no text",
    "bad_scheme": "URL was not http or https",
    "embedded_credentials": "URL carried embedded credentials",
}

PAGE_W, PAGE_H = letter


class Stack(Flowable):
    """Vertical stack that a table cell can hold as one flowable."""

    def __init__(self, items: list) -> None:
        super().__init__()
        self.items = items
        self._sizes: list[tuple[float, float]] = []

    def wrap(self, avail_width, avail_height):
        self.width = avail_width
        self._sizes = []
        height = 0
        for item in self.items:
            item_width, item_height = item.wrap(avail_width, avail_height)
            self._sizes.append((item_width, item_height))
            height += item_height
        self.height = height
        return avail_width, height

    def draw(self):
        y = self.height
        for item, (_width, height) in zip(self.items, self._sizes):
            y -= height
            item.drawOn(self.canv, 0, y)


@dataclass(frozen=True)
class FontSet:
    body: str
    bold: str
    semibold: str
    italic: str
    serif: str
    serif_bold: str
    serif_italic: str
    mono: str


_FONTS: FontSet | None = None


def render_pdf(brief: Brief, path: Path, json_sha256: str) -> None:
    fonts = register_fonts()
    styles = make_styles(fonts)
    frame = Frame(46, 46, PAGE_W - 92, PAGE_H - 46 - 52, id="body", showBoundary=0)
    cover = PageTemplate(id="cover", frames=[Frame(0, 0, PAGE_W, PAGE_H, id="cover-frame")], onPage=lambda c, d: draw_cover(c, brief, fonts))
    body = PageTemplate(id="body", frames=[frame], onPage=lambda c, d: draw_body_chrome(c, d, brief, fonts))
    doc = BaseDocTemplate(
        str(path),
        pagesize=letter,
        title=f"{brief.report_id} Open-source threat intelligence",
        author="ciso-intel",
        creator="ciso-intel",
        subject=f"Confirmed open-source supply-chain intelligence. report.json {json_sha256}",
    )
    doc.addPageTemplates([cover, body])
    story = [NextPageTemplate("body"), PageBreak()]
    story.extend(body_story(brief, styles, fonts, json_sha256))
    doc.build(story)


def register_fonts() -> FontSet:
    global _FONTS
    if _FONTS is not None:
        return _FONTS
    registered = set(pdfmetrics.getRegisteredFontNames())

    def add(name: str, path: str, fallback: str) -> str:
        if name in registered:
            return name
        if Path(path).is_file():
            pdfmetrics.registerFont(TTFont(name, path))
            registered.add(name)
            return name
        return fallback

    _FONTS = FontSet(
        body=add("CisoInter", "/usr/share/fonts/truetype/macos/Inter-Regular.ttf", "Helvetica"),
        bold=add("CisoInter-Bold", "/usr/share/fonts/truetype/macos/Inter-Bold.ttf", "Helvetica-Bold"),
        semibold=add("CisoInter-Semibold", "/usr/share/fonts/truetype/macos/Inter-SemiBold.ttf", "Helvetica-Bold"),
        italic=add("CisoInter-Italic", "/usr/share/fonts/truetype/macos/Inter-Italic.ttf", "Helvetica-Oblique"),
        serif=add("CisoSerif", "/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf", "Times-Roman"),
        serif_bold=add("CisoSerif-Bold", "/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf", "Times-Bold"),
        serif_italic=add("CisoSerif-Italic", "/usr/share/fonts/truetype/liberation/LiberationSerif-Italic.ttf", "Times-Italic"),
        mono=add("CisoMono", "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf", "Courier"),
    )
    return _FONTS


def make_styles(fonts: FontSet) -> dict[str, ParagraphStyle]:
    def style(name: str, **kwargs) -> ParagraphStyle:
        base = dict(fontName=fonts.body, fontSize=10.5, leading=14.5, textColor=INK, alignment=TA_LEFT)
        base.update(kwargs)
        return ParagraphStyle(name, **base)

    return {
        "kicker": style("kicker", fontName=fonts.semibold, fontSize=8.5, leading=11, textColor=GOLD, charSpace=0.6),
        "h1": style("h1", fontName=fonts.serif, fontSize=22, leading=26, textColor=NAVY),
        "posture": style("posture", fontName=fonts.serif, fontSize=28, leading=32, textColor=NAVY),
        "h2": style("h2", fontName=fonts.serif, fontSize=16, leading=20, textColor=NAVY, spaceBefore=8, spaceAfter=4, keepWithNext=True),
        "body": style("body"),
        "muted": style("muted", fontSize=9, leading=12.5, textColor=MUTED),
        "label": style("label", fontName=fonts.semibold, fontSize=8, leading=10.5, textColor=MUTED),
        "stat": style("stat", fontName=fonts.serif, fontSize=18, leading=21, textColor=NAVY, alignment=TA_LEFT),
        "card_meta": style("card_meta", fontName=fonts.semibold, fontSize=8, leading=11, textColor=MUTED),
        "card_title": style("card_title", fontName=fonts.semibold, fontSize=12, leading=15.5, textColor=INK),
        "quote": style("quote", fontName=fonts.serif_italic, fontSize=11, leading=15, textColor=INK),
        "small": style("small", fontSize=9, leading=12.5, textColor=INK),
        "method": style("method", fontSize=9, leading=11.5, textColor=INK, spaceAfter=2),
        "link": style("link", fontName=fonts.mono, fontSize=8, leading=11, textColor=LINK, wordWrap="CJK"),
        "action": style("action", fontSize=10.5, leading=14, textColor=INK, leftIndent=12, bulletIndent=0),
        "footer_note": style("footer_note", fontSize=9, leading=12.5, textColor=MUTED),
    }


def body_story(brief: Brief, styles: dict, fonts: FontSet, json_sha256: str) -> list:
    story: list = []
    story.append(Paragraph("01  /  SITUATION", styles["kicker"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(escape(brief.posture_label), styles["posture"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(escape(brief.posture_basis), styles["muted"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(escape(brief.executive.headline), styles["h1"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(escape(brief.executive.narrative), styles["body"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(escape(f"Ecosystems in scope: {', '.join(brief.ecosystems) or 'not limited'}."), styles["muted"]))
    story.append(Spacer(1, 12))
    story.extend(stat_blocks(brief, styles))
    story.append(Spacer(1, 10))
    story.append(
        Paragraph(
            "How to read this. Each finding is a quotation copied from a page this run retrieved. "
            "A paraphrase, when shown, is subordinate to that quotation. "
            "Candidates that failed re-checking are counted in the method section and are not findings.",
            styles["small"],
        )
    )
    story.append(Spacer(1, 12))
    story.append(Paragraph("Priority actions", styles["h2"]))
    if brief.executive.priority_actions:
        for index, action in enumerate(brief.executive.priority_actions, start=1):
            story.append(Paragraph(f"{index}.  {escape(action)}", styles["action"]))
    elif brief.findings:
        story.append(
            Paragraph(
                "No source-bound action was extracted. The quotations name the packages, model ids, and identifiers to hand to their owners.",
                styles["body"],
            )
        )
    else:
        story.append(Paragraph("No action. Nothing in this window passed verification.", styles["body"]))
    grouped = {key: [item for item in brief.findings if item.category == key] for key, _label in CATEGORIES}
    for number, (key, _label) in enumerate(CATEGORIES, start=2):
        heading = [
            Spacer(1, 10),
            Paragraph(f"{number:02d}", styles["kicker"]),
            Paragraph(escape(CATEGORY_SHORT[key]), styles["h2"]),
        ]
        items = grouped[key]
        if not items:
            story.append(KeepTogether(heading + [Paragraph("No confirmed item.", styles["muted"])]))
            continue
        story.append(KeepTogether(heading + [finding_card(items[0], styles)]))
        for finding in items[1:]:
            story.append(Spacer(1, 8))
            story.append(KeepTogether([finding_card(finding, styles)]))
    story.append(CondPageBreak(200))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"{len(CATEGORIES) + 2:02d}", styles["kicker"]))
    story.append(Paragraph("Method and limits", styles["h2"]))
    story.extend(method_blocks(brief, styles))
    return story


def stat_blocks(brief: Brief, styles: dict) -> list:
    cells = []
    for key, _label in CATEGORIES:
        count = sum(1 for item in brief.findings if item.category == key)
        cells.append(
            [
                Paragraph(str(count), styles["stat"]),
                Paragraph(escape(CATEGORY_SHORT[key]), styles["label"]),
            ]
        )
    per_row = 4
    col_width = 125
    blocks: list = []
    style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, -1), PAPER),
            ("BOX", (0, 0), (-1, -1), 0.4, RULE),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
    )
    for start in range(0, len(cells), per_row):
        row = cells[start : start + per_row]
        table = Table([[Stack(cell) for cell in row]], colWidths=[col_width] * len(row))
        table.setStyle(style)
        if blocks:
            blocks.append(Spacer(1, 6))
        blocks.append(table)
    return blocks


def finding_card(finding: FindingRecord, styles: dict) -> Table:
    meta = "  ·  ".join(
        [
            finding.id,
            finding.severity.upper(),
            finding.ecosystem or "ecosystem not stated",
            f"{finding.confidence} confidence",
        ]
    )
    blocks: list = [Paragraph(escape(meta), styles["card_meta"]), Spacer(1, 3), Paragraph(escape(finding.title), styles["card_title"])]
    if finding.severity_note:
        blocks.append(Spacer(1, 2))
        blocks.append(Paragraph(escape(finding.severity_note), styles["muted"]))
    if finding.social_only:
        blocks.append(Paragraph("Social post only. Not corroborated on a primary advisory site.", styles["muted"]))
    for evidence in finding.evidence:
        blocks.append(Spacer(1, 6))
        blocks.append(Paragraph(escape(evidence.excerpt), styles["quote"]))
        source = evidence.publisher or evidence.host or "source"
        blocks.append(Spacer(1, 3))
        blocks.append(
            Paragraph(
                f"{escape(source)} · {escape(evidence.host or 'host not stated')}"
                + (f" · {escape(evidence.published)}" if evidence.published else ""),
                styles["small"],
            )
        )
        blocks.append(link_paragraph(evidence.url, styles["link"]))
        blocks.append(
            Paragraph(
                f"Retrieved {escape(pretty_stamp(evidence.retrieved_at))} · HTTP {evidence.http_status} · quotation found on the page.",
                styles["muted"],
            )
        )
    if finding.paraphrase:
        blocks.append(Spacer(1, 4))
        blocks.append(Paragraph("PARAPHRASE", styles["label"]))
        blocks.append(Paragraph(escape(finding.paraphrase), styles["small"]))
    if finding.why_it_matters:
        blocks.append(Spacer(1, 4))
        blocks.append(Paragraph("WHY IT MATTERS", styles["label"]))
        blocks.append(Paragraph(escape(finding.why_it_matters), styles["small"]))
    if finding.actions:
        blocks.append(Spacer(1, 4))
        blocks.append(Paragraph("ACTIONS TIED TO THE SOURCE", styles["label"]))
        for action in finding.actions:
            blocks.append(Paragraph(f"–  {escape(action)}", styles["small"]))
    table = Table([[Stack(blocks)]], colWidths=[500])
    accent: Color = SEVERITY_COLOR.get(finding.severity, NAVY)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PAPER),
                ("BOX", (0, 0), (-1, -1), 0.4, RULE),
                ("LINEBEFORE", (0, 0), (0, -1), 3.5, accent),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def method_blocks(brief: Brief, styles: dict) -> list:
    model = brief.model
    enabled = ", ".join(_tool_label(item["name"]) for item in brief.tools_enabled) or "none"
    withheld = [f"{_tool_label(item['name'])} — {item['reason']}" for item in brief.tools_withheld]
    counts = brief.audit.get("omitted_by_reason", {})
    lines = [
        brief.audit["evidence_standard"],
        (
            f"Model {model['name']} at reasoning effort {model['reasoning_effort']}. "
            f"Published knowledge cutoff for this model: May 2026. "
            f"Live claims come from tools, then from pages this program fetched itself."
        ),
        f"Tools enabled: {enabled}.",
    ]
    lines.extend(withheld)
    lines.append(
        f"Candidates received: {brief.audit['candidates']}. Confirmed: {brief.audit['confirmed']}. "
        f"Excluded: {brief.audit['omitted_count']}."
    )
    if brief.audit.get("collection_note"):
        lines.append(brief.audit["collection_note"])
    if counts:
        rendered = "; ".join(f"{count} {REASON_LABELS.get(reason, reason)}" for reason, count in sorted(counts.items()))
        lines.append(f"Why candidates were excluded: {rendered}.")
    else:
        lines.append("No candidate was excluded.")
    if brief.audit.get("gaps"):
        lines.append("Coverage notes that did not name an unconfirmed identifier: " + " ".join(brief.audit["gaps"]))
    usage = brief.audit.get("token_usage") or {}
    if usage:
        lines.append(
            "Tokens — "
            + ", ".join(f"{key.replace('_', ' ')} {value}" for key, value in usage.items() if value)
            + "."
        )
    cost = brief.audit.get("cost_usd")
    if cost is not None:
        lines.append(f"Reported API cost for this run: ${cost:.4f}.")
    lines.append(
        "Scanned PDFs are not OCR'd. A page that blocks this program, or a quotation that is not on the page, drops the candidate. "
        "Image generation is not used as evidence."
    )
    return [Paragraph(escape(line), styles["method"]) for line in lines]


def _tool_label(name: str) -> str:
    return {
        "web_search": "web search",
        "x_search": "X search",
        "code_execution": "code execution",
        "collections_search": "collections search",
        "image_generation": "image generation",
        "mcp": "remote MCP",
    }.get(name, name.replace("_", " "))


def link_paragraph(url: str, style: ParagraphStyle) -> Paragraph:
    href = escape(url, {'"': "&quot;"})
    return Paragraph(f'<link href="{href}">{escape(url)}</link>', style)


def draw_cover(canvas, brief: Brief, fonts: FontSet) -> None:
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, 0, 8, PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.setFont(fonts.semibold, 9)
    canvas.drawString(56, PAGE_H - 72, "INTERNAL BRIEFING")
    canvas.setStrokeColor(GOLD)
    canvas.setLineWidth(0.6)
    canvas.line(56, PAGE_H - 86, PAGE_W - 56, PAGE_H - 86)
    canvas.setFillColor(HexColor("#F7F4EE"))
    canvas.setFont(fonts.serif, 36)
    canvas.drawString(56, PAGE_H - 142, "Open-source")
    canvas.setFont(fonts.serif_italic, 34)
    canvas.drawString(56, PAGE_H - 184, "threat intelligence")
    subtitle = Paragraph(
        "Malicious code, vulnerabilities, authors, license risk, typosquatting, and malicious or vulnerable Hugging Face models.",
        ParagraphStyle("cover-sub", fontName=fonts.body, fontSize=11, leading=15, textColor=HexColor("#E4D8C4")),
    )
    width, height = subtitle.wrap(PAGE_W - 112, 80)
    subtitle.drawOn(canvas, 56, PAGE_H - 214 - height)
    y = PAGE_H - 250 - height
    canvas.setStrokeColor(GOLD)
    canvas.line(56, y, 128, y)
    y -= 28
    rows = [
        ("WINDOW", brief.window["label"]),
        ("PREPARED", pretty_stamp(brief.generated_at)),
        ("MODEL", f"{brief.model['name']}  ·  reasoning {brief.model['reasoning_effort']}"),
        ("POSTURE", brief.posture_label),
        ("REPORT", brief.report_id),
    ]
    for label, value in rows:
        canvas.setFillColor(GOLD)
        canvas.setFont(fonts.semibold, 8)
        canvas.drawString(56, y, label)
        value_style = ParagraphStyle("cover-meta", fontName=fonts.body, fontSize=10.5, leading=14, textColor=HexColor("#F7F4EE"))
        paragraph = Paragraph(escape(value), value_style)
        used_w, used_h = paragraph.wrap(PAGE_W - 180, 40)
        paragraph.drawOn(canvas, 150, y - used_h + 10)
        y -= max(used_h, 14) + 10
    y -= 8
    standard = Paragraph(
        escape(brief.audit["evidence_standard"]) + " An empty brief is not an all-clear.",
        ParagraphStyle("cover-std", fontName=fonts.body, fontSize=9.5, leading=13, textColor=HexColor("#E4D8C4")),
    )
    used_w, used_h = standard.wrap(PAGE_W - 112, 120)
    standard.drawOn(canvas, 56, max(78, y - used_h))
    canvas.setFillColor(GOLD)
    canvas.setFont(fonts.serif, 11)
    canvas.drawString(56, 52, "For the Chief Information Security Officer")
    canvas.setFont(fonts.body, 8.5)
    canvas.setFillColor(HexColor("#E4D8C4"))
    canvas.drawString(56, 36, "Internal use. Not a scan of your environment.")
    canvas.restoreState()


def draw_body_chrome(canvas, doc, brief: Brief, fonts: FontSet) -> None:
    canvas.saveState()
    canvas.setFillColor(CREAM)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - 36, PAGE_W, 36, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, PAGE_H - 36, 8, 36, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#F7F4EE"))
    canvas.setFont(fonts.semibold, 8)
    canvas.drawString(46, PAGE_H - 22, "CISO   ·   OPEN-SOURCE THREAT INTELLIGENCE")
    canvas.setFont(fonts.body, 8)
    canvas.drawRightString(PAGE_W - 40, PAGE_H - 22, "INTERNAL")
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, 32, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, 0, 8, 32, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#E4D8C4"))
    canvas.setFont(fonts.body, 7.5)
    canvas.drawString(46, 13, f"{brief.report_id}    Confirmed findings only")
    canvas.setFont(fonts.semibold, 8)
    canvas.drawRightString(PAGE_W - 40, 13, str(doc.page))
    canvas.restoreState()


def pretty_stamp(value: str) -> str:
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        from datetime import timezone

        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(DETROIT)
    return f"{moment.day} {moment.strftime('%B')} {moment.year}, {moment.strftime('%H:%M')} ET"
