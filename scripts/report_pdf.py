#!/usr/bin/env python3
"""Write a PDF report on every build in the results tree, for OpenRepos users.

usage: report_pdf.py <store-dir> <out.pdf> [--date YYYY-MM-DD] [--subtitle TEXT]
                     [--note TEXT] [--pause-label TEXT]

<store-dir> is a checkout of the results branch. The report counts every build
in packages/*/index.json; grades, sandbox state and flags come from each
package's latest build.

--date         the report date, in the footer (default: today)
--subtitle     the line under the title (default: "OpenRepos uploads")
--note         a sentence appended to the summary, such as why scanning paused
--pause-label  labels the days between the last scan and the report date in
               the daily chart

Needs reportlab (pip install reportlab). The fonts are JetBrains Mono, from
scripts/fonts (SIL Open Font License).
"""
import argparse
import collections
import datetime
import glob
import json
import os
import re

from reportlab.graphics import renderPDF
from reportlab.graphics.shapes import Circle, Drawing, Line, Rect, String, Wedge
from reportlab.lib import colors
from reportlab.lib.fonts import addMapping
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

REPOSITORY = "github.com/SpecSierra/Coastguard"
FONTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")

INK, MUTED, LINE = colors.HexColor("#1d2a33"), colors.HexColor("#46535c"), colors.HexColor("#d5dde2")
PANEL, SEA = colors.HexColor("#f3f6f8"), colors.HexColor("#2f6f8f")
LOW, MED, HIGH = colors.HexColor("#a9b6bf"), colors.HexColor("#d99a2b"), colors.HexColor("#c4423a")
GRADE = {"low": LOW, "medium": MED, "high": HIGH}
GRADE_N = {"low": 0, "medium": 1, "high": 2}
BADGE_BG = {"high": HIGH, "medium": MED, "low": colors.HexColor("#dfe5e9")}
TINT = {"high": colors.HexColor("#fbeceb"), "medium": colors.HexColor("#fdf4e3"),
        "good": colors.HexColor("#eaf5ee"), "stripe": colors.HexColor("#f6f8f9")}
RED_TXT, GREEN_TXT, AMBER_TXT = "#a3322b", "#2e7d4f", "#a8670a"
SANDBOX = {"declared": "Declared", "disabled": "Turned off", "none": "Not declared", None: "No app launcher"}
SANDBOX_TXT = {"Turned off": AMBER_TXT, "Declared": GREEN_TXT, "Not declared": AMBER_TXT,
               "No app launcher": MUTED.hexval()}

W = A4[0] - 36 * mm - 12  # the frame pads 6pt on each side
HALF = (W - 8 * mm) / 2


def day(d):
    return f"{d.day} {d:%B %Y}"


def esc(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;")


# Data -----------------------------------------------------------------------

def load_builds(store):
    builds = []
    for path in sorted(glob.glob(os.path.join(store, "packages", "*", "index.json"))):
        name = os.path.basename(os.path.dirname(path))
        with open(path, encoding="utf-8") as fh:
            for entry in json.load(fh):
                entry["name"] = name
                builds.append(entry)
    return builds


def flags_of(build, change_flags=True):
    """Medium and high flags of a build by id; change flags ("new-...") only on request."""
    return {r["id"]: r["text"] for r in build["summary"]["risk"]["reasons"]
            if r["level"] != "info" and (change_flags or not r["id"].startswith("new-"))}


def flag_label(text):
    """"3 privileged files (setuid root)" -> "Privileged files", for counting across builds."""
    text = re.sub(r"\(.*\)", "", re.sub(r"^\d+ ", "", text)).strip().replace("Unsandboxed code", "Code")
    if text.startswith("root service"):
        return "Root services"
    if text.startswith("privileged file"):
        return "Privileged files"
    return text


def virustotal_counts(store, builds):
    queried = unknown = 0
    for b in builds:
        path = os.path.join(store, "packages", b["name"], b["sha256"] + ".json")
        try:
            with open(path, encoding="utf-8") as fh:
                vt = (json.load(fh).get("reputation") or {}).get("virustotal") or {}
        except OSError:
            continue
        queried += vt.get("queried", 0)
        unknown += vt.get("unknown", 0)
    return queried, unknown


def grade_changes(builds):
    """Updates whose grade differs from the previous build of the same package and
    architecture. Left out: a grade that falls back only because the change flags
    of the update before have expired, since nothing in the package changed."""
    by_arch = collections.defaultdict(list)
    for b in builds:
        by_arch[(b["name"], b["arch"])].append(b)
    changes = {}
    for (name, arch), seq in sorted(by_arch.items()):
        seq.sort(key=lambda b: b["buildtime"])
        for before, after in zip(seq, seq[1:]):
            ga, gc = before["summary"]["risk"]["grade"], after["summary"]["risk"]["grade"]
            if ga == gc:
                continue
            old, new = flags_of(before, False), flags_of(after)
            if GRADE_N[gc] < GRADE_N[ga] and old.keys() == flags_of(after, False).keys():
                continue
            key = f"{name} {before['version']} → {after['version']}"
            if key in changes:
                continue  # the same update on another architecture
            changes[key] = {
                "update": key, "from": ga, "to": gc, "first_seen": after["first_seen"],
                "added": "; ".join(t for k, t in new.items() if k not in old and "new-" + k not in new),
                "dropped": "; ".join(t for k, t in old.items() if k not in new),
            }
    return sorted(changes.values(), key=lambda c: c["first_seen"])


def summarize(store, builds):
    latest = {}
    for b in builds:
        if b["name"] not in latest or b["buildtime"] > latest[b["name"]]["buildtime"]:
            latest[b["name"]] = b
    packages = []
    for name, b in sorted(latest.items()):
        own = [x for x in builds if x["name"] == name]
        packages.append({
            "package": name, "latest_version": b["version"], "builds": len(own),
            "versions": len({x["version"] for x in own}),
            "grade": b["summary"]["risk"]["grade"], "sandbox": SANDBOX[b["summary"]["sandbox"]],
            "permissions": b["summary"]["permissions"],
            "flags": "; ".join(flags_of(b, False).values()),
        })

    seen_in = collections.defaultdict(set)
    worst = {}
    label = {}
    for b in builds:
        for r in b["summary"]["risk"]["reasons"]:
            if r["level"] == "info" or r["id"].startswith("new-"):
                continue
            seen_in[r["id"]].add(b["name"])
            label.setdefault(r["id"], flag_label(r["text"]))
            if r["level"] == "high" or r["id"] not in worst:
                worst[r["id"]] = r["level"]
    flags = sorted(({"label": label[k], "level": worst[k], "packages": len(v)} for k, v in seen_in.items()),
                   key=lambda f: (-f["packages"], f["label"]))
    permissions = collections.Counter(p for pkg in packages for p in pkg["permissions"]).most_common()

    checks = {}
    for check in ("clamav", "yara", "virustotal", "malwarebazaar"):
        counts = collections.Counter(b["summary"]["checks"].get(check) for b in builds)
        checks[check] = {"pass": counts["pass"], "error": counts["error"]}
    vt_queried, vt_unknown = virustotal_counts(store, builds)
    per_day = collections.Counter(b["first_seen"][:10] for b in builds)
    return {
        "builds": builds, "packages": packages, "flags": flags, "permissions": permissions,
        "changes": grade_changes(builds), "checks": checks, "per_day": per_day,
        "vt_queried": vt_queried, "vt_unknown": vt_unknown,
        "detected": sum(b["verdict"] != "clean" for b in builds),
        "first": datetime.date.fromisoformat(min(per_day)), "last": datetime.date.fromisoformat(max(per_day)),
    }


# Drawing --------------------------------------------------------------------

def styles():
    pdfmetrics.registerFont(TTFont("Mono", os.path.join(FONTS, "JetBrainsMonoNL-Medium.ttf")))
    pdfmetrics.registerFont(TTFont("Mono-Bold", os.path.join(FONTS, "JetBrainsMonoNL-ExtraBold.ttf")))
    pdfmetrics.registerFont(TTFont("Mono-Title", os.path.join(FONTS, "JetBrainsMonoNL-Bold.ttf")))
    addMapping("Mono", 0, 0, "Mono")
    addMapping("Mono", 1, 0, "Mono-Bold")

    def st(**kw):
        return ParagraphStyle("s", **{"fontName": "Mono", "fontSize": 8.8, "leading": 13, "textColor": INK, **kw})
    return {
        "name": st(fontName="Mono-Title", fontSize=28, leading=32),
        "tag": st(fontSize=13, leading=17, textColor=MUTED),
        "sub": st(fontSize=8, leading=11.5, textColor=MUTED),
        "h2": st(fontName="Mono-Bold", fontSize=11.5, leading=15, spaceBefore=12, spaceAfter=9),
        "h3": st(spaceAfter=4),
        "body": st(),
        "bullet": st(leftIndent=9, firstLineIndent=-9, spaceAfter=3),
        "note": st(fontSize=8, leading=11.5, textColor=MUTED, spaceAfter=6),
        "cell": st(fontSize=7.2, leading=9.5),
        "head": st(fontName="Mono-Bold", fontSize=7.2, leading=9.5, textColor=colors.white),
        "badge": st(fontName="Mono-Bold", fontSize=7.2, leading=9.5, textColor=colors.white, alignment=1),
        "badge_low": st(fontName="Mono-Bold", fontSize=7.2, leading=9.5, textColor=INK, alignment=1),
        "tile_n": st(fontName="Mono-Title", fontSize=18, leading=22),
        "tile_l": st(fontSize=7.2, leading=10, textColor=MUTED),
    }


def logo(size):
    """A lifebuoy: four red and four white segments on a ring."""
    d = Drawing(size, size)
    c, r, r1 = size / 2, size / 2 - 1, size * 0.27
    for i in range(8):
        d.add(Wedge(c, c, r, i * 45 + 22.5, (i + 1) * 45 + 22.5, radius1=r1,
                    fillColor=HIGH if i % 2 else colors.white, strokeColor=None))
    d.add(Circle(c, c, r, fillColor=None, strokeColor=INK, strokeWidth=1.2))
    d.add(Circle(c, c, r1, fillColor=None, strokeColor=INK, strokeWidth=1.2))
    return d


def daily_chart(per_day, first, end, last_scan, pause_label):
    days = [first + datetime.timedelta(i) for i in range((end - first).days + 1)]
    h, ml, mb, mt = 150, 24, 18, 14
    d = Drawing(W, h)
    step = (W - ml) / len(days)
    bw = step * 0.7
    top = (max(per_day.values()) // 20 + 1) * 20
    y = lambda v: mb + (h - mb - mt) * v / top  # noqa: E731
    for v in range(0, top + 1, 20):
        d.add(Line(ml, y(v), W, y(v), strokeColor=LINE, strokeWidth=0.5))
        d.add(String(ml - 4, y(v) - 3, str(v), fontName="Mono", fontSize=6.3, fillColor=MUTED, textAnchor="end"))
    paused = [i for i, dd in enumerate(days) if dd > last_scan]
    if paused and pause_label:
        x0, x1 = ml + paused[0] * step, ml + (paused[-1] + 1) * step
        d.add(Rect(x0, mb, x1 - x0, h - mb - mt, fillColor=PANEL, strokeColor=None))
        for n, word in enumerate(pause_label.split(" ", 1)):
            d.add(String((x0 + x1) / 2, y(top) - 12 - 9 * n, word, fontName="Mono", fontSize=6.3,
                         fillColor=MUTED, textAnchor="middle"))
    for i, dd in enumerate(days):
        x = ml + i * step + (step - bw) / 2
        n = per_day.get(dd.isoformat(), 0)
        if n:
            d.add(Rect(x, y(0), bw, y(n) - y(0), fillColor=SEA, strokeColor=None, rx=1.5, ry=1.5))
            d.add(String(x + bw / 2, y(n) + 2, str(n), fontName="Mono", fontSize=6, fillColor=MUTED,
                         textAnchor="middle"))
        if i % 2 == 0:
            d.add(String(x + bw / 2, 5, f"{dd.day} {dd:%b}", fontName="Mono", fontSize=6.3, fillColor=MUTED,
                         textAnchor="middle"))
    d.add(Line(ml, mb, W, mb, strokeColor=MUTED, strokeWidth=0.6))
    return d


def hbars(rows, color, width):
    """Rows of (label, value): the label above a rounded bar, the value at its end."""
    bar_h, row = 6, 19
    h = len(rows) * row
    d = Drawing(width, h)
    top = max(v for _, v in rows)
    for i, (text, value) in enumerate(rows):
        yy = h - (i + 1) * row + 2
        if len(text) > 52:
            text = text[:51] + "…"
        d.add(String(0, yy + bar_h + 3, text, fontName="Mono", fontSize=6.4, fillColor=INK))
        d.add(Rect(0, yy, width - 22, bar_h, fillColor=PANEL, strokeColor=None, rx=3, ry=3))
        d.add(Rect(0, yy, max((width - 22) * value / top, 2), bar_h, fillColor=color(i), strokeColor=None,
                   rx=3, ry=3))
        d.add(String(width, yy, str(value), fontName="Mono", fontSize=6.4, fillColor=MUTED, textAnchor="end"))
    return d


def grade_stack(rows, width):
    """One stacked bar of low/medium/high per (label, counts) row."""
    h = 36 * len(rows) + 2
    d = Drawing(width, h)
    for i, (label, counts) in enumerate(rows):
        total = sum(counts.values())
        yy = h - (i + 1) * 36
        d.add(String(0, yy + 22, f"{label} · {total:,}", fontName="Mono", fontSize=6.3, fillColor=INK))
        x = 0
        for g in ("low", "medium", "high"):
            w = width * counts[g] / total
            d.add(Rect(x, yy + 4, w - 1.5, 14, fillColor=GRADE[g], strokeColor=None))
            if counts[g] / total > 0.07:
                d.add(String(x + 4, yy + 8, f"{counts[g]:,}", fontName="Mono-Bold", fontSize=7,
                             fillColor=colors.white))
            x += w
    return d


def side_by_side(left, right):
    return Table([[left, right]], colWidths=[HALF + 4 * mm, HALF + 4 * mm],
                 style=[("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8 * mm)])


def table(s, head, rows, widths, grade_cols=(), tint=None, color=None, bold_first=True):
    """A sea-blue header, grade badges, rows tinted by tint(row) or striped, and
    color(col, value) picking a text colour per cell."""
    body = [[Paragraph(h, s["head"]) for h in head]]
    style = [("BACKGROUND", (0, 0), (-1, 0), SEA), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for i, r in enumerate(rows, 1):
        cells = []
        for c, v in enumerate(r):
            if c in grade_cols:
                cells.append(Paragraph(v, s["badge"] if v != "low" else s["badge_low"]))
                continue
            text = esc(v)
            hue = color(c, v) if color else None
            if hue:
                text = f'<font color="{hue}">{text}</font>'
            if c == 0 and bold_first:
                text = f"<b>{text}</b>"
            cells.append(Paragraph(text, s["cell"]))
        body.append(cells)
        bg = TINT.get(tint(r)) if tint else None
        if bg is None and i % 2 == 0:
            bg = TINT["stripe"]
        if bg is not None:
            style.append(("BACKGROUND", (0, i), (-1, i), bg))
        for c in grade_cols:  # the badge sits on top of the row tint
            style.append(("BACKGROUND", (c, i), (c, i), BADGE_BG[r[c]]))
    return Table(body, colWidths=[W * w for w in widths], repeatRows=1, style=TableStyle(style))


def page_canvas(report_date, subtitle):
    class PagedCanvas(Canvas):
        """Holds every page until the end, so the footer can say "Page 2/9"."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            for page in self._pages:
                self.__dict__.update(page)
                self.saveState()
                self.setFont("Mono", 7)
                self.setFillColor(MUTED)
                self.drawString(18 * mm, 10 * mm, f"Report of {day(report_date)}")
                self.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {self._pageNumber}/{len(self._pages)}")
                if self._pageNumber > 1:  # page 1 carries the full title
                    top = A4[1] - 13 * mm
                    renderPDF.draw(logo(13), self, 18 * mm + 6, top - 4)
                    self.setFont("Mono-Bold", 9)
                    self.setFillColor(INK)
                    self.drawString(18 * mm + 25, top, "Coastguard")
                    self.setFont("Mono", 7.5)
                    self.setFillColor(MUTED)
                    self.drawRightString(A4[0] - 18 * mm - 6, top, subtitle)
                    self.setStrokeColor(LINE)
                    self.setLineWidth(0.6)
                    self.line(18 * mm + 6, top - 7, A4[0] - 18 * mm - 6, top - 7)
                self.restoreState()
                super().showPage()
            super().save()
    return PagedCanvas


# The report -------------------------------------------------------------------

def story(data, s, report_date, subtitle, note, pause_label):
    builds, packages, changes, checks = data["builds"], data["packages"], data["changes"], data["checks"]
    grades = collections.Counter(p["grade"] for p in packages)
    sandbox_off = sum(p["sandbox"] == "Turned off" for p in packages)
    apps = sum(p["sandbox"] != "No app launcher" for p in packages)
    vt_known = data["vt_queried"] - data["vt_unknown"]
    raised = sum(GRADE_N[c["to"]] > GRADE_N[c["from"]] for c in changes)
    first, last = data["first"], data["last"]
    out = []

    # Page 1: the summary and what it means.
    out += [Table([[logo(46), [Paragraph("Coastguard", s["name"]), Paragraph(subtitle, s["tag"])]]],
                  colWidths=[58, W - 58],
                  style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                         ("RIGHTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 0),
                         ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]),
            Spacer(1, 14),
            Paragraph(f"What the packages uploaded to OpenRepos from {first.day} {first:%B} to {day(last)} get to do "
                      "on a Sailfish OS device. Grades and flags are those of each package's latest build.", s["sub"]),
            Spacer(1, 8),
            Paragraph(f"Coastguard looked at <b>{len(builds):,}</b> builds of <b>{len(packages)}</b> packages, without "
                      f"installing them. <b>{data['detected'] or 'None'}</b> matched known malware. "
                      f"<b>{grades['high']}</b> packages grade high and <b>{grades['medium']}</b> medium, mostly for a "
                      "turned-off sandbox, root services and setuid files." + (f" {note}" if note else ""), s["body"]),
            Spacer(1, 10)]
    tiles = [("Builds scanned", f"{len(builds):,}", INK), ("Packages", f"{len(packages):,}", INK),
             ("Known malware found", str(data["detected"]), colors.HexColor(GREEN_TXT)),
             ("Packages graded high", str(grades["high"]), HIGH), ("Apps with sandbox off", str(sandbox_off), INK),
             ("Files unknown to VirusTotal", f"{data['vt_unknown'] / max(data['vt_queried'], 1):.1%}", INK)]
    cells = [[Paragraph(f'<font color="{c.hexval()}">{n}</font>', s["tile_n"]), Paragraph(lbl, s["tile_l"])]
             for lbl, n, c in tiles]
    out.append(Table([cells[:3], cells[3:]], colWidths=[W / 3] * 3, style=[
        ("BACKGROUND", (0, 0), (-1, -1), PANEL), ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.white), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 9)]))

    out.append(Paragraph("What this means if you install from OpenRepos", s["h2"]))
    for text in [
        f"<b>No known malware was found.</b> None of the {len(builds):,} builds matched ClamAV, YARA, VirusTotal "
        "or MalwareBazaar. That only rules out malware someone has already catalogued; it does not make a package safe.",
        f"<b>The malware databases barely know Sailfish.</b> VirusTotal had seen only {vt_known} of the "
        f"{data['vt_queried']:,} files it was asked about. What a package installs and sets up tells you far more "
        "than its reputation.",
        f"<b>Most packages are unremarkable.</b> {grades['low']} of {len(packages)} grade low. A medium or high grade "
        "means the package does more on your phone, such as running code as root or outside the sandbox. System "
        "tools often need this; read the flags and decide whether the app you are installing should.",
        f"<b>Many apps turn the sandbox off.</b> {sandbox_off} of the {apps} packages with an app launcher run "
        "without Sailjail, so they can read everything your user account can: contacts, messages, photos and files.",
        f"<b>Updates change what a package does.</b> {raised} updates in this period raised a package's grade and "
        f"{len(changes) - raised} lowered it. Before updating, look at \"Changes since the previous version\" in "
        "the package's report.",
        f"<b>Look up any package</b> at {REPOSITORY}/tree/results/packages/&lt;package-name&gt;. Developers can "
        "answer a flag by shipping a short explanation in their package; it shows under the flag in the report.",
    ]:
        out.append(Paragraph("• " + text, s["bullet"]))

    # What packages get to do.
    builds_by_grade = collections.Counter(b["summary"]["risk"]["grade"] for b in builds)
    sandbox_rows = [(k, sum(p["sandbox"] == k for p in packages))
                    for k in ("Declared", "Turned off", "Not declared", "No app launcher")]
    left = [Paragraph("<b>Risk grade</b>", s["h3"]),
            Paragraph("High: review before installing. Medium: worth a look. A grade is a prompt to read the report, "
                      'not a verdict.<br/><font color="#a9b6bf">■</font> low <font color="#d99a2b">■</font> medium '
                      '<font color="#c4423a">■</font> high', s["note"]),
            grade_stack([("Packages (latest build)", {g: grades[g] for g in GRADE}),
                         ("All builds", {g: builds_by_grade[g] for g in GRADE})], HALF)]
    right = [Paragraph("<b>Sandbox (Sailjail)</b>", s["h3"]),
             Paragraph("Worst launcher per package, latest build. Packages with no launcher are libraries, patches "
                       "and services.", s["note"]),
             hbars(sandbox_rows, lambda i: MED if sandbox_rows[i][0] == "Turned off" else LOW, HALF)]
    top_flags = data["flags"][:14]
    flags_col = [Paragraph("<b>Most common flags</b>", s["h3"]),
                 Paragraph("Medium and high flags across every build, counted once per package. Red where the flag "
                           "can grade a package high.", s["note"]),
                 hbars([(f["label"], f["packages"]) for f in top_flags],
                       lambda i: HIGH if top_flags[i]["level"] == "high" else MED, HALF)]
    perms_col = [Paragraph("<b>Sandbox permissions asked for</b>", s["h3"]),
                 Paragraph("Packages whose latest build asks for each permission.", s["note"]),
                 hbars(data["permissions"][:14], lambda i: SEA, HALF)]
    out += [PageBreak(), Paragraph("What packages get to do", s["h2"]), side_by_side(left, right),
            Paragraph("Flags and permissions", s["h2"]), side_by_side(flags_col, perms_col)]

    # The packages to read about, and how updates changed them.
    high = sorted((p for p in packages if p["grade"] == "high"), key=lambda p: -p["builds"])
    out += [PageBreak(), Paragraph("Packages graded high", s["h2"]),
            Paragraph("Latest build of each. These packages install system-level parts, such as setuid helpers, root "
                      "services or install scripts that grant privileges. Read the report before installing.",
                      s["note"]),
            table(s, ["Package", "Latest version", "Builds", "Flags"],
                  [[p["package"], p["latest_version"], p["builds"], p["flags"]] for p in high],
                  [.25, .14, .08, .53], tint=lambda r: "high"),
            Paragraph("Grade changes between versions", s["h2"]),
            Paragraph("Each update whose risk grade differs from the previous scanned build of the same package and "
                      "architecture. Added lists the flags the new build brought in; Dropped lists the flags of the "
                      "previous build that are gone. A grade that returns to low only because an update's change "
                      "flags expired is left out, since nothing in the package changed.", s["note"]),
            table(s, ["Update", "From", "To", "Added", "Dropped"],
                  [[c["update"], c["from"], c["to"], c["added"], c["dropped"]] for c in changes],
                  [.31, .08, .08, .265, .265], grade_cols=(1, 2),
                  tint=lambda r: "high" if GRADE_N[r[2]] > GRADE_N[r[1]] else "good",
                  color=lambda c, v: RED_TXT if c == 3 else GREEN_TXT if c == 4 else None, bold_first=False)]

    # Every package.
    order = sorted(packages, key=lambda p: (-GRADE_N[p["grade"]], p["package"]))
    body = [[Paragraph(h, s["head"]) for h in ["Package", "Grade", "Sandbox", "Versions", "Builds", "Flags"]]]
    style = [("BACKGROUND", (0, 0), (-1, 0), SEA), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for i, p in enumerate(order, 1):
        g = p["grade"]
        body.append([Paragraph(f"<b>{esc(p['package'])}</b>", s["cell"]),
                     Paragraph(g, s["badge"] if g != "low" else s["badge_low"]),
                     Paragraph(f'<font color="{SANDBOX_TXT[p["sandbox"]]}">{esc(p["sandbox"])}</font>', s["cell"]),
                     Paragraph(str(p["versions"]), s["cell"]), Paragraph(str(p["builds"]), s["cell"]),
                     Paragraph(esc(p["flags"]) or '<font color="#8a979f">none</font>', s["cell"])])
        if g in TINT:
            style.append(("BACKGROUND", (0, i), (-1, i), TINT[g]))
        elif i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), TINT["stripe"]))
        style.append(("BACKGROUND", (1, i), (1, i), BADGE_BG[g]))
    out += [PageBreak(), Paragraph("Every package", s["h2"]),
            Paragraph("Latest build of each package, high grades first.", s["note"]),
            Table(body, colWidths=[W * w for w in (.27, .08, .14, .10, .08, .33)], repeatRows=1,
                  style=TableStyle(style))]

    # How the report was made.
    vt_err, mb_err = checks["virustotal"]["error"], checks["malwarebazaar"]["error"]
    out += [Spacer(1, 6), Paragraph("About this report", s["h2"]),
            Paragraph(f"Coastguard downloads every RPM uploaded to OpenRepos and unpacks it, without installing or "
                      "running it, to record what it would set up on a device. The full report for each build is on "
                      f"the results branch of {REPOSITORY}. This PDF is made from that branch by "
                      "scripts/report_pdf.py.", s["body"]),
            Spacer(1, 6),
            Paragraph(f"Known-malware checks: ClamAV and YARA scanned all {len(builds):,} builds. The VirusTotal "
                      f"lookup failed for {vt_err} {'build' if vt_err == 1 else 'builds'} and MalwareBazaar for "
                      f"{mb_err}; those builds were still scanned by the other checks.", s["body"]),
            Spacer(1, 8),
            Paragraph("<b>Builds scanned per day</b>", s["h3"]),
            Paragraph("All architectures, by the day each build was first scanned.", s["note"]),
            daily_chart(data["per_day"], first, max(report_date, last), last, pause_label)]
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("store")
    parser.add_argument("out")
    parser.add_argument("--date", type=datetime.date.fromisoformat, default=datetime.date.today())
    parser.add_argument("--subtitle", default="OpenRepos uploads")
    parser.add_argument("--note", default="")
    parser.add_argument("--pause-label", default="")
    args = parser.parse_args()

    data = summarize(args.store, load_builds(args.store))
    doc = SimpleDocTemplate(args.out, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=22 * mm,
                            bottomMargin=18 * mm, title=f"Coastguard: {args.subtitle}", author="Coastguard")
    doc.build(story(data, styles(), args.date, args.subtitle, args.note, args.pause_label),
              canvasmaker=page_canvas(args.date, args.subtitle))


if __name__ == "__main__":
    main()
