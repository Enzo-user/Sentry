"""A self-contained, offline HTML report.

No external CSS, fonts or JavaScript -- everything is inlined so the report is
a single portable file that renders identically offline and looks good pasted
into a slide or handed to a reviewer. Dark mode is handled with a CSS media
query so it adapts to the viewer's system theme.
"""

from __future__ import annotations

import datetime as _dt
import html

from .. import __version__
from ..models import FileResult, Severity

_SEV_COLORS = {
    Severity.CRITICAL: "#7f1d1d",
    Severity.HIGH: "#dc2626",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#0891b2",
    Severity.INFO: "#64748b",
}


def render_html(results: list[FileResult]) -> str:
    totals = {s: 0 for s in Severity}
    for result in results:
        for finding in result.findings:
            totals[finding.severity] += 1

    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    return _TEMPLATE.format(
        style=_STYLE,
        version=html.escape(__version__),
        generated=generated,
        chips=_summary_chips(totals),
        body=_body(results),
    )


def _summary_chips(totals: dict[Severity, int]) -> str:
    chips = []
    total = sum(totals.values())
    chips.append(f'<span class="chip total">{total} total</span>')
    for sev in sorted(Severity, reverse=True):
        count = totals[sev]
        if count:
            color = _SEV_COLORS[sev]
            chips.append(
                f'<span class="chip" style="background:{color}">{count} {sev.label.title()}</span>'
            )
    return "".join(chips)


def _body(results: list[FileResult]) -> str:
    sections = []
    for result in results:
        file = html.escape(result.file)
        ctype = html.escape(result.config_type)
        if not result.findings:
            sections.append(
                f'<section class="file"><h2>{file}<span class="type">{ctype}</span></h2>'
                f'<p class="clear">No findings &mdash; configuration looks hardened.</p></section>'
            )
            continue

        rows = []
        for finding in sorted(result.findings, key=lambda f: (-f.severity, f.rule_id)):
            color = _SEV_COLORS[finding.severity]
            location = f"line {finding.line}" if finding.line else "config"
            rows.append(
                f"""
        <article class="finding">
          <div class="sev" style="background:{color}">{finding.severity.label}</div>
          <div class="detail">
            <div class="titlerow">
              <span class="rid">{html.escape(finding.rule_id)}</span>
              <span class="title">{html.escape(finding.title)}</span>
              <span class="loc">{html.escape(location)}</span>
            </div>
            <p class="what">{html.escape(finding.detail)}</p>
            {_line("Fix", finding.remediation)}
            {_line("Reference", finding.reference)}
          </div>
        </article>"""
            )
        sections.append(
            f'<section class="file"><h2>{file}<span class="type">{ctype}</span></h2>'
            + "".join(rows)
            + "</section>"
        )
    return "\n".join(sections)


def _line(label: str, value: str) -> str:
    if not value:
        return ""
    return f'<p class="meta"><b>{label}:</b> {html.escape(value)}</p>'


_STYLE = """
:root{--bg:#f8fafc;--card:#ffffff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;}
@media (prefers-color-scheme:dark){
  :root{--bg:#0b1120;--card:#111827;--ink:#e5e7eb;--muted:#94a3b8;--line:#1f2937;}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
.wrap{max-width:900px;margin:0 auto;padding:40px 24px 80px}
header h1{margin:0;font-size:26px;letter-spacing:-.02em}
header .sub{color:var(--muted);font-size:14px;margin-top:4px}
.chips{margin:20px 0 8px;display:flex;flex-wrap:wrap;gap:8px}
.chip{color:#fff;font-size:13px;font-weight:600;padding:5px 12px;border-radius:999px}
.chip.total{background:#334155}
section.file{background:var(--card);border:1px solid var(--line);border-radius:14px;
  padding:20px 22px;margin-top:22px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
section.file h2{margin:0 0 14px;font-size:17px;display:flex;align-items:center;gap:10px}
.type{font-size:11px;font-weight:600;color:var(--muted);border:1px solid var(--line);
  padding:2px 8px;border-radius:6px;text-transform:uppercase;letter-spacing:.05em}
.clear{color:#16a34a;font-weight:600;margin:0}
.finding{display:flex;gap:14px;padding:14px 0;border-top:1px solid var(--line)}
.finding:first-of-type{border-top:none}
.sev{color:#fff;font-size:11px;font-weight:700;letter-spacing:.05em;padding:4px 8px;
  border-radius:6px;height:fit-content;min-width:64px;text-align:center}
.titlerow{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px}
.rid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--muted)}
.title{font-weight:600}
.loc{font-size:12px;color:var(--muted)}
.what{margin:6px 0}
.meta{margin:2px 0;font-size:14px;color:var(--muted)}
.meta b{color:var(--ink);font-weight:600}
footer{margin-top:40px;text-align:center;color:var(--muted);font-size:12px}
"""

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentry Security Report</title>
<style>{style}</style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>Sentry &mdash; Configuration Security Report</h1>
      <div class="sub">Generated {generated} &middot; sentry v{version}</div>
    </header>
    <div class="chips">{chips}</div>
    {body}
    <footer>
      Static analysis only. This tool inspects configuration text; it does not connect to or test any live system.
    </footer>
  </div>
</body>
</html>"""
