"""Human-friendly terminal output using `rich`.

`rich` automatically disables colour when output is piped or NO_COLOR is set,
so this stays readable in CI logs as well as an interactive terminal.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from ..models import FileResult, Severity

_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_console(results: list[FileResult], console: Console | None = None) -> None:
    console = console or Console()
    grand_total = {s: 0 for s in Severity}

    for result in results:
        console.rule(f"[bold]{result.file}[/]  ({result.config_type})")
        if not result.findings:
            console.print("  [green]No findings.[/] Configuration looks hardened.\n")
            continue

        ordered = sorted(result.findings, key=lambda f: (-f.severity, f.rule_id))
        for finding in ordered:
            grand_total[finding.severity] += 1
            tag = Text(f" {finding.severity.label:^8} ", style=_STYLE[finding.severity])
            location = f"line {finding.line}" if finding.line else "config"
            header = Text.assemble(tag, f"  {finding.rule_id}  ", (finding.title, "bold"))
            console.print(header)
            console.print(f"      {location}: {finding.detail}", style="dim")
            if finding.remediation:
                console.print(f"      fix: {finding.remediation}")
            if finding.reference:
                console.print(f"      ref: {finding.reference}", style="dim")
            console.print()

    _summary(console, grand_total)


def _summary(console: Console, totals: dict[Severity, int]) -> None:
    console.rule("[bold]Summary")
    total = sum(totals.values())
    if total == 0:
        console.print("[green]All clear -- no findings across scanned files.[/]")
        return
    parts = [
        Text(f"{count} {sev.label}", style=_STYLE[sev])
        for sev in sorted(Severity, reverse=True)
        if (count := totals[sev])
    ]
    line = Text("  ").join(parts)
    console.print(Text.assemble(f"{total} finding(s):  ", line))
