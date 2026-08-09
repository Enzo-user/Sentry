"""Reporters render scan results in a chosen output format."""

from __future__ import annotations

from ..models import FileResult
from .console import render_console
from .html_report import render_html
from .json_report import render_json

FORMATS = ("console", "json", "html")


def render(fmt: str, results: list[FileResult]) -> str | None:
    """Render results. ``console`` prints directly and returns None; the file
    formats return a string the caller can write to disk or stdout."""
    if fmt == "console":
        render_console(results)
        return None
    if fmt == "json":
        return render_json(results)
    if fmt == "html":
        return render_html(results)
    raise ValueError(f"unknown format {fmt!r}")
