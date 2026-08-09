"""Command-line interface and orchestration.

Responsibilities kept here (and nowhere else):
  * parse arguments,
  * decide which ruleset/parser each file needs (by name, or --type override),
  * drive parse -> evaluate -> report,
  * choose the process exit code so the tool is usable in CI.

Exit codes:
  0  no findings at or above the --fail-on threshold
  1  findings at or above the --fail-on threshold
  2  usage or input error (bad file, unknown type, etc.)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import evaluate, load_rules
from .models import FileResult, Severity
from .parsers import SUPPORTED_TYPES, parse
from .reporters import FORMATS, render

_USAGE_ERROR = 2


def detect_type(path: Path) -> str | None:
    """Guess a config type from a filename. Returns None if unrecognised."""
    name = path.name.lower()
    if "sshd_config" in name:
        return "sshd"
    if "nginx" in name or name.endswith(".conf"):
        return "nginx"
    if name.endswith((".yml", ".yaml")):
        return "docker-compose"
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentry",
        description="Static security linter for sshd, nginx, and docker-compose configs.",
        epilog="Static analysis only -- Sentry never connects to a live system.",
    )
    parser.add_argument("files", nargs="*", type=Path, help="configuration file(s) to scan")
    parser.add_argument(
        "-t", "--type", choices=SUPPORTED_TYPES,
        help="force a config type instead of auto-detecting from the filename",
    )
    parser.add_argument(
        "-f", "--format", choices=FORMATS, default="console",
        help="output format (default: console)",
    )
    parser.add_argument("-o", "--output", type=Path, help="write output to a file instead of stdout")
    parser.add_argument(
        "--min-severity", choices=[s.label.lower() for s in Severity], default="info",
        help="hide findings below this severity (default: info)",
    )
    parser.add_argument(
        "--fail-on", choices=[s.label.lower() for s in Severity], default="high",
        help="exit non-zero if any finding is at or above this severity (default: high)",
    )
    parser.add_argument(
        "--list-rules", action="store_true",
        help="list all bundled rules and exit",
    )
    parser.add_argument("--version", action="version", version=f"sentry {__version__}")
    return parser


def _scan_file(path: Path, forced_type: str | None, min_sev: Severity) -> FileResult:
    config_type = forced_type or detect_type(path)
    if config_type is None:
        raise ValueError(
            f"cannot determine config type for {path.name!r}; pass --type "
            f"({', '.join(SUPPORTED_TYPES)})"
        )
    text = path.read_text(encoding="utf-8", errors="replace")
    directives = parse(config_type, text)
    rules = load_rules(config_type)
    findings = [f for f in evaluate(rules, directives, str(path)) if f.severity >= min_sev]
    return FileResult(file=str(path), config_type=config_type, findings=findings)


def _list_rules() -> int:
    for config_type in SUPPORTED_TYPES:
        print(f"\n# {config_type}")
        for rule in load_rules(config_type):
            print(f"  {rule.id:<8} [{rule.severity.label:<8}] {rule.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        return _list_rules()

    if not args.files:
        print("error: no files given (use --help for usage)", file=sys.stderr)
        return _USAGE_ERROR

    min_sev = Severity.parse(args.min_severity)
    fail_on = Severity.parse(args.fail_on)

    results: list[FileResult] = []
    for path in args.files:
        if not path.is_file():
            print(f"error: not a file: {path}", file=sys.stderr)
            return _USAGE_ERROR
        try:
            results.append(_scan_file(path, args.type, min_sev))
        except (ValueError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return _USAGE_ERROR

    rendered = render(args.format, results)
    if rendered is not None:
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
            print(f"wrote {args.format} report to {args.output}")
        else:
            print(rendered)

    worst = max(
        (f.severity for r in results for f in r.findings),
        default=Severity.INFO,
    )
    any_findings = any(r.findings for r in results)
    return 1 if (any_findings and worst >= fail_on) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
