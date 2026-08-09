"""Core data structures shared across the whole tool.

Everything the linter passes around is one of the small, typed objects
defined here. Keeping them in one place (and keeping them "dumb" -- data
only, no behaviour) is what lets the engine stay generic and the rules
stay as data. That separation is the heart of the design.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered severities.

    Using an ``IntEnum`` (rather than plain strings) means we can compare
    severities directly -- e.g. ``finding.severity >= Severity.HIGH`` -- which
    is exactly what the ``--min-severity`` and ``--fail-on`` flags need.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError as exc:  # pragma: no cover - guards bad rule files
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {text!r}; expected one of: {valid}") from exc

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class Directive:
    """One normalised setting extracted from a config file.

    Every parser -- no matter how different the source syntax is -- produces a
    flat list of these. ``key`` is a lowercased name (sshd/nginx) or a dotted
    path (docker-compose, e.g. ``services.web.privileged``). That uniform shape
    is what allows a single rule engine to work across all three file types.
    """

    key: str
    value: str
    line: int = 0            # 1-based source line; 0 when unknown (e.g. YAML)
    raw: str = ""            # original snippet, used in reports
    path: str = ""           # block context for nginx (e.g. "http.server")


@dataclass(frozen=True, slots=True)
class Match:
    """The condition half of a rule -- what to look for and what to assert."""

    assertion: str                       # see engine.ASSERTIONS
    selector: str | None = None          # directive name / dotted glob (supports '*')
    selector_regex: str | None = None    # alternative: match keys by regex
    value: object | None = None          # comparison operand (str, list, or number)
    on_missing: str = "pass"             # "warn" | "pass" when selector matches nothing
    ignore_case: bool = True


@dataclass(frozen=True, slots=True)
class Rule:
    """A single check, loaded verbatim from a YAML ruleset."""

    id: str
    title: str
    severity: Severity
    match: Match
    rationale: str = ""
    remediation: str = ""
    reference: str = ""


@dataclass(frozen=True, slots=True)
class Finding:
    """A rule that fired against a specific file."""

    rule_id: str
    title: str
    severity: Severity
    detail: str
    remediation: str
    reference: str
    file: str
    line: int = 0

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "detail": self.detail,
            "remediation": self.remediation,
            "reference": self.reference,
            "file": self.file,
            "line": self.line,
        }


@dataclass(slots=True)
class FileResult:
    """All findings for one scanned file, plus which ruleset was applied."""

    file: str
    config_type: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out
