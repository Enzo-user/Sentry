"""The rule engine: the generic core that turns rules + directives into findings.

There is deliberately **no** knowledge of SSH, nginx, or Docker in this file.
It only knows how to:

  1. select directives that a rule cares about (``_selects``), and
  2. apply one of a fixed vocabulary of assertions to them (``_evaluate``).

New security checks are added by writing YAML -- not by editing this code.
That is the tool's original contribution and the reason it stays small enough
for every team member to explain line by line.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .models import Directive, Finding, Match, Rule, Severity

# Rulesets ship next to this file, in sentry/rules/. Loading them by path
# (rather than as importable package resources) means the tool works the same
# whether it is pip-installed or simply run from the project folder.
_RULES_DIR = Path(__file__).resolve().parent / "rules"

# Assertions evaluated once per matching directive.
_PER_OCCURRENCE = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "absent",
    "regex_forbidden",
    "at_most",
    "at_least",
    "secret",
}
# Assertions evaluated once over the whole set of matches.
_AGGREGATE = {"present", "any_contains"}

ASSERTIONS = _PER_OCCURRENCE | _AGGREGATE


# --------------------------------------------------------------------------- #
# Rule loading
# --------------------------------------------------------------------------- #
def load_rules(config_type: str) -> list[Rule]:
    """Load and validate the ruleset that ships for ``config_type``.

    Rulesets live inside the package (``sentry/rules/<type>.yaml``) and are
    read via ``importlib.resources`` so they work whether the tool is run from
    source or from an installed wheel.
    """
    resource = _RULES_DIR / f"{config_type}.yaml"
    if not resource.is_file():
        raise FileNotFoundError(f"no ruleset bundled for config type {config_type!r}")
    raw = yaml.safe_load(resource.read_text(encoding="utf-8")) or []
    return [_rule_from_dict(entry, config_type) for entry in raw]


def _rule_from_dict(entry: dict, config_type: str) -> Rule:
    try:
        raw_match = entry["match"]
        assertion = raw_match["assert"]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"malformed rule in {config_type}.yaml: {entry!r}") from exc

    if assertion not in ASSERTIONS:
        raise ValueError(f"rule {entry.get('id')!r} uses unknown assertion {assertion!r}")

    match = Match(
        assertion=assertion,
        selector=raw_match.get("selector"),
        selector_regex=raw_match.get("selector_regex"),
        value=raw_match.get("value"),
        on_missing=raw_match.get("on_missing", "pass"),
        ignore_case=raw_match.get("ignore_case", True),
    )
    return Rule(
        id=entry["id"],
        title=entry["title"],
        severity=Severity.parse(entry["severity"]),
        match=match,
        rationale=entry.get("rationale", ""),
        remediation=entry.get("remediation", ""),
        reference=entry.get("reference", ""),
    )


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #
def _selects(match: Match, key: str) -> bool:
    """Return True if a directive ``key`` is in scope for this rule."""
    if match.selector_regex is not None:
        return re.fullmatch(match.selector_regex, key, re.IGNORECASE) is not None

    selector = (match.selector or "").lower()
    if not selector:
        return False

    # Bare name (no path, no wildcard): match the full key or its last segment.
    # This lets a docker-compose rule target "privileged" wherever it appears,
    # while an sshd rule targeting "permitrootlogin" still matches exactly.
    if "*" not in selector and "." not in selector:
        return key == selector or key.rsplit(".", 1)[-1] == selector

    # Dotted/wildcard path: segment-by-segment, '*' matches any one segment.
    sel_parts = selector.split(".")
    key_parts = key.split(".")
    if len(sel_parts) != len(key_parts):
        return False
    return all(sp == "*" or sp == kp for sp, kp in zip(sel_parts, key_parts))


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def evaluate(rules: list[Rule], directives: list[Directive], filename: str) -> list[Finding]:
    """Run every rule against the parsed directives, collecting findings."""
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(_evaluate_rule(rule, directives, filename))
    return findings


def _evaluate_rule(rule: Rule, directives: list[Directive], filename: str) -> list[Finding]:
    matches = [d for d in directives if _selects(rule.match, d.key)]
    assertion = rule.match.assertion

    # Nothing matched. Only "must be configured" style assertions care.
    if not matches:
        if assertion in {"equals", "present", "at_most", "at_least", "contains", "any_contains"}:
            if rule.match.on_missing == "warn":
                return [_finding(rule, filename, 0, "setting is not present; relying on an insecure default")]
        return []

    if assertion in _AGGREGATE:
        return _evaluate_aggregate(rule, matches, filename)

    out: list[Finding] = []
    for directive in matches:
        detail = _check_one(assertion, rule.match, directive)
        if detail is not None:
            out.append(_finding(rule, filename, directive.line, detail))
    return out


def _evaluate_aggregate(rule: Rule, matches: list[Directive], filename: str) -> list[Finding]:
    m = rule.match
    if m.assertion == "present":
        return []  # matches is non-empty here, so the requirement is satisfied
    if m.assertion == "any_contains":
        needle = _norm(str(m.value), m.ignore_case)
        if any(needle in _norm(d.value, m.ignore_case) for d in matches):
            return []
        return [_finding(rule, filename, 0, f"no matching directive sets {m.value!r}")]
    return []  # pragma: no cover


def _check_one(assertion: str, m: Match, d: Directive) -> str | None:
    """Return a human-readable detail string if the rule is violated, else None."""
    value = d.value
    cmp = _norm(value, m.ignore_case)

    if assertion == "equals":
        want = _norm(str(m.value), m.ignore_case)
        if cmp != want:
            shown = value or "(empty)"
            return f"found {shown!r}, expected {m.value!r}"
        return None

    if assertion == "not_equals":
        bad = _norm(str(m.value), m.ignore_case)
        if cmp == bad:
            return f"insecure value {value!r} is set"
        return None

    if assertion == "not_contains":
        hits = [t for t in _as_list(m.value) if _norm(str(t), m.ignore_case) in cmp]
        if hits:
            return f"contains disallowed value(s): {', '.join(hits)}"
        return None

    if assertion == "contains":
        missing = [t for t in _as_list(m.value) if _norm(str(t), m.ignore_case) not in cmp]
        if missing:
            return f"missing required value(s): {', '.join(missing)}"
        return None

    if assertion == "absent":
        return f"directive is set ({value!r}) but should not be"

    if assertion == "secret":
        stripped = value.strip()
        # An empty value or an external reference (${VAR}, $VAR) is good practice,
        # not a hardcoded secret -- so those are deliberately not flagged.
        if not stripped or re.fullmatch(r"\$\{?[A-Za-z0-9_]+\}?", stripped):
            return None
        name = d.key.rsplit(".", 1)[-1]
        # Report the variable name only, never the secret value itself.
        return f"variable {name!r} appears to hold a hardcoded secret"

    if assertion == "regex_forbidden":
        flags = re.IGNORECASE if m.ignore_case else 0
        if re.search(str(m.value), value, flags):
            return f"value {value!r} matches forbidden pattern /{m.value}/"
        return None

    if assertion in {"at_most", "at_least"}:
        number = _to_number(value)
        limit = _to_number(str(m.value))
        if number is None or limit is None:
            return None  # non-numeric value: nothing sensible to assert
        if assertion == "at_most" and number > limit:
            return f"value {number} exceeds recommended maximum of {limit}"
        if assertion == "at_least" and number < limit:
            return f"value {number} is below recommended minimum of {limit}"
        return None

    return None  # pragma: no cover


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _finding(rule: Rule, filename: str, line: int, detail: str) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        detail=detail,
        remediation=rule.remediation,
        reference=rule.reference,
        file=filename,
        line=line,
    )


def _norm(text: str, ignore_case: bool) -> str:
    return text.lower() if ignore_case else text


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else [value]


def _to_number(text: str) -> float | None:
    match = re.search(r"-?\d+(?:\.\d+)?", text.strip())
    return float(match.group()) if match else None
