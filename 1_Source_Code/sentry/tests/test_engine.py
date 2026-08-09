"""Unit tests for the parsers and the rule engine.

These focus on the generic behaviour of the engine (selection + assertions) and
each parser's normalisation, so a change that breaks the core logic fails fast.
"""

from __future__ import annotations

from sentry.engine import _selects, evaluate, load_rules
from sentry.models import Directive, Match, Rule, Severity
from sentry.parsers import parse
from sentry.parsers.compose import parse_compose
from sentry.parsers.keyvalue import parse_keyvalue
from sentry.parsers.nginx import parse_nginx


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def test_keyvalue_parses_and_lowercases_keys():
    directives = parse_keyvalue("PermitRootLogin yes  # inline comment\n\n# full\nPort 22\n")
    keys = {d.key: d.value for d in directives}
    assert keys["permitrootlogin"] == "yes"
    assert keys["port"] == "22"
    assert len(directives) == 2  # comment-only and blank lines skipped


def test_nginx_flattens_nested_directives_with_context():
    text = "http {\n server {\n  ssl_protocols TLSv1.2;\n } \n}\n"
    directives = parse_nginx(text)
    ssl = next(d for d in directives if d.key == "ssl_protocols")
    assert ssl.value == "TLSv1.2"
    assert ssl.path == "http.server"


def test_compose_flattens_paths_and_env_names():
    text = (
        "services:\n"
        "  db:\n"
        "    privileged: true\n"
        "    environment:\n"
        "      - MYSQL_ROOT_PASSWORD=secret\n"
    )
    directives = parse_compose(text)
    keys = {d.key: d.value for d in directives}
    assert keys["services.db.privileged"] == "true"
    assert keys["services.db.environment.mysql_root_password"] == "secret"


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #
def test_bare_selector_matches_last_path_segment():
    m = Match(assertion="not_equals", selector="privileged", value="true")
    assert _selects(m, "services.web.privileged")
    assert not _selects(m, "services.web.image")


def test_wildcard_selector_matches_one_segment():
    m = Match(assertion="not_equals", selector="services.*.privileged", value="true")
    assert _selects(m, "services.web.privileged")
    assert not _selects(m, "services.web.build.privileged")


def test_regex_selector():
    m = Match(assertion="present", selector_regex=r"services\..*\.environment\..*password.*")
    assert _selects(m, "services.db.environment.postgres_password")
    assert not _selects(m, "services.db.environment.postgres_user")


# --------------------------------------------------------------------------- #
# Assertions
# --------------------------------------------------------------------------- #
def _rule(match: Match, sev=Severity.HIGH) -> Rule:
    return Rule(id="T-001", title="test", severity=sev, match=match, remediation="fix it")


def test_equals_flags_wrong_value():
    rule = _rule(Match(assertion="equals", selector="permitrootlogin", value="no"))
    directives = [Directive(key="permitrootlogin", value="yes", line=1)]
    findings = evaluate([rule], directives, "x")
    assert len(findings) == 1
    assert findings[0].rule_id == "T-001"


def test_equals_passes_correct_value():
    rule = _rule(Match(assertion="equals", selector="permitrootlogin", value="no"))
    directives = [Directive(key="permitrootlogin", value="no", line=1)]
    assert evaluate([rule], directives, "x") == []


def test_on_missing_warn_fires_when_absent():
    rule = _rule(Match(assertion="equals", selector="permitrootlogin", value="no", on_missing="warn"))
    assert len(evaluate([rule], [], "x")) == 1


def test_on_missing_pass_is_silent_when_absent():
    rule = _rule(Match(assertion="equals", selector="permitrootlogin", value="no", on_missing="pass"))
    assert evaluate([rule], [], "x") == []


def test_at_most_flags_high_number():
    rule = _rule(Match(assertion="at_most", selector="maxauthtries", value=4))
    directives = [Directive(key="maxauthtries", value="6", line=1)]
    assert len(evaluate([rule], directives, "x")) == 1


def test_not_contains_detects_weak_cipher():
    rule = _rule(Match(assertion="not_contains", selector="ciphers", value=["cbc", "3des"]))
    directives = [Directive(key="ciphers", value="aes256-cbc,aes128-ctr", line=1)]
    assert len(evaluate([rule], directives, "x")) == 1


def test_any_contains_passes_when_header_present():
    rule = _rule(Match(assertion="any_contains", selector="add_header", value="X-Frame-Options"))
    directives = [
        Directive(key="add_header", value="X-Frame-Options SAMEORIGIN", line=1),
        Directive(key="add_header", value="X-Powered-By nginx", line=2),
    ]
    assert evaluate([rule], directives, "x") == []


def test_any_contains_flags_when_header_absent():
    rule = _rule(Match(assertion="any_contains", selector="add_header", value="X-Frame-Options", on_missing="warn"))
    directives = [Directive(key="add_header", value="X-Powered-By nginx", line=1)]
    assert len(evaluate([rule], directives, "x")) == 1


def test_secret_flags_literal_but_reports_only_the_name():
    rule = _rule(Match(assertion="secret", selector="password"))
    directives = [Directive(key="services.db.environment.password", value="hunter2", line=0)]
    findings = evaluate([rule], directives, "x")
    assert len(findings) == 1
    assert "hunter2" not in findings[0].detail  # never echo the secret


def test_secret_ignores_env_reference():
    rule = _rule(Match(assertion="secret", selector="password"))
    directives = [Directive(key="services.db.environment.password", value="${DB_PASSWORD}", line=0)]
    assert evaluate([rule], directives, "x") == []


# --------------------------------------------------------------------------- #
# Rulesets load and apply end to end
# --------------------------------------------------------------------------- #
def test_bundled_rulesets_load():
    for ctype in ("sshd", "nginx", "docker-compose"):
        rules = load_rules(ctype)
        assert rules, f"{ctype} ruleset is empty"


def test_end_to_end_weak_sshd_has_findings():
    text = "PermitRootLogin yes\nPasswordAuthentication yes\n"
    directives = parse("sshd", text)
    findings = evaluate(load_rules("sshd"), directives, "sshd_config")
    ids = {f.rule_id for f in findings}
    assert "SSH-001" in ids
