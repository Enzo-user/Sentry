"""Parsers turn raw config text into a flat list of ``Directive`` objects.

Each parser handles one syntax family. They all share the same output type, so
the engine never needs to know which one produced the directives it evaluates.
"""

from __future__ import annotations

from collections.abc import Callable

from ..models import Directive
from .compose import parse_compose
from .keyvalue import parse_keyvalue
from .nginx import parse_nginx

# Maps a config type -> the function that parses it. The keys here must match
# the ruleset filenames in sentry/rules/ (e.g. "sshd" -> rules/sshd.yaml).
PARSERS: dict[str, Callable[[str], list[Directive]]] = {
    "sshd": parse_keyvalue,
    "nginx": parse_nginx,
    "docker-compose": parse_compose,
}

SUPPORTED_TYPES = tuple(PARSERS)


def parse(config_type: str, text: str) -> list[Directive]:
    try:
        parser = PARSERS[config_type]
    except KeyError as exc:
        raise ValueError(f"no parser for config type {config_type!r}") from exc
    return parser(text)
