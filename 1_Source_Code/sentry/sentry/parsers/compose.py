"""Parser for ``docker-compose`` (Compose) YAML files.

Compose files are nested YAML. We flatten them into dotted-path directives so
the same engine that handles flat ``key value`` files can also reason about
``services.web.privileged`` or ``services.db.environment.mysql_root_password``.

Two conveniences make the flattened form nicer to write rules against:
  * ``environment:`` given as a ``KEY=value`` list is normalised so each
    variable becomes its own path segment (``...environment.key``), which lets
    a rule regex-match variable *names* for hardcoded-secret detection.
  * list items keep their index as a segment (``...ports.0``).
"""

from __future__ import annotations

import yaml

from ..models import Directive


def parse_compose(text: str) -> list[Directive]:
    data = yaml.safe_load(text) or {}
    directives: list[Directive] = []
    _flatten(data, [], directives)
    return directives


def _flatten(node: object, path: list[str], out: list[Directive]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _flatten(value, path + [str(key)], out)
    elif isinstance(node, list):
        parent = path[-1].lower() if path else ""
        for index, item in enumerate(node):
            # Normalise `environment: ["KEY=value"]` into named segments.
            if parent == "environment" and isinstance(item, str) and "=" in item:
                name, _, val = item.partition("=")
                _flatten(val, path + [name.strip()], out)
            else:
                _flatten(item, path + [str(index)], out)
    else:
        key = ".".join(segment.lower() for segment in path)
        out.append(Directive(key=key, value=_scalar(node), line=0, raw=f"{'.'.join(path)}: {node}"))


def _scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)
