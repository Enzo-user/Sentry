"""Parser for line-oriented ``key value`` configs such as ``sshd_config``.

Format: one directive per line, first whitespace-delimited token is the name,
the remainder is the value. ``#`` starts a comment. Blank lines are ignored.
Every occurrence is kept (not just the last), so the linter can flag an
insecure value wherever it appears -- including inside ``Match`` blocks.
"""

from __future__ import annotations

from ..models import Directive


def parse_keyvalue(text: str) -> list[Directive]:
    directives: list[Directive] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        directives.append(Directive(key=key, value=value, line=lineno, raw=line))
    return directives
