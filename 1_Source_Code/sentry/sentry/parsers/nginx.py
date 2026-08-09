"""A small, dependency-free parser for nginx-style configuration.

nginx config is block-structured (``http { server { location { ... } } }``)
and terminates directives with ``;``. We tokenise the text ourselves rather
than pulling in a third-party parser, because:

  * it keeps the tool free of a hard-to-explain dependency, and
  * every security check we care about is about the *name and value* of a
    directive, regardless of which block it sits in.

So we flatten the tree into a list of directives, each tagged with the
block context it came from (e.g. ``http.server``) for reporting.
"""

from __future__ import annotations

from ..models import Directive

_SPECIAL = "{};"
_WHITESPACE = " \t\r\n"
_QUOTES = "\"'"


def _tokenize(text: str) -> list[tuple[str, int]]:
    """Split nginx text into (token, line_number) pairs.

    Tokens are words, quoted strings, or the single characters ``{ } ;``.
    Comments (``#`` to end of line) are dropped here.
    """
    tokens: list[tuple[str, int]] = []
    buf: list[str] = []
    buf_line = 1
    line = 1
    i, n = 0, len(text)

    def flush() -> None:
        nonlocal buf
        if buf:
            tokens.append(("".join(buf), buf_line))
            buf = []

    while i < n:
        ch = text[i]
        if ch == "\n":
            flush()
            line += 1
            i += 1
        elif ch == "#":
            flush()
            while i < n and text[i] != "\n":
                i += 1
        elif ch in _SPECIAL:
            flush()
            tokens.append((ch, line))
            i += 1
        elif ch in _WHITESPACE:
            flush()
            i += 1
        elif ch in _QUOTES:
            flush()
            quote, j, chars = ch, i + 1, []
            while j < n and text[j] != quote:
                if text[j] == "\n":
                    line += 1
                chars.append(text[j])
                j += 1
            tokens.append(("".join(chars), line))
            i = j + 1
        else:
            if not buf:
                buf_line = line
            buf.append(ch)
            i += 1
    flush()
    return tokens


def parse_nginx(text: str) -> list[Directive]:
    directives: list[Directive] = []
    context: list[str] = []       # stack of enclosing block names
    words: list[str] = []
    start_line = 0

    for token, lineno in _tokenize(text):
        if token == ";":
            if words:
                key = words[0].lower()
                value = " ".join(words[1:])
                directives.append(
                    Directive(
                        key=key,
                        value=value,
                        line=start_line,
                        raw=" ".join(words),
                        path=".".join(context),
                    )
                )
            words, start_line = [], 0
        elif token == "{":
            context.append(words[0].lower() if words else "")
            words, start_line = [], 0
        elif token == "}":
            if context:
                context.pop()
            words, start_line = [], 0
        else:
            if not words:
                start_line = lineno
            words.append(token)

    return directives
