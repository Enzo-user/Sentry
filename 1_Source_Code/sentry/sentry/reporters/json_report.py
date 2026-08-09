"""Machine-readable JSON output, suitable for piping into other tools or CI."""

from __future__ import annotations

import datetime as _dt
import json

from .. import __version__
from ..models import FileResult, Severity


def render_json(results: list[FileResult]) -> str:
    totals = {s.label: 0 for s in Severity}
    files = []
    for result in results:
        for finding in result.findings:
            totals[finding.severity.label] += 1
        files.append(
            {
                "file": result.file,
                "config_type": result.config_type,
                "finding_count": len(result.findings),
                "findings": [f.as_dict() for f in result.findings],
            }
        )

    document = {
        "tool": "sentry",
        "version": __version__,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "summary": {
            "files_scanned": len(results),
            "total_findings": sum(totals.values()),
            "by_severity": totals,
        },
        "results": files,
    }
    return json.dumps(document, indent=2)
