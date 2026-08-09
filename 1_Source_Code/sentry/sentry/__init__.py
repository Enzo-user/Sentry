"""Sentry -- a static security configuration linter.

Sentry reads server and container configuration files (sshd_config, nginx,
docker-compose) and reports insecure settings, insecure defaults, and missing
hardening directives, ranked by severity. It performs *static* analysis only:
it never connects to, scans, or tests any live system.
"""

from __future__ import annotations

__version__ = "0.1.0"
TOOL_NAME = "sentry"

__all__ = ["__version__", "TOOL_NAME"]
