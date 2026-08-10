# Sentry

A 3-in-1 static security config linter. One engine checks `sshd_config`, `nginx`,
and `docker-compose` files for insecure settings, unsafe defaults, and missing
hardening, and reports each issue with a severity, a short explanation, and a fix.

Built by **Hood Security Department** (NSSECU2, S04).

---

## Tool Name

**Sentry**, a static security configuration linter.

## Description

You give Sentry a config file. It checks that file against a set of known
security problems and prints a list of findings, sorted by severity. It's static
analysis only: it reads the config text and never connects to, scans, probes, or
tests any running system, service, or network.

It handles three different config formats with one engine:

| Config type | Example file | What it checks |
|-------------|--------------|----------------|
| `sshd` | `sshd_config` | OpenSSH server hardening (root login, auth, ciphers, timeouts) |
| `nginx` | `nginx.conf` | TLS versions, ciphers, security headers, information disclosure |
| `docker-compose` | `docker-compose.yml` | Privileged containers, host namespaces, capabilities, hardcoded secrets |

## Purpose

Most real breaches start with a misconfiguration, not some exotic exploit. Sentry
is meant to catch those mistakes before you deploy. It's safe to run anywhere (it
never touches a live system), and it's small enough that our whole team can read
and explain every line.

## Features

- **One engine, three formats.** sshd, nginx, and docker-compose all get turned
  into the same internal shape, so one rule engine handles all of them.
- **Rules are data, not code.** Every check lives in a YAML file under
  `sentry/rules/`. Adding a check means editing data, not writing code.
- **Severity ranking:** `critical` / `high` / `medium` / `low` / `info`.
- **A missing setting counts as a finding.** If a hardening directive isn't there
  and the default is unsafe, Sentry flags it. It doesn't only look at wrong values
  that are present.
- **Hardcoded-secret detection** for compose `environment:` values. It reports
  only the variable name (never the secret) and skips healthy `${ENV_VAR}`
  references.
- **Three output formats:** colored console, JSON, and a self-contained HTML report.
- **CI-friendly exit codes** (`--fail-on`) so it can run on its own in a pipeline.
- **No network access, ever.** It's fully offline.

## System Requirements

- **Python 3.10 or newer** (we built and tested on 3.12).
- `pip` to install two dependencies:
  - `pyyaml` (>= 6.0) for reading the YAML rules and compose files.
  - `rich` (>= 13.0) for colored console output.
- Works on **Linux, macOS, or Windows 11 / 10**. You don't need internet to run
  it. The only time it uses the network is once during install, to download those
  two packages from PyPI.

## Installation

Unzip the project, then open a terminal in the folder that has `pyproject.toml`.

### Option A: recommended (gives you the `sentry` command)

```bash
# 1. Create and activate a virtual environment
python -m venv .venv

#    Linux / macOS:
source .venv/bin/activate
#    Windows (PowerShell):
.venv\Scripts\Activate.ps1

# 2. Install Sentry and its dependencies
pip install -e .

# 3. Check it works
sentry --version
```

### Option B: no install, just the dependencies

```bash
pip install -r requirements.txt
python -m sentry --version
```

With Option B, just write `python -m sentry ...` wherever the examples below say
`sentry ...`.

> **Windows 11 note:** if PowerShell blocks `.venv\Scripts\Activate.ps1` and says
> "running scripts is disabled," run
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once,
> then activate again. The full Windows steps are in the user manual.

## Usage

```bash
# Scan a single file (type is detected from the name)
sentry samples/sshd_config.bad

# Scan several files of different types at once
sentry samples/sshd_config.bad samples/nginx.conf.bad samples/docker-compose.bad.yml

# Force the config type (handy when the filename is unusual)
sentry my_config.txt --type sshd

# Show only high-severity issues and up
sentry samples/nginx.conf.bad --min-severity high

# Make a shareable HTML report
sentry samples/nginx.conf.bad --format html --output report.html

# List every rule the tool has
sentry --list-rules
```

### Options

| Flag | What it does |
|------|---------|
| `-t`, `--type` | Force a config type (`sshd`, `nginx`, `docker-compose`) instead of auto-detecting |
| `-f`, `--format` | Output format: `console` (default), `json`, or `html` |
| `-o`, `--output` | Write the report to a file instead of the screen |
| `--min-severity` | Hide findings below this severity (default: `info`) |
| `--fail-on` | Exit non-zero if any finding is at or above this severity (default: `high`) |
| `--list-rules` | Print every bundled rule and exit |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the `--fail-on` threshold |
| `1` | Findings at or above the threshold |
| `2` | Usage or input error |

## Testing Environment

Sentry is safe to run anywhere because it only reads local text files. You don't
need a vulnerable VM or any lab target.

It comes with some deliberately weak sample files in the `samples/` folder:

| File | What it is |
|------|---------|
| `samples/sshd_config.bad` | A deliberately insecure SSH config (triggers lots of findings) |
| `samples/sshd_config.good` | A hardened SSH config (should report nothing) |
| `samples/nginx.conf.bad` | A deliberately insecure nginx config |
| `samples/docker-compose.bad.yml` | A deliberately insecure compose file |

To run the tests:

```bash
pip install -e ".[dev]"   # installs pytest
pytest
```

## Sample Output

Scanning the weak SSH sample (`sentry samples/sshd_config.bad`) prints a report
grouped by severity. Each finding shows the exact line, a short explanation, and a
fix. There's a full captured run in **`SAMPLE_OUTPUT.txt`**, and a ready-made HTML
report in **`example-report.html`** (just open it in any browser).

![Console output for sentry samples/nginx.conf.bad](assets/screenshot_console.png)

## Limitations

Sentry is a small, educational tool on purpose. It isn't meant to replace a mature
scanner, and here's what it doesn't do:

- **Small ruleset.** About 29 rules across three formats. Big tools like Checkov
  or Lynis have thousands.
- **nginx parsing is directive-level, not full context.** It flattens nginx
  directives across blocks.
- **No CVE or version-vulnerability checks.**
- **Pattern-based secret detection,** so it can miss oddly named secrets.
- **No line numbers for YAML findings** (they show line `0`).

## Future Improvements

- Support more config types (Dockerfile, Apache, PostgreSQL, Kubernetes).
- Add line numbers for YAML findings.
- Context-aware nginx parsing (scoped per `server` block).
- A `--fix` mode that suggests or writes hardened values.
- Map findings to a framework like CIS or OWASP ASVS.
- Let users load their own rule files with a `--rules` flag.

## Ethical Disclaimer

This tool was developed for **educational purposes only**. It must only be used in
**authorized and controlled testing environments**. Unauthorized testing against
real systems, public websites, or third-party services is strictly prohibited.

Sentry only does static analysis of config text you give it. It doesn't connect
to, scan, or test any live system. Make sure you have permission to review any
file you run it against.

## Group Members and Roles

Group: **Hood Security Department**. Course: **NSSECU2 (S04)**.

| Name | Role |
|------|------|
| James Edsel Alvarez | Team lead and system architecture |
| Hans Gabriel Obcena | Rule engine and matcher design |
| Lorenzo Enrique Suerte | Config parsers (sshd / nginx / compose) |
| Jarick Klein Viray | Reporters (console / JSON / HTML) |
| Jeruel Fabricante | Testing, QA, and documentation |

## Original Contribution

Our original contribution is a data-driven linting engine that handles three
unrelated config formats with one set of rules. Instead of writing a separate
scanner for each format, we turn line-based (`sshd`), block-based (`nginx`), and
nested-YAML (`docker-compose`) configs into one flat list of directives, so a
single engine of about 200 lines checks all three. All the security knowledge
lives as YAML data in `sentry/rules/`, which keeps the engine small enough for
every one of us to explain, and makes adding a new check a one-line edit.

Everything in this repo is our own work: the engine, the parsers, the rule
format, the rules themselves, and the reporters. We use `pyyaml` and `rich` as
libraries (we call them, we didn't modify them), and we didn't fork any existing
project.

Two design decisions we made and can explain:
1. The hardcoded-secret detector reports only the **variable name**, never the
   secret value, and it ignores `${ENV_VAR}` references so healthy configs don't
   get flagged.
2. A **missing** hardening directive counts as a finding on its own, because
   relying on an unsafe default is itself a risk.
