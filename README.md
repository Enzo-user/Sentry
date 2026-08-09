# Sentry — Submission Package

**Group:** Hood Security Department  **·  Course:** NSSECU2 (S04)

Sentry is a static security configuration linter for `sshd_config`, `nginx`, and
`docker-compose` files. It analyses configuration text and reports insecure
settings, insecure defaults, and missing hardening directives, each with a
severity and a recommended fix. It performs static analysis only and does not
connect to, scan, or test any live system.

## Package Contents

| Folder / file | Description |
|---|---|
| `1_Source_Code/sentry/` | The complete source repository. See its `README.md` for installation, usage, sample output, limitations, the ethical disclaimer, and the original-contribution statement. |
| `2_User_Manual/` | The user manual in DOCX and PDF (installation, usage, results explanation, troubleshooting, limitations, and ethical reminder). |
| `3_Presentation/` | The project presentation (PPTX). |
| `DEMO_SCRIPT.md` | Outline used to record the demonstration video (see below). |

## Running the Tool

Open a terminal in `1_Source_Code/sentry` (the folder containing `pyproject.toml`):

    python -m venv .venv
    source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
    pip install -e .
    sentry samples/sshd_config.bad

Complete instructions, including a Windows 11 section, are provided in the user
manual and the repository `README.md`.

## Team and Roles

| Name | Role |
|---|---|
| James Edsel Alvarez | Team lead & system architecture |
| Hans Gabriel Obcena | Rule engine & matcher design |
| Lorenzo Enrique Suerte | Configuration parsers (sshd / nginx / compose) |
| Jarick Klein Viray | Reporters (console / JSON / HTML) |
| Jeruel Fabricante | Testing, QA & documentation |

## Demonstration Video

The demonstration video is submitted separately (YouTube or MP4). `DEMO_SCRIPT.md`
contains the outline followed during recording.

## Ethical Use

This tool was developed for educational purposes only. It must only be used in
authorized and controlled testing environments. Unauthorized testing against
real systems, public websites, or third-party services is strictly prohibited.
