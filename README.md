# Sentry (Submission Package)

**Group:** Hood Security Department   

**Course:** NSSECU2 (S04)

Sentry is a static security config linter for `sshd_config`, `nginx`, and
`docker-compose` files. You point it at a config file and it tells you what's
insecure: bad settings, unsafe defaults, and missing hardening, each with a
severity and a suggested fix. It only reads text. It never connects to, scans,
or touches any live system.

## What's in here

| Folder / file | What it is |
|---|---|
| `1_Source_Code/sentry/` | The full source code. Its own `README.md` covers install, usage, sample output, limits, the ethical note, and what we built ourselves. |
| `2_User_Manual/` | The user manual (DOCX and PDF): install, usage, reading the results, troubleshooting, limits, and the ethical reminder. |
| `3_Presentation/` | The slide deck (PPTX). |

## How to run it

Open a terminal in `1_Source_Code/sentry` (the folder with `pyproject.toml`), then run:

    python -m venv .venv
    source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
    pip install -e .
    sentry samples/sshd_config.bad

Full steps, including the Windows 11 notes, are in the user manual and the source README.

## Team and roles

| Name | Role |
|---|---|
| James Edsel Alvarez | Team lead and system architecture |
| Hans Gabriel Obcena | Rule engine and matcher design |
| Lorenzo Enrique Suerte | Config parsers (sshd / nginx / compose) |
| Jarick Klein Viray | Reporters (console / JSON / HTML) |
| Jeruel Fabricante | Testing, QA, and documentation |

## Demo video

The demo video is submitted separately (YouTube or MP4).

## Ethical use

This tool was developed for educational purposes only. It must only be used in
authorized and controlled testing environments. Unauthorized testing against
real systems, public websites, or third-party services is strictly prohibited.
