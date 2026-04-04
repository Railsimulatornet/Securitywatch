#!/usr/bin/env python3
# Copyright Roman Glos 2026
import argparse
import json
import shlex
import smtplib
from email.message import EmailMessage
from pathlib import Path


def parse_env(path: Path) -> dict:
    data = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not value:
            data[key] = ""
            continue

        try:
            parsed = shlex.split(value, comments=False, posix=True)
            if len(parsed) == 1:
                data[key] = parsed[0]
            else:
                data[key] = value
        except ValueError:
            data[key] = value

    return data


def to_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_lang(value: str) -> str:
    lang = (value or "de").strip().lower()
    return lang if lang in {"de", "en"} else "de"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--mail-txt", required=True)
    parser.add_argument("--mail-html", required=True)
    args = parser.parse_args()

    env = parse_env(Path(args.env_file))
    summary = json.loads(Path(args.summary_json).read_text(encoding="utf-8"))
    total = int(summary.get("total", 0))
    critical = int(summary.get("critical", 0))
    high = int(summary.get("high", 0))
    lang = normalize_lang(env.get("OUTPUT_LANG") or env.get("LANGUAGE") or summary.get("language") or "de")

    only_on_findings = to_bool(env.get("MAIL_ONLY_ON_FINDINGS", "1"), True)
    send_ok = to_bool(env.get("MAIL_SEND_OK", "0"), False)

    required_fields = ["SMTP_SERVER", "SMTP_FROM", "SMTP_TO"]
    missing_fields = [field for field in required_fields if not (env.get(field) or "").strip()]
    if missing_fields:
        missing_text = ", ".join(missing_fields)
        if lang == "en":
            raise SystemExit(f"Missing required SMTP settings in .env: {missing_text}")
        raise SystemExit(f"Fehlende SMTP-Pflichtwerte in der .env: {missing_text}")

    if total == 0 and only_on_findings and not send_ok:
        if lang == "en":
            print("No findings and MAIL_ONLY_ON_FINDINGS is enabled. No email will be sent.")
        else:
            print("Keine Treffer und MAIL_ONLY_ON_FINDINGS aktiv. Keine Mail wird versendet.")
        return

    subject_prefix = env.get("MAIL_SUBJECT_PREFIX", "[UGREEN SecurityWatch]")
    if total == 0:
        subject = (
            f"{subject_prefix} No High/Critical findings"
            if lang == "en"
            else f"{subject_prefix} Keine High/Critical-Funde"
        )
    else:
        subject = f"{subject_prefix} {critical} Critical, {high} High"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = env["SMTP_FROM"]
    msg["To"] = env["SMTP_TO"]
    msg.set_content(Path(args.mail_txt).read_text(encoding="utf-8"))
    msg.add_alternative(Path(args.mail_html).read_text(encoding="utf-8"), subtype="html")

    user = env.get("SMTP_USER", "")
    password = env.get("SMTP_PASS", "")

    if not password:
        pass_file = env.get("SMTP_PASS_FILE", "")
        if pass_file:
            pass_path = Path(pass_file)
            if not pass_path.exists():
                if lang == "en":
                    raise SystemExit(f"SMTP password file not found: {pass_file}")
                raise SystemExit(f"SMTP-Passwortdatei nicht gefunden: {pass_file}")
            password = pass_path.read_text(encoding="utf-8").strip()

    server = env["SMTP_SERVER"]
    port = int(env.get("SMTP_PORT", "587"))
    starttls = to_bool(env.get("SMTP_STARTTLS", "1"), True)

    with smtplib.SMTP(server, port, timeout=30) as smtp:
        smtp.ehlo()
        if starttls:
            smtp.starttls()
            smtp.ehlo()
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)

    if lang == "en":
        print("Email sent successfully.")
    else:
        print("Mail erfolgreich versendet.")


if __name__ == "__main__":
    main()
