"""
alerts.py
Sends notifications when the detector flags something. Two options are
provided — pick whichever is easier for your team to set up:

1. EMAIL (SMTP) — works with Gmail if you generate an "App Password"
2. DISCORD/SLACK WEBHOOK — usually faster to set up for a demo, no email
   credentials needed at all

Both are optional. If you don't configure either, alerts still get saved
to the database and show up on the dashboard — notifications are a bonus
layer on top, not a requirement for the core project to work.
"""

import json
import smtplib
import urllib.request
from email.mime.text import MIMEText

# ---- Fill these in when you're ready to enable notifications ----
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = ""          # e.g. "yourteam@gmail.com"
SMTP_APP_PASSWORD = ""      # Gmail "App Password", not your normal password
ALERT_RECIPIENT = ""        # where alerts get sent

DISCORD_WEBHOOK_URL = ""    # e.g. "https://discord.com/api/webhooks/..."


def send_email_alert(subject, message):
    if not (SMTP_USERNAME and SMTP_APP_PASSWORD and ALERT_RECIPIENT):
        print("[alerts] Email not configured — skipping email alert.")
        return

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = SMTP_USERNAME
    msg["To"] = ALERT_RECIPIENT

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_APP_PASSWORD)
            server.send_message(msg)
        print("[alerts] Email alert sent.")
    except Exception as e:
        print(f"[alerts] Failed to send email: {e}")


def send_discord_alert(message):
    if not DISCORD_WEBHOOK_URL:
        print("[alerts] Discord webhook not configured — skipping.")
        return

    payload = json.dumps({"content": f":rotating_light: {message}"}).encode("utf-8")
    req = urllib.request.Request(
        DISCORD_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        print("[alerts] Discord alert sent.")
    except Exception as e:
        print(f"[alerts] Failed to send Discord alert: {e}")


def dispatch(message, subject="Network Monitor Alert"):
    """Call this from your main loop whenever the detector triggers something."""
    print(f"[ALERT] {message}")
    send_email_alert(subject, message)
    send_discord_alert(message)
