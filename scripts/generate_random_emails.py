#!/usr/bin/env python3
"""Generate random emails and inject them into a user's mailbox.

About 40% of injected emails are randomly picked from pre-built .eml files
in mails/. The rest are generated on the fly in one of five formats:
  plain      - simple plain-text message
  html       - HTML-only email with a styled layout and a table
  long       - long multi-paragraph plain-text email
  reply      - reply with a quoted previous message
  multipart  - multipart/alternative (plain + HTML parts)
"""

import argparse
import random
import shutil
import sys
import tempfile
from datetime import datetime
from email.utils import formatdate
from pathlib import Path

from lib import MAILS_DIR, DOCKER_CONTAINER, inject_mail

# ---------------------------------------------------------------------------
# Data pools
# ---------------------------------------------------------------------------

SENDERS = [
    "Alice Johnson <alice@example.com>",
    "Bob Smith <bob@company.org>",
    "No-Reply <no-reply@service.io>",
    "Newsletter Team <newsletter@updates.com>",
    "Support <support@help.dev>",
    "Dev Bot <devbot@ci.internal>",
    "Sarah Connor <sarah@resistance.net>",
    "Marketing <marketing@brandco.com>",
    "HR Department <hr@corp.example>",
]

SUBJECTS = [
    "Welcome to our platform",
    "Your invoice is ready",
    "Weekly developer digest",
    "Reset your password",
    "Security alert: new login detected",
    "Special 50% OFF promo - this weekend only",
    "Project meeting tomorrow at 10am",
    "Introducing our new product line",
    "Re: weekend plans",
    "Onboarding documents attached",
    "Action required: verify your email",
    "Your subscription renewal is due",
    "Reminder: outstanding approval request",
    "New comment on your post",
    "Your order has shipped!",
    "Critical: deployment failed on staging",
    "Invitation: team retrospective Friday",
    "Your free trial ends in 3 days",
    "Monthly activity summary",
    "Follow-up from our last meeting",
]

PLAIN_BODIES = [
    "Just a quick note to let you know everything is up and running. No action needed on your end.",
    "We noticed some activity on your account and wanted to follow up. Everything looks fine from our side.",
    "Please review the attached information at your earliest convenience and let us know if you have questions.",
    "This is an automated notification. If you did not request this, contact our support team immediately.",
    "Your request has been received and is being processed. You will hear back within 1-2 business days.",
    "A reminder that the deadline for submitting your response is this Friday at 5pm.",
    "Thanks for getting in touch! We have forwarded your message to the relevant team.",
]

# ---------------------------------------------------------------------------
# Email generators
# Each returns a complete RFC 2822 .eml string.
# ---------------------------------------------------------------------------

def _date_header() -> str:
    return formatdate(localtime=True)


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def generate_plain(sender: str, to: str, subject: str) -> str:
    body = random.choice(PLAIN_BODIES)
    return (
        f"From: {sender}\n"
        f"To: {to}\n"
        f"Subject: {subject}\n"
        f"Date: {_date_header()}\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=UTF-8\n"
        "\n"
        f"{body}\n"
        "\n"
        "Thanks,\n"
        "The Team\n"
        "\n"
        "---\n"
        'To unsubscribe, reply with "unsubscribe" in the subject line.\n'
    )


def generate_html(sender: str, to: str, subject: str) -> str:
    today = _today()
    return (
        f"From: {sender}\n"
        f"To: {to}\n"
        f"Subject: {subject}\n"
        f"Date: {_date_header()}\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/html; charset=UTF-8\n"
        "\n"
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head><meta charset=\"UTF-8\"><title>{subject}</title></head>\n"
        '<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;">\n'
        '<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">\n'
        '  <tr><td align="center">\n'
        '    <table width="600" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.1);">\n'
        f'      <tr><td style="background:#3b5998;padding:24px 32px;"><h1 style="margin:0;color:#fff;font-size:20px;">{subject}</h1></td></tr>\n'
        '      <tr><td style="padding:28px 32px;color:#333;font-size:15px;line-height:1.6;">\n'
        '        <p>Hello,</p>\n'
        '        <p>We have an important update for you. Please review the information below.</p>\n'
        '        <table width="100%" cellpadding="10" cellspacing="0" style="border-collapse:collapse;font-size:14px;margin-bottom:24px;">\n'
        '          <thead><tr style="background:#f0f0f0;">\n'
        '            <th align="left" style="border:1px solid #ddd;padding:10px;">Item</th>\n'
        '            <th align="left" style="border:1px solid #ddd;padding:10px;">Status</th>\n'
        '            <th align="right" style="border:1px solid #ddd;padding:10px;">Due date</th>\n'
        "          </tr></thead>\n"
        "          <tbody>\n"
        f'            <tr><td style="border:1px solid #ddd;">Account review</td><td style="border:1px solid #ddd;color:#27ae60;font-weight:bold;">Completed</td><td style="border:1px solid #ddd;" align="right">{today}</td></tr>\n'
        f'            <tr style="background:#fafafa;"><td style="border:1px solid #ddd;">Profile update</td><td style="border:1px solid #ddd;color:#e67e22;font-weight:bold;">Pending</td><td style="border:1px solid #ddd;" align="right">{today}</td></tr>\n'
        f'            <tr><td style="border:1px solid #ddd;">Security check</td><td style="border:1px solid #ddd;color:#e74c3c;font-weight:bold;">Overdue</td><td style="border:1px solid #ddd;" align="right">{today}</td></tr>\n'
        "          </tbody>\n"
        "        </table>\n"
        '        <p><a href="#" style="display:inline-block;background:#3b5998;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;font-size:14px;font-weight:bold;">View full details</a></p>\n'
        "      </td></tr>\n"
        '      <tr><td style="background:#f9f9f9;padding:16px 32px;border-top:1px solid #eee;">\n'
        '        <p style="margin:0;font-size:12px;color:#999;">You received this email because you are subscribed to account notifications. <a href="#" style="color:#3b5998;">Unsubscribe</a></p>\n'
        "      </td></tr>\n"
        "    </table>\n"
        "  </td></tr>\n"
        "</table>\n"
        "</body></html>\n"
    )


def generate_long(sender: str, to: str, subject: str) -> str:
    return (
        f"From: {sender}\n"
        f"To: {to}\n"
        f"Subject: {subject}\n"
        f"Date: {_date_header()}\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=UTF-8\n"
        "\n"
        "Hi there,\n"
        "\n"
        "I hope this message finds you well. I wanted to take a moment to write a\n"
        "thorough update on everything that has been happening over the past few weeks,\n"
        "since there is quite a lot to cover.\n"
        "\n"
        "First and foremost, the project we have been working on has reached a\n"
        "significant milestone. The development team has completed the core\n"
        "infrastructure work and we are now moving into the testing and validation\n"
        "phase.\n"
        "\n"
        "On the topic of infrastructure, we have made several important changes:\n"
        "\n"
        "1. Migrated the primary database to a new cluster with improved redundancy\n"
        "2. Updated all third-party dependencies to their latest stable versions\n"
        "3. Implemented a new monitoring dashboard with real-time performance insights\n"
        "4. Rolled out improved logging across all services to accelerate debugging\n"
        "5. Introduced automated nightly backups with off-site replication\n"
        "\n"
        "Additionally, we have been reviewing feedback from users and have identified\n"
        "a number of areas where the user experience could be improved. The design\n"
        "team has been working closely with engineering to prototype new workflows.\n"
        "\n"
        "Looking ahead to the next quarter, our priorities are:\n"
        "\n"
        "  - Complete the integration with the new payment provider\n"
        "  - Launch the redesigned onboarding flow for new users\n"
        "  - Begin migrating legacy services to the new platform\n"
        "  - Continue expanding test coverage across all critical paths\n"
        "\n"
        "I will be scheduling individual check-ins with each team lead over the next\n"
        "two weeks to review these priorities in detail.\n"
        "\n"
        "Best regards,\n"
        "The Management Team\n"
    )


def generate_reply(sender: str, to: str, subject: str) -> str:
    date = _date_header()
    return (
        f"From: {sender}\n"
        f"To: {to}\n"
        f"Subject: Re: {subject}\n"
        f"Date: {date}\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=UTF-8\n"
        "\n"
        "Thanks for the update - that all makes sense. I will follow up once I have\n"
        "had a chance to review the details. Should be by end of week.\n"
        "\n"
        f"On {date}, Someone Else <someone@example.com> wrote:\n"
        "> Hi,\n"
        ">\n"
        "> Just wanted to confirm we are still on track for the end-of-month deadline.\n"
        "> The last batch of changes has been merged and all automated tests are\n"
        "> passing in CI.\n"
        ">\n"
        "> Let me know if you need anything from my side before the release.\n"
        ">\n"
        "> Best,\n"
        "> Someone Else\n"
        "\n"
        "---\n"
        "Sent from mobile. Please excuse any brevity.\n"
    )


def generate_multipart(sender: str, to: str, subject: str) -> str:
    boundary = f"----=_Part_{random.randint(100000, 999999)}"
    return (
        f"From: {sender}\n"
        f"To: {to}\n"
        f"Subject: {subject}\n"
        f"Date: {_date_header()}\n"
        "MIME-Version: 1.0\n"
        f'Content-Type: multipart/alternative; boundary="{boundary}"\n'
        "\n"
        f"--{boundary}\n"
        "Content-Type: text/plain; charset=UTF-8\n"
        "Content-Transfer-Encoding: 7bit\n"
        "\n"
        "Hello,\n"
        "\n"
        "This is a multipart email. If your mail client supports HTML you will see a\n"
        "formatted version of this message.\n"
        "\n"
        "Key highlights:\n"
        "  * Feature A has been released and is available to all users\n"
        "  * Feature B is in beta - opt in from your account settings\n"
        "  * Feature C is scheduled for next quarter\n"
        "\n"
        "Thank you,\n"
        "The Team\n"
        "\n"
        f"--{boundary}\n"
        "Content-Type: text/html; charset=UTF-8\n"
        "Content-Transfer-Encoding: 7bit\n"
        "\n"
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        f"<head><meta charset=\"UTF-8\"><title>{subject}</title></head>\n"
        '<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#333;">\n'
        f'  <h2 style="color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:8px;">{subject}</h2>\n'
        "  <p>Hello,</p>\n"
        "  <p>This is a <strong>multipart email</strong>. Your client is rendering the <em>HTML part</em> correctly.</p>\n"
        '  <div style="margin:20px 0;padding:14px 18px;background:#eaf4fb;border-left:4px solid #3498db;border-radius:3px;">\n'
        "    <strong>Key highlights</strong>\n"
        '    <ul style="margin:8px 0 0;padding-left:20px;">\n'
        "      <li>Feature A has been released and is available to all users</li>\n"
        "      <li>Feature B is in beta - opt in from your account settings</li>\n"
        "      <li>Feature C is scheduled for next quarter</li>\n"
        "    </ul>\n"
        "  </div>\n"
        "  <p>Thank you,<br><strong>The Team</strong></p>\n"
        "</body></html>\n"
        "\n"
        f"--{boundary}--\n"
    )


GENERATORS = {
    "plain": generate_plain,
    "html": generate_html,
    "long": generate_long,
    "reply": generate_reply,
    "multipart": generate_multipart,
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate random emails and inject them into a mailbox.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s 50 dev@local.test           # 50 emails, 2.5s delay
  %(prog)s 50 dev@local.test --delay 0 # no delay (faster, may cause lock conflicts)
  %(prog)s                              # 100 emails to dev@local.test
""",
    )
    parser.add_argument("count", nargs="?", type=int, default=100, help="Number of emails (default: 100)")
    parser.add_argument("email", nargs="?", default="dev@local.test", help="Target email (default: dev@local.test)")
    parser.add_argument("--delay", type=float, default=2.5, help="Seconds between injections (default: 2.5)")
    args = parser.parse_args()

    # Collect pre-built .eml files (top-level mails/ only, not threads)
    prebuilt = sorted(MAILS_DIR.glob("*.eml"))

    tmp_dir = Path(tempfile.mkdtemp(prefix="gen-emails-"))

    print(f"Generating {args.count} emails for user: {args.email} (delay: {args.delay}s)")
    if prebuilt:
        print(f"  {len(prebuilt)} pre-built .eml files available (~40% chance each round)")
    print("-" * 40)

    try:
        for i in range(1, args.count + 1):
            # ~40%: inject a random pre-built .eml
            if prebuilt and random.random() < 0.4:
                src = random.choice(prebuilt)
                print(f"[{i}] Pre-built: {src.name} -> INBOX")
                inject_mail(args.email, src, "INBOX", args.delay)
                continue

            # Otherwise: generate a random email
            gen_name = random.choice(list(GENERATORS.keys()))
            subject = f"{random.choice(SUBJECTS)} #{i}"
            sender = random.choice(SENDERS)

            content = GENERATORS[gen_name](sender, args.email, subject)
            tmp_file = tmp_dir / f"{i:03d}-{gen_name}.eml"
            tmp_file.write_text(content)

            print(f"[{i}] Generated ({gen_name}): \"{subject}\" -> INBOX")
            inject_mail(args.email, tmp_file, "INBOX", args.delay)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print("-" * 40)
    print(f"Done. Injected {args.count} messages for {args.email}.")


if __name__ == "__main__":
    main()
