#!/usr/bin/env python3
"""Generate a random email thread and save it under mails/threads/<name>/."""

import argparse
import html
import random
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from email.utils import formatdate, parseaddr
from pathlib import Path

THREADS_DIR = Path(__file__).resolve().parent.parent / "mails" / "threads"

# ---------------------------------------------------------------------------
# Data pools for random content generation
# ---------------------------------------------------------------------------

SUBJECTS = [
    "Quarterly planning sync",
    "Build failures on staging",
    "New onboarding flow feedback",
    "Database migration timeline",
    "Customer escalation - account #4827",
    "Design review: dashboard redesign",
    "Deployment checklist for Friday",
    "Vendor contract renewal discussion",
    "Incident postmortem - March outage",
    "Feature flag rollout strategy",
    "CI/CD pipeline improvements",
    "Security audit findings",
    "API rate limiting proposal",
    "Mobile app release blockers",
    "Infrastructure cost optimization",
]

# Each entry is a short paragraph. Emails combine 1-3 of these.
BODY_BLOCKS = [
    "I took a look at this earlier today and I think we're on the right track. A few things stood out that we should probably address before moving forward, but nothing that would block us.",
    "Just wanted to flag that I noticed some inconsistencies in the latest data export. It might be related to the timezone handling changes we merged last week. I'll dig into it more tomorrow.",
    "I spoke with the team on the other side and they're aligned with the proposed approach. They asked if we could share a brief summary doc so they can loop in their stakeholders.",
    "Quick update: the CI pipeline is green again after the config fix. I also bumped the timeout on the integration tests since they were flaking under load.",
    "One thing to consider - we should probably run this by legal before making it public. I don't think there's an issue, but better to check early than scramble later.",
    "I've been looking at the metrics from last week and the numbers are trending in the right direction. Conversion is up about 12% and bounce rate dropped noticeably after the last deploy.",
    "Can someone take a look at the staging environment? I'm seeing some weird behavior with the cache layer - responses are stale even after invalidation. Might be a TTL misconfiguration.",
    "Attached is the updated spec with the changes we discussed yesterday. Main differences are in sections 3 and 5. Let me know if anything looks off.",
    "I think we should schedule a quick sync to align on priorities for next sprint. Too many things are being pulled in different directions and it's starting to affect velocity.",
    "Heads up: the vendor pushed back on the timeline we proposed. They're saying 6 weeks minimum for the integration. I'm going to try to negotiate but we should have a Plan B.",
    "Reviewed the PR and left a few comments. Mostly minor - naming conventions and a potential edge case in the error handling path. Overall looks solid though.",
    "The staging deployment went smoothly. I've been poking around for the last hour and haven't found any regressions. I think we're good to ship this to production.",
    "Just a reminder that the deadline for feedback on the RFC is this Friday. If you haven't had a chance to review it yet, please try to do so before then.",
    "I ran the benchmarks on the new implementation and results are promising. Throughput is up ~25% and memory usage is roughly flat. Full report is in the shared drive.",
    "Worth noting that the API change we're discussing would be a breaking change for at least two downstream consumers. We should coordinate with those teams before shipping.",
    "Looping back on the action items from last week: items 1 and 3 are done, item 2 is in progress and should land by Wednesday. Item 4 is blocked on the external dependency.",
    "I paired with the DevOps team this morning and we identified the root cause. It was a misconfigured environment variable in the staging cluster. Fix is deployed and verified.",
    "FYI - the design team shared updated mocks in Figma. The new flow looks much cleaner. I left some comments on the edge cases we discussed.",
]

SIGNOFFS = [
    "Thanks,",
    "Best,",
    "Cheers,",
    "Regards,",
    "Talk soon,",
    "Let me know what you think.",
    "Looking forward to your thoughts.",
]


def display_name(addr: str) -> str:
    """Extract the display name from an address, falling back to the local part."""
    name, email = parseaddr(addr)
    if name:
        return name
    # "alice@local.test" -> "alice"
    return email.split("@")[0].capitalize()


def make_slug(text: str, max_len: int = 30) -> str:
    """Turn the first few words of text into a filename-safe slug."""
    words = re.sub(r"[^a-z0-9 ]", "", text.lower()).split()[:4]
    return "-".join(words)[:max_len]


def random_body() -> str:
    """Build a random plain-text body from 1-3 paragraphs."""
    blocks = random.sample(BODY_BLOCKS, k=random.randint(1, 3))
    return "\n\n".join(blocks)


def build_html(body: str, signoff: str, sender_name: str) -> str:
    """Convert plain text body into a simple HTML version."""
    paragraphs = [p.strip() for p in body.split("\n\n") if p.strip()]
    p_tags = "\n".join(f"  <p>{html.escape(p)}</p>" for p in paragraphs)
    return (
        '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;'
        'line-height:1.6;color:#222;">\n'
        f"{p_tags}\n"
        f"  <p>{html.escape(signoff)}<br>{html.escape(sender_name)}</p>\n"
        "</div>"
    )


def build_eml(
    *,
    msg_date: datetime,
    sender: str,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    message_id: str,
    in_reply_to: str | None,
    references: list[str],
    body: str,
    signoff: str,
    sender_name: str,
) -> str:
    """Assemble a complete multipart/alternative .eml string."""
    boundary = f"----=_GenThread_{random.randint(100000, 999999)}"
    date_str = formatdate(msg_date.timestamp(), localtime=True)

    lines = [
        "MIME-Version: 1.0",
        f"Date: {date_str}",
        f"From: {sender}",
        f"To: {', '.join(to)}",
    ]
    if cc:
        lines.append(f"Cc: {', '.join(cc)}")
    if bcc:
        lines.append(f"Bcc: {', '.join(bcc)}")
    lines += [
        f"Subject: {subject}",
        f"Message-ID: {message_id}",
    ]
    if in_reply_to:
        lines.append(f"In-Reply-To: {in_reply_to}")
    if references:
        lines.append(f"References: {' '.join(references)}")
    lines += [
        "Content-Language: en-US",
        "X-Mailer: Thread Generator",
        f'Content-Type: multipart/alternative; boundary="{boundary}"',
        "",
        f"--{boundary}",
        "Content-Type: text/plain; charset=UTF-8",
        "Content-Transfer-Encoding: 7bit",
        "",
        body,
        "",
        signoff,
        sender_name,
        "",
        f"--{boundary}",
        "Content-Type: text/html; charset=UTF-8",
        "Content-Transfer-Encoding: 7bit",
        "",
        build_html(body, signoff, sender_name),
        "",
        f"--{boundary}--",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a random email thread under mails/threads/<name>/.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s --name onboarding --count 8 \\
    --from "Alice <alice@local.test>" --from "Bob <bob@local.test>" \\
    --to carol@local.test --cc dave@local.test

  %(prog)s --name quick-chat --count 5 \\
    --from dev@local.test --from qa@local.test \\
    --to dev@local.test --subject "Build failures on staging"
""",
    )
    parser.add_argument("--name", required=True, help="Thread folder name")
    parser.add_argument("--count", required=True, type=int, help="Number of emails")
    parser.add_argument("--from", dest="senders", action="append", required=True,
                        metavar="ADDR", help="Sender (repeatable)")
    parser.add_argument("--to", dest="recipients", action="append", required=True,
                        metavar="ADDR", help="Recipient (repeatable)")
    parser.add_argument("--cc", action="append", default=[], metavar="ADDR",
                        help="CC (repeatable)")
    parser.add_argument("--bcc", action="append", default=[], metavar="ADDR",
                        help="BCC (repeatable)")
    parser.add_argument("--subject", default=None, help="Thread subject (default: random)")

    args = parser.parse_args()

    thread_dir = THREADS_DIR / args.name
    if thread_dir.exists():
        print(f"Error: thread directory already exists: {thread_dir}", file=sys.stderr)
        print("Delete it first or choose a different --name.", file=sys.stderr)
        sys.exit(2)

    thread_dir.mkdir(parents=True)

    subject = args.subject or random.choice(SUBJECTS)
    # Unique prefix so Message-IDs don't collide across runs
    thread_id = f"gen-{int(time.time())}-{random.randint(1000, 9999)}"

    print(f"Generating thread '{args.name}' ({args.count} emails) ...")
    print(f"  Subject: {subject}")
    print(f"  From:    {', '.join(args.senders)}")
    print(f"  To:      {', '.join(args.recipients)}")
    if args.cc:
        print(f"  Cc:      {', '.join(args.cc)}")
    if args.bcc:
        print(f"  Bcc:     {', '.join(args.bcc)}")
    print()

    references: list[str] = []
    # Start from "now" and space each message 30-180 minutes apart
    msg_time = datetime.now(tz=timezone(timedelta(hours=-3)))

    for i in range(1, args.count + 1):
        # Round-robin through senders
        sender = args.senders[(i - 1) % len(args.senders)]
        sender_name = display_name(sender)

        msg_id = f"<{thread_id}-{i}@local.test>"
        msg_subject = subject if i == 1 else f"Re: {subject}"

        body = random_body()
        signoff = random.choice(SIGNOFFS)

        eml = build_eml(
            msg_date=msg_time,
            sender=sender,
            to=args.recipients,
            cc=args.cc,
            bcc=args.bcc,
            subject=msg_subject,
            message_id=msg_id,
            in_reply_to=references[-1] if references else None,
            references=list(references),
            body=body,
            signoff=signoff,
            sender_name=sender_name,
        )

        slug = make_slug(body)
        filename = f"{i:02d}_{slug}.eml"
        filepath = thread_dir / filename
        filepath.write_text(eml)

        print(f"  [{i}/{args.count}] {filename} ({sender_name})")

        references.append(msg_id)
        # Space messages 30-180 minutes apart
        msg_time += timedelta(minutes=random.randint(30, 180))

    print()
    print(f"Done! Generated {args.count} emails in: {thread_dir}")
    print()
    print("Send the thread with:")
    print(f"  ./scripts/send_thread.sh --thread {args.name} --email <TARGET_EMAIL>")


if __name__ == "__main__":
    main()
