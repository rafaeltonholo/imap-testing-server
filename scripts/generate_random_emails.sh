#!/usr/bin/env bash
set -e

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

# Usage:
#   ./generate_random_emails.sh [count] [email] [delay]
# Examples:
#   ./generate_random_emails.sh              # 100 mails to dev@local.test, 2.5s delay
#   ./generate_random_emails.sh 50           # 50 mails
#   ./generate_random_emails.sh 25 alice@local.test
#   ./generate_random_emails.sh 25 alice@local.test 0   # no delay (faster, may cause lock conflicts)
#
# About 40% of injected emails are randomly picked from the pre-built .eml
# files in mails/. The rest are generated on the fly in one of five formats:
#   plain      — simple plain-text message
#   html       — HTML-only email with a styled layout and a table
#   long       — long multi-paragraph plain-text email
#   reply      — reply with a quoted previous message
#   multipart  — multipart/alternative (plain + HTML parts)

COUNT="${1:-100}"
EMAIL="${2:-dev@local.test}"
DELAY="${3:-2.5}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MAILS_DIR="$ROOT/mails"
TEMPDIR="$ROOT/mails/temp"
mkdir -p "$TEMPDIR"

# ---------------------------------------------------------------------------
# Data pools — picked at random when generating emails
# ---------------------------------------------------------------------------

SENDERS=(
  "Alice Johnson <alice@example.com>"
  "Bob Smith <bob@company.org>"
  "No-Reply <no-reply@service.io>"
  "Newsletter Team <newsletter@updates.com>"
  "Support <support@help.dev>"
  "Dev Bot <devbot@ci.internal>"
  "Sarah Connor <sarah@resistance.net>"
  "Marketing <marketing@brandco.com>"
  "HR Department <hr@corp.example>"
)

SUBJECTS=(
  "Welcome to our platform"
  "Your invoice is ready"
  "Weekly developer digest"
  "Reset your password"
  "Security alert: new login detected"
  "Special 50% OFF promo — this weekend only"
  "Project meeting tomorrow at 10am"
  "Introducing our new product line"
  "Re: weekend plans"
  "Onboarding documents attached"
  "Action required: verify your email"
  "Your subscription renewal is due"
  "Reminder: outstanding approval request"
  "New comment on your post"
  "Your order has shipped!"
  "Critical: deployment failed on staging"
  "Invitation: team retrospective Friday"
  "Your free trial ends in 3 days"
  "Monthly activity summary"
  "Follow-up from our last meeting"
)

# ---------------------------------------------------------------------------
# Email type generators
# Each function writes a complete RFC 2822 .eml to the path in $1.
# ---------------------------------------------------------------------------

# Plain-text email — short, no formatting
generate_plain_email() {
  local file="$1" from="$2" to="$3" subject="$4"

  local BODIES=(
    "Just a quick note to let you know everything is up and running. No action needed on your end."
    "We noticed some activity on your account and wanted to follow up. Everything looks fine from our side."
    "Please review the attached information at your earliest convenience and let us know if you have questions."
    "This is an automated notification. If you did not request this, contact our support team immediately."
    "Your request has been received and is being processed. You will hear back within 1–2 business days."
    "A reminder that the deadline for submitting your response is this Friday at 5pm."
    "Thanks for getting in touch! We have forwarded your message to the relevant team."
  )
  local body="${BODIES[$((RANDOM % ${#BODIES[@]}))]}"

  cat > "$file" <<EOF
From: $from
To: $to
Subject: $subject
Date: $(date -R)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

$body

Thanks,
The Team

---
To unsubscribe, reply with "unsubscribe" in the subject line.
EOF
}

# HTML-only email with a header banner, a data table, and a CTA button
generate_html_email() {
  local file="$1" from="$2" to="$3" subject="$4"

  cat > "$file" <<EOF
From: $from
To: $to
Subject: $subject
Date: $(date -R)
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>$subject</title>
</head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:6px;overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.1);">

        <!-- Header -->
        <tr>
          <td style="background:#3b5998;padding:24px 32px;">
            <h1 style="margin:0;color:#ffffff;font-size:20px;font-weight:bold;">$subject</h1>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:28px 32px;color:#333333;font-size:15px;line-height:1.6;">
            <p style="margin:0 0 16px;">Hello,</p>
            <p style="margin:0 0 20px;">
              We have an important update for you. Please review the information below carefully
              and take any required action before the deadline shown in the table.
            </p>

            <!-- Data table -->
            <table width="100%" cellpadding="10" cellspacing="0"
                   style="border-collapse:collapse;font-size:14px;margin-bottom:24px;">
              <thead>
                <tr style="background:#f0f0f0;">
                  <th align="left"  style="border:1px solid #ddd;padding:10px;">Item</th>
                  <th align="left"  style="border:1px solid #ddd;padding:10px;">Status</th>
                  <th align="right" style="border:1px solid #ddd;padding:10px;">Due date</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style="border:1px solid #ddd;">Account review</td>
                  <td style="border:1px solid #ddd;color:#27ae60;font-weight:bold;">Completed</td>
                  <td style="border:1px solid #ddd;" align="right">$(date +%Y-%m-%d)</td>
                </tr>
                <tr style="background:#fafafa;">
                  <td style="border:1px solid #ddd;">Profile update</td>
                  <td style="border:1px solid #ddd;color:#e67e22;font-weight:bold;">Pending</td>
                  <td style="border:1px solid #ddd;" align="right">$(date -v+7d +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)</td>
                </tr>
                <tr>
                  <td style="border:1px solid #ddd;">Security check</td>
                  <td style="border:1px solid #ddd;color:#e74c3c;font-weight:bold;">Overdue</td>
                  <td style="border:1px solid #ddd;" align="right">$(date +%Y-%m-%d)</td>
                </tr>
              </tbody>
            </table>

            <!-- CTA button -->
            <p style="margin:0 0 8px;">
              <a href="#"
                 style="display:inline-block;background:#3b5998;color:#ffffff;padding:12px 24px;
                        text-decoration:none;border-radius:4px;font-size:14px;font-weight:bold;">
                View full details
              </a>
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f9f9f9;padding:16px 32px;border-top:1px solid #eeeeee;">
            <p style="margin:0;font-size:12px;color:#999999;">
              You received this email because you are subscribed to account notifications.
              <a href="#" style="color:#3b5998;">Unsubscribe</a>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
EOF
}

# Long plain-text email — several paragraphs, numbered list, closing
generate_long_email() {
  local file="$1" from="$2" to="$3" subject="$4"

  cat > "$file" <<EOF
From: $from
To: $to
Subject: $subject
Date: $(date -R)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hi there,

I hope this message finds you well. I wanted to take a moment to write a
thorough update on everything that has been happening over the past few weeks,
since there is quite a lot to cover.

First and foremost, the project we have been working on has reached a
significant milestone. The development team has completed the core
infrastructure work and we are now moving into the testing and validation
phase. This is a major step forward and would not have been possible without
the hard work and dedication of everyone involved.

On the topic of infrastructure, we have made several important changes:

1. Migrated the primary database to a new cluster with improved redundancy
2. Updated all third-party dependencies to their latest stable versions
3. Implemented a new monitoring dashboard with real-time performance insights
4. Rolled out improved logging across all services to accelerate debugging
5. Introduced automated nightly backups with off-site replication

Additionally, we have been reviewing feedback from users and have identified
a number of areas where the user experience could be improved. The design
team has been working closely with engineering to prototype new workflows,
and early testing has been very positive.

Looking ahead to the next quarter, our priorities are:

  - Complete the integration with the new payment provider
  - Launch the redesigned onboarding flow for new users
  - Begin migrating legacy services to the new platform
  - Continue expanding test coverage across all critical paths

I will be scheduling individual check-ins with each team lead over the next
two weeks to review these priorities in detail. Please feel free to reach out
if you have any questions or concerns before then.

Finally, I want to take a moment to thank everyone for their continued
patience and hard work during this transition period. It is not easy to
maintain high-quality output while adapting to new tools and processes, and
the team has handled it remarkably well.

Looking forward to seeing everything come together in the weeks ahead.

Best regards,
The Management Team

---
This email was sent to you as part of your subscription to internal
communications. To update your preferences, visit your account settings.
EOF
}

# Reply-style email — short response with a quoted original message below
generate_reply_thread() {
  local file="$1" from="$2" to="$3" subject="$4"

  # Use the original subject without a "Re:" prefix (we add it in the header)
  cat > "$file" <<EOF
From: $from
To: $to
Subject: Re: $subject
Date: $(date -R)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Thanks for the update — that all makes sense. I will follow up once I have
had a chance to review the details. Should be by end of week.

On $(date -R), Someone Else <someone@example.com> wrote:
> Hi,
>
> Just wanted to confirm we are still on track for the end-of-month deadline.
> The last batch of changes has been merged and all automated tests are
> passing in CI.
>
> Let me know if you need anything from my side before the release.
>
> Best,
> Someone Else

---
Sent from mobile. Please excuse any brevity.
EOF
}

# Multipart/alternative email — both a plain-text and an HTML part
# Mail clients that support HTML will show the HTML version; others fall back to plain text.
generate_multipart_email() {
  local file="$1" from="$2" to="$3" subject="$4"
  # A MIME boundary is a unique string that separates the parts inside the email body
  local boundary="----=_Part_$(date +%s)_${RANDOM}${RANDOM}"

  cat > "$file" <<EOF
From: $from
To: $to
Subject: $subject
Date: $(date -R)
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="$boundary"

--$boundary
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

Hello,

This is a multipart email. If your mail client supports HTML you will see a
formatted version of this message. Otherwise this plain-text fallback is
shown instead.

Key highlights:
  * Feature A has been released and is available to all users
  * Feature B is in beta — opt in from your account settings
  * Feature C is scheduled for next quarter

Thank you,
The Team

--$boundary
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>$subject</title></head>
<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#333;">
  <h2 style="color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:8px;">$subject</h2>
  <p>Hello,</p>
  <p>
    This is a <strong>multipart email</strong>. Your client is rendering
    the <em>HTML part</em> correctly.
  </p>

  <!-- Highlighted callout block -->
  <div style="margin:20px 0;padding:14px 18px;background:#eaf4fb;border-left:4px solid #3498db;border-radius:3px;">
    <strong>Key highlights</strong>
    <ul style="margin:8px 0 0;padding-left:20px;">
      <li>Feature A has been released and is available to all users</li>
      <li>Feature B is in beta — opt in from your account settings</li>
      <li>Feature C is scheduled for next quarter</li>
    </ul>
  </div>

  <p>Thank you,<br><strong>The Team</strong></p>
  <hr style="border:none;border-top:1px solid #eee;margin-top:32px;">
  <p style="font-size:12px;color:#999;">
    You received this because you are subscribed to product updates.
  </p>
</body>
</html>

--$boundary--
EOF
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

# Collect all pre-built .eml files from mails/ (one level deep, no subdirs)
PREBUILT_EMLS=()
while IFS= read -r -d '' f; do
  PREBUILT_EMLS+=("$f")
done < <(find "$MAILS_DIR" -maxdepth 1 -name "*.eml" -print0 2>/dev/null)

GENERATORS=(plain html long reply multipart)

echo "Generating $COUNT emails for user: $EMAIL (delay: ${DELAY}s)"
[[ ${#PREBUILT_EMLS[@]} -gt 0 ]] && \
  echo "  ${#PREBUILT_EMLS[@]} pre-built .eml files available for random injection (~40% chance each round)"
echo "----------------------------------------"

for i in $(seq 1 "$COUNT"); do
  mailbox="INBOX"

  # ~40% of the time: inject a randomly chosen pre-built .eml from mails/
  # This gives the inbox a realistic mix of real templates alongside generated ones.
  if [[ ${#PREBUILT_EMLS[@]} -gt 0 && $((RANDOM % 10)) -lt 4 ]]; then
    src="${PREBUILT_EMLS[$((RANDOM % ${#PREBUILT_EMLS[@]}))]}"
    echo "[$i] Pre-built: $(basename "$src") -> $mailbox"
    inject_mail "$EMAIL" "$src" "$mailbox" "$DELAY"
    continue
  fi

  # Otherwise: pick a random generator and compose a new email on the fly
  gen_type="${GENERATORS[$((RANDOM % ${#GENERATORS[@]}))]}"
  subject="${SUBJECTS[$((RANDOM % ${#SUBJECTS[@]}))]}"
  from="${SENDERS[$((RANDOM % ${#SENDERS[@]}))]}"
  tmpfile="$TEMPDIR/$(printf "%03d-%s.eml" "$i" "$gen_type")"

  case "$gen_type" in
    plain)     generate_plain_email     "$tmpfile" "$from" "$EMAIL" "$subject #$i" ;;
    html)      generate_html_email      "$tmpfile" "$from" "$EMAIL" "$subject #$i" ;;
    long)      generate_long_email      "$tmpfile" "$from" "$EMAIL" "$subject #$i" ;;
    reply)     generate_reply_thread    "$tmpfile" "$from" "$EMAIL" "$subject #$i" ;;
    multipart) generate_multipart_email "$tmpfile" "$from" "$EMAIL" "$subject #$i" ;;
  esac

  echo "[$i] Generated ($gen_type): \"$subject #$i\" -> $mailbox"
  inject_mail "$EMAIL" "$tmpfile" "$mailbox" "$DELAY"
done

# Clean up any temp files we generated
rm -rf "$TEMPDIR"

echo "----------------------------------------"
echo "Done. Injected $COUNT messages for $EMAIL."
