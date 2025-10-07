#!/usr/bin/env bash
set -e

# ----------------------------------------
# Usage:
#   ./generate-mails.sh [count] [email]
# Example:
#   ./generate-mails.sh          # 100 mails for dev@local.test
#   ./generate-mails.sh 50       # 50 mails for dev@local.test
#   ./generate-mails.sh 25 alice@local.test
# ----------------------------------------

COUNT="${1:-100}"
EMAIL="${2:-dev@local.test}"

MAILDIR="./mails/temp"
mkdir -p "$MAILDIR"

# Subjects, bodies, and target mailboxes
SUBJECTS=(
  "Welcome to our platform"
  "Your invoice is ready"
  "Weekly developer digest"
  "Reset your password"
  "Security alert detected"
  "Special 50% OFF promo"
  "Project meeting tomorrow"
  "Introducing our new product"
  "Re: weekend plans"
  "Onboarding documents"
)
BODIES=(
  "Hello there,\n\nThis is a randomly generated test email."
  "Hi,\n\nYour account is now active. Enjoy testing Dovecot!"
  "Important update:\n- Feature A improved\n- Bug B fixed"
  "This is a friendly reminder to check your inbox regularly."
  "Security notice: new login detected from a different device."
  "Biggest sale of the year! Use code SALE50 at checkout."
  "Your subscription will expire in 3 days. Renew today!"
  "Your payment was processed successfully. Thanks for using us!"
  "Here's your monthly activity summary. Everything looks great."
  "Please review and approve the attached document."
)
#MAILBOXES=(INBOX INBOX.Sent INBOX.Drafts INBOX.Trash)
MAILBOXES=(INBOX)

echo "📧 Generating $COUNT emails for user: $EMAIL"
echo "----------------------------------------"

for i in $(seq 1 "$COUNT"); do
  subject=${SUBJECTS[$((RANDOM % ${#SUBJECTS[@]}))]}
  body=${BODIES[$((RANDOM % ${#BODIES[@]}))]}
  mailbox=${MAILBOXES[$((RANDOM % ${#MAILBOXES[@]}))]}
  filename=$(printf "%03d-mail.eml" "$i")

  cat > "$MAILDIR/$filename" <<EOF
From: No-Reply <no-reply@example.com>
To: $EMAIL
Subject: $subject #$i
Date: $(date -R)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

$body

--
This is a generated test message ($i).
EOF

  docker cp "$MAILDIR/$filename" dovecot-dev:/tmp/$filename
  docker exec dovecot-dev doveadm save -u "$EMAIL" -m "$mailbox" "/tmp/$filename" >/dev/null 2>&1

  echo "[$i] Added \"$subject #$i\" → $mailbox"
done

rm -r $MAILDIR

echo "----------------------------------------"
echo "✅ Successfully generated and added $COUNT messages for $EMAIL"
