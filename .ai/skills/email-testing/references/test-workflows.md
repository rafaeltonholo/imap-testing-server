# Test Workflows

## Single Message Injection

```bash
python3 scripts/send_message.py --email dev@local.test --message mails/16-test.eml
python3 scripts/send_message.py --email dev@local.test --message mails/foo.eml --folder INBOX.Sent
```

## Bulk Random Emails

```bash
# 50 emails with default 2.5s delay
python3 scripts/generate_random_emails.py 50 dev@local.test

# 50 emails with no delay (risk of lock conflicts)
python3 scripts/generate_random_emails.py 50 dev@local.test --delay 0
```

## Thread Generation and Injection

```bash
# Generate a thread
python3 scripts/generate_thread.py --name onboarding --count 8 \
  --from "Alice <alice@local.test>" --from "Bob <bob@local.test>" \
  --to carol@local.test

# Inject the thread
python3 scripts/send_thread.py --thread onboarding --email dev@local.test
```

## Full Account Setup

```bash
# Create user + seed all .eml files
python3 scripts/create_and_feed_account.py --email dev@local.test

# Create user without seeding
python3 scripts/create_and_feed_account.py --email dev@local.test --no-feed

# Seed only (user already exists)
python3 scripts/create_and_feed_account.py --email dev@local.test --only-feed
```

## Verification

```bash
# Check messages arrived
docker exec -it dovecot-dev doveadm fetch -u dev@local.test 'hdr.subject' mailbox INBOX

# List mailboxes
docker exec -it dovecot-dev doveadm mailbox list -u dev@local.test
```
