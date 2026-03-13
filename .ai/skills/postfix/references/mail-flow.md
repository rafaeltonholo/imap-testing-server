# Mail Flow

## SMTP → LMTP Delivery Path

```
Client (port 1025 or 587)
    │
    ▼
Postfix (SMTP)
    │  Accepts mail for @local.test
    │
    ▼
Dovecot LMTP (port 24)
    │  Delivers to user's Maildir
    │
    ▼
vmail/<email>/Maildir/new/
```

## Testing

```bash
# Send test mail via SMTP
swaks --to dev@local.test --from sender@local.test --server localhost:1025

# Or with Python
python3 -c "
import smtplib
from email.message import EmailMessage
msg = EmailMessage()
msg['From'] = 'test@local.test'
msg['To'] = 'dev@local.test'
msg['Subject'] = 'Test'
msg.set_content('Hello')
with smtplib.SMTP('localhost', 1025) as s:
    s.send_message(msg)
"
```
