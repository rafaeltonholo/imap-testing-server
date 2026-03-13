# Postfix Configuration

## Files

| File                   | Purpose                                      |
|------------------------|----------------------------------------------|
| `postfix/Dockerfile`   | Builds Postfix container from base image     |
| `postfix/main.cf`      | Main Postfix configuration                   |
| `postfix/entrypoint.sh`| Container entrypoint (copies config, starts) |

## Key Settings (main.cf)

- `myhostname`: Set for `local.test` domain
- `mydomain`: `local.test`
- `mydestination`: Accepts mail for `local.test`
- `mailbox_transport`: LMTP delivery to Dovecot (`lmtp:dovecot-dev:24`)
- `smtpd_recipient_restrictions`: Permits local network delivery

## Ports

- Host `1025` → Container `25` (SMTP)
- Host `587` → Container `587` (Submission)
