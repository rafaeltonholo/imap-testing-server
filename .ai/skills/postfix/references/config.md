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
- `smtpd_relay_restrictions`: Permits local-domain delivery and rejects external relay
- `smtpd_tls_security_level`: Advertises STARTTLS with the dev certificate

## Ports

- Host `1025` → Container `25` (SMTP)
- Host `465` → Container `465` (SMTPS)
- Host `587` → Container `587` (Submission)
