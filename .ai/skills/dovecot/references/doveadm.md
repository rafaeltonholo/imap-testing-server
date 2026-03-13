# Doveadm Commands

Common `doveadm` commands used in this project (run via `docker exec`):

## Mail Operations

```bash
# Save an .eml file to a user's mailbox
docker exec -i dovecot-dev doveadm save -u dev@local.test -m INBOX < file.eml

# Fetch subject lines from INBOX
docker exec -it dovecot-dev doveadm fetch -u dev@local.test 'hdr.subject' mailbox INBOX

# List mailboxes
docker exec -it dovecot-dev doveadm mailbox list -u dev@local.test

# Create a mailbox
docker exec -it dovecot-dev doveadm mailbox create -u dev@local.test INBOX.Archive

# Force mailbox subscription
docker exec -it dovecot-dev doveadm mailbox subscribe -u dev@local.test INBOX.Archive
```

## User/Session Operations

```bash
# List active connections
docker exec -it dovecot-dev doveadm who

# Kick a user's sessions
docker exec -it dovecot-dev doveadm kick dev@local.test
```

## Debugging

```bash
# Check auth
docker exec -it dovecot-dev doveadm auth test dev@local.test dev

# View full logs
docker compose logs -f dovecot
```
