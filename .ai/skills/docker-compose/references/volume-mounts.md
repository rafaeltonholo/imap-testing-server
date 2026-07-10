# Volume Mounts

## Dovecot

| Host Path   | Container Path          | Mode | Purpose                      |
|-------------|-------------------------|------|------------------------------|
| `./config`  | `/etc/dovecot/conf.d`   | ro   | Dovecot configuration files  |
| `./ssl`     | `/etc/dovecot/ssl`      | ro   | TLS certificates             |
| `./vmail`   | `/srv/vmail`            | rw   | Maildir storage              |
| `./logs`    | `/var/log/dovecot`      | rw   | Log files                    |

## Postfix

| Host Path | Container Path       | Mode | Purpose                    |
|-----------|----------------------|------|----------------------------|
| `./ssl`   | `/etc/postfix/ssl`   | ro   | SMTP TLS certificates      |

## Stalwart

| Host Path            | Container Path               | Mode | Purpose              |
|----------------------|------------------------------|------|----------------------|
| `./stalwart/config.toml` | `/opt/stalwart/etc/config.toml` | ro | Stalwart config   |
| `./stalwart-data`   | `/opt/stalwart/data`         | rw   | SQLite data storage  |

## Notes

- Read-only mounts require container restart to pick up changes.
- `vmail/` and `stalwart-data/` are gitignored runtime data.
- `ssl/` is gitignored; generate with `python3 scripts/setup.py`.
