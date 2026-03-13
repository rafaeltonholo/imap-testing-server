# scripts/lib.py API

Shared utilities used by all Python scripts.

## Functions

| Function                           | Purpose                                                |
|------------------------------------|--------------------------------------------------------|
| `inject_mail(email, file_path, mailbox, delay)` | Copy .eml into container, save via `doveadm save` |
| `create_mailbox(email, folder)`    | Create a mailbox folder via `doveadm mailbox create`  |
| `docker_exec(cmd)`                 | Run a command inside the Dovecot container             |
| `docker_cp(src, dest)`             | Copy a file into the Dovecot container                 |
| `display_name(addr)`               | Extract display name from an email address             |
| `make_slug(text)`                  | Generate a filesystem-safe slug from text              |
| `parse_date_arg(date_str)`         | Parse a date string into a datetime object             |
| `epoch_to_rfc2822(epoch)`          | Convert Unix epoch to RFC 2822 date string             |

## Constants

| Constant        | Value                           |
|-----------------|---------------------------------|
| `ROOT_DIR`      | Project root directory          |
| `MAILS_DIR`     | `<root>/mails/`                 |
| `THREADS_DIR`   | `<root>/mails/threads/`         |
| `VMAIL_DIR`     | `<root>/vmail/`                 |
| `CONFIG_DIR`    | `<root>/config/`                |
| `USERS_FILE`    | `<root>/config/users`           |
| `CONTAINER_NAME`| `dovecot-dev`                   |

## Usage Pattern

```python
from lib import inject_mail, create_mailbox, docker_exec, ROOT_DIR
```
