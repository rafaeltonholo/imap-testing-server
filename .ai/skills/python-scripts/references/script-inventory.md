# Script Inventory

All scripts are in `scripts/` and use Python 3 stdlib only.

| Script                        | Purpose                                              |
|-------------------------------|------------------------------------------------------|
| `setup.py`                    | Generate self-signed SSL certificates                |
| `create_and_feed_account.py`  | Create user in passwd-file and seed inbox with .eml files |
| `send_message.py`             | Inject a specific .eml file into a user's mailbox    |
| `create_folder.py`            | Create a mailbox folder for a user                   |
| `generate_random_emails.py`   | Generate and inject random test emails               |
| `generate_thread.py`          | Generate a random email thread (saved to mails/threads/) |
| `send_thread.py`              | Send a pre-built thread into a user's mailbox        |
| `sync_stalwart_users.py`      | Sync users from config/users into Stalwart via admin API |
| `reset.py`                    | Wipe vmail/, stalwart-data/, and restore defaults    |
| `lib.py`                      | Shared utilities (not a standalone script)            |
