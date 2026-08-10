# Script Inventory

All scripts are in `scripts/`. They use Python 3 stdlib only unless the table
explicitly identifies an optional dependency.

| Script                         | Purpose |
|--------------------------------|---------|
| `setup.py`                     | Generate self-signed SSL certificates |
| `create_and_feed_account.py`   | Create a user in the passwd-file and seed the inbox with `.eml` files |
| `send_message.py`              | Inject a specific `.eml` file into a user's mailbox |
| `create_folder.py`             | Create a mailbox folder for a user |
| `generate_random_emails.py`    | Generate and inject random test emails |
| `generate_thread.py`           | Generate a random email thread under `mails/threads/` |
| `send_thread.py`               | Send a pre-built thread into a user's mailbox |
| `users_file.py`                | Bootstrap, reset, mutate, and verify the canonical Dovecot passwd-file authority |
| `capture_stalwart_v015.py`     | Capture and verify the stopped v0.15 store and prove isolated rollback |
| `stalwart_v016.py`             | Plan, apply, retire, and inspect the fail-closed v0.16 migration |
| `bootstrap_stalwart_v016.py`   | Validate fixed assets and bootstrap the scoped v0.16 runtime |
| `stalwart_v016_registry.py`    | Provide the pinned stdlib Registry transport used by the migration tools (not a standalone CLI) |
| `convert_msg.py`               | Convert Outlook `.msg` files to `.eml`; optional legacy helper requiring `extract-msg` |
| `reset.py`                     | With explicit destructive authorization, wipe both provider stores and restore verified Dovecot defaults |
| `lib.py`                       | Shared utilities (not a standalone script) |
