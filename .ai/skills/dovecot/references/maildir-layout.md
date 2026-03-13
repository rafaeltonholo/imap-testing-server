# Maildir Layout

## Structure

```
vmail/
└── dev@local.test/
    └── Maildir/
        ├── cur/          # read messages
        ├── new/          # unread messages
        ├── tmp/          # messages being delivered
        ├── .INBOX.Sent/
        │   ├── cur/
        │   ├── new/
        │   └── tmp/
        └── .INBOX.Drafts/
            ├── cur/
            ├── new/
            └── tmp/
```

## Conventions

- Base path: `/srv/vmail/<email>/Maildir/` (container), `./vmail/<email>/Maildir/` (host)
- Namespace prefix: `INBOX.` with `.` separator (configured in `15-namespace.conf`)
- Subfolder format: `.INBOX.<FolderName>/` (Maildir++ convention)
- All users share UID/GID 1000
