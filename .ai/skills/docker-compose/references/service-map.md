# Service Map

## Port Assignments

| Service     | Container Name  | Host Port | Container Port | Protocol      |
|-------------|-----------------|-----------|----------------|---------------|
| dovecot     | dovecot-dev     | 143       | 31143          | IMAP STARTTLS |
| dovecot     | dovecot-dev     | 993       | 31993          | IMAPS (TLS)   |
| postfix     | postfix-dev     | 1025      | 25             | SMTP          |
| postfix     | postfix-dev     | 587       | 587            | SMTP Submission |
| oauth2-mock | oauth2-mock     | 8080      | 8080           | HTTP          |
| stalwart    | stalwart-dev    | 8443      | 8080           | HTTP (JMAP)   |

## Dependency Chain

```
oauth2-mock (no dependencies, starts first)
    └── dovecot (depends on oauth2-mock healthy)
            └── postfix (depends on dovecot healthy)

stalwart (independent, starts in parallel)
```

## Healthchecks

| Service     | Method                          | Interval | Start Period |
|-------------|---------------------------------|----------|--------------|
| dovecot     | `doveadm who`                   | 10s      | 15s          |
| oauth2-mock | HTTP GET `/health`              | 5s       | 5s           |
| stalwart    | TCP check on port 8080          | 10s      | 15s          |
| postfix     | (none defined)                  | —        | —            |
