# Skills Catalog

Curated skills for AI agents working in mail-sandbox.

## Available Skills

- [docker-compose](./docker-compose/SKILL.md): Docker Compose service orchestration and configuration
- [dovecot](./dovecot/SKILL.md): Dovecot IMAP server configuration and administration
- [stalwart](./stalwart/SKILL.md): Stalwart JMAP server configuration and user provisioning
- [postfix](./postfix/SKILL.md): Postfix SMTP server configuration and mail routing
- [oauth2](./oauth2/SKILL.md): OAuth2 mock server and token introspection flows
- [python-scripts](./python-scripts/SKILL.md): Python automation scripts and shared utilities
- [email-testing](./email-testing/SKILL.md): Email injection, thread generation, and test workflows

## How To Use

1. Pick the skill matching the task area.
2. Follow "When to use", then execute the "Workflow" steps.
3. Validate with the "Done criteria" before finishing.
4. Combine skills only when needed (e.g., `dovecot` + `oauth2` for auth config changes).
