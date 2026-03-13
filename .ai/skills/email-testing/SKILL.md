---
name: email-testing
description: Create, inject, and manage test email data. Use when generating .eml files, building email threads, seeding mailboxes, or designing test scenarios for IMAP/JMAP clients.
---

# Email Testing

## Tool integration
- Use [references/eml-format.md](./references/eml-format.md) for .eml file structure and conventions.
- Use [references/test-workflows.md](./references/test-workflows.md) for common testing patterns.

## Workflow
1. Identify what test data is needed (single message, thread, bulk).
2. Create .eml files in `mails/` or generate with scripts.
3. Inject into mailbox using appropriate script.
4. Verify via `doveadm fetch` or IMAP client.

## Guardrails
- Do not inject mail without delay in bulk — use at least 2.5s between messages to avoid lock conflicts.
- Do not modify existing .eml files in `mails/` without understanding downstream impact.
- Do not create .eml files with missing required headers (`From`, `To`, `Date`, `Subject`, `Message-ID`).
- Do not use real email addresses in test data — use `@local.test` domain only.

## Done criteria
- Test emails are valid RFC 5322 messages.
- Messages appear in the target mailbox after injection.
- Thread structure is correct (proper `In-Reply-To` and `References` headers).
