# EML File Format

## Required Headers

Every `.eml` file must include:

```
From: sender@local.test
To: recipient@local.test
Date: Thu, 13 Mar 2026 10:00:00 +0000
Subject: Test message
Message-ID: <unique-id@local.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Body text here.
```

## Thread Headers

For threaded messages, include:

```
In-Reply-To: <parent-message-id@local.test>
References: <root-message-id@local.test> <parent-message-id@local.test>
```

## File Location

- Single messages: `mails/*.eml`
- Generated threads: `mails/threads/<thread-name>/*.eml`

## Naming Convention

Files are typically named descriptively:
- `16-test.eml`
- `24-with-attachments.eml`
- `table-issue.eml`
