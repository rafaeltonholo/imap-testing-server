# AI Self-Review Guidelines

Use this checklist before finalizing any response or code change.

## 1. Scope Accuracy

- Did I address the exact user request (not a nearby request)?
- Did I avoid adding unsolicited architecture changes?
- Did I keep changes minimal and focused?

## 2. Repository Conventions

- Python scripts use stdlib only (no pip dependencies).
- Scripts share utilities via `scripts/lib.py` — reuse before duplicating.
- Docker config files are mounted read-only; runtime state lives in `vmail/` and `stalwart-data/`.
- SSL certs are gitignored and generated via `scripts/setup.py`.

## 3. Service Correctness (when applicable)

- Are Dovecot config directives valid for the current Dovecot version?
- Are Stalwart TOML settings valid per Stalwart documentation?
- Are Postfix `main.cf` parameters correct and non-conflicting?
- Are OAuth2 endpoints consistent across all services that reference them?

## 4. Documentation Quality

- Paths are repository-relative and navigable.
- Statements are concrete, testable, and non-handwavy.
- Cross-document references are consistent and not stale.

## 5. Validation Commands

Run what applies:

```bash
docker-compose config --quiet
docker-compose up -d
docker compose logs dovecot
python3 scripts/create_and_feed_account.py --email dev@local.test
```

If validation cannot run due to environment restrictions, state it explicitly.

## 6. Final Response Quality

- Summarize what changed with precise file paths.
- Call out anything not completed and why.
- Avoid vague claims without evidence.
