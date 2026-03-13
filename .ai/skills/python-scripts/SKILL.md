---
name: python-scripts
description: Write and maintain Python automation scripts for user management, mail injection, and environment operations. Use when adding new scripts, modifying existing ones, or extending the shared library.
---

# Python Scripts

## Tool integration
- Use [references/lib-api.md](./references/lib-api.md) for the shared utility API in `scripts/lib.py`.
- Use [references/script-inventory.md](./references/script-inventory.md) for existing scripts and their purposes.

## Workflow
1. Check if existing scripts already handle the task ([references/script-inventory.md](./references/script-inventory.md)).
2. Reuse utilities from `scripts/lib.py` ([references/lib-api.md](./references/lib-api.md)).
3. Write scripts using Python 3 stdlib only — no pip dependencies.
4. Test the script manually: `python3 scripts/<script>.py --help`.
5. Update `CLAUDE.md` if adding a new user-facing script.

## Guardrails
- Do not add external Python dependencies — stdlib only.
- Do not duplicate functionality already in `scripts/lib.py`.
- Do not hardcode container names — use `CONTAINER_NAME` from `lib.py`.
- Do not remove the default 2.5s injection delay unless explicitly requested.
- Do not use `subprocess.shell=True` — use list-form commands for safety.

## Done criteria
- Script runs without errors.
- Shared utilities are reused where applicable.
- Script has `--help` documentation via `argparse`.
