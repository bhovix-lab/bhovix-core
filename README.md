# bhovix-core

Shared building blocks for Bhovix Lab's fixed-price AI builds, and the demo builds that use them.

| Folder | What it holds |
|---|---|
| `src/bhovix_core/` | The reusable core: one interface per capability, with backends chosen per client in config |
| `demos/` | Demo builds on the core (invoice & PO automation, document Q&A) |
| `tests/` | Tests for the core and the repository rules |

Rules:
- The core never imports anything from `demos/` (a test enforces it), so a client delivery can take the core alone.
- Demo data is synthetic only. No client data, secrets, account ids or personal details are ever committed.

## Licence

Proprietary. Copyright (c) 2026 Bhovix Lab. All rights reserved. See [LICENSE](LICENSE). Viewing this repository
does not grant any licence to use it.

## Security

See [SECURITY.md](SECURITY.md).
