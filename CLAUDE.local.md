<!-- BEGIN basemind (managed by `basemind init`) -->

## basemind — prefer it over grep / read / git

basemind is this repo's indexed context layer. Prefer it BEFORE grep, before reading files to find structure, and before naked `git` — it's the default, not a preference. basemind returns paths, lines, and signatures at a fraction of the tokens of reading source.

### Routing

| Reach for | Instead of |
|---|---|
| `code` modes `symbols` / `definition` / `references` / `callers` / `implementations` / `grep`, `graph` mode `calls` | `grep` / `rg` / opening files to find a symbol |
| `code` mode `outline` (code files only) / `graph` mode `map` | reading whole files to learn their shape |
| `git` modes `recent` / `blame_symbol` / `touching` / `diff` | `git log` / `git blame` / `git diff` |
| `code` mode `find` (fuzzy path search) | `find` / `fd` / `ls -R` to locate a file by name |
| `agents` (modes `post` / `inbox` / `thread_list`) | assuming you're the only agent in the repo |
| `workspace` (modes `workspaces` / `worktrees` / `claim`) | editing a worktree another session may already own |
| `memory` mode `documents` (PDFs, Office, markdown, config and data files; the code map holds code only) / `web` (modes `scrape` / `crawl` / `map`) | manually reading PDFs / docs / config files or ad-hoc fetching |
| `code` mode `semantic` (then `chunk`) | keyword-only guessing at where a concept lives |

### Red flags — stop and re-route

- About to `grep` / `rg`? → `code` mode `grep`.
- About to open a file just to find a symbol? → `code` modes `outline` / `symbols`.
- About to `git log` / `git blame`? → `git` modes `recent` / `blame_symbol`.
- Already mapped a file with basemind? Don't re-read it.

### Setup & maintenance

- Install the basemind Claude Code plugin from its marketplace (`/plugin marketplace add Goldziher/basemind`, then install `basemind`).
- Keep basemind current: enable plugin auto-update, or update the binary regularly so the index format and tools stay in sync.
- Re-run `basemind init` (or `/bm-init`) after enabling new capabilities to refresh this block.

<!-- END basemind -->
