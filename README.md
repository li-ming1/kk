# kk

**A coding agent that lives in your terminal. One C file, one `.exe`, no runtime.**

`kk` is a Windows terminal coding agent: a single ~12k-line translation unit built with
MSVC against Win32 and the CRT. Transport, JSON, UTF-8, Markdown, terminal UI and
session persistence are all hand-written. No package manager, no interpreter, no
bundled runtime. It talks to any OpenAI-compatible `/chat/completions` endpoint that
streams SSE and supports function calling.

```console
kk                      interactive REPL
kk -p "why X?"          one-shot: stream one answer, exit
kk -c                   continue the most recent session
```

Three commitments shape the whole program:

- **One file, one binary.** ~286 KB on disk, statically linked CRT, runs on a bare
  Windows box.
- **Five tools, and nothing else.** `read`, `write`, `bash`, `find`, `grep`.
- **Cost is displayed, never estimated.** Every turn ends with a line of real numbers
  from the endpoint, including how many bytes of your request it was able to reuse.

## Requirements

- Windows 10 1903+ (the embedded manifest pins the process codepage to UTF-8).
- A terminal that speaks VT: Windows Terminal or conhost.
- An API key for a chat-completions endpoint with tool support.
- Optional: `fff.dll` beside `kk.exe`, which upgrades `find` and `grep` from
  "shell out and hope" to a resident index. See [Credits](#credits).

## Build

```bat
build.bat
```

The script locates `vsdevcmd.bat` (edit `VSD` at the top if your Visual Studio lives
elsewhere) and compiles with `/std:c11 /W4 /O1 /GL /MT /Zi /utf-8`, linking `/LTCG
/OPT:REF /OPT:ICF /MAP` into a static-CRT `kk.exe`.

Two of those flags are load-bearing for the size. `/Zi` implies `/DEBUG` at link
time, and `/DEBUG` switches `/OPT:REF` and `/OPT:ICF` off — roughly 480 KB of
unfolded COMDATs then sit in `.text`. Re-enabling them is the default release
shape; adding `/O1` takes it from 358 KB to 286 KB. `kk.map` is not incidental
either: it is what turns the RVAs in a crash report back into function names
offline.

## Configure

Precedence is **flag > environment > config file**.

`%APPDATA%\kk\config` holds `key=value` lines; `#` starts a comment:

```ini
base_url = https://api.openai.com/v1
api_key  = sk-...
model    = gpt-4o
```

| Flag | Environment | Fallback env |
| --- | --- | --- |
| `--base URL` | `KK_BASE_URL` | `OPENAI_BASE_URL` |
| `--key KEY` | `KK_API_KEY` | `OPENAI_API_KEY` |
| `--model M` | `KK_MODEL` | — |

| Variable | Default | Effect |
| --- | --- | --- |
| `KK_MAX_OUTPUT_TOKENS` | 32768 | `max_tokens` sent with every request |
| `KK_CONTEXT_WINDOW` | 262144 | Assumed context window, in tokens |
| `KK_READ_MAX_BYTES` | 65536 | Byte cap on one `read` page |
| `KK_IMG_MAX_EDGE` | 1568 | Long-edge cap for pasted images, before PNG encoding (below 64 disables) |
| `KK_IMG_MAX_BYTES` | 8 MB | Cap on a pasted image's base64 length |
| `KK_DUMP_REQ=<path>` | — | Overwrite that file with every request body, verbatim |
| `KK_FORCE_CONSOLE` | — | Emit VT even when stdout is redirected (for testing) |
| `KK_GOAL_ROUNDS` | 50 | Max rounds before a goal run stops itself |
| `KK_GOAL_MINUTES` | 60 | Max wall-clock minutes for a goal run |
| `KK_GOAL_TOKENS` | 5000000 | Max cumulative in+out tokens for a goal run |

Pasted images are capped at 1568 px on the long edge (bilinear, aspect preserved)
before encoding. Vision endpoints downscale past that themselves and refuse base64
bodies over 5–10 MB, so an uncropped 4K screenshot would encode to a ~25 MB PNG — a
~33 MB request that gets rejected, or costs 2–3× the tokens.

`-h` / `--help` and `--version` finish the flag list. An unknown flag, or a
value-taking flag with no value, exits `2`. A turn cancelled with Ctrl+C exits `130`.

## What the model gets

| Tool | Does |
| --- | --- |
| `read` | Numbered lines, `offset`/`limit` paging, images returned as attachments |
| `write` | Create, overwrite, or — with `old_string` — replace an exact occurrence |
| `bash` | PowerShell, one persistent session: cwd and environment carry over |
| `find` | Fuzzy file-name / glob search over a warm in-process index |
| `grep` | Content search: smart-case, optional regex, multi-pattern OR in one pass |

`find` and `grep` need `fff.dll`. Without it they fail with a one-line explanation and
the agent falls back to shell pipelines — everything else keeps working.

What surrounds the tools in the system prompt:

- **`AGENTS.md`**, collected from the working directory upward, parent-first.
- **A skill index** — every `<workspace>\.agents\skills\<name>\SKILL.md` and
  `%USERPROFILE%\.agents\skills\...`, the workspace shadowing a user-level name. Only
  the name and the leading sentences of the description (at most 240 bytes, cut at a
  sentence end) enter the prompt, because every byte of the index is re-sent on every
  round; the model `read`s the body when a task matches. `/skills` prints exactly what
  the model was offered.
- **A workspace snapshot** — the most-touched files with sizes and git status, so the
  first round is not spent discovering the directory.

## The REPL

The composer docks to the bottom edge and stays put; output scrolls above it.
Answers stream through a single-pass Markdown painter that handles headings, code
fences, lists, tables, CJK and emoji widths.

- Type while a turn is running: the line is queued and handed to the model as
  mid-turn steering, not after the turn finishes.
- Consecutive `read` calls at the head of a tool batch run in parallel.

| Key | Action |
| --- | --- |
| `Enter` / `Tab` | submit / complete the highlighted command |
| `Ctrl+C` | cancel the running turn, clear the draft, or quit |
| `Ctrl+D` | quit |
| `Ctrl+V` | paste clipboard text, or an image as a path |
| `Ctrl+Z` | undo the last destructive edit |
| `Ctrl+A` / `Ctrl+E` | move to line start / line end |
| `Ctrl+U` / `Ctrl+W` | kill line / kill word |
| `Ctrl+P` / `Ctrl+N` | history back / forward |
| `↑` `↓` `←` `→` | move the cursor |

Slash commands: `/new` (fresh session), `/resume` (full-screen session picker;
`/resume <n>` picks from the numbered list it prints when stdin is scripted),
`/goal <task>` (autonomous mode, below), `/skills`, `/compact` (fold early history
into a summary).

Paste or drop an image path and up to 4 images ship with the message as base64
attachments — that needs a vision-capable model.

## Goal mode

`/goal <task>` hands one large task to the agent and lets it run without you
re-typing "继续" between rounds. Every round is a full turn — stream, tools, display,
session log, auto-compaction — so a goal run behaves exactly like one long turn; it
just continues itself with a tagged nudge instead of waiting for keystrokes.

The model ends it by prefixing its final answer with ✅. Three hard stops, whichever
comes first: the ✅ marker, a budget, or you — Ctrl+C or any real message hands
control straight back. A goal never overrules the human.

Each round prints the usual stats line plus a dim cumulative counter
(`🎯 第 k/N 轮 · 累计 in+out X tokens`), so the burn is visible while it runs.

## Sessions and cost

Every session is append-only JSONL under `%LOCALAPPDATA%\kk\sessions\`, and
`%LOCALAPPDATA%\kk\current` points at the one `--continue` reopens. The log holds
messages, tool calls and results, per-round usage including cached tokens, and
compaction summaries.

Context is reclaimed in stages, cheapest first: bulky tool results the model has
already seen in two rounds (2 KB and up) are replaced by visible stubs — it can
re-run the call to get them back — and only then is history folded into a summary,
once the request outgrows ¾ of the window. `-p` mode never compacts; nothing follows
it. The assumed window is corrected downward at runtime when an endpoint's overflow
rejection names the real limit.

Each turn ends with a stats line:

```
[in 41230 · out 1815 · 62.4 t/s · ch 78.3% · sh 91.2% · 1m12s]
```

`ch` is the prompt-cache hit rate (one decimal, because a 1% hit rounded to 0% reads
as broken caching) and `sh` is how many bytes of this request repeated the previous one
from byte 0 — high `sh` with `ch 0%` is the endpoint's fault, a falling `sh` is ours.
At session start `kk` also prints the static head: the per-round cost of tools,
`AGENTS.md`, base prompt, skills and snapshot, since that is the part every single
round re-pays.

A degenerate output loop is detected and the turn interrupted, rather than left to
burn tokens into the context.

## When it breaks

An unhandled fault writes `kk_crash.txt` in the working directory: exception code,
faulting address, and the return addresses as RVAs, which `kk.map` names offline.
`KK_DUMP_REQ=<path>` answers "why is this request bigger than the messages in the log"
by keeping the exact bytes that were sent.

## Credits

`find` and `grep` are powered by [fff](https://github.com/dmtrKovalenko/fff) — a file
search toolkit by Dmitriy Kovalenko and contributors, MIT licensed. `fff.h` here is
its cbindgen-generated C ABI, and `fff.dll` is loaded at runtime, not linked.

## Repository

```
kk.c         the whole program
fff.h        C ABI of the fff search library (types only; resolved via LoadLibrary)
build.bat    MSVC build
kk.manifest  UTF-8 process codepage
LICENSE      MIT
```

The rules the code follows: full features, minimal implementation — delete before
refactor, merge before abstract, and every layer has to answer why it exists.

## License

MIT. See [LICENSE](LICENSE).