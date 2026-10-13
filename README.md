# kk

A Windows coding agent that lives in your terminal — one C file, one `.exe`, no runtime.

`kk.c` is a single translation unit (~10.4k lines) built with MSVC against Win32 +
the CRT only: WinHTTP for transport, hand-written JSON / UTF-8 / Markdown / SSE,
console VT rendering. No package manager, no interpreter, no bundled runtime.
It talks to any OpenAI-compatible `/chat/completions` endpoint that streams SSE and
supports function calling.

```
kk                    interactive REPL
kk -p "why X?"        one-shot: stream one answer, exit
kk -c                 continue the most recent session
```

## Requirements

- Windows 10 1903+ (the embedded manifest pins the process codepage to UTF-8).
- A terminal that speaks VT: Windows Terminal or conhost.
- `fff.dll` next to `kk.exe` for the `find` and `grep` tools and the startup
  workspace snapshot. Everything else runs without it — `kk` just falls back to
  letting the model explore with `bash`.
- An API key for a chat-completions endpoint with tool support.

## Build

```bat
build.bat
```

The script locates `vsdevcmd.bat` (edit `VSD` at the top if your Visual Studio is
elsewhere) and compiles with `/std:c11 /W4 /O2 /GL /MT /utf-8`, linking
`/LTCG /MAP` into a static-CRT `kk.exe` (~820 KB). `/MAP` is not incidental:
`kk.map` is what turns the RVAs in a crash report back into function names.

## Configure

Precedence is **flag > environment > config file**.

`%APPDATA%\kk\config` — `key=value` lines, `#` comments:

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

Other environment variables:

| Variable | Effect |
| --- | --- |
| `KK_MAX_OUTPUT_TOKENS` | `max_tokens` sent with every request (default 32768) |
| `KK_CONTEXT_WINDOW` | Assumed context window in tokens (default 262144) |
| `KK_DUMP_REQ=<path>` | Overwrite that file with every request body, verbatim |
| `KK_FORCE_CONSOLE` | Emit VT even when stdout is redirected (for testing) |
| `KK_IMG_MAX_EDGE` | Long-edge cap for pasted images before PNG encoding (default 1568; below 64 disables) |

Images are capped at 1568px on the long edge (bilinear, aspect preserved)
before encoding: vision endpoints downscale past that themselves and refuse
base64 bodies over 5–10MB, so a 4K screenshot would otherwise encode to a
~25MB PNG — a ~33MB request that gets rejected, or costs 2–3x the tokens.

`--help` and `--version` finish the flag list. Unknown flags exit `2`; a turn
cancelled with Ctrl+C exits `130`.

## What it gives the model

Five tools, and that is the whole surface:

| Tool | Does |
| --- | --- |
| `read` | Numbered lines, `offset`/`limit` paging, images returned as attachments |
| `write` | Create, overwrite, or — with `old_string` — replace an exact occurrence |
| `bash` | PowerShell, one persistent session: cwd and environment carry over |
| `find` | Fuzzy file-name / glob search over a warm in-process index |
| `grep` | Content search, smart-case, optional regex, multi-pattern OR in one pass |

Beyond the tools, the system prompt carries three things you control:

- **`AGENTS.md`** files found from the working directory upward, parent-first.
- **A skill index**: every `<workspace>\.agents\skills\<name>\SKILL.md` and
  `%USERPROFILE%\.agents\skills\...` (the workspace shadows a user-level name).
  Only the name and the leading sentences of the description — at most 240
  bytes, cut at a sentence end — go into the prompt, because every byte of the
  index is re-sent on every round; the model `read`s the body when a task
  matches. `/skills` prints exactly what the model was offered.
- **A workspace snapshot**: the most-touched files with sizes and git status, so
  the first round is not spent discovering the directory.

## Using the REPL

The composer docks to the bottom edge and stays put; output scrolls above it.
Answers stream through a single-pass Markdown painter (headings, code fences,
lists, tables, CJK and emoji widths handled).

- Type while a turn is running: the line is queued and handed to the model as
  mid-turn steering, not after it finishes.
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
`/goal <task>` (autonomous mode — see below), `/skills`, `/compact` (fold early
history into a summary).

## Goal mode

`/goal <task>` hands one large task to the agent and lets it run without you
re-typing "继续" between rounds. Every round is a full turn — stream, tools,
display, session log, auto-compaction — so a goal run behaves exactly like one
long turn; it just continues itself with a tagged nudge instead of waiting for
keystrokes.

The model ends it by prefixing its final answer with ✅. Three hard stops,
whichever comes first: the ✅ marker, a budget, or you — Ctrl+C or any real
message hands control straight back (a goal never overrules the human).

| Variable | Default | Effect |
| --- | --- | --- |
| `KK_GOAL_ROUNDS` | 50 | Max rounds before the budget stops the run |
| `KK_GOAL_MINUTES` | 60 | Max wall-clock minutes |
| `KK_GOAL_TOKENS` | 5000000 | Max cumulative in+out tokens |

Each round prints the usual stats line plus a dim cumulative counter
(`🎯 第 k/N 轮 · 累计 in+out X tokens`), so the burn is visible while it runs.

Paste or drop an image path and up to 4 images ship with the message as
base64 attachments — that needs a vision-capable model.

## Sessions and cost

Every session is append-only JSONL under `%LOCALAPPDATA%\kk\sessions\`, and
`%LOCALAPPDATA%\kk\current` points at the one `--continue` reopens. The log holds
messages, tool calls and results, per-round usage (including cached tokens), and
compaction summaries.

Context is reclaimed in stages, cheapest first: bulky tool results the model
has already seen in two rounds (2 KB and up) are replaced by visible stubs — it
can re-run the call to get them back — and only then is history folded into a
summary, once the request outgrows 3/4 of the window.
`-p` mode never compacts — nothing follows. The assumed window is corrected
downward at runtime when an endpoint's overflow rejection names the real limit.

Money is shown, not guessed. Each turn ends with a stats line —

```
[in 41230 · out 1815 · 62.4 t/s · ch 78.3% · sh 91.2% · 1m12s]
```

`ch` is the prompt-cache hit rate (one decimal, because a 1% hit rounded to 0%
reads as broken caching) and `sh` is how many bytes of the last request repeated
the previous one from byte 0: high `sh` with `ch 0%` is the endpoint's fault, a
falling `sh` is ours. At session start `kk` also prints the static head — the
per-round cost of tools, `AGENTS.md`, base prompt, skills and snapshot — since
that is the part every single round re-pays.

A degenerate output loop is detected and the turn interrupted rather than left to
burn tokens into the context.

## When it breaks

An unhandled fault writes `kk_crash.txt` in the working directory: exception code,
faulting address, and the return addresses as RVAs, which `kk.map` names offline.
`KK_DUMP_REQ=<path>` answers "why is this request bigger than the messages in the
log" by keeping the exact bytes that were sent.

## Repository

```
kk.c         the whole program
fff.h        C ABI of the fff search library (types only; resolved via LoadLibrary)
build.bat    MSVC build
kk.manifest  UTF-8 process codepage
help.md      design doctrine: what may be deleted, what must not
LICENSE      MIT
```

The rules the code follows are in `help.md`: full features, minimal implementation
— delete before refactor, merge before abstract, and every layer has to answer why
it exists.

## License

MIT. See [LICENSE](LICENSE).
