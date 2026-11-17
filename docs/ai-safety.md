# Stage 5: optional, read-only AI

ExposureIQ works without AI. A **digest** is a small, code-built summary of saved
scan facts. AI reads that summary, not a live target. Chat may explain selected
evidence in its own words, with bounded fact/evidence/safety checks. That is not
full verification of arbitrary prose. Summaries/reports retain the stricter
code-approved sentence catalogue.

## What owns the facts?

- Scan schema **0.2** stays unchanged. No AI preference, key, conversation or log
  is added to a saved scan. Existing schema 0.1 snapshots remain readable.
- Code groups findings, counts severity, ranks priorities and computes history.
  Chat checks allowed references and code-filled factual placeholders; requested
  lists must follow the code-selected priority order. Strict summaries also
  require coverage of every included high-severity group.
- Unknown references/placeholders, literal numeric facts/CVEs, known unsafe
  command/acting claims and malformed JSON are rejected. A rejected reply uses a
  checked built-in explanation. Rule-based checks cannot catch every unsupported
  statement in model prose; people must review the wording and saved evidence.
- Replies are labelled **AI draft**, with an honest source. Chat says
  `saved evidence checked; wording needs review`, with `wording_verified=False`
  in diagnostic data. Strict summaries retain `verified X of Y claims`, model
  and time. Neither checks the accuracy or completeness of a scan or proves a fix.
- The current internal prompt version is `grounded-chat-4`; disposable caches use
  `s5-digest-2`. Cached claims are checked again before display. Digest envelopes
  include input and value checksums; a checksum is not protection against a
  malicious process running as the same user.
- SIMPLE is the default. Code adds first-use term definitions without changing
  host names, spells out small counts and provides urgent/important/minor labels.
  TECHNICAL is available through the TUI/web control or CLI `--mode technical`.
  Default replies group at most three themes, avoid report lists/headings and keep
  references in one collapsed Evidence row (one plain line in CLI output).
  Built-in fallback leads with one code-ranked example per theme rather than a
  paragraph covering every rule. Detailed lists appear only when asked for.

### Risk and history

The exposure index is:

`risk = 10 × high + 3 × medium + low + 5 × ports.*_exposed findings`

`risk per host = risk / distinct hosts` (zero when there are no hosts).

This is not a probability of compromise or a standard vulnerability score.
Missing or failed checks can lower it without making an organization safer.
Code compares first→last and previous→last risk per host. A meaningful movement
is at least `max(0.5, 10% of baseline)`. Finding changes also matter; opposing
movement or changes give `mixed`, not an AI-selected verdict. The ten-scan demo
currently has the code verdict **mixed**.

History layers are L1 scan summaries, L2 adjacent comparisons, L3 a timeline and
L4 the bounded domain digest. More than fifty scans use weekly end-point buckets;
very long timelines merge older ranges and disclose omitted detail. The latest
scan and the last five comparisons are retained at their bounded summary level.

History identity uses **host/rule/IP/port**, not per-scan `F-…` IDs:

- **Still unfixed:** present throughout the last three eligible observations
  (or both, when only two are available).
- **New recently:** first seen within that recent window and still present.
- **Absent after two observations:** absent in two subsequent observations of
  that host. This is not live verification of remediation.
- **Regression:** returns after such a confirmed absence.

Schema 0.2 does not record full check coverage. Passive-only/all-empty or
coverage-unknown scans are therefore excluded from finding comparisons and the
verdict needs at least two scans with check evidence. Missing hosts do not
confirm a fix. This conservative inference is imperfect and is disclosed.

## Modes and private settings

Open the TUI with `exposureiq`, then **⚙ Settings → AI settings**. No key is accepted
as a CLI argument or by the browser viewer.

| Mode | What happens |
| --- | --- |
| Off (no AI), the default | No AI tabs/buttons or requests. Saving Off removes the stored key and clears displayed chat. |
| Local URL | Only numeric loopback or `localhost`, which is pinned to `127.0.0.1`; no key is sent. |
| Remote API | Final HTTPS base URL, model and key; OpenAI-compatible or native Anthropic Messages API. Host-named consent is required. HTTP is allowed only for loopback fakes. |

There is no Demo setting. Explicit `ai ... --demo` and `web --demo` commands still
use deterministic offline fakes for tests/classroom evidence. Old saved Demo
preferences load as Off, without a request or a write just from reading them.
The CLI retains checked offline fallback and `--no-fallback` failure behavior.
Enabled local/remote chat also uses checked fallback if the AI fails.

**Settings → Developer mode** is off by default. It shows the AI log and the
scan's fake-data badge; it never enables AI or sends a request by itself. Turning
it off returns to chat and hides logs. A plain warning remains on synthetic scan
data, so hiding the badge cannot make a demo look like a real scan.

### Local setup

1. Separately run a local service exposing OpenAI-compatible chat completions,
   for example an already-installed Ollama instance with an available model.
   ExposureIQ does not install/start it or download a model.
2. Select **Local URL**, enter its base URL (default
   `http://127.0.0.1:11434/v1`) and the exact available model name, then Save.
3. Optionally use **Test connection**. It contacts only that endpoint with a
   small readiness request, not scan data. This run did not test a real service.
4. Read saved data with `exposureiq ai summary example.com` or
   `exposureiq ai history example.com`. The TUI and web viewer use the same
   service and checker. Local mode ignores remote stored/environment keys.

### Remote setup

1. Obtain your team's permission to share scan data with the provider.
2. Select **Remote API** and a provider preset, or **Custom** for another
   OpenAI-compatible service. Enter a model available at that endpoint.
   ExposureIQ appends `/chat/completions`, or `/messages` for Anthropic.
3. Enter a key only in the masked field, privately. Do not paste it into chat,
   a shell command, a scan file, a screenshot or a support log.
4. Before Save or Test, read the dialog naming the destination host. Cancel
   makes no request and no settings write. Changing the base URL needs new
   consent. A connection test sends no scan digest, but still sends a remote
   credential to the approved endpoint.
5. Use saved-data summaries/chat only. Domains/host names, normalized finding
   groups, counts, history and selected technology/service hints can be shared.
   They are not anonymous. Provider retention is governed by its own policy.

Presets are conveniences, not endorsements or live interoperability tests:

| Preset | Base URL | Evidence in this work |
| --- | --- | --- |
| Custom | User-selected final URL | Main configuration path; verify before sharing. |
| OpenAI | `https://api.openai.com/v1` | [Chat Completions documentation](https://platform.openai.com/docs/api-reference/chat/create) checked on 2026-11-16; fake HTTP tests only. |
| Anthropic | `https://api.anthropic.com/v1` | [API overview](https://platform.claude.com/docs/en/api/overview) and [2026-10-21 migration](https://platform.claude.com/docs/en/api/migration-2026-10-21) checked on 2026-11-16; fake native Messages/tool exchange only. |
| OpenRouter | `https://openrouter.ai/api/v1` | URL checked against [official documentation](https://openrouter.ai/docs/quickstart). |
| Groq | `https://api.groq.com/openai/v1` | URL checked against [official documentation](https://console.groq.com/docs/openai). |
| Mistral | `https://api.mistral.ai/v1` | **Unverified:** official documentation request timed out. |
| Gemini (OpenAI-compatible) | `https://generativelanguage.googleapis.com/v1beta/openai` | URL checked against [official documentation](https://ai.google.dev/gemini-api/docs/openai). |

Other documentation checks were recorded on 2026-11-14. No real endpoint/model or key
was tested; features such as JSON responses and tool calls may differ by model.

OpenAI requests use `max_completion_tokens` and omit temperature for newer
models. Anthropic uses `anthropic-version: 2026-10-21`, bearer-key authentication,
top-level system text, text blocks and client-side read-only tool results. Its
current API version removes sampling parameters, so none are sent. Use a
workspace-scoped Anthropic key; the app does not choose a workspace for an
organization-wide key. No server-side web-search/code-execution tools are
advertised, and unsupported response blocks are rejected safely. These are
documentation and offline format checks, not live interoperability claims.

### Storage and networking limits

- Config: `${XDG_CONFIG_HOME:-~/.config}/exposureiq/ai.json`.
  Cache: `${XDG_CACHE_HOME:-~/.cache}/exposureiq/s5-digest-2-*.json`.
  Neither is allowed inside the source tree. Caches contain normalized evidence
  and accepted claims, not chat or API logs; they can still be sensitive.
- Directories/files use `0700`/`0600` permissions on POSIX. A stored key is **plain
  text**, not encrypted. Windows permission handling is not an audited ACL-based
  secret store. Use a private user account/folder; never share these files.
- `EXPOSUREIQ_AI_KEY` overrides a stored remote key and is never written to
  preferences. Configure it privately outside command history. Off/local modes
  ignore it; saving Off cannot remove an environment variable from your shell.
- Only the configured endpoint may receive AI HTTP requests. Redirects,
  environment proxies and ambient `netrc` credentials are disabled. Remote
  endpoints require normal HTTPS certificate validation.
- A completion has a 60-second requests timeout, a 128,000-byte reply cap and one
  timeout/5xx retry. The timeout is per attempt, not an overall answer deadline.
  There is at most one structured-JSON repair request. All HTTP attempts,
  retries, tool follow-ups and connection tests share **eight attempts/minute**.
- Scan digests are at most 2,400 compact JSON characters; history 12,000; each
  tool result 6,000. Token estimates are characters ÷ four, not a real tokenizer.
  Counts include items omitted by the top-five/list budgets; truncation is noted.

## Chat and audit boundaries

The policy gate permits saved-scan questions, possible consequences, ExposureIQ
explanations and defensive fixes. It refuses off-topic requests, offensive payloads/attack steps,
acting on targets, scope changes and requests for keys or private instructions.
The gate and independent chat checker are bounded rule sets, not universal intent
or prose verifiers. They reject known fact/safety violations; they do not prove
that every sentence a model writes is correct or safe. The tool interface itself
has no scanning, shell, scope-writing or target-contact capability.

Questions such as **"then what posible damage it can make?"** are on-topic.
The answer explains possible harm from the recorded rules first, rather than
repeating the fix list. Reviewed consequences stay conditional: an exposed port
does not prove weak account protection, stored private data or a break-in. A
question about whether data was actually taken gets an explicit evidence limit,
not an invented incident report.

Short neutral follow-ups such as **"Why?"** or **"Explain more"** use a prior
checked exchange. Code remembers the selected host/finding and presentation topic,
not new facts or permission to act. A whole-scan request clears that focus;
selecting new data, clearing chat or saving Off starts a new conversation. The
gate still checks private/offensive/off-topic rules first. CLI `ai ask` is a
single turn; separate invocations do not retain memory.

Greetings and thanks make no model call. The generic consequences disclaimer and
`Offline mode: answers come from built-in explanations, not a live model.` are
added by code at most once per conversation. A model may still phrase an evidence
limit in its own words; arbitrary wording is not fully certified.

The six tools are `get_finding`, `list_findings`, `get_host`, `get_diff`,
`get_history` and `list_unfixed`. Arguments select existing IDs/names, never file
paths or commands. There are at most **four tool calls per answer**. Tool outputs
are normalized, bounded saved data; no tool probes a target or writes a file.

Chat keeps six messages (three exchanges); questions are limited to 1,000
characters. Selection/generation guards prevent a late worker from attaching an
old answer to newly selected scan data or an Off AI view. No conversation is
written to disk. An already-sent HTTP request cannot be unsent by hiding the UI;
its worker may finish under the existing bounded timeout/retry rules.

The normal AI view is chat only, with three quick questions and eight more
common questions. A sent receipt appears immediately; ASCII feedback moves
while an answer is pending. User and assistant messages have different, subdued
styles. The browser shows a sent receipt first and adds the user's actual text
only after server-side private redaction; no private key is sent to the browser.

The developer-only AI log holds the last thirty calls in memory, including connection checks,
sent non-system messages, replies, rejected claims and fixed error categories.
Credentials, JSON-escaped secrets and echoes of private system instructions are
redacted. Host names/evidence remain visible to the local user; the log is not
an anonymized export. A policy refusal makes no model call. Closing the process
loses the conversation and audit.

Saved findings, questions, logs and replies are rendered literally with
Rich/Textual `Text` or `markup=False`. Browser strings use `textContent`, never
HTML execution sinks. Hostile-looking scan text is flagged and treated as data.

## Local web viewer

```bash
exposureiq web --demo --port 0       # offline fake AI; read existing saved JSON
exposureiq web --results-dir results # use privately configured AI; Off hides chat
exposureiq web example.com --open    # open the actual HTML report in one command
```

It binds only to **127.0.0.1**, not a LAN/public address. Open the full printed
URL, including `#…`; keep it private. The per-launch token is sent in a session
header for API requests, not HTTP URLs. The native report form sends that same
session token in its bounded POST body; the response never embeds it. A temporary
fragment hands it to the report page and is replaced with `#domain-home` before
live replies are enabled. Fragments never enter HTTP referrer headers.
Ctrl+C stops the server. `--open` optionally opens the private local URL.

- Strict Host/Origin checks, no cross-origin permission, session authentication,
  security headers and an explicit route allowlist protect browser boundaries.
- Referrer policy is `same-origin` so Firefox's native same-origin POST form can
  supply its required Origin. It does not relax exact Host/Origin checks and does
  not send a fragment or provider key in a referrer.
- Static assets are packaged and local. There is no key/config-write, scan,
  scope, command, file-write or arbitrary-file API. `POST /api/report` only renders
  an existing saved report in memory. AI POST routes only read saved
  data, although approved AI networking/private caching may occur server-side.
- Off disables all AI POST routes and the log route. The log route also requires
  Developer mode when AI is enabled. The report checks settings before/after
  questions, on focus and about every five seconds while visible. Off hides its
  icon/drawer and clears pending context; server checks enforce authorization.
  A report initially opened while Off contains no chat assets: reopen its local
  URL after enabling AI. The older domain-list viewer uses its Refresh button.
- Scan reads are descriptor-relative and use `O_NOFOLLOW` at each component.
  Traversal, symlinks and directory-swap races fail closed; selected changed
  files must be refreshed before display.
- **Platform limit:** secure reads need `dir_fd`, `O_NOFOLLOW` and `O_DIRECTORY`.
  Without them (including typical Windows Python), saved files are excluded,
  not read through a weaker fallback. Use the TUI or generated offline reports.
- Limits: 500 indexed files / 32 MB total, 8 MB per scan, 500 displayed finding
  rows, 8 KB request bodies, eight chat contexts and one simultaneous AI answer.
  Conversation identifiers isolate browser tabs and clear-chat requests. Off
  clears server chat memory when checked, and a reply finishing after Off is
  rejected. File/count exclusions are disclosed. Saved JSON is never modified.

This is a private single-user viewer, not a deployed multi-user web application.
Session tokens/permissions do not protect against a malicious process with the
same local-user access.

## Portable HTML chat

The `report` command produces a self-contained, **scan-only** `index.html`.
PDF/DOCX keep their original renderers. `exposureiq web example.com --open`
renders the actual report in memory with a floating chat icon and side drawer
when TUI AI settings are enabled. All questions go to the same natural,
contextual chat service as the TUI. Simple/Technical controls and collapsed
Evidence are retained. **Off** produces no chat icon, markup or metadata.

The enabled server page embeds only snapshot labels/signatures and twelve
suggested questions, not prepared answers, digests, raw scans, banners or HTTP
headers. The earlier prepared helpers and evidence remain as historical
regression material, but generated reports no longer include their replies or
scripts. A double-clicked file cannot read private TUI settings or use real AI.

- No key, provider URL, settings, cache, raw model reply or conversation is embedded.
  A sharing warning reminds users that saved host names/findings are sensitive.
- JSON is inert and escapes `<` as `\u003c`. Saved strings use `textContent`.
  Executable scripts have SHA-256 hashes in the **Content Security Policy (CSP)**,
  the browser's resource allowlist. Offline pages use `connect-src 'none'` and no
   external assets. File pages contain no chat and cannot turn on live replies.
- Above 2,000,000 bytes (about two MB) a visible size warning appears. Above
  10,000,000 bytes the export is refused before any requested format is written.
- The viewer's **Open HTML report** uses a token-protected, exact-origin native
  POST form. The server renders in memory with the same size checks, no file
  writes or model calls. The one-command source URL serves only a static handoff,
  then makes the same authenticated POST in that tab. The source must already
  be in the confined saved-results catalog. No session token is put in a query.
- The server-only adapter accepts only HTTP on `127.0.0.1`, uses relative,
  authenticated `/api/health` and `/api/ai/ask` requests and matches the exact saved
  scan signature. Health checks configuration readiness, not provider connectivity;
  it makes no model call. The server page allows only same-origin connections.
- Ready AI settings enable replies automatically; opening the icon or checking
  health does not call a model. Remote replies show the configured destination
  host. Consent must
  already be confirmed in private terminal Settings; the browser cannot save keys
  or grant that consent. Provider requests stay server-side and endpoint-confined.
- Provider failure uses the TUI service's clearly labelled, checked built-in reply.
  Server/authentication/connection failure shows an unavailable message, never
  prepared text, and does not display unchecked private question text.
  Off and stale replies are suppressed; changing scans or clearing chat
  resets tab-local context. Conversation data is not persisted by the page.

The approved local-server drawer replaces the earlier offline-first chat design.
Optional export L3 remains off; no browser-to-provider transport is added.

## Observed evaluation and remaining validation

[The evaluation table](stage5-evidence/evaluation.md) records **22/22** offline
safety rows: eight normal summaries accepted, eight wrong drafts rejected with
verified fallback, and six policy refusals with zero model calls. Cases include
invented counts/severity/CVEs, missing high-rule coverage, hostile scan text,
mixed history, empty/passive uncertainty and invalid JSON. These are safety
regression tests, **not real-model accuracy evidence**.

[Twelve SVGs](stage5-evidence/README.md) are real Textual headless captures with
only external font rules removed. The key is fake; remote consent was cancelled.
[The full follow-up transcript](stage5-evidence/follow-up-transcript.md) uses the
saved peak-exposure sample, **DEMO-HISTORY-04**, with the same eleven high findings
as the reported example. Its shorter consequence reply uses fresh offline-fake
wording, selected evidence and the code-added disclaimer, not a full high-finding
report or proof of a breach.
[Cross-interface transcripts](stage5-evidence/natural-chat-transcripts.md) record
twenty TUI/CLI/viewer cases and eighty-four observed turns, including both modes,
host follow-ups, thanks and simulated timeout fallback.
[Wheel smoke evidence](stage5-evidence/natural-short-fallback-package-check.txt) verifies imports and
packaged resources outside the editable tree, with networking blocked.

[Real Firefox scan-only/live-drawer checks](stage5-evidence/live-drawer-browser.json)
and three fresh-profile repeat runs use loopback HTTP and offline fakes only.
They check browser presentation/transport, not a real model's accuracy. The
shipped scripts also have fake-DOM/fake-fetch regression checks.

Not observed: a real AI service/key test or a Python 3.10 runtime test. Python 3.10
grammar was checked, but is not a runtime claim. Existing Windows helper tests
need PowerShell/native Windows. Full-suite output and exact skip reasons are in
[latest full-suite output](stage5-evidence/natural-short-fallback-final-suite.txt); earlier suite
logs and failed captures are retained in [the evidence index](stage5-evidence/README.md).
