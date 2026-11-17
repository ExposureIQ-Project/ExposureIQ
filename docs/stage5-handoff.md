# Stage 5 team handoff

## Current task: dynamic chat, split panes and TUI reports

Branch: `feature/s5-dynamic-chat`, created from `feature/s5-human-voice` with
Saif's approval to preserve the existing uncommitted Stage 5 work rather than
switching/pulling main. Nothing is staged, committed or pushed. The agent has
not run `git commit`, `git push` or `gh`; the user owns those operations.

The three ordered tiers implement question-aware saved facts and follow-up
memory, short small-model phrasing with checked fallback, accessible
split-screen browser chat, and `Open HTML report` / `h` on the TUI results,
domain and AI screens. The report action reuses one private loopback daemon,
opens the selected saved scan, shows its URL and stops the viewer on exit.
The ordinary `exposureiq web <domain> --open` command is retained.

Validation and complete evidence are in
[`tests/fixtures/dynamic_chat/final-evidence.md`](../tests/fixtures/dynamic_chat/final-evidence.md).
All three complete, unfiltered gates are green: **1,843 passed** at Tier 1,
**1,851 passed** at Tier 2, and **1,873 passed** at Tier 3. Each had sixty-six
Windows/PowerShell skips and four passing subtests. The final run took
**223.93 seconds**. Its first run had one fixture-metadata failure, corrected
without weakening the example-data check; the failed run remains recorded.

- [Complete before/after built-in and fake-server answers](../tests/fixtures/dynamic_chat/transcripts.md)
- [Observed synthetic failure cases](../tests/fixtures/dynamic_chat/failure-table.md)
- [Tier 2 browser checks and source/image hashes](../tests/fixtures/dynamic_chat/tier2-browser.json)
- [Tier 3 deep-link and shutdown checks](../tests/fixtures/dynamic_chat/tier3-browser.json)
- [Installed Qwen trial and model-size advice](../tests/fixtures/dynamic_chat/ollama-advice.md)
- [Task-only tier diffs and actual Git status](../tests/fixtures/dynamic_chat/diffs.md)
- [Changed-test list](../tests/fixtures/dynamic_chat/changed-tests.md)
- [Five current attributed commit drafts](../tests/fixtures/dynamic_chat/commit-drafts.md)

The latest real Firefox checks passed nineteen split-chat checks and nine
report-lifecycle checks, with seven screenshots. A single installed local
`qwen2.5:3b-instruct` trial produced three live replies and three honest checked
fallbacks; thanks made no model call. No real key, remote-model traffic, model
download or scan-target traffic was used. No native Windows, Python 3.10
runtime, real phone or OS-default-browser observation is claimed.

The facts badge reports bounded evidence/number/focus checks, not proof of
every model-written sentence. Human fixes/recheck commands remain advice,
never actions. Schema 0.2, scope gating, escaped literal rendering, CSP,
exact Host/Origin authentication and scan-only disk exports remain intact.
No dependency was added for these tiers; the existing `.venv` was reused.

---

## Earlier Stage 5 handoff — historical

The text and evidence below describe the preserved earlier work. Their older
branch names, test totals, screenshots and draft messages are historical,
not validation of the dynamic-chat task above. Use the current links above
for this task's review.

Branch: `feature/s5-human-voice`, created from `feature/s5-ai` with existing
uncommitted work preserved. Nothing is staged, committed or pushed. No
`git commit`, `git push` or `gh` command was run; the user owns commits and the PR.

## Delivered and boundaries

- Natural, contextual saved-data chat across the TUI, CLI and loopback viewer.
  Chat accepts fresh wording with bounded evidence/fact/safety checks. Its footer
  says **saved evidence checked; wording needs review**; arbitrary model prose is
  not fully verified. Strict summaries/reports retain approved-sentence checking.
- Code owns counts, severity, risk/verdict and priority order. Schema **0.2** is
  unchanged. Digests and private disposable caches do not modify saved scans.
- SIMPLE is the default; TECHNICAL is selectable. Code adds first-use definitions
  without changing host strings, spells out small counts and supplies
  urgent/important/minor labels. Short default replies group at most three themes,
  with one code-ranked example per theme in built-in fallback;
  detailed report sections/lists appear only when requested. Evidence is collapsed
  in the TUI/browser and one plain line in CLI output.
- Greetings/thanks make no model call. Code adds the generic consequences
  disclaimer and honest offline notice at most once per conversation. Vague
  follow-ups retain the selected host/finding; clear-chat, new data and Off reset
  context. CLI `ai ask` is a single turn, not cross-command memory.
- Gear Settings with matching Off/Remote/Local tabs, OpenAI and native Anthropic
  support, separate Local/Remote drafts, host-named remote consent and bounded,
  endpoint-confined provider transport. Keys/config/cache stay outside the repo.
- Off hides AI controls and clears chat; Demo is no longer a saved UI mode.
  Explicit CLI/web `--demo` fakes and checked offline fallback remain available.
  Legacy saved Demo preferences load as Off. Developer mode reveals diagnostics
  without enabling AI.
- Six read-only tools and bounded memory (six messages/three exchanges), four
  tool calls per answer, one timeout/5xx retry and one JSON repair. Policy/checker
  rules are not universal prose verifiers; the tool interface itself cannot scan,
  execute commands, change scope, exploit or contact a target.
- Home retained; domain folders plus All files; a single scan/history chat view
  with common questions, immediate sent receipts, ASCII thinking feedback and
  distinct user/AI styles. An inactive Diff-pane clipping bug was fixed without
  changing diff computation. Normal views retain a plain synthetic-data warning.
- `ai summary|history|ask|eval`, a token-protected `127.0.0.1` viewer, packaged
  static/fixture resources and offline evaluation; no new dependency was added.

### Approved local HTML drawer; optional L3 off

- `exposureiq web example.com --open` opens the actual saved report in one command.
  With enabled TUI AI settings, a floating icon opens/closes its side drawer.
  Questions use the same natural chat service as the TUI; Simple/Technical and
  collapsed Evidence remain. Health checks and opening the drawer do not call AI.
  Explicit `--demo` uses an offline fake, not a real model.
- Off hides the icon and drawer and clears pending context. A report initially
  opened while Off contains no chat markup or metadata; reopen its local URL
  after enabling AI. The server checks settings before/after questions, on focus
  and about every five seconds while visible.
- Existing `report` exports are now self-contained, **scan-only** HTML. A
  double-clicked file cannot access private TUI settings. The server page embeds
  snapshot labels/signatures and question ideas only—no prepared answers.
  Historical prepared helpers/evidence remain, but their replies/scripts are not
  attached to generated reports. PDF/DOCX behavior is preserved.
- Inert JSON escapes `<` as `\u003c`; untrusted strings use `textContent`.
  Executable scripts have hash-based Content Security Policy (CSP), the browser's
  resource allowlist. There are no external assets. Disk exports prohibit network
  connections; above about two MB they warn, and above about ten MB they refuse
  before writing any requested format. Sharing the HTML shares saved findings.
- **Open HTML report** uses an authenticated, exact-origin native POST form.
  The viewer renders the same report in memory, without files or model calls.
  The one-command URL uses that same form in its own tab. It accepts only a saved
  domain/JSON path already in the confined catalog. A session-token fragment is
  cleared before revealing chat; provider keys remain server-side.
- Token-protected same-origin `/api/health` matches exact saved-scan signatures
  and checks configuration readiness, not provider connectivity. Ready AI
  settings enable replies automatically; remote replies show the configured
  host and require prior terminal consent.
  Browser requests stay relative; provider networking stays endpoint-confined.
- Provider failure gives a checked built-in reply; server/auth/connection failure
  gives an unavailable message, **not** a prepared answer. Unchecked private
  question text is not displayed without the server. Clear-chat isolates tabs,
  selecting another scan clears context, Off drops
  pending replies, and generation guards suppress stale replies.

See [safety/setup and verification limits](ai-safety.md),
[eight-step presentation](stage5-presentation.md) and
[consolidated evidence/failure index](stage5-evidence/README.md).

## Observed validation

The final [full-suite output](stage5-evidence/live-drawer-final-suite.txt)
is the source of truth: **1775 passed, 66 skipped, 4 subtests passed in 226.48s
(0:03:46)**.
Observed command: `TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra`, with
no test-selection filters. Sixty-five skips need PowerShell; one needs native
Windows batch execution. Do not call those passed or claim zero skips on Linux.

| Check | Observed result and artifact |
| --- | --- |
| TUI captures/evaluation | [Twelve actual SVGs and 22/22 rows](stage5-evidence/natural-short-fallback-captures.txt); manifest hashes updated. |
| Natural transcripts | [Twenty cases, eighty-four turns](stage5-evidence/natural-chat-transcripts.md); both modes, no-call thanks, selected-host context and timeout fallback. |
| Export/drawer script | [Actual embedded drawer checks](stage5-evidence/live-drawer-dom-check.txt); authenticated relative requests, literal Evidence, Off/stale/malformed guards, no prepared replies. |
| Browser | [Real Firefox scan-only/live drawer](stage5-evidence/live-drawer-browser-confirmed.txt); three fresh profiles/servers pass, with PNGs and JSON transcript. |
| Shipped viewer JS | [Literal rendering and mode/Off checks](stage5-evidence/live-drawer-viewer-dom.txt) with fake DOM/fetch, not visual evidence. |
| Packaged wheel | [Isolated imports/assets, CLI and scan-only/live reports](stage5-evidence/live-drawer-final-package-check.txt), networking blocked; [offline build](stage5-evidence/live-drawer-final-wheel-build.txt). |
| Compatibility | Python **3.14.8** runtime; **84** packaged files parse with Python 3.10 grammar. No Python 3.10 executable is installed, so no runtime claim. |

[Final handoff checks](stage5-evidence/live-drawer-handoff-check.txt) also cover local
documentation links, draft-message format, unchanged dependencies/protected files
and UTF-8/Unix text. All **69 changed Python files**, including test/evidence
helpers, parse with Python 3.10 grammar; this is still syntax-only evidence.

The latest export measured **408,373 bytes** disk and **433,305 bytes** served
locally. Disk HTML has **one executable script, zero inert JSON blocks**,
no external assets and ten synthetic scans. The enabled server page adds a
hashed drawer script and inert metadata JSON; it contains no prepared answers.

[The drawer-focused regressions](stage5-evidence/live-drawer-focused-current.txt)
passed **211** tests. The retained cross-interface timeout-fallback answers peak at **118 words**;
the multi-finding tests bound the default examples to 180 words in both modes.
Requested technical lists retain additional code-selected detail and order.
This is not a universal length or accuracy guarantee for a real model.

The [pre-drawer 1767-pass baseline](stage5-evidence/natural-short-fallback-final-suite.txt)
and prepared-chat parity/browser evidence remain historical, not current-export
validation. The current browser rerun retained a server-stop timing failure and
then checked both honest outcomes: unavailable reply after sending, or a disabled
composer with failed-health explanation and no answer. All three fresh sessions
passed. Firefox clamped the requested narrow window; recorded content dimensions
were **500 × 758 pixels**, not a native-phone test.

The exact host sequence `Which host is the most exposed?` → `then why would i fix
it first?` → `what would that do or cause if didn't fixed?` keeps `db.example.com`
and code score **45**. **DEMO-HISTORY-04** has eleven global high findings; scan ten
has only a low referrer-policy finding. The ten-scan verdict remains **mixed**.
Do not substitute scan ten or attribute every global finding to the selected host.

All evidence used offline fakes and synthetic saved scans, not a real key/model
or target. Firefox used loopback HTTP with non-loopback HTTP sent to a refusing
local proxy. Current TUI/Firefox images were inspected; that does not establish
real-model accuracy, target safety or a successful fix. Earlier green baselines,
failed suite/capture logs and the failed SVG remain in the evidence index.

```text
Tier: Natural chat and local HTML drawer — GREEN
Tests: 1775 passed; 4 subtests passed
Skips: 65 PowerShell tests; 1 native Windows test
Safety: no real keys, live AI or target traffic
Evidence: 12 captures; 84 turns; evaluation 22/22; Firefox 3/3
Git: feature/s5-human-voice; unstaged, uncommitted, unpushed
```

## Grouped git status and diff review

Nothing is staged. This snapshot includes inherited uncommitted Stage 5 work,
the human-voice refinements and the approved live HTML drawer:

| Change group | Modified tracked | New/untracked | Total |
| --- | --- | --- | --- |
| AI and saved-data core | 2 | 36 | 38 |
| TUI/domain browsing | 5 | 6 | 11 |
| CLI/secure viewer/evaluation | 2 | 12 | 14 |
| Scan-only exports/live HTML drawer | 3 | 7 | 10 |
| Safety/scripts/evidence | 1 | 159 | 160 |
| **Total** | **13** | **220** | **233** |

Tracked `git diff --stat`: **13 files, 456 insertions / 39 deletions**. It excludes
the 220 untracked files; the complete review includes them and binary evidence.
Current review directory:
`/tmp/opencode/s5-live-drawer-review-01jacg2e/`.

- `review.diff`: complete tracked/untracked patch.
- `01-ai-data.diff`, `02-tui.diff`, `03-cli-viewer.diff`,
  `04-portable-chat.diff`, `05-docs-evidence.diff`: the five review groups above.
- `live-drawer.diff`: this request's changes against the preserved pre-request
  files in `/tmp/opencode/s5-live-drawer-before-ox67srau/before/`, using the earlier
  complete review snapshot for other existing paths. It is review-only, not an
  instruction to apply a patch or discard inherited work. The older
  `natural-redesign.diff` remains in `/tmp/opencode/s5-human-voice-review-4t7ifpnp/`.
- `review.json`, `paths.json`, `status.txt`, `tracked.diff`, `tracked-stat.txt`
  and `after/`: attributed file groups, content hashes and a source snapshot.
- `commit-drafts.md`: the draft messages below, including AI-assistance disclosure.

Review `git diff` and `git diff --no-index -- /dev/null FILE` for new files (exit
one means a diff exists). Never stage real results, private config/cache or a key.
Older review snapshots remain in `/tmp/opencode`; none were removed or applied.

## Review ownership and limits

- Stage 5 lead should review AI code, bounded chat checks versus strict report
  checking, privacy/consent and the read-only tools. Another member reviews the
  lead's own work. Fresh prose must not be described as fully verified.
- TUI/history owners should review `exposureiq/tui/app.py` integration and the
  minimal legacy test changes. Tab **availability** now belongs to the tab
  button; only ContentSwitcher controls pane display.
- CLI/packaging owner should review `exposureiq/cli.py` and `pyproject.toml`.
  Viewer assets/evaluation fixtures are package data, not new dependencies.
- Report/viewer owners should review `exposureiq/report/html.py`, `render.py`,
  live-only metadata/drawer assets, authenticated health/native report form and
  one-command saved-report handoff. Referrer policy is `same-origin` for Firefox native POST
  compatibility; exact Host/Origin checks remain. Provider keys are server-only.
- Storage/schema owner need not accept a format migration: `storage.py` and
  `docs/findings-format.md` were not changed. Neither were `web.py`, `scope.py`,
  `scope.txt` or `.github`.
- README edits are confined to the requested features table, quick start and
  Responsible AI section. The older introduction/status/design text still says
  AI is planned; update those only with permission for a broader README edit.
- Real AI/key interoperability, Python 3.10 runtime,
  Windows PowerShell/native batch execution and Windows secret-file ACL security
  remain unverified. Mistral's preset documentation check timed out.
- OpenAI/Anthropic documentation was checked on 2026-11-16. Native Anthropic
  authentication, system/text/tool formats, errors and retries were tested with
  loopback fakes only. Unsupported/server-side blocks fail closed; no provider
  acting tools are enabled.
- Secure web reads fail closed on platforms without descriptor-relative
  `O_NOFOLLOW` support. Typical Windows users should use the TUI/offline reports.
- Risk/verdict and fix/regression labels describe saved observations. Coverage
  inference, bounded digest/list budgets and built-in fallback wording can hide
  nuance; they are
  not a proof of safety, remediation, complete high coverage or model accuracy.
- Stored keys are unencrypted private files; normalized caches may be sensitive.
  A malicious process running as the same local user is outside this boundary.

## Suggested split commits — drafts only

Review `git status` and both tracked/untracked diffs before selecting files.
Do not stage ignored real results, private config/cache or a key. Each draft
below includes AI-assistance disclosure. All summaries are within fifty chars.
These are logical review groups with dependencies, not promises that each split
commit passes independently. Keep this task on one branch/PR; the team chooses
the split and the stage lead squash-merges after review.

### 1. Grounded AI and data core

Group: `.gitignore`, `exposureiq/history.py`, `exposureiq/insight/`,
`exposureiq/ai/` **except** `commands.py`, `evaluate.py` and `fixtures/`,
`tests/conftest.py`, `tests/test_ai_{chat,checker,config,conversation,policy,provider,tools}.py`
and `tests/test_insight_*.py`.

```text
feat(ai): allow natural saved-evidence chat

What I did:
Add bounded digests, code-owned facts, private config/cache,
natural contextual chat, short fallback, first-use definitions
and once-only notices. Keep strict report checks and adapters,
read-only tools and redacted memory-only audit.
Why:
Explain selected saved evidence naturally without giving AI
control of facts or any capability to act on targets.
How to test:
.venv/bin/python -m pytest -q -ra
Stage: 5, natural read-only AI and saved-data core

Written with an AI assistant (opencode).
```

### 2. TUI and saved-domain browsing

Group: `exposureiq/tui/app.py`, the new `ai_log.py`, `ai_panel.py`,
`ai_settings.py`, `domain_browser.py`, `tests/test_tui_ai*.py` and the minimal
changes to `tests/test_saved_open.py`, `test_tui.py`, `test_tui_clipboard.py`,
`test_tui_history.py`.

```text
feat(cli): add contextual TUI chat settings

What I did:
Retain Home/All files; add Simple/Technical chat, common
questions, collapsed Evidence, private settings and honest
reply labels. Keep Off/developer controls, response feedback
and inactive Diff panes from clipping the selected tab.
Why:
Make saved evidence and reviewable drafts easy to understand.
How to test:
.venv/bin/python -m pytest -q tests/test_tui_ai.py
.venv/bin/python -m pytest -q tests/test_tui_ai_chat.py
Stage: 5, TUI integration and domain browsing

Written with an AI assistant (opencode).
```

### 3. CLI, local viewer and offline evaluation

Group: `exposureiq/cli.py`, `exposureiq/ai/commands.py`, `evaluate.py`,
`fixtures/`, `exposureiq/viewer/`, `pyproject.toml`, `tests/test_ai_cli.py`,
`tests/test_ai_eval.py`, `tests/test_viewer.py`.
Exclude the viewer's `export.py`, `static/offline-chat.*`, `static/live-chat.*`
and `static/report-session.js`, which are in group four. The retained intent
helper is `exposureiq/ai/export_intents.py` in group one, not a viewer module.

```text
feat(cli): add secure saved-data web viewer

What I did:
Add offline AI CLI/evaluation and a token-protected loopback
viewer with a one-command saved-report handoff, confined
file reads and literal rendering. Keep
server-side private settings, tab-isolated chat, Clear chat,
Off/stale guards and code-owned paragraph layout.
Why:
Expose saved findings without scan, scope or credential APIs.
How to test:
.venv/bin/python -m pytest -q tests/test_ai_cli.py
.venv/bin/python -m pytest -q tests/test_viewer.py
.venv/bin/exposureiq ai eval
Stage: 5, CLI viewer and fake-model evaluation

Written with an AI assistant (opencode).
```

### 4. Scan-only exports and live HTML AI drawer

Group: `exposureiq/report/html.py`, `render.py`, `exposureiq/viewer/export.py`,
`static/offline-chat.{js,css}` (retained legacy helpers), `static/live-chat.{js,css}`,
`static/report-session.js`,
`tests/test_export_chat.py` and the minimal `tests/test_report_domain.py` change.

```text
feat(report): add local HTML AI drawer

What I did:
Keep disk exports scan-only; add an open/close live AI drawer
with TUI settings, both modes and literal Evidence. Preserve
hash-based CSP, sharing warnings and pre-write size limits.
Use authenticated health/replies; Off hides chat and keys
remain server-side. Never substitute browser-prepared replies.
Why:
Explain saved reports naturally through a small local server
without putting provider credentials in a shared HTML file.
How to test:
.venv/bin/python -m pytest -q tests/test_export_chat.py
.venv/bin/python -m pytest -q tests/test_report_domain.py
.venv/bin/python -m pytest -q tests/test_viewer.py
Stage: 5, scan-only exports and local HTML AI drawer

Written with an AI assistant (opencode).
```

### 5. Safety, reproducible evidence and handoff

Group: the limited `README.md` changes, `docs/ai-safety.md`,
`docs/stage5-presentation.md`, this handoff, `docs/stage5-evidence/`,
all `scripts/stage5_*` capture/fake/browser/package helpers and
`tests/test_stage5_evidence.py`.

```text
docs(ai): refresh safety and offline evidence

What I did:
Document bounded verification and one-command setup; retain
twelve TUI captures, eighty-four turns and evaluation. Refresh
Firefox drawer, full-suite and wheel evidence. Retain failures,
skip reasons and attributed review snapshots.
Why:
Give the team reproducible evidence without overstating it.
How to test:
.venv/bin/python -m pytest -q tests/test_stage5_evidence.py
node scripts/stage5_dom_check.cjs
.venv/bin/python scripts/stage5_export_evidence.py --browser --live --live-repeats 3
Stage: 5, safety presentation and team handoff

Written with an AI assistant (opencode).
```

PR title can be the lead commit's first line. Description: What/Why/How to test,
with these evidence/limitation links. Reviewer: Stage 5 lead (or another member
for the lead's own PR). Staging, commits, push and PR creation remain the user's
next action; no agent Git writes are pending.
