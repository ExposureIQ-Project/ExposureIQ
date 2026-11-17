# Five commit drafts — user review only

Keep `feature/s5-dynamic-chat` as one task branch/PR. These are logical review
groups, not five promises of independently passing intermediate commits.
Several shared files need hunk-level review (selecting parts of a file). Use
the [tier diffs](diffs.md) to distinguish this task from inherited Stage 5 work.
No staging, commit, push or GitHub operation has been performed.

All five subjects are at most fifty characters. Each message includes the
team's What/Why/How to test/Stage fields and AI-assistance attribution.

## 1. Question-aware saved facts

Group: `exposureiq/ai/{intents,facts,fixes,context,chat,conversation,glossary}.py`
and the related parts of `tests/test_dynamic_chat.py` and
`tests/dynamic_chat_fakes.py`. Retain inherited data/schema behavior.

```text
feat(ai): select question-aware saved facts

What I did:
Add fourteen intents, light typo handling, finding and host
follow-up memory, and defensive fix/owner/effort guidance.
Keep counts, severity and sensitive-exposure priority in code.
Why:
Answer the actual question without repeating a scan overview
or letting a model choose facts or actions.
How to test:
TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra
Stage: 5, dynamic saved-facts and defensive guidance

Written with an AI assistant (opencode).
```

## 2. Small-model replies and honest fallback

Group: `exposureiq/ai/{plain,prompts,checker,provider,service,fallback,schema,policy}.py`,
reply-label/retry/log parts of `exposureiq/tui/{ai_panel,ai_log}.py`,
`exposureiq/viewer/server.py` and `static/app.js`, plus their AI/TUI/viewer tests.
Review shared Tier 1 files together; do not replace inherited code wholesale.

```text
fix(ai): ground small-model chat replies

What I did:
Use short tagged plain-text prompts, tolerant decoding and
a shorter retry. Check references and typed facts, preserve
strict summaries, and add redacted memory-only attempt logs.
Label every live or built-in answer and keep retry focus.
Why:
Handle imperfect small-model replies without claiming their
whole wording is verified or calling live failures offline.
How to test:
TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra
Stage: 5, small-model phrasing and checked fallback

Written with an AI assistant (opencode).
```

## 3. Split-screen browser chat

Group: Tier 2 parts of `exposureiq/report/html.py`,
`exposureiq/viewer/{export,server}.py`, `static/live-chat.{js,css}`,
`tests/test_split_chat.py` and the related `tests/test_viewer.py` changes.

```text
feat(report): add split-screen saved chat

What I did:
Add independent half-width panes, a bounded accessible
divider, tab-local layout, one options menu, real progress,
copy/retry controls and narrow full-screen chat.
Preserve private authentication, CSP and scan-only exports.
Why:
Keep the report visible while discussing saved findings
without moving the reader or exposing provider credentials.
How to test:
TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra
Stage: 5, split-screen local browser chat

Written with an AI assistant (opencode).
```

## 4. Open HTML reports from the TUI

Group: `exposureiq/viewer/{browser,session}.py`, Tier 3 parts of
`exposureiq/tui/{app,domain_browser}.py`, `exposureiq/cli.py`,
`exposureiq/report/html.py`, `exposureiq/viewer/{server,export}.py`,
`static/{app,live-chat,report-session}.js`, `tests/test_report_open.py`
and launcher changes in `tests/test_ai_cli.py`.

```text
feat(cli): open saved HTML from the TUI

What I did:
Add Open HTML report and h on results/domain/AI screens.
Reuse one free-port loopback daemon, select the exact saved
scan, notify its private URL and stop the viewer on exit.
Use a quiet Linux launcher with a standard fallback.
Why:
Open saved reports without another terminal, target traffic
or losing the existing authenticated web --open command.
How to test:
TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra
Stage: 5, TUI saved-report opening and viewer lifecycle

Written with an AI assistant (opencode).
```

## 5. Evidence and team handoff

Group: `tests/fixtures/dynamic_chat/`, `docs/stage5-handoff.md` and current
provenance assertions in `tests/test_stage5_evidence.py`. Keep historical
`docs/stage5-evidence/` captures/manifests and capture helpers intact. Review
the large inherited untracked set separately before choosing what to include.

```text
docs(ai): record dynamic-chat validation

What I did:
Record full-suite results and skips, complete before/after
answers, synthetic failure cases and real Firefox captures.
Document the installed Qwen trial, limits, protected hashes,
tier diffs and attributed commit drafts. Retain failures.
Why:
Give the team observed evidence without overstating model
accuracy, browser coverage or inherited work.
How to test:
TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra
Stage: 5, dynamic-chat evidence and team handoff

Written with an AI assistant (opencode).
```

The user selects files/hunks, stages and commits. The Stage 5 lead reviews and
squash-merges the PR; another member reviews the lead's own work. Do not add
private settings/cache, real results or credentials to a commit.
