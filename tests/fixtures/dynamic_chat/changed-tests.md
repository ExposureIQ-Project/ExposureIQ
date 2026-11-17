# Test changes in this task

Earlier uncommitted Stage 5 tests are preserved. The changes below are relative
to the pre-task source snapshot, not a claim that this branch started clean.

## Tier 1

- `tests/test_dynamic_chat.py` (new): all fourteen intents and light typos;
  distinct finding/fix/effort/owner/verify replies; complete emitted-rule fix
  guidance; exact question sequence; prose and recoverable/malformed JSON;
  typed numbers/references; retry focus; ordinals; refusal/no-call boundaries;
  host-scoped counts; memory-only diagnostic redaction; HSTS human guidance.
- `tests/dynamic_chat_fakes.py` (new): reserved-data scan and fake loopback
  small-model reply shapes. The fake proves parsing and transport, not model
  accuracy. Fresh host wording uses the code facts without an old prompt.
- `tests/test_ai_chat.py`, `tests/test_ai_conversation.py`: update superseded
  model-selected-tool/two-call, full-digest prompt and old label expectations.
  Keep host score forty-five, follow-up focus, conditional consequences,
  unknown-evidence, off-topic and unsafe-output checks. Three-theme limits are
  intentional; explicit finding questions still cover every rule.
- `tests/test_ai_provider.py`: reject unexpected native Anthropic tool calls
  without executing extra reads; accept plain tagged text through the same
  checker. Keep the real transport's endpoint/redirection/secret boundaries.
- `tests/test_ai_cli.py`, `tests/test_tui_ai.py`, `tests/test_tui_ai_chat.py`,
  `tests/test_viewer.py`: honest per-message labels and bounded facts notes;
  actual stage names; memory-only attempt details; conversation-bound retries.
- `tests/test_stage5_evidence.py`: unchanged historical artifact hashes remain
  enforced. Capture-time source hashes have explicit replacement provenance
  instead of falsely treating earlier screenshots as current-code validation.
  The current fresh-host regression uses a facts-pack fake; the old evidence
  helper and old transcripts were not rewritten.
  This inherited test was not copied into the pre-task snapshot, so its exact
  task-only delta cannot be shown. The diff review does not count its entire
  current source as newly written.

## Tier 2

- `tests/test_split_chat.py` (new): live-only pane/menu markup, bounded divider,
  literal rendering and real progress while a phraser is blocked. Progress
  requires the same session/Origin and a bounded conversation/request pair;
  it is memory-only, bounded and cleared when AI is off.
- `tests/test_viewer.py`: the live page may store exactly one tab-local layout
  percentage. No other storage or provider connection is permitted. Disk and
  AI-Off script prohibitions remain unchanged.
- `tests/fixtures/dynamic_chat/check_split_browser.py` (new): optional real
  installed-Firefox capture, no package installation, fresh isolated profile,
  synthetic saved strings and loopback-only fakes. Screenshots and outcomes
  are accepted only from a completed passing run.

## Tier 3

Started only after the unfiltered Tier 2 suite passed.

- `tests/test_report_open.py` (new): fake quiet Linux launcher/standard fallback,
  loopback-only URLs, one lazy free-port daemon, fresh tokens, idempotent stop,
  shared locks during an active-request folder switch and no-symlink roots.
  Native deep-link POST keeps exact Origin/token/CSP checks and Off behavior.
  Headless results/domain/AI buttons and `h` reuse the actual viewer; input
  typing stays text; missing scans and failed launchers show honest notices.
- `tests/test_ai_cli.py`: patch the shared launcher, not the old direct
  `webbrowser.open`, so tests never open a real OS browser. Keep the one-command
  source/handoff, explicit `--open` and invalid-source/no-scan checks.
- `tests/fixtures/dynamic_chat/check_report_browser.py` (new): installed Firefox
  observes older/newer scan deep links, token removal, service/server reuse,
  AI-Off content, unchanged scan bytes and actual listener shutdown.
- The historical provenance manifest explicitly names the newly replaced CLI,
  root-viewer handoff and Off-session script; earlier artifacts remain intact.
