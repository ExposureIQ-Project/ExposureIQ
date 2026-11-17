# Final evidence: three green dynamic-chat tiers

**Delivered:** question-aware saved-data answers and follow-up memory;
accessible split-screen browser chat; `Open HTML report` and `h` on the TUI
results, domain and AI screens. Inherited Stage 5 work is preserved on
`feature/s5-dynamic-chat`. Nothing is staged, committed or pushed.

## Complete suite gates

Every gate reused the existing virtual environment and ran the whole suite:

```text
TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra
```

There were no test selections, `--ignore` options or exclusions in these gates.
The exact final lines are:

| Gate | Observed final line | Full log | Six status lines |
| --- | --- | --- | --- |
| Fresh baseline | `1775 passed, 66 skipped, 4 subtests passed in 214.24s (0:03:34)` | [baseline-suite.txt](baseline-suite.txt) | [baseline-status.txt](baseline-status.txt) |
| Tier 1 | `1843 passed, 66 skipped, 4 subtests passed in 226.65s (0:03:46)` | [tier1-suite-02.txt](tier1-suite-02.txt) | [tier1-status.txt](tier1-status.txt) |
| Tier 2 | `1851 passed, 66 skipped, 4 subtests passed in 224.94s (0:03:44)` | [tier2-suite-01.txt](tier2-suite-01.txt) | [tier2-status.txt](tier2-status.txt) |
| Tier 3 | `1873 passed, 66 skipped, 4 subtests passed in 223.93s (0:03:43)` | [tier3-suite-02.txt](tier3-suite-02.txt) | [tier3-status.txt](tier3-status.txt) |

Each green run had **zero failures**. Of the sixty-six skips, sixty-five require
PowerShell and one requires native Windows batch execution. The full logs keep
every skip reason and test location. Runtime validation used **Python 3.14.8**;
Python 3.10 and native Windows runtime validation are unavailable, not passed.
No dependency was added in this task. `git diff --check` passed.

The ordered gates were respected: Tier 2 started only after green Tier 1, and
Tier 3 only after green Tier 2. Focused checks were extra diagnostics, not
substitutes for the full suite. Failed full runs and browser checks remain
recorded. The first full Tier 3 run rejected a literal loopback address in
trial metadata; the metadata now says “loopback only”. No application source,
observed answer or fixture-validation rule was changed for that correction.

## Why answers now differ

- Fourteen question intents (question types), light typo tolerance and shared
  code-selected facts route definitions, fixes, effort, ownership, history,
  priority and opinion separately. Follow-ups retain finding/theme/host focus,
  including “it”, “that one”, “the first one”, “the other one” and “that host”.
- Code owns counts, severity, sensitive-exposure ranking, verdict and priority.
  The defensive fix registry supplies definitions, impact, steps, usual owners,
  effort ranges and human verification guidance for the checks' rule families.
- Both live and built-in replies use the same facts pipeline. Built-in wording
  is selected deterministically from the scan ID and question. SIMPLE remains
  the default, TECHNICAL remains available, and courtesy needs no model call.
- Chat asks for short plain text with finding/rule tags, not forced JSON. It
  checks references and typed facts, tries one shorter prompt when necessary,
  then uses an honestly labelled checked built-in answer. Recoverable JSON and
  fences are still tolerated; report/summary content checking remains strict.
- Every model attempt records bounded redacted diagnostic details in memory
  only. The approximately 1,500-token prompt budget is a byte-budget estimate,
  not a tokenizer measurement. No model acting tools are provided.

## Complete answers, before and after

[transcripts.md](transcripts.md) contains **all twenty-eight answers**, not
selected excerpts: seven questions through each before/after built-in and
fake-server path. The exact required sequence is retained, from “what is the
most bad finding here in this scan?” through fix, effort, opinion, SMB, owner
and thanks. Machine-readable records are [before-transcripts.json](before-transcripts.json)
and [after-transcripts.json](after-transcripts.json).

The before path uses preserved pre-task source. It reproduces the forced-format
repair failure and repeated generic paragraphs. The after fake server phrases
the checked facts deterministically: it proves the transport, parser, facts
checking and focus pipeline, **not real-model reasoning accuracy**. The
database focus persists through its fix/effort/opinion questions; SMB changes
the focus, so the owner reply then discusses SMB. The banned generic lead
`The saved scan shows things your team can tighten` is not used in new replies.

## Failure and security boundaries

[failure-table.md](failure-table.md) records eighteen synthetic observed
outcomes, with [tier1-failures.json](tier1-failures.json) as the machine-readable
record: tagged prose, recoverable and malformed JSON, empty content, injection,
invented numbers/references and provider failures. Unsupported or unsafe model
content does not become an unlabelled answer. Retries keep the original
question/finding focus.

Provider failures may return **Built-in answer**, with a reason and Try again.
Browser/viewer authentication or connection failures instead show an error and
disable chat; no prepared answer replaces a stopped or unauthenticated viewer.
Both boundaries were exercised in the real-browser checks below.

**Facts checked against your saved scan** means the code ran bounded
reference/number/focus checks. It is not proof of every model-written sentence;
live prose retains `wording_verified = False` and needs human review. General
fix steps, effort and owners are advice, not measured scan facts or promises.

Schema **0.2** is unchanged. The AI reads saved data only: no target probes,
scope changes, acting tools, exploits or executed suggestions. Loopback-only
serving, exact Host/Origin checks, fresh session tokens, same-origin handoff,
hash-based CSP, escaped inert JSON, literal rendering, server-side credentials,
endpoint-confined provider calls and no external assets remain enforced.
Disk exports are still scan-only; AI-Off reports contain no chat metadata.

## Real Firefox screenshots

The final rechecks completed **nineteen split-chat checks** and **nine
report-lifecycle/deep-link checks**, with **seven real screenshots**. The
manifests match each image's size/hash and the sources used at capture time.

| Evidence | Capture |
| --- | --- |
| Desktop half-width panes and live answer | [split-desktop.png](split-desktop.png) |
| One Chat options menu | [split-menu.png](split-menu.png) |
| Actual blocked model-phrasing stage | [split-stage.png](split-stage.png) |
| Labelled fallback and Try again | [split-fallback.png](split-fallback.png) |
| Narrow full-screen chat, sticky input | [split-narrow.png](split-narrow.png) |
| Exact older scan, AI off | [report-open-off.png](report-open-off.png) |
| Newer scan after service/server reuse | [report-open-live.png](report-open-live.png) |

- Split recheck: [tier3-split-browser-run-02.txt](tier3-split-browser-run-02.txt),
  [tier2-browser.json](tier2-browser.json). The manifest filename is retained;
  its current images/hashes come from this final passing recheck.
- Report recheck: [tier3-browser-run-02.txt](tier3-browser-run-02.txt),
  [tier3-browser.json](tier3-browser.json).
- Browser checks observed real divider dragging/keyboard bounds, tab-only
  persistence, Enter/Shift+Enter, collapsed Evidence, clipboard acknowledgement,
  Esc/focus restoration, non-disruptive scrolling, narrow inert/modal behavior,
  retry focus after an SMB detour, auth failures and an actually stopped server.
- The report checks observed selected older/newer scan anchors, token removal,
  one reused daemon/port, settings replacement, no opening/health model calls,
  unchanged scan bytes and shutdown disabling browser chat. Headless TUI tests
  additionally exercised buttons, `h`, URL notices and typing `h` as chat text.

Firefox used an isolated fresh profile and a refusing proxy for external HTTP;
Python evidence sockets were limited to loopback. Desktop was **1280 × 914**;
narrow was **500 × 814**, not a real phone. Native mobile browsers, Windows and
the actual OS-default browser were not observed. Quiet Linux launch/fallback
was tested with fakes; a successful launcher means “Browser launch requested”,
not proof that a browser window appeared.

## Installed local Qwen trial

The installed `qwen2.5:3b-instruct` received the synthetic seven-question
sequence through local Ollama. **Three live replies**, **three checked
fallbacks** and **one no-call thanks** took **15.08 seconds** and **eleven
attempts**. No model was downloaded and no saved settings or real API key was
read. Full visible answers are in [ollama-trial.json](ollama-trial.json);
[ollama-advice.md](ollama-advice.md) explains observed failures and size advice.

This single trial did not repeat the old generic answers, but 3B was not
consistently successful. Keep it if memory is tight and labelled fallback is
acceptable; consider a 7B instruct model for steadier phrasing if memory allows.
Roughly eight-to-twelve GB free is a planning estimate for a compressed 7B
model plus working memory, **not a measurement here**. No 7B trial ran.
Documented Ollama `/v1` options were checked; no undocumented context-size or
`num_ctx` option was added. More parameters do not replace code checks or review.

## Review and ownership

- [diffs.md](diffs.md): real task-only source/test diffs by tier, compared with
  preserved pre-task and green-tier snapshots; complete available patches are
  linked. The inherited `tests/test_stage5_evidence.py` had no pre-task source
  copy, so its exact Tier 1 delta is unavailable, not reconstructed or counted
  as a newly written file. Its documented changes/current source are linked.
- [git-status.txt](git-status.txt), [git-diff-stat.txt](git-diff-stat.txt) and
  [git-working-tree.patch](git-working-tree.patch): actual Git state and tracked
  diff. That ordinary diff includes inherited Stage 5 changes and omits the
  untracked packages; it is not mislabelled as only this task.
- [review.json](review.json): protected-file hashes and review counts.
  `fingerprint/web.py`, `discovery/scope.py`, `scope.txt` and `storage.py` match
  pre-task hashes. `.github` is untouched; no `AGENTS.md` was created.
- [changed-tests.md](changed-tests.md): changed tests and why their old
  expectations changed. Historical captures/manifests remain byte-for-byte
  intact, with explicit [source provenance](source-provenance.json).
- [commit-drafts.md](commit-drafts.md): five messages with subjects at most
  fifty characters, What/Why/How to test/Stage and
  `Written with an AI assistant (opencode).` No commit was run.

The user reviews files/hunks, stages and commits; the Stage 5 lead reviews the
PR and squash-merges. No agent staging, commit, push or PR action is pending.
