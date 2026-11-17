# Observed Stage 5 evidence

All data here is synthetic. No real key, real model endpoint or target traffic
was used. The twelve SVGs are actual Textual headless captures at **132 × 54**
terminal cells. Only Rich's external font rules were removed so they open
offline; text, colours, geometry and clipping were retained. The masked key is
fake and the remote confirmation was cancelled.

| Capture | What it demonstrates |
| --- | --- |
| [01 · Home/drawer](01-home-drawer.svg) | Retained Home, Settings gear and sliding drawer with Developer mode off. |
| [02 · Masked settings](02-masked-settings.svg) | Uniform Off/Remote/Local tabs, Custom endpoint and a masked fake key; no connection test. |
| [03 · Remote consent](03-remote-consent.svg) | Exact destination host, explicit confirm/cancel; cancelled in the script. |
| [04 · Domain folders](04-domain-folders.svg) | Domain-first results and retained All files browser. |
| [05 · Domain scans](05-domain-scans.svg) | Ten dated rows, counts, code verdict and risk sparkline. |
| [06 · History chat](06-history-summary.svg) | Short prose with code-owned changes, persistent findings and confirmed returns. |
| [07 · User scan chat](07-scan-summary.svg) | Simple/Technical control, honest draft source and evidence footer; no developer logs. |
| [08 · Chat refusal](08-chat-refusal.svg) | An offensive request refused without a model call; distinct sent/reply messages. |
| [09 · Developer AI log](09-ai-log.svg) | Developer-only redacted audit and fake-data badge; deliberately wrong fake rejected. |
| [10 · Thinking feedback](10-chat-thinking.svg) | Fake reply deliberately held pending; immediate sent receipt and moving ASCII indicator. |
| [11 · AI Off](11-ai-off.svg) | AI controls hidden, saved-scan Summary still available, plain synthetic-data warning retained. |
| [12 · Damage follow-up](12-impact-follow-up.svg) | Exact natural-language question; conditional consequences and references on the saved peak-exposure sample. |

The normal TUI has no AI Demo setting. These captures inject an offline
fresh-wording test fake behind local settings; no local URL is contacted. The legacy 06/07
filenames remain for existing links, but the visible UI is chat-only.

[The full two-turn transcript](follow-up-transcript.md) reproduces the reported
eleven-high-finding example using **DEMO-HISTORY-04**, not the low-finding scan ten.
The short consequence reply groups three themes, keeps evidence references and
shows the once-only code-added disclaimer. Its footer says **saved evidence
checked; wording needs review**. Bounded checks are not full verification of
arbitrary prose. Strict summary/report evaluation still uses approved sentences.

[Cross-interface transcripts](natural-chat-transcripts.md) and
[structured turns](natural-chat.json) record twenty cases and eighty-four turns:
both modes, the acceptance and three-turn host sequences, no-call thanks and
simulated timeout fallback. CLI commands are independent turns, not a persistent
chat. The selected `db.example.com` host retains code score 45; eleven global
high findings do not become eleven findings on that host.

The capture run exposed and fixed a pre-existing Diff-pane visibility problem:
making an inactive pane visible pushed AI controls below the screen. Regression
tests now check that only the selected pane is displayed at two screen sizes.

## Evaluation table

[Complete 22-row table](evaluation.md) · [structured result](evaluation.json)

| Offline group | Observed outcome |
| --- | --- |
| Eight normal summary drafts | 8/8 accepted; displayed claims verified. |
| Eight deliberately wrong summary drafts | 8/8 rejected; checked template shown; included highs covered. |
| Six policy rows (three questions × two fakes) | 6/6 refused; zero model calls. |
| Total | **22/22 safety rows passed.** |

This is safety regression evidence, **not a real-model accuracy benchmark**.
Token counts are length-based estimates. See the full JSON for rejected reasons
and the normal/wrong provider call counts, including a JSON repair.

## Reproducibility and validation

### Current local HTML drawer

The local-server drawer supersedes the earlier prepared-chat export design.
Disk HTML is scan-only; live pages contain snapshot metadata and question ideas,
not prepared answers. Real replies use the same service/settings as the TUI.
Off removes the icon/drawer; a stopped server does not substitute saved text.
Optional L3 remains off.

- [live-drawer-final-suite.txt](live-drawer-final-suite.txt): **1775 passed,
  66 skipped, 4 subtests passed in 226.48s**. Complete virtual-environment suite,
  no selection filters. Sixty-five skips need PowerShell; one needs native
  Windows batch execution. These are unrun, not passes.
- [live-drawer-final-status.txt](live-drawer-final-status.txt): six final status
  lines; local HTML drawer is green, optional L3 off.
- [live-drawer-browser-confirmed.txt](live-drawer-browser-confirmed.txt): current
  real Firefox checks, repeated with **three fresh profiles/servers**.
- [live-drawer-browser.json](live-drawer-browser.json) and
  [three repeat runs](live-drawer-repeatability.json): one-command native report
  handoff, open/close/Escape/focus, mobile bounds, contextual replies, both modes,
  no model call for health/greetings/thanks, literal Evidence, scan/context
  clearing, provider fallback, Off and server-stop handling.
- [Scan-only Firefox image](live-drawer-offline-browser.png),
  [closed drawer](live-drawer-browser-closed.png),
  [open drawer](live-drawer-browser.png) and
  [mobile layout](live-drawer-browser-mobile.png): actual installed Firefox
  captures. The requested 390-wide browser window was clamped by Firefox;
  recorded content bounds were **500 × 758** pixels. This is not a native-phone test.
- [live-drawer-dom-check.txt](live-drawer-dom-check.txt): the actual embedded
  drawer script with fake DOM/fetch; checks relative authenticated requests,
  settings-driven visibility, malformed/stale replies and no prepared substitute.
- [live-drawer-structure.json](live-drawer-structure.json): ten synthetic scans;
  **408,373 bytes** disk / **433,305 bytes** local-server report. Disk HTML has
  **one executable script, zero inert JSON blocks and zero external assets**.
- [live-drawer-manifest.json](live-drawer-manifest.json): current source and
  browser/transcript/image hashes, not a claim about real-model accuracy.
- [live-drawer-focused-current.txt](live-drawer-focused-current.txt): **211 passed**.
- [live-drawer-final-package-check.txt](live-drawer-final-package-check.txt) and
  [offline wheel build](live-drawer-final-wheel-build.txt): isolated installed-wheel
  imports, packaged drawer assets, scan-only disk output and enabled/Off server
  pages. **84** Python files pass Python 3.10 grammar parsing; runtime was **3.14.8**.
- [live-drawer-viewer-dom.txt](live-drawer-viewer-dom.txt): shipped domain-list
  viewer script with fake DOM/fetch; this is not visual browser evidence.
- [live-drawer-handoff-check.txt](live-drawer-handoff-check.txt): resolved local
  documentation links, unchanged dependencies/protected files, UTF-8/Unix text,
  **69 changed Python files** passing Python 3.10 grammar and five attributed
  split commit drafts. No Python 3.10 runtime is installed or claimed.

### Retained pre-drawer baseline

- [manifest.json](manifest.json): twelve filenames, actual byte counts, SHA-256
  checksums, observed labels and the follow-up transcript hash.
- [natural-short-fallback-final-suite.txt](natural-short-fallback-final-suite.txt):
  **1767 passed, 66 skipped, 4 subtests passed in 240.54s**. This is the pre-drawer full virtual-environment suite, without
  selection filters; exact skip reasons are retained. Sixty-five skips require
  PowerShell and one requires native Windows batch execution. They did not pass.
- [natural-short-fallback-final-status.txt](natural-short-fallback-final-status.txt): six status lines; mandatory
  natural-chat and the earlier export L1/L2 tiers were green. Optional L3 stays off.
- [natural-safeguards-focused-current.txt](natural-safeguards-focused-current.txt):
  246 passed; [natural-presentation-focused.txt](natural-presentation-focused.txt):
  285 passed; [natural-short-fallback-regressions.txt](natural-short-fallback-regressions.txt):
  **358 passed**. The full suite supersedes these focused runs.
- [natural-short-fallback-captures.txt](natural-short-fallback-captures.txt): twelve
  headless captures and evaluation 22/22.
- [natural-short-fallback-transcripts.txt](natural-short-fallback-transcripts.txt) and
  [natural-manifest.json](natural-manifest.json): eighty-four observed turns with
  transcript/JSON hashes, fresh-wording and timeout fakes only.
  Recorded fallback replies peak at **118 words**; the multi-finding defaults are
  regression-checked under 180 words, without removing requested list detail.
- [natural-short-fallback-package-check.txt](natural-short-fallback-package-check.txt): current isolated wheel
  imports, all chat assets/fixtures, CLI commands and a ten-scan offline report.
- [natural-short-fallback-wheel-build.txt](natural-short-fallback-wheel-build.txt): build with existing local tools
  from a private source snapshot outside the repository;
  no dependencies installed or downloaded.
- [natural-handoff-check.txt](natural-handoff-check.txt): local documentation links,
  five attributed draft messages, unchanged dependencies/protected files and
  UTF-8/Unix text checks. Sixty-nine changed Python files also pass Python 3.10
  grammar parsing; no extra runtime-compatibility claim is made.
- [natural-viewer-dom-refreshed.txt](natural-viewer-dom-refreshed.txt): actual
  shipped viewer script with fake DOM/fetch; not a browser visual test.
- [export-short-fallback-final-capture.txt](export-short-fallback-final-capture.txt): actual embedded
  offline/live scripts, Python/JavaScript parity and real Firefox checks, repeated
  three times with fresh profiles and servers.
- [export-structure.json](export-structure.json): ten scans, twelve intents,
  both modes, **1,406,175 bytes** offline / **1,415,223 bytes** live report;
  offline has two executable scripts, one inert JSON block, no external assets.
- [export-parity.json](export-parity.json) and [export-dom-check.txt](export-dom-check.txt):
  forty phrase routes and thirty turns agree between Python and shipped JavaScript.
- [export-live-dom-check.txt](export-live-dom-check.txt): token/relative-request
  boundaries, literal Evidence, consent, conversation isolation, stale/Off guards
  and server-failure fallback with fake DOM/fetch.
- [Offline Firefox PNG](export-browser-l1.png), [offline checks/JSON](export-browser-l1.json),
  [live-fake Firefox PNG](export-browser-l2.png),
  [browser checks/transcript](export-browser-l2.json) and
  [three repeat runs](export-l2-repeatability.json): real installed Firefox,
  synthetic evidence and loopback/offline fake transport only. These do not
  establish real-model accuracy or provider interoperability.
- [Eight-step presentation](../stage5-presentation.md) and [safety/setup](../ai-safety.md).

### Earlier results and retained failures

Earlier green baselines are historical, not validation of the final safeguards:
[natural Tier 1](natural-tier1-suite.txt) (1636 passed),
[export L1](export-l1-suite.txt) (1723 passed),
[export L2](export-l2-suite.txt) (1751 passed), and
[the pre-redesign suite](follow-up-test-suite.txt) (1522 passed). The
[1763-pass earlier final run](natural-final-suite.txt) and its
[six status lines](natural-final-status.txt) predate the short-fallback fix;
the 1767-pass suite also predates the live HTML drawer.
All also recorded 66 skips and four passing subtests. Older package/DOM outputs
and the original [test-suite.txt](test-suite.txt) remain available.

Failures are not hidden or relabelled green. In particular:

- [live-drawer-focused-initial.txt](live-drawer-focused-initial.txt) retains a
  test fixture missing the report's `tool_version`; the fixture was corrected.
- [live-drawer-browser-final.txt](live-drawer-browser-final.txt) retains a
  server-stop timing failure: a readiness check can disable Send before clicking.
  The browser assertion now checks either a sent-question unavailable reply or
  a disabled composer with the failed-health explanation and **no answer**.
  [The confirmed rerun](live-drawer-browser-confirmed.txt) passes all three sessions.
- [live-drawer-browser-initial.txt](live-drawer-browser-initial.txt) and
  [live-drawer-script-initial.txt](live-drawer-script-initial.txt) are earlier
  green drawer checks, before final screenshot/source-manifest refinements.
- [natural-tui-safeguards-initial.txt](natural-tui-safeguards-initial.txt) retains
  the old-heading assertion; its replacement checks short default history and
  detailed sections only on request.
- [natural-tui-capture-current.txt](natural-tui-capture-current.txt),
  [diagnostic run](natural-tui-capture-diagnostic.txt) and
  [failed SVG](failures/12-impact-follow-up.svg) retain off-screen disclaimer
  evidence. Shorter fake prose made it visible; the safeguard already existed.
- [natural-transcripts-capture.txt](natural-transcripts-capture.txt) retains the
  viewer paragraph mismatch. Private fields are now redacted before code-owned
  paragraph layout is built; tests preserve redaction and paragraph breaks.
- [export-l2-safeguards-browser.txt](export-l2-safeguards-browser.txt) and
  [safe enable diagnostic](export-l2-enable-diagnostic.txt) retain the early
  disabled-checkbox click. The helper now checks readiness and clicks in the same
  browser task, avoiding a native-POST/page-load race without weakening Origin.
- [natural-final-safeguards.txt](natural-final-safeguards.txt) and earlier export
  diagnostic logs remain intermediate failures. Despite its filename,
  [export-l2-capture-success.txt](export-l2-capture-success.txt) is a failed run;
  use the current final capture/suite above, not names, to judge success.
- [natural-short-fallback-initial.txt](natural-short-fallback-initial.txt) retains
  a wrong test assumption: an explicitly injected offline fake does not become
  unavailable just because its configuration says Off.
  [natural-short-fallback-confirmed.txt](natural-short-fallback-confirmed.txt)
  then uses an unavailable timeout fake and records the overlong default replies
  (344/324 words) and nine finding citations. The fix chooses one code-ranked
  example per theme and retains longer technical lists only when requested.

### Regenerate with installed tools only

```bash
TMPDIR=/tmp/opencode .venv/bin/python scripts/stage5_evidence.py --replace-generated
TMPDIR=/tmp/opencode .venv/bin/python scripts/stage5_natural_evidence.py
TMPDIR=/tmp/opencode .venv/bin/python scripts/stage5_export_evidence.py \
  --browser --live --live-repeats 3
node scripts/stage5_dom_check.cjs
TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra
```

Build a wheel from an empty, private source snapshot with **already-installed**
build tools (copy `exposureiq/`, `pyproject.toml`, `README.md` and `LICENSE` first):

```bash
cd "/tmp/opencode/<private-source-snapshot>"
python3 -m pip wheel --no-deps --no-build-isolation --no-index \
  --wheel-dir /tmp/opencode/s5-wheel .
cd /path/to/ExposureiQ
.venv/bin/python scripts/stage5_package_check.py \
  --wheel /tmp/opencode/s5-wheel/exposureiq-0.1.0-py3-none-any.whl
```

Replace the placeholder paths before running the wheel example.

`/tmp/opencode` was the approved temporary directory in this environment; choose
your own empty private temporary directory elsewhere. The observed build used
existing system setuptools/wheel because they were absent from the venv. No
runtime dependency was added. Runtime validation used **Python 3.14.8 on Linux**;
all **84** packaged Python files passed Python 3.10 grammar parsing, but no Python
3.10 executable is installed here and runtime compatibility is untested. No real
AI service/key test was run. TUI SVGs and real Firefox PNGs are presentation
evidence, not proof of target safety, remediation or real-model correctness.
