# Tier 2 layout and safety

The authenticated report has a scrollable report region and chat region.
Desktop starts at half-and-half. The divider supports pointer dragging, arrow
keys and Home/End within a thirty-to-seventy-percent range. Only that layout
percentage is stored in `sessionStorage` for the current tab. No token, question,
reply, settings or credential is stored there.

Chat uses sixteen-pixel text, its own scroll area and a sticky composer.
New replies follow the bottom only when the reader is already near it. The
page retains at most thirty UI turns in memory; the model still sees only the
last three exchanges and the code-resolved focus. Close restores report width,
report scroll and button focus. Below nine hundred pixels, chat fills the
viewport and keeps keyboard focus outside the inert report. Reduced-motion
preferences remove the chat animation and transitions.

One `Chat options` popover holds Scan, Wording, Ideas to ask, configured-model
status, Check settings and Clear chat. Three suggestion chips appear only in
an empty chat. Replies have a source badge, Copy answer, an optional Try again,
a bounded checked-facts note and one collapsed Evidence row. Inline references
are not shown in the answer text. Clipboard success is reported only after the
browser API succeeds; otherwise the answer is selected for manual copying.

Live stages are not guessed from time. The existing chat service calls a
memory-only progress callback for Reading your scan, Phrasing your answer and
Checking the facts. The page reads that state from an authenticated same-origin
route using a bounded request and conversation ID. It contains no question,
answer, credentials or actions, and is cleared when AI is switched off.

The Host/Origin/session boundary, no-redirect same-origin browser networking,
server-only provider settings, CSP hashes and escaped inert metadata remain.
All dynamic text uses `textContent`. Disk exports and AI-Off reports do not
get the chat region, split layout, storage code or live metadata. No model is
called by opening the panel, checking settings or reading progress. Provider
failures may use the labelled saved-facts answer; browser/server failures do
not substitute prepared answers.

`tier2-preflight-01.txt` records 209 passing focused structure, report and
security checks. `check_split_browser.py` uses the installed Firefox through
the existing local control helper; it installs nothing, gives Firefox a fresh
profile and a minimal key-free environment, and uses only synthetic reserved
data and loopback fakes. Its screenshot/JSON outputs count as new evidence
only after the check actually finishes successfully. A narrow headless browser
viewport is not a native phone test.

The unfiltered Tier 2 run passed: 1,851 tests, sixty-six skips and four
subtests in 224.94 seconds. `tier2-browser-run-06.txt` completed nineteen
real-browser checks and five screenshots, including the provider-format
fallback and retry focus after an SMB detour. Earlier browser recheck failures
were handoff/readiness waits in the capture helper; they remain recorded. The
passing check requires a new authenticated report document, restored layout
and ready input before sending; it does not weaken application checks.
