# Tier 3: open the saved HTML report from the TUI

Results and their AI tab have `Open HTML report` in the header and `h` in
the footer. The domain screen and its history AI tab have the same action.
The highlighted domain row—not always the latest scan—is selected. Typing
`h` in a chat/domain input remains text. Settings and confirmation modals do
not enable this shortcut; unsaved results cannot open a report.

`ViewerSession` starts lazily on the first report request: one daemon thread,
`127.0.0.1`, a free port and a fresh per-session token. Repeated openings reuse
the same server. An explicitly opened file in another results folder can
replace only the saved-data catalog, through TUI code, with the original
no-symlink descriptor-relative reader. AI/report locks remain shared across a
folder switch. There is no browser/AI route to choose a root or write files.
Settings replacement updates the existing viewer's service and clears old
chat/retry contexts. App unmount stops the listener; shutdown is idempotent.

The TUI requests a bounded `view=scan` handoff hint. The root viewer still
requires the private fragment token and exact Host/Origin checks; its native
POST sends the session in the body. The server computes an existing
`scan-<hash>` view, rather than accepting an arbitrary anchor from the browser.
Only that saved view is marked in the HTML. Live and AI-Off report scripts
clear the temporary token, select `#scan-<hash>` and activate the matching
scan. Off still has no chat metadata, storage or model call. Ordinary CLI
`exposureiq web <domain> --open` keeps its domain-home behavior and the same
authenticated report path.

Linux requests a quiet `Popen(["xdg-open", url], stdout=DEVNULL,
stderr=DEVNULL)` without a shell, with a standard browser fallback if it cannot
start or returns failure. Other platforms use that fallback directly. A
successful launcher means only **Browser launch requested**, never proof of a
visible page. Failure shows the local URL for manual opening. The TUI always
notifies the URL and explains that it is private and stops on exit.

The first focused run found a real Textual message-registration bug: its
acronym handler name did not match. An explicit `@on(HTMLReportOpened)` fixed
the missing notice and stuck opening state. A later synthetic repeated-click
test was inside Textual's normal two-tenths-of-a-second button effect; the
test now waits for that effect rather than mistaking an ignored click for a
new request. Earlier failed checks remain recorded.

`tier3-browser-run-02.txt` completed nine real Firefox deep-link/lifecycle
checks and captured AI-Off and enabled report views. It selects an older saved
scan, removes the token, reuses the same server after settings replacement,
keeps scan bytes unchanged, makes zero model calls and observes a stopped
listener disabling browser chat. Capture waits for the actual report entrance
animation to finish. Native Windows/default-OS-browser execution is not
tested; unsupported secure file reads still fail closed. Only a passing full,
unfiltered Tier 3 suite can be the final validation result.

The first full suite passed 1,872 tests and four subtests, with sixty-six
Windows/PowerShell skips, but failed the example-only fixture check. Its local
model trial metadata contained a literal loopback address. The correction
keeps the observed trial intact and says “loopback only” instead; it does not
allow new addresses in the fixture validator. The complete suite must rerun.

The complete rerun is green: `tier3-suite-02.txt` records **1,873 passed,
sixty-six skipped and four passing subtests in 223.93 seconds**. No application
source or collected test changed after this run. `git diff --check` is clean.
