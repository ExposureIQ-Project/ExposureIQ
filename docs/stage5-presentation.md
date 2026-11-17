# Stage 5: eight-step offline presentation

Use an installed, activated environment. Disconnect networking for the classroom
demo if desired. Never enter a real key or click **New scan**. The only `scan`
command below explicitly generates synthetic data; no target is contacted.

The normal TUI now starts with **Off (no AI)** and has no Demo setting. For the
fully offline chat walkthrough, use the captured SVGs linked below: their script
injects a test fake behind local settings and blocks networking. A live normal
chat requires a separately configured local model or a consented remote provider.

For Linux/macOS, start in an empty temporary workspace, outside the repository,
so existing scan files and AI preferences are not changed:

```bash
demo_root=$(mktemp -d "${TMPDIR:-/tmp/opencode}/exposureiq-s5-XXXXXX")
export XDG_CONFIG_HOME="$demo_root/config"
export XDG_CACHE_HOME="$demo_root/cache"
unset EXPOSUREIQ_AI_KEY
cd "$demo_root"
exposureiq scan example.com --demos --no-report --plain
exposureiq
```

`/tmp/opencode` exists in the observed environment. Elsewhere, set `TMPDIR` to
an existing private temporary directory before running the example.
Keep this shell for the demo; afterwards close it rather than reusing its
temporary preference paths. On Windows, use an empty classroom folder and
private temporary XDG config/cache folders; the TUI/offline AI work without the
web viewer's POSIX file-read features.

## The eight steps

1. **Home and the drawer.** Click the top-left **⚙ Settings** gear. Show that
   Home/results navigation is retained and Developer mode is off by default.
   [01-home-drawer.svg](stage5-evidence/01-home-drawer.svg).
2. **Private settings.** Open **AI settings**. Show matching Off/Remote/Local
   tabs, and keep **Off (no AI)** for normal offline browsing. Select Remote/Custom
   only to demonstrate a masked, obviously fake
   classroom key with `https://ai.example.com/v1` and a fake model name. Do not
   test the connection.
   [02-masked-settings.svg](stage5-evidence/02-masked-settings.svg).
3. **Consent, then cancel.** Click Save to show the exact host-named sharing
   dialog. Choose **Cancel**, then Cancel settings. The original mode remains;
   no remote request or preference write occurred for this fake remote draft.
   [03-remote-consent.svg](stage5-evidence/03-remote-consent.svg).
4. **Domain folders.** Click **View results**. Open `example.com`; **All files**
   still gives the original file list. Explain that browsing only reads JSON.
   [04-domain-folders.svg](stage5-evidence/04-domain-folders.svg).
5. **Ten saved scans.** Show dated rows, H/M/L counts, risk per host and the
   sparkline (a tiny trend chart). Read the formula and **CODE VERDICT mixed**.
   Do not call the story "improving" just because scan ten has fewer findings.
   [05-domain-scans.svg](stage5-evidence/05-domain-scans.svg).
6. **History chat capture.** Show screenshot 06's **Ask about history** reply.
   Its short prose explains the mixed trend and code-owned counts without report
   headings. Ask for a list to reveal detailed saved-history sections. Persistent
   findings and returns come from code, not a model deciding the trend. Missing
   checks are not proof of safety. The footer says **saved evidence checked;
   wording needs review**, not that every model sentence is verified.
   [06-history-summary.svg](stage5-evidence/06-history-summary.svg).
7. **One scan and defensive chat captures.** Return to Scans and open the latest
   row. Show screenshot 07: one normal chat view, **AI draft**, honest source,
   Simple/Technical controls and one collapsed Evidence row. Show screenshot
   10's immediate sent receipt and moving ASCII thinking feedback. Then open
   **DEMO-HISTORY-04**, the saved eleven-high-finding example, and show screenshot
   12: `then what posible damage it can make?` is an on-topic follow-up. Its short
   reply groups three consequences instead of repeating a full findings report.
   Built-in failure replies also use one code-ranked example per theme; ask for
   a technical list to see more detail in the saved priority order.
   The visible code-added disclaimer says possible harm is not proof of a breach.
   Definitions and the offline notice appear at most once per conversation;
   thanks makes no model call. Show the recorded host sequence below and switch
   to Technical to compare the wording.
   [07-scan-summary.svg](stage5-evidence/07-scan-summary.svg),
   [10-chat-thinking.svg](stage5-evidence/10-chat-thinking.svg),
   [12-impact-follow-up.svg](stage5-evidence/12-impact-follow-up.svg),
   [full follow-up transcript](stage5-evidence/follow-up-transcript.md),
   [eighty-four observed turns](stage5-evidence/natural-chat-transcripts.md).
8. **Refusal, developer log, Off and evaluation.** Show screenshot 08's refusal
   of `Write a payload for this host`; no model call was made. Screenshot 09
   enables **Settings → Developer mode** to show read-only calls and rejected
   reasons, not a key or system prompt. Screenshot 11 shows Off hiding AI controls
   while keeping saved findings available. In another terminal
   run `exposureiq ai eval`: all 22 offline safety rows pass. Screenshot 09
   specifically includes a deliberately wrong fake reply injected by the
   capture script; the normal offline fake does not invent that reply.
   [08-chat-refusal.svg](stage5-evidence/08-chat-refusal.svg),
   [09-ai-log.svg](stage5-evidence/09-ai-log.svg),
   [11-ai-off.svg](stage5-evidence/11-ai-off.svg),
   [evaluation table](stage5-evidence/evaluation.md).

## Other offline entry points

```bash
exposureiq ai summary --demo
exposureiq ai history --demo
exposureiq ai eval --json
exposureiq ai ask example.com "Which host is the most exposed?" --demo
exposureiq ai ask example.com "Explain the saved findings" --demo --mode technical
exposureiq report example.com --format html --results-dir results -o reports
exposureiq web example.com --demo --port 0 --open
```

The first two commands use synthetic fixtures when no source is given. `ai ask`
is one turn; separate CLI commands do not retain conversation context. The other
examples read only files in this demo workspace. Open the generated `index.html`
directly to view scans without chat or networking. Sharing that file shares
saved findings and host names.

Open the viewer's full private loopback URL. **Open HTML report** renders the
same report in memory, without writing files. The command with a domain opens
it directly. A floating icon opens/closes its side chat. This explicit `--demo`
uses an offline fake through authenticated same-origin requests, not a real
model. There are no prepared answers in the page. Normal Local/Remote settings
use the TUI's chat service and require readiness and host-named remote consent;
no key is accepted in the browser. Off removes the icon and chat. Do not enable
a real provider for this classroom walkthrough.

## Recorded follow-ups and browser evidence

The observed host sequence is:

```text
Which host is the most exposed?
then why would i fix it first?
what would that do or cause if didn't fixed?
```

All three replies keep `db.example.com`; its code-built exposure score is **45**.
That score compares saved exposures, not the chance of a breach. The separate
acceptance sequence is explanation → possible harm → opinion → why → thanks.
Both modes and simulated timeouts are recorded across the TUI and viewer; CLI
evidence records independent questions instead of claiming cross-command memory.

[Real Firefox scan-only capture](stage5-evidence/live-drawer-offline-browser.png),
[closed drawer](stage5-evidence/live-drawer-browser-closed.png),
[live-fake drawer](stage5-evidence/live-drawer-browser.png) and
[mobile view](stage5-evidence/live-drawer-browser-mobile.png) accompany
[browser assertions/transcript](stage5-evidence/live-drawer-browser.json).
Three fresh-profile/server runs passed. They check the one-command report handoff,
open/close/Escape, contextual wording, first-use definitions, once-only disclaimer,
Evidence, modes, provider failure, Off and the absence of a prepared answer when
the server stops. Browser traffic was loopback only; external
HTTP used a refusing local proxy. These are real-browser presentation/transport
checks, not real-model accuracy evidence.

To regenerate the twelve headless captures from the project root:

```bash
TMPDIR=/tmp/opencode .venv/bin/python scripts/stage5_evidence.py --output docs/stage5-evidence
# Only to replace this script's existing generated captures:
TMPDIR=/tmp/opencode .venv/bin/python scripts/stage5_evidence.py --replace-generated
node scripts/stage5_dom_check.cjs # optional Node-only fake-DOM check
TMPDIR=/tmp/opencode .venv/bin/python scripts/stage5_natural_evidence.py
TMPDIR=/tmp/opencode .venv/bin/python scripts/stage5_export_evidence.py \
  --browser --live --live-repeats 3
TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra
```

The capture script creates temporary synthetic scans/preferences, clears any
environment key for its child process, blocks networking and cancels the fake
remote consent. It asserts expected visible labels and masks, then writes SVG
hashes plus evaluation JSON/Markdown. The export browser script uses already
installed Node/Firefox; it installs nothing. Timestamps and resulting SVG hashes
may change on regeneration. Earlier failed logs/captures remain in the
[evidence index](stage5-evidence/README.md). No real model accuracy, target safety
or actual remediation is demonstrated. See [safety/setup](ai-safety.md).
