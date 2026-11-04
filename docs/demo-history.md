# Ten-scan demo history

```bash
exposureiq scan example.com --demos
```

This is a **simulated story, not a real incident**. No discovery, DNS, HTTP,
TLS or port-scan tools run. No exploitation is attempted, and no confirmed
compromise or CVE is invented. Evidence explains potential service risks;
the existing check rules supply the actual severity and recommendations.

`--demo` still makes one sample scan. `--demos` makes ten snapshots using
`example.com`, documentation-only IP addresses, and fixed dates from
1–10 October 2026. There is no randomness or current-clock data in the JSON.

## Story

The full demo (without `--passive` or `--no-apex`) has this fixed timeline:

| Scan | Hosts | High | Medium | Low | What happened |
| --- | ---: | ---: | ---: | ---: | --- |
| 1 | 4 | 0 | 0 | 2 | Baseline public HTTPS sites; routine header/version hardening |
| 2 | 5 | 0 | 2 | 3 | Staging deployment adds an exposed administration console |
| 3 | 7 | 5 | 5 | 3 | Firewall regression exposes Redis, MySQL, Telnet and SMB; a certificate expires |
| 4 | 9 | 11 | 8 | 4 | Peak: more databases, RDP/VNC and administration services become public |
| 5 | 9 | 7 | 9 | 4 | Containment closes some services; an emergency self-signed certificate still needs work |
| 6 | 8 | 1 | 8 | 4 | Remote access is restricted; one public database remains |
| 7 | 7 | 0 | 2 | 4 | Database and certificate fixes take effect; browser policies remain |
| 8 | 6 | 0 | 1 | 2 | Legacy systems are retired; one browser policy still needs hardening |
| 9 | 4 | 0 | 0 | 2 | Temporary hosts are retired; routine low-severity items remain |
| 10 | 4 | 0 | 0 | 1 | Normal range: only HTTPS ports and one referrer-policy privacy item |

The medium count can briefly rise during recovery because an emergency
self-signed certificate reduces a high-severity outage to a medium-severity
trust issue. It is then properly fixed. Findings never have their severity
randomly changed to manufacture a trend.

## Files and options

- JSON: `results/example.com/demo_history_01.json` through `demo_history_10.json`.
- PDFs: `report/example.com/example.com_DEMO-HISTORY-01.pdf` through `…-10.pdf`.
- HTML export: `report/example.com/index.html`, with all ten dated scan cards.
- `--plain`: same output files without the full-screen TUI.
- `--no-report`: keep all ten JSON files, skip automatic PDFs.
- `--no-save`: display the story only; no JSON or reports are written.
- `--passive`: keep simulated discovery, omit sample ports/check findings.
- `--no-apex`: omit the `example.com` host itself.
- `-o demo-results/`: put the ten JSON files in `demo-results/example.com/`.
- `-o story.json`: write `story_01.json` through `story_10.json`.

Repeating an identical demo reuses existing JSON files without rewriting them.
If any numbered output contains different data, the entire set is checked and
rejected before new snapshots are written. Choose another output directory
when changing demo options. Nothing changes the user's scope files.

## Explore the history

After generation, the TUI shows scan 10. Browse saved results to open scan 3
or 4 and inspect the peak findings. Its **Diff** tab shows history only through
that scan. **Export → HTML** creates the whole-domain workspace; **DOCX** exports
the selected snapshot.

```bash
exposureiq diff results/example.com/demo_history_03.json
exposureiq diff example.com                       # first → latest compatible scan
exposureiq report example.com --format html --open
exposureiq report results/example.com/demo_history_05.json --format docx
```

The HTML home lists newest scans first. Select a card for its findings and
inventory, or hover a chart for a dashed cursor, scan number and UTC date. Click
the nearest point to scroll to that scan's exact change entry. Graphs grow on
their first reveal; reduced-motion preferences disable animation.

Scan details show overall baseline-to-selected changes and each intermediate step.
Scan 3 uses only scans 1–3; scan 5 uses 1–5; scan 10 uses the whole story. The
findings trend chart preserves the rise and recovery even when the overall
net change is small. Later scans never leak into an earlier scan's detail view,
PDF or DOCX. The home page intentionally shows the full saved domain history.

For a custom JSON directory, pass `--results-dir demo-results/` to the report
command. Single-file diffs and TUI exports use the selected file's directory.
Demo history stays separate from real scans and unrelated one-off demos.
Older flat files remain readable without being moved or overwritten.
