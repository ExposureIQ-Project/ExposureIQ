# Actual task-only source diffs

Tier diffs compare preserved pre-task and green-tier snapshots. The ordinary Git diff also includes inherited tracked Stage 5 work; it omits untracked packages. No staging/commit/push/gh command ran.

| Tier | Source/test files | Added lines | Removed lines | Full diff |
| --- | ---: | ---: | ---: | --- |
| 1 | 28 | 1792 | 285 | [tier1-source.patch](tier1-source.patch) |
| 2 | 8 | 402 | 63 | [tier2-source.patch](tier2-source.patch) |
| 3 | 14 | 595 | 48 | [tier3-source.patch](tier3-source.patch) |

New acceptance scripts, synthetic transcripts, screenshots and documentation are listed by the full [Git status](git-status.txt); they are not hidden inside source-diff counts.

## Changed source/test files

### Tier 1

- `exposureiq/ai/chat.py` (+100/−79)
- `exposureiq/ai/checker.py` (+76/−2)
- `exposureiq/ai/context.py` (+93/−29)
- `exposureiq/ai/conversation.py` (+3/−2)
- `exposureiq/ai/facts.py` (+259/−0)
- `exposureiq/ai/fixes.py` (+175/−0)
- `exposureiq/ai/glossary.py` (+4/−2)
- `exposureiq/ai/intents.py` (+95/−0)
- `exposureiq/ai/plain.py` (+113/−0)
- `exposureiq/ai/policy.py` (+5/−2)
- `exposureiq/ai/prompts.py` (+46/−56)
- `exposureiq/ai/provider.py` (+25/−10)
- `exposureiq/ai/schema.py` (+67/−7)
- `exposureiq/ai/service.py` (+56/−23)
- `exposureiq/tui/ai_log.py` (+8/−3)
- `exposureiq/tui/ai_panel.py` (+39/−11)
- `exposureiq/viewer/server.py` (+4/−2)
- `exposureiq/viewer/static/live-chat.js` (+9/−2)
- `tests/dynamic_chat_fakes.py` (+140/−0)
- `tests/fixtures/dynamic_chat/source-provenance.json` (+15/−0)
- `tests/test_ai_chat.py` (+19/−15)
- `tests/test_ai_cli.py` (+2/−1)
- `tests/test_ai_conversation.py` (+15/−14)
- `tests/test_ai_provider.py` (+21/−8)
- `tests/test_dynamic_chat.py` (+311/−0)
- `tests/test_tui_ai.py` (+4/−4)
- `tests/test_tui_ai_chat.py` (+56/−9)
- `tests/test_viewer.py` (+32/−4)

### Tier 2

- `exposureiq/report/html.py` (+4/−0)
- `exposureiq/viewer/export.py` (+11/−3)
- `exposureiq/viewer/server.py` (+42/−3)
- `exposureiq/viewer/static/live-chat.css` (+87/−39)
- `exposureiq/viewer/static/live-chat.js` (+139/−16)
- `tests/fixtures/dynamic_chat/source-provenance.json` (+12/−0)
- `tests/test_split_chat.py` (+102/−0)
- `tests/test_viewer.py` (+5/−2)

### Tier 3

- `exposureiq/cli.py` (+4/−3)
- `exposureiq/report/html.py` (+7/−4)
- `exposureiq/tui/app.py` (+88/−5)
- `exposureiq/tui/domain_browser.py` (+24/−2)
- `exposureiq/viewer/browser.py` (+39/−0)
- `exposureiq/viewer/export.py` (+3/−2)
- `exposureiq/viewer/server.py` (+22/−19)
- `exposureiq/viewer/session.py` (+76/−0)
- `exposureiq/viewer/static/app.js` (+5/−3)
- `exposureiq/viewer/static/live-chat.js` (+6/−2)
- `exposureiq/viewer/static/report-session.js` (+6/−2)
- `tests/fixtures/dynamic_chat/source-provenance.json` (+12/−0)
- `tests/test_ai_cli.py` (+6/−6)
- `tests/test_report_open.py` (+297/−0)

## Unavailable pre-task delta

- `tests/test_stage5_evidence.py`: Inherited before this task, but absent from the pre-task source snapshot. Its exact Tier 1 delta is unavailable, not reconstructed or counted as a new file. See [changed-tests.md](changed-tests.md) and the [current source](../../test_stage5_evidence.py).

## Protected boundaries

All four protected files match their pre-task hashes; `.github` has no tracked change. Nothing is staged. The existing virtual environment was reused; no dependency installation or pyproject edit was made in this task.
