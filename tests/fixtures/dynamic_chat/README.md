# Dynamic chat validation

Task branch: `feature/s5-dynamic-chat`, preserving the uncommitted Stage 5 work
from `feature/s5-human-voice` with Saif's approval. No checkout/pull of main,
staging, commit, push or GitHub CLI operation is part of this task.

The existing `.venv` is reused. Whole-suite runs use
`TMPDIR=/tmp/opencode .venv/bin/python -m pytest -q -ra` with no selection filters.
Test/tool temporary files use the existing approved temporary directory.
Evidence uses synthetic saved scans, offline fakes and loopback servers. The
separate optional trial reached the installed local Ollama/Qwen model; its
observed answers and limits are in `ollama-trial.json` and `ollama-advice.md`.
No real key, remote model, download or scan-target traffic was used.

All three full gates are green. [Final evidence](final-evidence.md) contains
the observed last suite lines and skips, complete transcript links, failure
outcomes, screenshots, the local-model trial and review limits.

- [Complete before/after answers](transcripts.md)
- [Synthetic failure table](failure-table.md)
- [Changed tests](changed-tests.md)
- [Actual Git status and task-only tier diffs](diffs.md)
- [Five attributed commit drafts](commit-drafts.md)

Earlier Stage 5 artifacts are retained; they do not validate this new
implementation. Failed checks are also retained, not hidden or relabelled.
