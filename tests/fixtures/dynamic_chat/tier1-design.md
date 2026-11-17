# Tier 1 diagnosis and boundaries

The previous path forced a JSON object in the OpenAI-compatible request and
then accepted only strict JSON. Both “most bad” and “how can I fix it” missed
the previous question selectors and reached the same scan-overview fallback.
This reproduces the code path behind the reported repetition. It is not a
claim about the accuracy of Saif's real `qwen2.5:3b-instruct` installation.

The new path is:

1. Check the original question against the existing defensive safety gate.
2. Select intent, remembered finding/host and priority in Python.
3. Read only validated saved evidence; build a short intent-specific facts pack.
4. Ask the configured endpoint for short plain text with existing evidence tags.
5. Bind typed numbers and references to that pack, run the bounded checker,
   remove unsupported secondary sentences only when enough answer remains,
   and reject an unsupported lead or known unsafe instructions.
6. Try one shorter prompt, then use the same facts pack for a labelled built-in
   answer. A provider failure never changes the saved scan.

The model no longer receives tool definitions, a full digest, the entire
glossary or a fallback to copy. Code-selected saved-data reads remain available.
The model cannot act, contact a scan target, change scope or run commands.
The fixed recheck reminder is text for an authorized human, with the original
scope and opt-in checks; a passive-only rerun cannot validate active findings.

## Facts badge

`Facts checked against your saved scan` appears only after the checker ran.
It describes bounded reference, typed-number, severity/focus and priority
checks—not semantic proof of every sentence. The result keeps
`verification = "evidence-and-facts"` and `wording_verified = False` for
model-written prose. Evidence includes this limitation. Fix steps, usual owners
and effort ranges are general guidance, not scan observations or promises.

Every phrasing attempt records its number, reply length, first three hundred
redacted characters and parse error in the existing memory-only AI log.
System instructions and credentials are excluded. No conversation or API log
is written to a scan snapshot or an AI cache.

## Ollama options

Read `https://docs.ollama.com/openai` during this task. The documented
OpenAI-compatible chat options include `temperature` and `max_tokens`; the
page explicitly says that this API has no context-size parameter. Chat uses
temperature 0.3, a 640-token output allowance and no forced JSON response
format. No undocumented `num_ctx` or native-only options are sent to `/v1`.
The request content is capped at 6,000 UTF-8 bytes—about 1,500 tokens, not a
measured tokenizer count. History is shortened before relevant facts are lost.

## Evidence

`before-transcripts.json` loads the preserved pre-task source in a disposable
child process. `after-transcripts.json` uses the working code. Both capture
the exact seven requested questions through built-in answers and a loopback
small-model-shaped fake server. The after fake deterministically phrases the
facts pack; it proves the request/parsing/checking path, not model reasoning.

`tier1-preflight-01.txt` through `tier1-preflight-03.txt` retain failures found
while developing. `tier1-preflight-04.txt` records 343 passing focused checks.
Only an unfiltered `tier1-suite-*.txt` run can authorize moving to Tier 2.
The earlier Stage 5 evidence remains unchanged and historical.

The first full Tier 1 run found two evidence regressions (1,841 passed).
The old fresh-wording fake expected the superseded prompt; its current host
regression now uses an independent facts-pack fake without editing the old
helper. Historical browser source hashes remain capture-time provenance.
`source-provenance.json` pins the unchanged earlier manifest and explicitly
names sources replaced by this task; untouched source hashes and every earlier
artifact hash are still checked. The original capture hashes were compared
with the preserved pre-task sources and matched. New browser evidence must
validate the new tiers separately; no earlier result is rewritten as current.
