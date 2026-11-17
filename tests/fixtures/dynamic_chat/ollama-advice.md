# Observed local Qwen trial and size advice

The installed `qwen2.5:3b-instruct` was reached through local Ollama's
OpenAI-compatible `/v1`. No model was downloaded. The trial used the synthetic
reserved-name/address acceptance scan, explicit temporary local settings,
blocked external sockets/DNS and no saved settings or API key. Nothing scanned,
executed a suggested command or modified a saved scan.

The seven requested questions produced:

| Question | Observed result | Model attempts |
| --- | --- | ---: |
| What is the most bad finding? | Live database explanation | 1 |
| Then how can I fix it? | Live defensive database steps | 2 |
| How long would that take? | Checked built-in database effort range | 2 |
| What do you think? | Checked built-in database opinion | 2 |
| What does SMB mean? | Live SMB definition | 2 |
| Who should fix it? | Checked built-in SMB owner guidance | 2 |
| Thanks | Built-in courtesy; no model call | 0 |

Three of six substantive replies were live; three fell back honestly. Eleven
model attempts took 15.08 seconds in this single trial, including the first
reply's 5.55 seconds. The answers did not repeat the old generic overview and
follow-up focus stayed appropriate: database through opinion, SMB through its
owner question. No configured-live failure displayed “Offline mode”.

Full user-visible replies are in `ollama-trial.json`. Raw attempt diagnostics
were not exported; they remained in memory. Its first summary counter used
the wrong source name (`ai` instead of `local`); the counter was corrected from
the unchanged captured turns, with no extra model call. The original printed
run is retained. Reference/number checking does not prove every prose claim,
and this small synthetic trial is not a general accuracy benchmark.

The first full Tier 3 suite rejected the trial's literal loopback address as
non-example fixture text. Only that network metadata was changed to “loopback
only”; recorded questions, answers, timings and source hashes stayed intact.
The application was not changed, the fixture rule was not weakened and no
extra inference ran for that correction.

**Advice:** keep 3B if memory is tight and clearly labelled built-in answers are
acceptable. For steadier instruction following, consider a 7B-class instruct
model, such as `qwen2.5:7b-instruct`, if the machine has enough free memory.
Four-bit quantization means compressed model weights; a typical 7B model can
need roughly five GB for weights plus additional working/context memory.
Planning for roughly eight-to-twelve GB free is safer than counting weights
alone. These are approximate planning figures, not measured on this machine.
A 7B model was neither downloaded nor tested here. More parameters can help
wording/formatting; they do not replace the saved-facts checker or human review.

Ollama's documented OpenAI-compatible options were checked before changes:
`https://docs.ollama.com/openai`. The application uses temperature 0.3 and a
640-token chat output allowance without forced JSON. It sends no undocumented
`num_ctx`/context-size option to `/v1`; its short prompt budget is approximately
1,500 tokens, not a tokenizer measurement.
