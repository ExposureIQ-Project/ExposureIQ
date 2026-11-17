# Observed Tier 1 failure/format outcomes

Synthetic replies and loopback servers only. No real-model accuracy claim.

| Case | Source | Attempts | Result | Retry |
| --- | --- | ---: | --- | --- |
| tagged | Live AI · synthetic-small-model | 1 | Accepted after reference/number checks | No |
| prose | Built-in answer | 2 | reply_format | Yes |
| fences | Live AI · synthetic-small-model | 1 | Accepted after reference/number checks | No |
| surrounding | Live AI · synthetic-small-model | 1 | Accepted after reference/number checks | No |
| trailing_comma | Live AI · synthetic-small-model | 1 | Accepted after reference/number checks | No |
| single_quotes | Live AI · synthetic-small-model | 1 | Accepted after reference/number checks | No |
| truncated | Live AI · synthetic-small-model | 1 | Accepted after reference/number checks | No |
| unfinished_text | Built-in answer | 2 | reply_format | Yes |
| empty | Built-in answer | 2 | empty | Yes |
| injection | Built-in answer | 2 | evidence | Yes |
| provider_connection | Built-in answer | 1 | connection | Yes |
| provider_timeout | Built-in answer | 1 | timeout | Yes |
| provider_auth | Built-in answer | 1 | auth | Yes |
| provider_not_found | Built-in answer | 1 | not_found | Yes |
| provider_bad_request | Built-in answer | 1 | bad_request | Yes |
| provider_unavailable | Built-in answer | 1 | unavailable | Yes |
| invented_number | Built-in answer | 2 | evidence | Yes |
| unknown_reference | Built-in answer | 2 | evidence | Yes |

Every displayed answer passed the saved-facts checker and retained the database focus.
Configured local-model failures never displayed “Offline mode”. Safe prose still needs human review.

Provider failures may use a labelled built-in answer. Browser-server/auth/connection failures must instead show an error, with no prepared answer. Tier 2 browser evidence checks that separate boundary.
