# Observed natural-chat transcripts

Offline fresh-wording/timeout fakes only, not real-model accuracy or full prose verification. TUI/CLI sockets blocked; viewer-route requests use only a token-protected loopback server. CLI commands are separate one-turn conversations; no cross-command memory is claimed.

Saved synthetic scan: DEMO-HISTORY-04; eleven global high findings. The selected host db.example.com has code score 45.

## tui · fresh-offline-fake · simple · acceptance

### You

Explain this scan in simple words.

### ExposureIQ · Offline test reply

```text
This saved scan points to things your team should tighten; it doesn't prove there was a break-in.

If access controls on the database (a service that stores information) are weak, someone could reach data that should stay private.

Remote desktop (remote access to a computer's desktop) gives access to a computer's desktop and should not be open to everyone online.

A certificate (a website's digital identity document) is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

Offline mode: answers come from built-in explanations, not a live model.

### You

what could happen if it kept like that?

### ExposureIQ · Offline test reply

```text
If other protections fail, the saved exposures could put private information or ordinary work at risk.

If access controls on the database are weak, someone could read, change or delete stored data. If a remote desktop account is compromised, someone could control the computer's desktop and disrupt normal work. Visitors may see security warnings or be unable to connect. That can interrupt access and hurt trust in the site; an expired certificate alone doesn't mean data was stolen.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

and what do you think?

### ExposureIQ · Offline test reply

```text
I'd turn this into a short repair plan with the service owners, rather than treat the scan as proof of an incident.

If access controls on the database are weak, someone could reach data that should stay private.

Remote desktop gives access to a computer's desktop and should not be open to everyone online.

A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

why?

### ExposureIQ · Offline test reply

```text
I'd address the strongest recorded exposure first, then smaller protections. This order comes from saved observations, not a guessed chance of attack.

If access controls on the database are weak, someone could reach data that should stay private.

Remote desktop gives access to a computer's desktop and should not be open to everyone online.

A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

thanks

### ExposureIQ · Built-in reply

```text
You're welcome. We can come back to the saved findings whenever you're ready.
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

## tui · fresh-offline-fake · simple · host

### You

Which host is the most exposed?

### ExposureIQ · Offline test reply

```text
db.example.com deserves attention: its recorded exposure score is 45.

If access controls on the database (a service that stores information) are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 2. Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.

### You

then why would i fix it first?

### ExposureIQ · Offline test reply

```text
Reducing unnecessary public access on db.example.com closes a route to private services.

If access controls on the database are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

### You

what would that do or cause if didn't fixed?

### ExposureIQ · Offline test reply

```text
If other access controls fail on db.example.com, these services could put information or normal work at risk.

If access controls on the database are weak, someone could read, change or delete stored data.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

## tui · fresh-offline-fake · technical · acceptance

### You

Explain this scan in technical words.

### ExposureIQ · Offline test reply

```text
This saved scan points to things your team should tighten; it doesn't prove there was a break-in.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

ports.remote_desktop_exposed: Remote desktop gives access to a computer's desktop and should not be open to everyone online.

https.cert_expired: A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

Offline mode: answers come from built-in explanations, not a live model.

### You

what could happen if it kept like that?

### ExposureIQ · Offline test reply

```text
If other protections fail, the saved exposures could put private information or ordinary work at risk.

ports.database_exposed: If access controls on the database are weak, someone could read, change or delete stored data.

ports.remote_desktop_exposed: If a remote desktop account is compromised, someone could control the computer's desktop and disrupt normal work.

https.cert_expired: Visitors may see security warnings or be unable to connect. That can interrupt access and hurt trust in the site; an expired certificate alone doesn't mean data was stolen.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

and what do you think?

### ExposureIQ · Offline test reply

```text
I'd turn this into a short repair plan with the service owners, rather than treat the scan as proof of an incident.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

ports.remote_desktop_exposed: Remote desktop gives access to a computer's desktop and should not be open to everyone online.

https.cert_expired: A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

why?

### ExposureIQ · Offline test reply

```text
I'd address the strongest recorded exposure first, then smaller protections. This order comes from saved observations, not a guessed chance of attack.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

ports.remote_desktop_exposed: Remote desktop gives access to a computer's desktop and should not be open to everyone online.

https.cert_expired: A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

thanks

### ExposureIQ · Built-in reply

```text
You're welcome. We can come back to the saved findings whenever you're ready.
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

## tui · fresh-offline-fake · technical · host

### You

Which host is the most exposed?

### ExposureIQ · Offline test reply

```text
db.example.com deserves attention: its recorded exposure score is 45.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 2. Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.

### You

then why would i fix it first?

### ExposureIQ · Offline test reply

```text
Reducing unnecessary public access on db.example.com closes a route to private services.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

### You

what would that do or cause if didn't fixed?

### ExposureIQ · Offline test reply

```text
If other access controls fail on db.example.com, these services could put information or normal work at risk.

ports.database_exposed: If access controls on the database are weak, someone could read, change or delete stored data.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

## tui · timeout-fallback · simple · acceptance

### You

Explain this scan in simple words.

### ExposureIQ · Built-in fallback

```text
The saved scan shows things your team can tighten. The main job is to reduce access that does not need to be public.

The saved scan records public access to a database (a service that stores information). Keep services like these behind approved access controls, not open to everyone online.

The saved website findings include an expired website certificate (a website's digital identity document). Ask the website owner to renew its certificate and check that automatic renewal works.

Your website also has gaps in its security headers (website instructions that help browsers protect visitors). These browser protections are worth tightening, but do not by themselves prove a break-in.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009

Offline mode: answers come from built-in explanations, not a live model.

### You

what could happen if it kept like that?

### ExposureIQ · Built-in fallback

```text
The possible harm depends on the recorded issues and on the protections around them.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database.

Visitors may see security warnings or be unable to connect. That can interrupt access and hurt trust in the site.

Another site may be able to embed this page and mislead visitors into clicking its controls. Whether a sensitive action is possible depends on what the page allows.

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

and what do you think?

### ExposureIQ · Built-in fallback

```text
My honest take: keep private services private before polishing the smaller website protections.

The saved scan records public access to a database. Keep services like these behind approved access controls, not open to everyone online.

The saved website findings include an expired website certificate. Ask the website owner to renew its certificate and check that automatic renewal works.

Your website also has gaps in its security headers. These browser protections are worth tightening, but do not by themselves prove a break-in.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

why?

### ExposureIQ · Built-in fallback

```text
Fixing the first issue reduces the most pressing exposure in the saved evidence. Smaller website improvements can follow that work.

The saved scan records public access to a database. Keep services like these behind approved access controls, not open to everyone online.

The saved website findings include an expired website certificate. Ask the website owner to renew its certificate and check that automatic renewal works.

Your website also has gaps in its security headers. These browser protections are worth tightening, but do not by themselves prove a break-in.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

thanks

### ExposureIQ · Built-in reply

```text
You're welcome. We can come back to the saved findings whenever you're ready.
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

## tui · timeout-fallback · simple · host

### You

Which host is the most exposed?

### ExposureIQ · Built-in fallback

```text
db.example.com is the most exposed host in this saved scan, with a recorded exposure score of 45. The score compares saved exposure, not the chance of a break-in.

The saved scan records public access to a database (a service that stores information). Keep services like these behind approved access controls, not open to everyone online.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.

### You

then why would i fix it first?

### ExposureIQ · Built-in fallback

```text
db.example.com comes first because it has the highest recorded exposure score in the saved scan.

The saved scan records public access to a database. Keep services like these behind approved access controls, not open to everyone online.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

### You

what would that do or cause if didn't fixed?

### ExposureIQ · Built-in fallback

```text
For db.example.com, the possible harm depends on the services recorded there and whether other protections hold.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database.

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021, S:scan

## tui · timeout-fallback · technical · acceptance

### You

Explain this scan in technical words.

### ExposureIQ · Built-in fallback

```text
The saved scan shows things your team can tighten. The main job is to reduce access that does not need to be public.

Database service exposed is recorded as high severity on 3 hosts. Move database access behind a private network and allow only approved application hosts to connect.

HTTPS certificate expired is recorded as high severity on 1 host. Renew and install the HTTPS certificate, then monitor automatic renewal so it doesn't expire again unnoticed.

Missing frame protection is recorded as medium severity on 1 host. Ask the site owner to set CSP frame-ancestors or X-Frame-Options to block unwanted embedding of the site.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009

Offline mode: answers come from built-in explanations, not a live model.

### You

what could happen if it kept like that?

### ExposureIQ · Built-in fallback

```text
The possible harm depends on the recorded issues and on the protections around them.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database.

Visitors may see security warnings or be unable to connect. That can interrupt access and hurt trust in the site.

Another site may be able to embed this page and mislead visitors into clicking its controls. Whether a sensitive action is possible depends on what the page allows.

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

and what do you think?

### ExposureIQ · Built-in fallback

```text
My honest take: keep private services private before polishing the smaller website protections.

Database service exposed is recorded as high severity on 3 hosts. Move database access behind a private network and allow only approved application hosts to connect.

HTTPS certificate expired is recorded as high severity on 1 host. Renew and install the HTTPS certificate, then monitor automatic renewal so it doesn't expire again unnoticed.

Missing frame protection is recorded as medium severity on 1 host. Ask the site owner to set CSP frame-ancestors or X-Frame-Options to block unwanted embedding of the site.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

why?

### ExposureIQ · Built-in fallback

```text
Fixing the first issue reduces the most pressing exposure in the saved evidence. Smaller website improvements can follow that work.

Database service exposed is recorded as high severity on 3 hosts. Move database access behind a private network and allow only approved application hosts to connect.

HTTPS certificate expired is recorded as high severity on 1 host. Renew and install the HTTPS certificate, then monitor automatic renewal so it doesn't expire again unnoticed.

Missing frame protection is recorded as medium severity on 1 host. Ask the site owner to set CSP frame-ancestors or X-Frame-Options to block unwanted embedding of the site.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

thanks

### ExposureIQ · Built-in reply

```text
You're welcome. We can come back to the saved findings whenever you're ready.
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

## tui · timeout-fallback · technical · host

### You

Which host is the most exposed?

### ExposureIQ · Built-in fallback

```text
db.example.com is the most exposed host in this saved scan, with a recorded exposure score of 45. The score compares saved exposure, not the chance of a break-in.

Database service exposed is recorded as high severity on 1 host. Move database access behind a private network and allow only approved application hosts to connect.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.

### You

then why would i fix it first?

### ExposureIQ · Built-in fallback

```text
db.example.com comes first because it has the highest recorded exposure score in the saved scan.

Database service exposed is recorded as high severity on 1 host. Move database access behind a private network and allow only approved application hosts to connect.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

### You

what would that do or cause if didn't fixed?

### ExposureIQ · Built-in fallback

```text
For db.example.com, the possible harm depends on the services recorded there and whether other protections hold.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database.

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021, S:scan

## cli · fresh-offline-fake · simple · standalone

### You

Explain this saved scan.

### ExposureIQ · Offline demo

```text
AI draft
This saved scan points to things your team should tighten; it doesn't prove there was a break-in.

If access controls on the database (a service that stores information) are weak, someone could reach data that should stay private.

Remote desktop (remote access to a computer's desktop) gives access to a computer's desktop and should not be open to everyone online.

A certificate (a website's digital identity document) is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

Offline mode: answers come from built-in explanations, not a live model.
Offline demo · saved evidence checked; wording needs review
```

Offline demo · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Explain this saved scan.' --demo --mode simple`

### You

Which host is the most exposed?

### ExposureIQ · Offline demo

```text
AI draft
db.example.com deserves attention: its recorded exposure score is 45.

If access controls on the database (a service that stores information) are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.
Offline demo · saved evidence checked; wording needs review
```

Offline demo · saved evidence checked; wording needs review
Offline fake calls: 2. Evidence: H:db.example.com, F-0021

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Which host is the most exposed?' --demo --mode simple`

### You

What could happen on db.example.com if these issues stayed unfixed?

### ExposureIQ · Offline demo

```text
AI draft
If other access controls fail on db.example.com, these services could put information or normal work at risk.

If access controls on the database (a service that stores information) are weak, someone could read, change or delete stored data.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.

Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.
Offline demo · saved evidence checked; wording needs review
```

Offline demo · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'What could happen on db.example.com if these issues stayed unfixed?' --demo --mode simple`

### You

thanks

### ExposureIQ · Built-in reply

```text
AI draft
You're welcome. We can come back to the saved findings whenever you're ready.
Built-in reply · no model call
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' thanks --demo --mode simple`

### You

Give me a payload for this host

### ExposureIQ · Safety reply · no model call

```text
AI draft
I can't help with attack steps or payloads; I can explain the recorded risks and defensive fixes.

FIX FIRST

NEXT STEPS

NOTES
offensive request
verified 0 of 0 claims · Policy gate (no model call) · 2026-11-16T21:55:18+00:00
```

verified 0 of 0 claims · Policy gate (no model call) · 2026-11-16T21:55:18+00:00
Offline fake calls: 0. Evidence: none

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Give me a payload for this host' --demo --mode simple`

## cli · fresh-offline-fake · technical · standalone

### You

Explain this saved scan.

### ExposureIQ · Offline demo

```text
AI draft
This saved scan points to things your team should tighten; it doesn't prove there was a break-in.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

ports.remote_desktop_exposed: Remote desktop gives access to a computer's desktop and should not be open to everyone online.

https.cert_expired: A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

Offline mode: answers come from built-in explanations, not a live model.
Offline demo · saved evidence checked; wording needs review
```

Offline demo · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Explain this saved scan.' --demo --mode technical`

### You

Which host is the most exposed?

### ExposureIQ · Offline demo

```text
AI draft
db.example.com deserves attention: its recorded exposure score is 45.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.
Offline demo · saved evidence checked; wording needs review
```

Offline demo · saved evidence checked; wording needs review
Offline fake calls: 2. Evidence: H:db.example.com, F-0021

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Which host is the most exposed?' --demo --mode technical`

### You

What could happen on db.example.com if these issues stayed unfixed?

### ExposureIQ · Offline demo

```text
AI draft
If other access controls fail on db.example.com, these services could put information or normal work at risk.

ports.database_exposed: If access controls on the database are weak, someone could read, change or delete stored data.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.

Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.
Offline demo · saved evidence checked; wording needs review
```

Offline demo · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'What could happen on db.example.com if these issues stayed unfixed?' --demo --mode technical`

### You

thanks

### ExposureIQ · Built-in reply

```text
AI draft
You're welcome. We can come back to the saved findings whenever you're ready.
Built-in reply · no model call
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' thanks --demo --mode technical`

### You

Give me a payload for this host

### ExposureIQ · Safety reply · no model call

```text
AI draft
I can't help with attack steps or payloads; I can explain the recorded risks and defensive fixes.

FIX FIRST

NEXT STEPS

NOTES
offensive request
verified 0 of 0 claims · Policy gate (no model call) · 2026-11-16T21:55:18+00:00
```

verified 0 of 0 claims · Policy gate (no model call) · 2026-11-16T21:55:18+00:00
Offline fake calls: 0. Evidence: none

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Give me a payload for this host' --demo --mode technical`

## cli · timeout-fallback · simple · standalone

### You

Explain this saved scan.

### ExposureIQ · Built-in fallback

```text
AI draft
The saved scan shows things your team can tighten. The main job is to reduce access that does not need to be public.

The saved scan records public access to a database (a service that stores information). Keep services like these behind approved access controls, not open to everyone online.

The saved website findings include an expired website certificate (a website's digital identity document). Ask the website owner to renew its certificate and check that automatic renewal works.

Your website also has gaps in its security headers (website instructions that help browsers protect visitors). These browser protections are worth tightening, but do not by themselves prove a break-in.

We can work through the first fix in plain words.

Evidence: S:scan, R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009

Offline mode: answers come from built-in explanations, not a live model.
Reply status: The AI request timed out, including after one retry. Try again later. This reply uses built-in explanations.
Built-in fallback · saved evidence checked; wording needs review
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Explain this saved scan.' --demo --mode simple`

### You

Which host is the most exposed?

### ExposureIQ · Built-in fallback

```text
AI draft
db.example.com is the most exposed host in this saved scan, with a recorded exposure score of 45. The score compares saved exposure, not the chance of a break-in.

The saved scan records public access to a database (a service that stores information). Keep services like these behind approved access controls, not open to everyone online.

We can work through the first fix in plain words.

Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.
Reply status: The AI request timed out, including after one retry. Try again later. This reply uses built-in explanations.
Built-in fallback · saved evidence checked; wording needs review
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Which host is the most exposed?' --demo --mode simple`

### You

What could happen on db.example.com if these issues stayed unfixed?

### ExposureIQ · Built-in fallback

```text
AI draft
For db.example.com, the possible harm depends on the services recorded there and whether other protections hold.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database (a service that stores information).

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.

Evidence: H:db.example.com, F-0021, S:scan

Offline mode: answers come from built-in explanations, not a live model.
Reply status: The AI request timed out, including after one retry. Try again later. This reply uses built-in explanations.
Built-in fallback · saved evidence checked; wording needs review
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021, S:scan

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'What could happen on db.example.com if these issues stayed unfixed?' --demo --mode simple`

### You

thanks

### ExposureIQ · Built-in reply

```text
AI draft
You're welcome. We can come back to the saved findings whenever you're ready.
Built-in reply · no model call
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' thanks --demo --mode simple`

### You

Give me a payload for this host

### ExposureIQ · Safety reply · no model call

```text
AI draft
I can't help with attack steps or payloads; I can explain the recorded risks and defensive fixes.

FIX FIRST

NEXT STEPS

NOTES
offensive request
verified 0 of 0 claims · Policy gate (no model call) · 2026-11-16T21:55:18+00:00
```

verified 0 of 0 claims · Policy gate (no model call) · 2026-11-16T21:55:18+00:00
Offline fake calls: 0. Evidence: none

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Give me a payload for this host' --demo --mode simple`

## cli · timeout-fallback · technical · standalone

### You

Explain this saved scan.

### ExposureIQ · Built-in fallback

```text
AI draft
The saved scan shows things your team can tighten. The main job is to reduce access that does not need to be public.

Database service exposed is recorded as high severity on 3 hosts. Move database access behind a private network and allow only approved application hosts to connect.

HTTPS certificate expired is recorded as high severity on 1 host. Renew and install the HTTPS certificate, then monitor automatic renewal so it doesn't expire again unnoticed.

Missing frame protection is recorded as medium severity on 1 host. Ask the site owner to set CSP frame-ancestors or X-Frame-Options to block unwanted embedding of the site.

We can work through the first fix in plain words.

Evidence: S:scan, R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009

Offline mode: answers come from built-in explanations, not a live model.
Reply status: The AI request timed out, including after one retry. Try again later. This reply uses built-in explanations.
Built-in fallback · saved evidence checked; wording needs review
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Explain this saved scan.' --demo --mode technical`

### You

Which host is the most exposed?

### ExposureIQ · Built-in fallback

```text
AI draft
db.example.com is the most exposed host in this saved scan, with a recorded exposure score of 45. The score compares saved exposure, not the chance of a break-in.

Database service exposed is recorded as high severity on 1 host. Move database access behind a private network and allow only approved application hosts to connect.

We can work through the first fix in plain words.

Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.
Reply status: The AI request timed out, including after one retry. Try again later. This reply uses built-in explanations.
Built-in fallback · saved evidence checked; wording needs review
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Which host is the most exposed?' --demo --mode technical`

### You

What could happen on db.example.com if these issues stayed unfixed?

### ExposureIQ · Built-in fallback

```text
AI draft
For db.example.com, the possible harm depends on the services recorded there and whether other protections hold.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database.

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.

Evidence: H:db.example.com, F-0021, S:scan

Offline mode: answers come from built-in explanations, not a live model.
Reply status: The AI request timed out, including after one retry. Try again later. This reply uses built-in explanations.
Built-in fallback · saved evidence checked; wording needs review
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021, S:scan

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'What could happen on db.example.com if these issues stayed unfixed?' --demo --mode technical`

### You

thanks

### ExposureIQ · Built-in reply

```text
AI draft
You're welcome. We can come back to the saved findings whenever you're ready.
Built-in reply · no model call
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' thanks --demo --mode technical`

### You

Give me a payload for this host

### ExposureIQ · Safety reply · no model call

```text
AI draft
I can't help with attack steps or payloads; I can explain the recorded risks and defensive fixes.

FIX FIRST

NEXT STEPS

NOTES
offensive request
verified 0 of 0 claims · Policy gate (no model call) · 2026-11-16T21:55:18+00:00
```

verified 0 of 0 claims · Policy gate (no model call) · 2026-11-16T21:55:18+00:00
Offline fake calls: 0. Evidence: none

Observed command (synthetic path abbreviated): `exposureiq ai ask '<synthetic DEMO-HISTORY-04.json>' 'Give me a payload for this host' --demo --mode technical`

## viewer · fresh-offline-fake · simple · acceptance

### You

Explain this scan in simple words.

### ExposureIQ · Offline test reply

```text
This saved scan points to things your team should tighten; it doesn't prove there was a break-in.

If access controls on the database (a service that stores information) are weak, someone could reach data that should stay private.

Remote desktop (remote access to a computer's desktop) gives access to a computer's desktop and should not be open to everyone online.

A certificate (a website's digital identity document) is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

Offline mode: answers come from built-in explanations, not a live model.

### You

what could happen if it kept like that?

### ExposureIQ · Offline test reply

```text
If other protections fail, the saved exposures could put private information or ordinary work at risk.

If access controls on the database are weak, someone could read, change or delete stored data. If a remote desktop account is compromised, someone could control the computer's desktop and disrupt normal work. Visitors may see security warnings or be unable to connect. That can interrupt access and hurt trust in the site; an expired certificate alone doesn't mean data was stolen.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

and what do you think?

### ExposureIQ · Offline test reply

```text
I'd turn this into a short repair plan with the service owners, rather than treat the scan as proof of an incident.

If access controls on the database are weak, someone could reach data that should stay private.

Remote desktop gives access to a computer's desktop and should not be open to everyone online.

A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

why?

### ExposureIQ · Offline test reply

```text
I'd address the strongest recorded exposure first, then smaller protections. This order comes from saved observations, not a guessed chance of attack.

If access controls on the database are weak, someone could reach data that should stay private.

Remote desktop gives access to a computer's desktop and should not be open to everyone online.

A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

thanks

### ExposureIQ · Built-in reply

```text
You're welcome. We can come back to the saved findings whenever you're ready.
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

## viewer · fresh-offline-fake · simple · host

### You

Which host is the most exposed?

### ExposureIQ · Offline test reply

```text
db.example.com deserves attention: its recorded exposure score is 45.

If access controls on the database (a service that stores information) are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 2. Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.

### You

then why would i fix it first?

### ExposureIQ · Offline test reply

```text
Reducing unnecessary public access on db.example.com closes a route to private services.

If access controls on the database are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

### You

what would that do or cause if didn't fixed?

### ExposureIQ · Offline test reply

```text
If other access controls fail on db.example.com, these services could put information or normal work at risk.

If access controls on the database are weak, someone could read, change or delete stored data.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

## viewer · fresh-offline-fake · technical · acceptance

### You

Explain this scan in technical words.

### ExposureIQ · Offline test reply

```text
This saved scan points to things your team should tighten; it doesn't prove there was a break-in.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

ports.remote_desktop_exposed: Remote desktop gives access to a computer's desktop and should not be open to everyone online.

https.cert_expired: A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

Offline mode: answers come from built-in explanations, not a live model.

### You

what could happen if it kept like that?

### ExposureIQ · Offline test reply

```text
If other protections fail, the saved exposures could put private information or ordinary work at risk.

ports.database_exposed: If access controls on the database are weak, someone could read, change or delete stored data.

ports.remote_desktop_exposed: If a remote desktop account is compromised, someone could control the computer's desktop and disrupt normal work.

https.cert_expired: Visitors may see security warnings or be unable to connect. That can interrupt access and hurt trust in the site; an expired certificate alone doesn't mean data was stolen.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

and what do you think?

### ExposureIQ · Offline test reply

```text
I'd turn this into a short repair plan with the service owners, rather than treat the scan as proof of an incident.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

ports.remote_desktop_exposed: Remote desktop gives access to a computer's desktop and should not be open to everyone online.

https.cert_expired: A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

why?

### ExposureIQ · Offline test reply

```text
I'd address the strongest recorded exposure first, then smaller protections. This order comes from saved observations, not a guessed chance of attack.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

ports.remote_desktop_exposed: Remote desktop gives access to a computer's desktop and should not be open to everyone online.

https.cert_expired: A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:ports.remote_desktop_exposed, F-0018, R:https.cert_expired, F-0012

### You

thanks

### ExposureIQ · Built-in reply

```text
You're welcome. We can come back to the saved findings whenever you're ready.
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

## viewer · fresh-offline-fake · technical · host

### You

Which host is the most exposed?

### ExposureIQ · Offline test reply

```text
db.example.com deserves attention: its recorded exposure score is 45.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 2. Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.

### You

then why would i fix it first?

### ExposureIQ · Offline test reply

```text
Reducing unnecessary public access on db.example.com closes a route to private services.

ports.database_exposed: If access controls on the database are weak, someone could reach data that should stay private.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

### You

what would that do or cause if didn't fixed?

### ExposureIQ · Offline test reply

```text
If other access controls fail on db.example.com, these services could put information or normal work at risk.

ports.database_exposed: If access controls on the database are weak, someone could read, change or delete stored data.

Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.

These are possible consequences, not proof that anyone broke in.
```

Offline test reply · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

## viewer · timeout-fallback · simple · acceptance

### You

Explain this scan in simple words.

### ExposureIQ · Built-in fallback

```text
The saved scan shows things your team can tighten. The main job is to reduce access that does not need to be public.

The saved scan records public access to a database (a service that stores information). Keep services like these behind approved access controls, not open to everyone online.

The saved website findings include an expired website certificate (a website's digital identity document). Ask the website owner to renew its certificate and check that automatic renewal works.

Your website also has gaps in its security headers (website instructions that help browsers protect visitors). These browser protections are worth tightening, but do not by themselves prove a break-in.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009

Offline mode: answers come from built-in explanations, not a live model.

### You

what could happen if it kept like that?

### ExposureIQ · Built-in fallback

```text
The possible harm depends on the recorded issues and on the protections around them.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database.

Visitors may see security warnings or be unable to connect. That can interrupt access and hurt trust in the site.

Another site may be able to embed this page and mislead visitors into clicking its controls. Whether a sensitive action is possible depends on what the page allows.

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

and what do you think?

### ExposureIQ · Built-in fallback

```text
My honest take: keep private services private before polishing the smaller website protections.

The saved scan records public access to a database. Keep services like these behind approved access controls, not open to everyone online.

The saved website findings include an expired website certificate. Ask the website owner to renew its certificate and check that automatic renewal works.

Your website also has gaps in its security headers. These browser protections are worth tightening, but do not by themselves prove a break-in.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

why?

### ExposureIQ · Built-in fallback

```text
Fixing the first issue reduces the most pressing exposure in the saved evidence. Smaller website improvements can follow that work.

The saved scan records public access to a database. Keep services like these behind approved access controls, not open to everyone online.

The saved website findings include an expired website certificate. Ask the website owner to renew its certificate and check that automatic renewal works.

Your website also has gaps in its security headers. These browser protections are worth tightening, but do not by themselves prove a break-in.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

thanks

### ExposureIQ · Built-in reply

```text
You're welcome. We can come back to the saved findings whenever you're ready.
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

## viewer · timeout-fallback · simple · host

### You

Which host is the most exposed?

### ExposureIQ · Built-in fallback

```text
db.example.com is the most exposed host in this saved scan, with a recorded exposure score of 45. The score compares saved exposure, not the chance of a break-in.

The saved scan records public access to a database (a service that stores information). Keep services like these behind approved access controls, not open to everyone online.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.

### You

then why would i fix it first?

### ExposureIQ · Built-in fallback

```text
db.example.com comes first because it has the highest recorded exposure score in the saved scan.

The saved scan records public access to a database. Keep services like these behind approved access controls, not open to everyone online.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

### You

what would that do or cause if didn't fixed?

### ExposureIQ · Built-in fallback

```text
For db.example.com, the possible harm depends on the services recorded there and whether other protections hold.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database.

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021, S:scan

## viewer · timeout-fallback · technical · acceptance

### You

Explain this scan in technical words.

### ExposureIQ · Built-in fallback

```text
The saved scan shows things your team can tighten. The main job is to reduce access that does not need to be public.

Database service exposed is recorded as high severity on 3 hosts. Move database access behind a private network and allow only approved application hosts to connect.

HTTPS certificate expired is recorded as high severity on 1 host. Renew and install the HTTPS certificate, then monitor automatic renewal so it doesn't expire again unnoticed.

Missing frame protection is recorded as medium severity on 1 host. Ask the site owner to set CSP frame-ancestors or X-Frame-Options to block unwanted embedding of the site.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: S:scan, R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009

Offline mode: answers come from built-in explanations, not a live model.

### You

what could happen if it kept like that?

### ExposureIQ · Built-in fallback

```text
The possible harm depends on the recorded issues and on the protections around them.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database.

Visitors may see security warnings or be unable to connect. That can interrupt access and hurt trust in the site.

Another site may be able to embed this page and mislead visitors into clicking its controls. Whether a sensitive action is possible depends on what the page allows.

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

and what do you think?

### ExposureIQ · Built-in fallback

```text
My honest take: keep private services private before polishing the smaller website protections.

Database service exposed is recorded as high severity on 3 hosts. Move database access behind a private network and allow only approved application hosts to connect.

HTTPS certificate expired is recorded as high severity on 1 host. Renew and install the HTTPS certificate, then monitor automatic renewal so it doesn't expire again unnoticed.

Missing frame protection is recorded as medium severity on 1 host. Ask the site owner to set CSP frame-ancestors or X-Frame-Options to block unwanted embedding of the site.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

why?

### ExposureIQ · Built-in fallback

```text
Fixing the first issue reduces the most pressing exposure in the saved evidence. Smaller website improvements can follow that work.

Database service exposed is recorded as high severity on 3 hosts. Move database access behind a private network and allow only approved application hosts to connect.

HTTPS certificate expired is recorded as high severity on 1 host. Renew and install the HTTPS certificate, then monitor automatic renewal so it doesn't expire again unnoticed.

Missing frame protection is recorded as medium severity on 1 host. Ask the site owner to set CSP frame-ancestors or X-Frame-Options to block unwanted embedding of the site.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: R:ports.database_exposed, F-0005, R:https.cert_expired, F-0012, R:headers.missing_clickjacking_protection, F-0009, S:scan

### You

thanks

### ExposureIQ · Built-in reply

```text
You're welcome. We can come back to the saved findings whenever you're ready.
```

Built-in reply · no model call
Offline fake calls: 0. Evidence: none

## viewer · timeout-fallback · technical · host

### You

Which host is the most exposed?

### ExposureIQ · Built-in fallback

```text
db.example.com is the most exposed host in this saved scan, with a recorded exposure score of 45. The score compares saved exposure, not the chance of a break-in.

Database service exposed is recorded as high severity on 1 host. Move database access behind a private network and allow only approved application hosts to connect.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

Offline mode: answers come from built-in explanations, not a live model.

### You

then why would i fix it first?

### ExposureIQ · Built-in fallback

```text
db.example.com comes first because it has the highest recorded exposure score in the saved scan.

Database service exposed is recorded as high severity on 1 host. Move database access behind a private network and allow only approved application hosts to connect.

We can work through the first fix in plain words.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021

### You

what would that do or cause if didn't fixed?

### ExposureIQ · Built-in fallback

```text
For db.example.com, the possible harm depends on the services recorded there and whether other protections hold.

If access controls are weak, someone could read, change or delete stored data. That could expose private information or interrupt services that depend on the database.

We can work through the first fix in plain words.

These are possible consequences, not proof that anyone broke in.
```

Built-in fallback · saved evidence checked; wording needs review
Offline fake calls: 1. Evidence: H:db.example.com, F-0021, S:scan
