(() => {
  "use strict";
  // Only Python-prepared defensive text can be selected. No network, keys,
  // storage, commands, HTML parsing, links or provider connection exist here.
  const $ = id => document.getElementById(id);
  let bundle;
  try { bundle = JSON.parse($("exposureiq-chat-data").textContent); }
  catch (_) { $("export-chat-status").textContent = "The prepared chat data could not be read."; return; }
  if (bundle.version !== "offline-chat-1") {
    $("export-chat-status").textContent = "This chat data version isn't supported."; return;
  }
  const rules = bundle.rules, patterns = {};
  for (const [name, pattern] of Object.entries(rules.patterns)) patterns[name] = new RegExp(pattern, "i");
  let selected = bundle.default_scan, state = {}, sender = null, resetter = null;
  const normal = value => value.normalize("NFKC").replace(/[\u200b-\u200f\u2060\ufeff]/g, "").toLowerCase();
  const escapeRE = value => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  function oneEdit(left, right) {
    if (Math.abs(left.length - right.length) > 1) return false;
    if (left.length === right.length) {
      const positions = [];
      for (let i = 0; i < left.length; i++) if (left[i] !== right[i]) positions.push(i);
      return positions.length <= 1 || positions.length === 2 && positions[1] === positions[0] + 1 &&
        left[positions[0]] === right[positions[1]] && left[positions[1]] === right[positions[0]];
    }
    const short = left.length < right.length ? left : right, long = left.length < right.length ? right : left;
    for (let i = 0; i < long.length; i++) if (long.slice(0, i) + long.slice(i + 1) === short) return true;
    return false;
  }
  function corrected(value) {
    return normal(value).replace(/[a-z]+/g, word => {
      if (rules.vocabulary.includes(word) || word.length < 5) return word;
      const candidates = rules.vocabulary.filter(candidate => oneEdit(word, candidate));
      return candidates.length === 1 ? candidates[0] : word;
    });
  }
  const tokens = value => new Set((value.match(/[a-z0-9]+/g) || []).map(word => rules.synonyms[word] || word));
  function routeQuestion(question, previousKind = "") {
    if (typeof question !== "string" || !question.trim() || [...question].length > rules.max_chars)
      return {kind: "invalid", message: "Ask a nonempty question of at most 1000 characters."};
    const value = normal(question), repaired = corrected(question);
    for (const name of ["private", "offensive", "active", "off_topic"])
      if (patterns[name].test(value) || patterns[name].test(repaired)) return {kind: "refusal", message: rules.refusals[name], reason: name};
    if (patterns.friendly.test(repaired)) return {kind: /^(hi|hello|hey)/.test(repaired.trim()) ? "greeting" : /^thank/.test(repaired.trim()) ? "thanks" : "acknowledgement"};
    if (/\b(mean|meaning|what\s+is|what\s+are|define)\b/.test(repaired))
      for (const term of bundle.glossary_order) if (new RegExp("\\b" + escapeRE(term) + "\\b", "i").test(repaired)) return {kind: "definition", term};
    if (patterns.incident.test(repaired)) return {kind: "incident"};
    if (patterns.opinion.test(repaired)) return {kind: "opinion"};
    if (patterns.why.test(repaired) || /^(?:then\s+|and\s+|so\s+)?why(?:\s+is\s+that)?[.!?\s]*$/.test(repaired)) return {kind: "why"};
    if (/\bhow\s+long\b/.test(repaired)) return {kind: "timing"};
    if (/\bwho\b.{0,40}\b(?:fix|own|manage)\w*\b/.test(repaired)) return {kind: "owner"};
    if (patterns.impact.test(repaired)) return {kind: "impact"};
    for (const [kind, pattern] of [["app", /\bexposureiq\b/], ["scope", /\bscope\b/], ["severity", /\bseverity\b/],
      ["coverage", /\b(?:not\s+checked|missing\s+checks|limitations)\b/], ["confirm", /\b(?:confirm|verify\s+a\s+fix)\b/]])
      if (pattern.test(repaired)) return {kind};
    if (/\bf-\d{4,}\b/.test(value)) return {kind: "finding"};
    if (previousKind && patterns.follow_up.test(repaired)) return {kind: previousKind === "fix" ? "why" : previousKind};
    const words = tokens(repaired);
    for (const kind of ["host", "risk", "history", "headers", "timing", "owner", "fix", "impact", "opinion", "why", "finding", "overview"]) {
      const intent = rules.intents.find(item => item.kind === kind);
      if (intent.phrases.some(phrase => [...tokens(phrase)].every(word => words.has(word)))) return {kind};
    }
    return {kind: "unknown", message: rules.unknown};
  }
  function definitions(value) {
    const seen = new Set(state.defined_terms || []);
    for (const term of bundle.glossary_order) {
      const entry = bundle.glossary[term];
      if (seen.has(term)) continue;
      const pattern = new RegExp("(^|[^\\w.-])(" + escapeRE(term) + ")(?![\\w-]|\\.[\\w-])", "i");
      if (pattern.test(value)) {
        if (!value.toLowerCase().includes(entry.explanation.toLowerCase())) value = value.replace(pattern, (_match, prefix, word) => prefix + word + " (" + entry.explanation + ")");
        seen.add(term);
      }
    }
    state.defined_terms = [...seen].sort();
    return value;
  }
  function answer(question) {
    const row = bundle.scans[selected], route = routeQuestion(question, state.kind || ""), kind = route.kind;
    let mode = $("export-chat-mode").value;
    const base = {source: "offline", mode, kind, refs: [], notice: "", focus: state.focus || "scan"};
    if (["refusal", "invalid", "unknown"].includes(kind)) return {...base, text: route.message, reason: route.reason || ""};
    if (bundle.friendly[kind]) return {...base, text: bundle.friendly[kind], source: "built-in"};
    const value = normal(question);
    if (/\btechnical(?:ly)?\b/.test(value)) mode = "technical";
    else if (/\b(?:simple|plain)\s+(?:words|english)|\bsimpler\b/.test(value)) mode = "simple";
    base.mode = mode; $("export-chat-mode").value = mode;
    let focus = ["impact", "why", "opinion", "owner", "timing", "risk"].includes(kind) || patterns.follow_up.test(value) ? state.focus || "scan" : "scan";
    const fid = value.match(/\bf-\d{4,}\b/i), named = row.hosts.filter(host => new RegExp("(^|[^\\w.-])" + escapeRE(host) + "($|[^\\w.-])", "i").test(value));
    if (fid) focus = "finding:" + fid[0].toUpperCase();
    else if (named.length === 1) focus = "host:" + named[0];
    else if (patterns.whole_scan.test(value)) focus = "scan";
    else if (kind === "host") focus = row.top_host ? "host:" + row.top_host : "scan";
    if (/\b(?:the\s+)?other\s+one\b/.test(value)) {
      const others = (state.alternatives || []).filter(item => item !== state.focus);
      if (others.length !== 1) return {...base, kind: "clarification", text: rules.clarify};
      focus = others[0];
    }
    const unknownHost = /\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\b/.test(value) && !named.length && !fid && !["app", "scope", "headers", "history"].includes(kind);
    if (!Object.hasOwn(row.replies, focus) || unknownHost) return {...base, kind: "unknown", text: rules.missing};
    let reply;
    if (kind === "definition") {
      const entry = bundle.glossary[route.term], verb = route.term === "security headers" ? " are " : " means ";
      reply = {text: route.term + verb + entry.explanation + ". Think of it as " + entry.analogy + ".", refs: ["S:scan"], proof_relevant: false};
      state.defined_terms = [...new Set([...(state.defined_terms || []), route.term])];
    } else reply = row.common[mode][kind] || row.replies[focus][mode][kind] || row.replies.scan[mode][kind];
    // A corrupt or hand-edited bundle must not manufacture an Evidence badge.
    if (!reply || reply.refs.some(ref => !Object.hasOwn(row.references, ref))) return {...base, kind: "invalid", text: "The prepared reply has invalid evidence and wasn't shown."};
    let text = reply.text;
    if (reply.proof_relevant && !state.proof_notice_seen) { text += "\n\n" + bundle.proof_note; state.proof_notice_seen = true; }
    if (mode === "simple") text = definitions(text);
    const notice = state.offline_notice_seen ? "" : bundle.offline_notice;
    state.offline_notice_seen = true;
    Object.assign(state, {kind, focus, alternatives: kind === "host" ? row.hosts.map(host => "host:" + host) : row.alternatives.map(fid => "finding:" + fid)});
    return {...base, text, refs: [...reply.refs], notice, focus};
  }
  function node(tag, text, className = "") {
    const element = document.createElement(tag); element.textContent = String(text);
    if (className) element.className = className;
    return element;
  }
  function cleanQuestion(value) {
    return value.normalize("NFKC").replace(/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, " ")
      .replace(/\b(?:sk-[A-Za-z0-9_-]{4,}|FAKE-[A-Z0-9_-]*KEY[A-Z0-9_-]*|(?:api[_-]?key|token|password)\s*[:=]\s*\S+)/gi, "[redacted]");
  }
  function renderReply(question, result, existing = null) {
    const turn = existing || node("article", "", "export-chat-turn");
    const user = node("div", "", "export-chat-user"), reply = node("div", "", "export-chat-reply");
    user.append(node("strong", "You · sent"), node("pre", question));
    const label = result.pending ? "thinking" : result.label || (result.kind === "refusal" ? "safety reply" : "built-in explanation");
    reply.append(node("strong", "ExposureIQ · " + label), node("pre", result.text));
    if (result.notice) reply.append(node("p", result.notice, "export-chat-note"));
    if (result.refs.length) {
      const evidence = node("details", "", "export-chat-evidence"); evidence.append(node("summary", "Evidence"));
      for (const ref of result.refs) evidence.append(node("span", ref, "export-chat-ref"));
      reply.append(evidence);
    }
    turn.replaceChildren(user, reply);
    if (!existing) $("export-chat-log").append(turn);
    const log = $("export-chat-log");
    while (log.children.length > 3) log.removeChild(log.children[0]);
    $("export-chat-input").value = "";
    $("export-chat-status").textContent = result.pending ? "Thinking · reading saved data and checking the answer…" : result.footer || (result.refs.length ? "Saved evidence checked · built-in wording; review with your team." : "Built-in reply · no model call.");
    log.scrollTop = log.scrollHeight;
    return turn;
  }
  function sendQuestion(value = $("export-chat-input").value) {
    const question = cleanQuestion(value).trim(); if (!question) return;
    if (sender) return sender(question);
    const result = answer(question);
    renderReply(question, result);
    return result;
  }
  function reset() {
    state = {}; $("export-chat-log").replaceChildren(); $("export-chat-status").textContent = "Chat cleared. No conversation is saved.";
    if (resetter) resetter();
  }
  function rememberServerReply(result) {
    const row = bundle.scans[selected], focus = result.answer_focus || {};
    if (result.answer_kind && !["greeting", "thanks", "acknowledgement", "clarification"].includes(result.answer_kind)) {
      state.kind = result.answer_kind;
      state.focus = focus.finding_id ? "finding:" + focus.finding_id : focus.host ? "host:" + focus.host : "scan";
      state.alternatives = result.answer_kind === "host" ? row.hosts.map(host => "host:" + host) : row.alternatives.map(fid => "finding:" + fid);
    }
    if (result.offline_notice) state.offline_notice_seen = true;
    if (result.proof_notice) state.proof_notice_seen = true;
    for (const term of bundle.glossary_order) if (result.text.toLowerCase().includes(bundle.glossary[term].explanation.toLowerCase()))
      state.defined_terms = [...new Set([...(state.defined_terms || []), term])];
  }
  function selectScan(identifier) {
    if (!Object.hasOwn(bundle.scans, identifier) || identifier === selected) return;
    selected = identifier; $("export-chat-scan").value = selected; reset();
    $("export-chat-omitted").textContent = bundle.scans[selected].omitted_findings ? "Chat uses a compact digest; the report may contain more findings." : "";
  }
  function syncReportSelection() {
    for (const identifier of Object.keys(bundle.scans)) {
      const view = $(identifier);
      if (view && view.classList.contains("is-active")) { selectScan(identifier); return; }
    }
  }
  $("export-sharing-warning").textContent = bundle.sharing_warning;
  for (const [identifier, row] of Object.entries(bundle.scans)) { const option = node("option", row.scan_id + " · " + row.date); option.value = identifier; $("export-chat-scan").append(option); }
  $("export-chat-scan").value = selected;
  $("export-chat-omitted").textContent = bundle.scans[selected].omitted_findings ? "Chat uses a compact digest; the report may contain more findings." : "";
  for (const intent of rules.intents) { const option = node("option", intent.example); option.value = intent.example; $("export-chat-common").append(option); }
  $("export-chat-send").addEventListener("click", () => sendQuestion());
  $("export-chat-clear").addEventListener("click", reset);
  $("export-chat-scan").addEventListener("change", () => selectScan($("export-chat-scan").value));
  $("export-chat-common").addEventListener("change", () => { const question = $("export-chat-common").value; $("export-chat-common").value = ""; if (question) sendQuestion(question); });
  $("export-chat-input").addEventListener("keydown", event => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); sendQuestion(); } });
  window.addEventListener("hashchange", syncReportSelection); window.addEventListener("popstate", syncReportSelection);
  if (typeof MutationObserver !== "undefined") new MutationObserver(syncReportSelection).observe($("report-main"), {attributes: true, subtree: true, attributeFilter: ["class"]});
  // The separately hashed, server-only script shares this one chat view.
  // Neither this bridge nor the portable page knows a provider key or URL.
  window.ExposureIQOfflineChat = Object.freeze({routeQuestion, answer, renderReply, reset, rememberServerReply,
    current: () => ({scan: selected, signature: bundle.scans[selected].signature, mode: $("export-chat-mode").value, kind: state.kind || ""}),
    install: (send, onReset) => { sender = send; resetter = onReset; }});
  syncReportSelection();
})();
