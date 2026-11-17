"use strict";
// Saved strings are text only. Never parse them as markup, HTML or links.
const token = window.location.hash.slice(1);
const $ = (id) => document.getElementById(id);
let domain = "", scan = "", generation = 0, busy = false, transcript = [];
let aiEnabled = false, developerMode = false;
let conversation = newConversation();

function newConversation() {
  const bytes = new Uint8Array(16); window.crypto.getRandomValues(bytes);
  return Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
}

function node(tag, value, className = "") {
  const element = document.createElement(tag);
  element.textContent = String(value);
  if (className) element.className = className;
  return element;
}

async function api(path, payload) {
  const options = { headers: { "X-ExposureIQ-Session": token }, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "same-origin" };
  if (payload !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) { const error = new Error(data.error || "Local viewer request failed."); error.status = response.status; throw error; }
  return data;
}

function controls() {
  for (const id of ["explain", "send", "fix-first", "most-exposed", "common-questions", "question", "wording-mode"]) $(id).disabled = busy || !domain || !aiEnabled;
  $("open-report").disabled = !scan;
}

function tab(name) {
  if (!aiEnabled || (name === "log" && !developerMode)) name = "scans";
  for (const id of ["scans", "chat", "log"]) $(id).hidden = id !== name;
  for (const button of document.querySelectorAll("[data-tab]")) button.classList.toggle("active", button.dataset.tab === name);
  if (name === "log") showLog();
}

function clearAnswer() {
  generation += 1;
  conversation = newConversation();
  busy = false;
  transcript = [];
  $("chat-result").replaceChildren(node("p", "Choose a common question, or type your own. I only explain saved data; I don't scan or take action."));
  $("chat-verified").textContent = "";
  $("finding-detail").textContent = "";
}

async function openScan(id, title) {
  clearAnswer();
  const current = generation;
  scan = id;
  controls();
  try {
    const data = await api("/api/scan?scan=" + encodeURIComponent(id));
    if (current !== generation) return;
    $("scan-title").textContent = title;
    $("warning").textContent = data.digest.hostile_text_seen ? "Hostile-looking saved text detected. It is displayed as literal text, never instructions or executable HTML." : "";
    if (data.truncated) $("warning").textContent += " Findings table shortened to 500 rows; total: " + data.finding_count;
    const table = document.createElement("table"), head = document.createElement("tr");
    for (const name of ["Finding", "Severity", "Title", "Host"]) head.append(node("th", name));
    table.append(head);
    for (const finding of data.findings) {
      const row = document.createElement("tr");
      row.tabIndex = 0;
      row.append(node("td", finding.id), node("td", finding.severity, finding.severity), node("td", finding.title), node("td", finding.host));
      const detail = () => { $("finding-detail").textContent = finding.id + " · " + finding.rule + "\n" + finding.detail + "\nDefensive fix: " + finding.recommendation; };
      row.addEventListener("click", detail);
      row.addEventListener("keydown", (event) => { if (event.key === "Enter") detail(); });
      table.append(row);
    }
    $("findings").replaceChildren(table);
  } catch (error) { if (current === generation) $("status").textContent = error.message; }
}

async function openDomain(name) {
  clearAnswer();
  const current = generation;
  domain = name; scan = "";
  $("title").textContent = "Domain / " + name;
  $("findings").replaceChildren(); $("scan-title").textContent = "Choose a saved scan. AI chat can also explain this domain's saved history.";
  controls(); tab("scans");
  try {
    const data = await api("/api/scans?domain=" + encodeURIComponent(name));
    if (current !== generation) return;
    $("verdict").textContent = "CODE VERDICT · " + data.verdict;
    $("sparkline").textContent = "Risk per host  " + data.sparkline;
    $("formula").textContent = data.formula;
    $("status").textContent = data.note;
    const buttons = data.scans.map((item) => {
      const label = item.date + " · " + item.scan_id + " · H/M/L " + [item.risk.high, item.risk.medium, item.risk.low].join("/");
      const button = node("button", label);
      button.addEventListener("click", () => openScan(item.id, item.scan_id + " · " + item.date));
      return button;
    });
    $("scan-list").replaceChildren(...buttons);
  } catch (error) { if (current === generation) $("status").textContent = error.message; }
}

async function refresh() {
  try {
    const [data, settings] = await Promise.all([api("/api/domains"), api("/api/health")]);
    aiEnabled = settings.enabled;
    developerMode = settings.developer_mode;
    for (const button of document.querySelectorAll("[data-tab]")) {
      if (button.dataset.tab === "chat") button.hidden = !aiEnabled;
      if (button.dataset.tab === "log") button.hidden = !aiEnabled || !developerMode;
    }
    if (!aiEnabled) { clearAnswer(); tab("scans"); }
    if (!developerMode && !$("log").hidden) tab(aiEnabled ? "chat" : "scans");
    controls();
    $("status").textContent = (aiEnabled ? "AI: " + settings.mode + " · " + settings.model : "AI is off. Enable Local or Remote in terminal Settings to use chat.") + ". " + (data.warning || "No network or probes are used to browse saved data.");
    const buttons = data.domains.map((item) => {
      const button = node("button", item.domain + " · " + item.scans + " scans · " + item.arrow + " " + item.verdict + (item.demo ? " · DEMO" : ""));
      button.addEventListener("click", () => openDomain(item.domain));
      return button;
    });
    $("domains").replaceChildren(...buttons);
    if (!buttons.length) $("domains").append(node("p", "No valid saved scans. Create an offline demo first."));
  } catch (error) { $("status").textContent = error.message; }
}

async function answer(kind, question = "") {
  if (busy || !domain || !aiEnabled || kind !== "ask") return;
  if (!question.trim() || question.length > 1000) { $("status").textContent = "Type a question first (up to 1000 characters)."; return; }
  const current = generation;
  busy = true; controls();
  let frame = 0;
  const frames = ["[=    ]", "[ =   ]", "[  =  ]", "[   = ]", "[    =]", "[   = ]", "[  =  ]", "[ =   ]"];
  const thinking = () => { if (current === generation && busy) $("status").textContent = frames[frame++ % frames.length] + " Thinking · reading saved data and checking the answer…"; };
  thinking();
  const timer = setInterval(thinking, 150);
  const payload = { ...(scan ? { scan } : { domain }), question, mode: $("wording-mode").value, conversation };
  tab("chat");
  $("question").value = "";
  // The browser has no private key to compare against. Do not display a raw
  // question before the server has redacted credentials; show a sent receipt.
  const turn = { user: "Question sent. Your text will appear after private redaction.", reply: "Thinking…", pending: true };
  transcript.push(turn); transcript = transcript.slice(-3);
  renderTranscript(); $("chat-verified").textContent = "";
  try {
    const result = await api("/api/ai/" + kind, payload);
    if (current !== generation) return;
    turn.user = result.user; turn.reply = result.text; turn.pending = false;
    turn.label = result.label || "AI draft"; turn.refs = result.evidence_refs || [];
    turn.notice = result.offline_notice || ""; turn.failure = result.failure_kind ? result.reason : "";
    if (result.mode) $("wording-mode").value = result.mode;
    renderTranscript(); $("chat-verified").textContent = result.footer || "";
    $("status").textContent = result.reason || "Reply ready. Review this draft with your team.";
  } catch (error) {
    if (current === generation && error.status === 409) {
      await refresh();
      if (current !== generation) return;
    }
    if (current === generation) { turn.reply = error.message; turn.pending = false; renderTranscript(); $("status").textContent = "Reply unavailable. You can try another question."; }
  } finally { clearInterval(timer); if (current === generation) busy = false; controls(); }
}

function renderTranscript() {
  const turns = transcript.map((turn) => {
    const group = node("div", "", "chat-turn");
    const user = node("article", "", "chat-message user-message");
    user.append(node("strong", "You · sent"), node("pre", turn.user));
    const reply = node("article", "", "chat-message assistant-message");
    reply.append(node("strong", turn.pending ? "ExposureIQ · thinking" : "ExposureIQ · " + (turn.label || "AI draft") + " · AI draft"), node("pre", turn.reply));
    if (turn.notice) reply.append(node("p", turn.notice, "reply-status"));
    if (turn.failure) reply.append(node("p", turn.failure, "reply-status"));
    if (turn.refs && turn.refs.length) {
      const evidence = node("details", "", "evidence"), summary = node("summary", "Evidence");
      evidence.append(summary);
      for (const ref of turn.refs) evidence.append(node("span", ref, "evidence-ref"));
      reply.append(evidence);
    }
    group.append(user, reply);
    return group;
  });
  $("chat-result").replaceChildren(...turns);
  if (turns.length) turns[turns.length - 1].scrollIntoView({ block: "nearest" });
}

async function showLog() {
  if (!aiEnabled || !developerMode) return;
  try { $("log-result").textContent = JSON.stringify(await api("/api/log"), null, 2); }
  catch (error) { $("status").textContent = error.message; }
}

for (const button of document.querySelectorAll("[data-tab]")) button.addEventListener("click", () => tab(button.dataset.tab));
$("refresh").addEventListener("click", refresh);
$("clear-chat").addEventListener("click", () => { clearAnswer(); controls(); $("status").textContent = "Chat cleared. No conversation is saved to disk."; });
function openReport(identifier, target = "_blank", focusScan = false) {
  if (!/^[a-f0-9]{24}$/.test(identifier)) return;
  const form = document.createElement("form");
  form.method = "POST"; form.action = "/api/report#" + token; form.target = target; form.rel = "noopener";
  const fields = [["scan", identifier], ["session", token]];
  if (focusScan) fields.push(["view", "scan"]);
  for (const [name, value] of fields) {
    const field = document.createElement("input"); field.type = "hidden"; field.name = name; field.value = value; form.append(field);
  }
  document.body.append(form); form.submit(); form.remove();
}
$("open-report").addEventListener("click", () => openReport(scan));
$("explain").addEventListener("click", () => answer("ask", scan ? "Explain this scan in simple words." : "What changed in this domain's saved history?"));
$("send").addEventListener("click", () => answer("ask", $("question").value));
$("fix-first").addEventListener("click", () => answer("ask", "What should I fix first?"));
$("most-exposed").addEventListener("click", () => answer("ask", "Which host is the most exposed?"));
$("common-questions").addEventListener("change", () => { const value = $("common-questions").value; $("common-questions").value = ""; if (value) answer("ask", value); });
$("question").addEventListener("keydown", (event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); answer("ask", $("question").value); } });
if (!token) $("status").textContent = "Open the full per-launch URL printed by exposureiq web. Its fragment starts a private viewer session.";
else if (window.location.search) {
  const requested = new URLSearchParams(window.location.search).get("report");
  if (/^[a-f0-9]{24}$/.test(requested || ""))
    api("/api/health").then(() => openReport(requested, "_self", new URLSearchParams(window.location.search).get("view") === "scan")).catch(() => { $("status").textContent = "The private report session could not be opened. Use the full URL printed by exposureiq web."; });
  else $("status").textContent = "Choose a saved report from this local viewer.";
}
else refresh();
