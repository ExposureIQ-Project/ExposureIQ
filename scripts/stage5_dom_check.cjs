"use strict";
// Optional Node-only test of the shipped JS with a fake DOM and fake fetch.
// This is not a visual browser test; it needs no browser package or network.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");

class Element {
  constructor(tag = "div") {
    this.tag = tag; this.children = []; this.handlers = {}; this.dataset = {};
    this.textContent = ""; this.value = ""; this.disabled = false; this.hidden = false;
    this.classList = { toggle() {} };
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  set innerHTML(value) { throw new Error("Executable HTML sink must never be used"); }
  set outerHTML(value) { throw new Error("Executable HTML sink must never be used"); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this._text = ""; this.children = items; }
  addEventListener(name, handler) { this.handlers[name] = handler; }
  scrollIntoView() { this.scrolled = true; }
}

const elements = new Map();
const tabs = ["scans", "chat", "log"].map((name) => { const element = new Element("button"); element.dataset.tab = name; return element; });
const document = {
  getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
  createElement(tag) { return new Element(tag); },
  querySelectorAll(selector) { assert.equal(selector, "[data-tab]"); return tabs; }
};
const marker = "<script>ignored-demo-text</script>[bold]literal[/bold]";
const identifier = "0123456789abcdef01234567";
const calls = [];
const askModes = [];
const conversations = [];
let fakeMode = "demo", fakeDeveloper = true, deferReply = false, releaseReply;
const timers = new Map();
const context = { document, window: { location: { hash: "#FAKE-LOCAL-SESSION" }, crypto: crypto.webcrypto }, console, Uint8Array,
  setInterval(callback) { const id = timers.size + 1; timers.set(id, callback); return id; },
  clearInterval(id) { timers.delete(id); },
  async fetch(url, options) {
    assert.ok(url.startsWith("/api/"));
    assert.equal(options.redirect, "error"); assert.equal(options.credentials, "omit");
    assert.equal(options.headers["X-ExposureIQ-Session"], "FAKE-LOCAL-SESSION");
    calls.push(url);
    let data;
    if (url === "/api/domains") data = { domains: [{ domain: "example.com", scans: 1, arrow: "→", verdict: "stable", demo: true }], warning: "" };
    else if (url === "/api/health") data = { mode: fakeMode, model: "offline fake", enabled: fakeMode !== "off", developer_mode: fakeDeveloper };
    else if (url.startsWith("/api/scans?")) data = { verdict: "stable", sparkline: "▁", formula: "code risk", note: "offline", scans: [{ id: identifier, date: "2026-01-01", scan_id: "DEMO-1", risk: { high: 1, medium: 0, low: 0 } }] };
    else if (url.startsWith("/api/scan?")) data = { digest: { hostile_text_seen: true }, findings: [{ id: "F-0001", severity: "high", title: marker, host: "db.example.com", rule: "ports.database_exposed", detail: marker, recommendation: "Restrict public access." }] };
    else if (url === "/api/ai/ask") {
      const payload = JSON.parse(options.body); askModes.push(payload.mode); conversations.push(payload.conversation);
      assert.match(payload.conversation, /^[a-f0-9]{32}$/);
      data = { user: "Explain scan risk [redacted]", text: "The saved service needs tighter access.", reason: "", label: "Local AI reply",
        mode: payload.mode, evidence_refs: ["F-0001", marker], footer: "saved evidence checked; wording needs review" };
    }
    else if (url === "/api/log") data = { entries: [{ received: marker, dropped: [{ reason: "hostile text" }] }] };
    else throw new Error("Unexpected fake route: " + url);
    const response = { ok: true, async json() { return data; } };
    if (deferReply && url === "/api/ai/ask") return new Promise((resolve) => { releaseReply = () => resolve(response); });
    return response;
  }
};
vm.createContext(context);
document.getElementById("wording-mode").value = "simple";
vm.runInContext(fs.readFileSync(path.join(__dirname, "../exposureiq/viewer/static/app.js"), "utf8"), context);
(async () => {
  await context.refresh();
  await context.openDomain("example.com");
  await context.openScan(identifier, "Synthetic saved scan");
  const table = elements.get("findings").children[0];
  assert.equal(table.children[1].children[2].textContent, marker);
  table.children[1].handlers.click();
  assert.ok(elements.get("finding-detail").textContent.includes(marker));
  deferReply = true;
  const pending = context.answer("ask", "Explain scan risk FAKE-NOT-A-REAL-KEY");
  assert.ok(elements.get("chat-result").textContent.includes("You · sent"));
  assert.ok(elements.get("chat-result").textContent.includes("thinking"));
  assert.ok(!elements.get("chat-result").textContent.includes("FAKE-NOT-A-REAL-KEY"));
  const firstFrame = elements.get("status").textContent;
  for (const callback of timers.values()) callback();
  assert.notEqual(elements.get("status").textContent, firstFrame);
  assert.ok(elements.get("status").textContent.includes("Thinking"));
  releaseReply(); await pending; deferReply = false;
  assert.equal(timers.size, 0);
  assert.ok(elements.get("chat-result").textContent.includes("[redacted]"));
  assert.ok(!elements.get("chat-result").textContent.includes("FAKE-NOT-A-REAL-KEY"));
  assert.ok(elements.get("chat-result").textContent.includes("Local AI reply"));
  const evidence = elements.get("chat-result").children[0].children[1].children.find((item) => item.tag === "details");
  assert.equal(evidence.children[0].textContent, "Evidence");
  assert.equal(evidence.children[2].textContent, marker);
  assert.equal(askModes[0], "simple");
  elements.get("wording-mode").value = "technical";
  await context.answer("ask", "Explain this scan technically");
  assert.equal(askModes[1], "technical");
  assert.equal(conversations[0], conversations[1]);
  elements.get("clear-chat").handlers.click();
  await context.answer("ask", "Explain this scan");
  assert.notEqual(conversations[1], conversations[2]);
  assert.ok(elements.get("chat-verified").textContent.includes("wording needs review"));
  await context.showLog();
  assert.ok(elements.get("log-result").textContent.includes(marker));
  assert.ok(calls.length >= 7);
  fakeDeveloper = false; await context.refresh();
  let count = calls.length; await context.showLog();
  assert.equal(calls.length, count); assert.equal(tabs[2].hidden, true);
  fakeMode = "off"; await context.refresh();
  count = calls.length; await context.answer("ask", "Explain this scan");
  assert.equal(calls.length, count); assert.equal(tabs[1].hidden, true);
  assert.equal(elements.get("send").disabled, true);
  assert.equal(elements.get("chat").hidden, true);
  assert.ok(!elements.get("chat-result").textContent.includes("Local AI reply"));
  console.log("PASS: shipped JS keeps strings/evidence literal, labels model replies honestly, sends both wording modes, separates messages, animates pending replies, hides Off AI/developer logs and uses only relative fake API calls.");
})().catch((error) => { console.error(error); process.exitCode = 1; });
