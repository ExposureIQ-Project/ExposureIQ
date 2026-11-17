"use strict";
// Exercise the ACTUAL live drawer script from an in-memory server report.
// All fetches are fakes; this does not replace the real Firefox evidence.
const assert = require("node:assert/strict"), fs = require("node:fs"), vm = require("node:vm"), crypto = require("node:crypto");
const page = fs.readFileSync(process.argv[2], "utf8");
const scripts = [...page.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
const data = scripts.find(item => item[1].includes('id="exposureiq-chat-data"'))[2];
const live = scripts.find(item => item[1].includes('id="exposureiq-live-chat"'))[2];
assert.equal(JSON.parse(data).version, "live-chat-1");
assert.ok(!page.includes('id="exposureiq-offline-chat"'));
class Element {
  constructor(tag = "div") { this.tag = tag; this.children = []; this.handlers = {}; this.attributes = {}; this.value = ""; this.hidden = true; this.disabled = false; this.open = false; this.active = false; this.classList = {contains: () => this.active}; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return (this.text || "") + this.children.map(item => item.textContent).join(""); }
  set innerHTML(_) { throw new Error("HTML sink used"); }
  set outerHTML(_) { throw new Error("HTML sink used"); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.text = ""; this.children = items; }
  removeChild(item) { this.children = this.children.filter(child => child !== item); }
  addEventListener(name, callback) { this.handlers[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  focus() { this.focused = true; }
}
async function flush() { for (let i = 0; i < 12; i++) await Promise.resolve(); }
async function boot({protocol = "http:", hostname = "127.0.0.1", hash = "#" + "T".repeat(43)} = {}) {
  const elements = new Map(), calls = [], askPayloads = [], events = {}, timers = new Map(), createdTags = [];
  for (const match of page.matchAll(/\bid="([^"]+)"/g)) elements.set(match[1], new Element());
  const document = {readyState: "complete", visibilityState: "visible", getElementById(id) {return elements.get(id) || null;}, createElement(tag) {createdTags.push(tag); return new Element(tag);}, addEventListener() {}};
  const window = {location: {protocol, hostname, hash, pathname: "/api/report", search: ""}, history: {replaceState(_state, _title, target) {window.location.hash = target.slice(target.indexOf("#"));}}, crypto: crypto.webcrypto, addEventListener(name, callback) {(events[name] ||= []).push(callback);}};
  const environment = {mode: "local", ready: true, scanId: "0123456789abcdef01234567", failHealth: false, failAsk: false, badReply: false, defer: false, release: null};
  const context = {document, window, console, AbortController, Uint8Array, setTimeout, clearTimeout,
    setInterval(callback) {const id = timers.size + 1; timers.set(id, callback); return id;}, clearInterval(id) {timers.delete(id);},
    localStorage: new Proxy({}, {get() {throw new Error("Persistent storage used");}}), sessionStorage: new Proxy({}, {get() {throw new Error("Persistent storage used");}}),
    async fetch(path, options) {
      assert.ok(path.startsWith("/api/health?") || path === "/api/ai/ask");
      assert.equal(options.headers["X-ExposureIQ-Session"], "T".repeat(43));
      assert.equal(options.credentials, "omit"); assert.equal(options.redirect, "error"); assert.equal(options.mode, "same-origin");
      assert.equal(options.cache, "no-store"); assert.equal(options.referrerPolicy, "same-origin");
      calls.push(path);
      let body;
      if (path.startsWith("/api/health?")) {
        if (environment.failHealth) throw new Error("FAKE-RAW-PRIVATE-ERROR");
        body = {protocol: "ExposureIQ-local-v1", loopback: true, mode: environment.mode, enabled: environment.mode !== "off", ready: environment.ready,
          scan_id: environment.scanId, endpoint_host: environment.mode === "remote" ? "ai.example.com" : "127.0.0.1:11434", model: "offline fake"};
      } else {
        const payload = JSON.parse(options.body); askPayloads.push(payload);
        assert.match(payload.conversation, /^[a-f0-9]{32}$/); assert.ok(["simple", "technical"].includes(payload.mode));
        assert.equal(payload.scan, environment.scanId); assert.equal(options.method, "POST");
        body = {text: "FRESH-SERVER-REPLY: db.example.com has saved exposure that deserves closer attention.", user: "Explain [redacted]", source: "fake", label: "Offline test reply", mode: payload.mode,
          footer: "saved evidence checked; wording needs review", evidence_refs: ["F-0005", '<img src=x onerror="literal-text-only">'], answer_kind: "host", answer_focus: {host: "db.example.com", finding_id: "", scope: "host"}};
        if (environment.failAsk) throw new Error("FAKE-RAW-PRIVATE-ERROR");
        if (environment.badReply) body.evidence_refs = [null];
      }
      const response = {ok: true, status: 200, async text() {return JSON.stringify(body);}};
      if (environment.defer && path === "/api/ai/ask") return new Promise(resolve => {environment.release = (status = 200) => resolve({...response, ok: status === 200, status});});
      return response;
    }};
  document.getElementById("exposureiq-chat-data").textContent = data;
  document.getElementById("export-chat-mode").value = "simple";
  vm.createContext(context); vm.runInContext(live, context);
  await flush(); await new Promise(resolve => setTimeout(resolve, 60)); await flush();
  return {elements, calls, askPayloads, environment, window, events, timers, createdTags,
    async health() { await window.ExposureIQLiveChat.checkHealth(); },
    toggle() {elements.get("export-chat-toggle").handlers.click?.();},
    send(question) { elements.get("export-chat-input").value = question; return elements.get("export-chat-send").handlers.click?.(); }};
}
(async () => {
  for (const options of [{protocol: "file:"}, {hostname: "example.com"}, {protocol: "https:"}, {hash: ""}, {hash: "#wrong"}]) {
    const app = await boot(options);
    assert.equal(app.calls.length, 0); await app.send("Which host is the most exposed?");
    assert.equal(app.elements.get("export-chat-toggle").hidden, true);
    assert.ok(!app.elements.get("export-chat-log").textContent.includes("45"));
  }
  const app = await boot();
  assert.equal(app.window.location.hash, "#domain-home"); assert.equal(app.askPayloads.length, 0);
  assert.equal(app.elements.get("export-chat-toggle").hidden, false);
  assert.equal(app.elements.get("export-chat").hidden, true);
  assert.equal(app.elements.get("export-chat-send").disabled, false);
  app.toggle(); assert.equal(app.elements.get("export-chat").hidden, false);
  assert.equal(app.elements.get("export-chat-toggle").attributes["aria-expanded"], "true");
  assert.equal(app.elements.get("export-chat-input").focused, true);
  app.elements.get("export-chat-close").handlers.click();
  assert.equal(app.elements.get("export-chat").hidden, true);
  assert.equal(app.elements.get("export-chat-toggle").focused, true);
  app.toggle(); app.elements.get("export-chat").handlers.keydown({key: "Escape", preventDefault() {}});
  assert.equal(app.elements.get("export-chat").hidden, true); app.toggle();
  app.window.location.hash = "#" + "T".repeat(43);  // Native form restores its initial fragment.
  for (const callback of app.events.hashchange) callback();
  assert.equal(app.window.location.hash, "#domain-home");
  let requests = app.askPayloads.length;
  for (const question of ["hi", "thanks", "Give me a paylod"]) await app.send(question);
  assert.equal(app.askPayloads.length, requests + 3); // Server owns friendly/policy checks, not a browser matcher.
  await app.send("Tell me more about this saved exposure FAKE-NOT-A-REAL-KEY");
  assert.equal(app.askPayloads.at(-1).mode, "simple");
  const log = app.elements.get("export-chat-log");
  assert.ok(log.textContent.includes("[redacted]")); assert.ok(!log.textContent.includes("FAKE-NOT-A-REAL-KEY"));
  assert.ok(log.textContent.includes("FRESH-SERVER-REPLY"));
  const details = log.children.at(-1).children[1].children.find(child => child.tag === "details");
  assert.equal(details.open, false); assert.equal(details.children[0].textContent, "Evidence");
  assert.equal(details.children[2].tag, "span"); assert.ok(details.children[2].textContent.includes("<img"));
  assert.ok(!app.createdTags.includes("img"));
  app.elements.get("export-chat-mode").value = "technical";
  await app.send("Explain this scan technically"); assert.equal(app.askPayloads.at(-1).mode, "technical");
  const conversation = app.askPayloads.at(-1).conversation;
  app.elements.get("export-chat-clear").handlers.click(); await app.send("Explain this scan");
  assert.notEqual(app.askPayloads.at(-1).conversation, conversation);
  app.environment.mode = "remote"; await app.health();
  assert.ok(app.elements.get("export-live-status").textContent.includes("ai.example.com"));
  assert.equal(log.children.length, 0); app.environment.defer = true;
  const pending = app.send("Explain the saved scan"); await flush();
  assert.ok(log.textContent.includes("thinking")); assert.equal(app.elements.get("export-chat-send").disabled, true);
  app.environment.mode = "off"; app.environment.ready = false; await app.health(); app.environment.release(); await pending;
  assert.equal(log.children.length, 0); assert.equal(app.elements.get("export-chat-toggle").hidden, true);
  assert.equal(app.elements.get("export-chat").hidden, true); assert.equal(app.elements.get("export-chat-send").disabled, true);
  app.environment.mode = "local"; app.environment.ready = true; app.environment.defer = false; await app.health(); app.toggle();
  app.environment.failHealth = true; await app.send("Which host is the most exposed?");
  assert.ok(log.textContent.includes("Reply unavailable")); assert.ok(!log.textContent.includes("45"));
  assert.ok(app.elements.get("export-chat-status").textContent.includes("No prepared answer was substituted"));
  assert.ok(!log.textContent.includes("FAKE-RAW-PRIVATE-ERROR"));
  assert.equal(app.elements.get("export-chat-send").disabled, true);
  app.environment.failHealth = false; await app.health(); app.environment.failAsk = true;
  await app.send("Explain this scan"); assert.ok(log.textContent.includes("Reply unavailable"));
  app.environment.failAsk = false; app.environment.scanId = ""; await app.health();
  assert.equal(app.elements.get("export-chat-send").disabled, true);
  const count = app.askPayloads.length; await app.send("Explain this scan"); assert.equal(app.askPayloads.length, count);
  app.environment.scanId = "0123456789abcdef01234567"; await app.health(); app.environment.defer = true;
  const stale = app.send("Explain this scan"); await flush();
  app.elements.get("export-chat-clear").handlers.click(); app.environment.release(); await stale;
  assert.equal(log.children.length, 0);
  app.environment.defer = false; app.environment.badReply = true; await app.send("Explain this scan");
  assert.ok(log.textContent.includes("Reply unavailable")); assert.ok(!log.textContent.includes("FRESH-SERVER-REPLY"));
  app.environment.badReply = false;
  const rows = Object.keys(JSON.parse(data).scans), current = app.elements.get("export-chat-scan").value;
  const other = rows.find(id => id !== current);
  app.elements.get("export-chat-scan").value = other; app.elements.get("export-chat-scan").handlers.change(); await flush();
  assert.equal(log.children.length, 0); assert.equal(app.window.location.hash, "#" + other + "-overview");
  app.environment.mode = "off"; app.environment.ready = false;
  for (const callback of app.timers.values()) callback(); await flush();
  assert.equal(app.elements.get("export-chat-toggle").hidden, true);
  console.log("PASS: actual live drawer uses only token-protected relative requests, no prepared replies or browser intent matching; icon/close/Escape/focus work, settings enable chat automatically, both modes and redaction work, Evidence stays literal, scan/clear isolate conversations, host-named consent is visible, Off hides chat and drops pending replies, stale/malformed replies are suppressed and server failure never substitutes saved answers.");
})().catch(error => {console.error(error); process.exitCode = 1;});
