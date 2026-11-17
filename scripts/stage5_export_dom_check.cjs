"use strict";
// Run the ACTUAL script embedded in an exported HTML file, with an offline
// fake DOM. This is a parity/interaction test, not a visual browser test.
const assert = require("node:assert/strict"), fs = require("node:fs"), vm = require("node:vm");
const [htmlPath, parityPath] = process.argv.slice(2);
if (!htmlPath || !parityPath) throw new Error("Pass exported index.html and Python-built parity JSON.");
const page = fs.readFileSync(htmlPath, "utf8"), parity = JSON.parse(fs.readFileSync(parityPath, "utf8"));
const scripts = [...page.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
const data = scripts.find(item => item[1].includes('id="exposureiq-chat-data"'))[2];
const script = scripts.find(item => item[1].includes('id="exposureiq-offline-chat"'))[2];
class Element {
  constructor(tag = "div") {
    this.tag = tag; this.children = []; this.handlers = {}; this.value = ""; this.open = false;
    this.classList = {contains() { return false; }};
  }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return (this.text || "") + this.children.map(child => child.textContent).join(""); }
  set innerHTML(_) { throw new Error("Executable HTML sink used"); }
  set outerHTML(_) { throw new Error("Executable HTML sink used"); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.text = ""; this.children = items; }
  removeChild(item) { this.children = this.children.filter(child => child !== item); }
  addEventListener(name, callback) { this.handlers[name] = callback; }
}
const elements = new Map(), document = {
  getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
  createElement(tag) { return new Element(tag); },
};
const window = {addEventListener() {}, location: {protocol: "file:"}};
const blocked = () => { throw new Error("Offline chat attempted networking or persistent storage"); };
const context = {document, window, console, fetch: blocked, XMLHttpRequest: blocked, WebSocket: blocked,
  localStorage: new Proxy({}, {get: blocked}), sessionStorage: new Proxy({}, {get: blocked})};
document.getElementById("exposureiq-chat-data").textContent = data;
document.getElementById("export-chat-mode").value = "simple";
vm.createContext(context); vm.runInContext(script, context);
for (const row of parity.routes) {
  const actual = JSON.parse(JSON.stringify(window.ExposureIQOfflineChat.routeQuestion(row.question, row.previous_kind || "")));
  assert.deepEqual(actual, row.expected, row.question);
}
let exchanges = 0;
for (const sequence of parity.sequences) {
  elements.get("export-chat-clear").handlers.click();
  elements.get("export-chat-scan").value = sequence.scan;
  elements.get("export-chat-scan").handlers.change();
  for (const row of sequence.turns) {
    elements.get("export-chat-mode").value = row.mode;
    elements.get("export-chat-input").value = row.question;
    const actual = JSON.parse(JSON.stringify(elements.get("export-chat-send").handlers.click()));
    assert.deepEqual(actual, row.expected, row.question);
    const turn = elements.get("export-chat-log").children.at(-1), reply = turn.children[1];
    const evidence = reply.children.find(child => child.tag === "details");
    if (actual.refs.length) { assert.equal(evidence.open, false); assert.equal(evidence.children[0].textContent, "Evidence"); }
    else assert.equal(evidence, undefined);
    exchanges++;
  }
}
const marker = '<img src=x onerror="literal-text-only">';
elements.get("export-chat-input").value = marker;
elements.get("export-chat-send").handlers.click();
assert.ok(elements.get("export-chat-log").textContent.includes(marker));
assert.ok(elements.get("export-chat-log").children.at(-1).children[0].children.every(child => child.tag !== "img"));
assert.ok(elements.get("export-sharing-warning").textContent.includes("No API key is included"));
elements.get("export-chat-common").value = "Which host is the most exposed?";
elements.get("export-chat-common").handlers.change();
assert.ok(elements.get("export-chat-log").textContent.includes("exposure score"));
elements.get("export-chat-clear").handlers.click();
assert.equal(elements.get("export-chat-log").children.length, 0);
console.log(`PASS: exported script agrees with Python on ${parity.routes.length} phrase routes and ${exchanges} chat turns; modes, focus, literal text, collapsed evidence, common questions and clear-chat work without networking/storage.`);
