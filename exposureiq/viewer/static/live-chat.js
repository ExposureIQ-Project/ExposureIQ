(() => {
  "use strict";
  let started = false;
  function start() {
    if (started) return;
    started = true;
    // Only the authenticated loopback report gets this script. There are no
    // prepared answers, browser credentials, provider connections or acting tools.
    const $ = id => document.getElementById(id), location = window.location;
    const token = location.hash.slice(1);
    if (location.protocol !== "http:" || location.hostname !== "127.0.0.1" || !/^[A-Za-z0-9_-]{43}$/.test(token)) return;
    let bundle;
    try {
      bundle = JSON.parse($("exposureiq-chat-data").textContent);
      if (bundle.version !== "live-chat-1" || !bundle.scans || !Object.hasOwn(bundle.scans, bundle.default_scan)
          || Object.keys(bundle.scans).length > 500 || !Array.isArray(bundle.questions) || bundle.questions.length > 20
          || bundle.questions.some(value => typeof value !== "string" || value.length > 160)
          || Object.entries(bundle.scans).some(([id, row]) => !/^scan-[a-f0-9]{20}$/.test(id)
            || !row || !/^[a-f0-9]{64}$/.test(row.signature) || typeof row.scan_id !== "string" || typeof row.date !== "string")) return;
    } catch (_) { return; }

    function clearSessionFragment() {
      if (window.location.hash.slice(1) === token) {
        const start = $("report-main").dataset.startView;
        const initial = /^scan-[a-f0-9]{20}$/.test(start || "") && $(start)?.classList.contains("scan-view") ? start : "domain-home";
        window.history.replaceState(null, "", window.location.pathname + window.location.search + "#" + initial);
        window.dispatchEvent(new Event("hashchange"));
      }
    }
    clearSessionFragment();
    window.addEventListener("hashchange", clearSessionFragment);
    const pane = $("report-pane"), narrow = window.matchMedia("(max-width: 899px)");
    if (!pane) return;
    let selected = bundle.default_scan, health = null, connectionReady = false, busy = false, opened = false, optionsOpen = false;
    let sessionReady = false, generation = 0, healthGeneration = 0, active = null, healthController = null, turns = 0;
    let conversation = newConversation();
    let stopProgress = null;
    function setSplit(value, save = false) {
      const ratio = Math.max(30, Math.min(70, Math.round(Number(value) * 1000) / 1000));
      if (!Number.isFinite(ratio)) return;
      document.body.style.setProperty("--report-split", ratio + "%");
      $("export-chat-divider").setAttribute("aria-valuenow", String(Math.round(ratio)));
      if (save) { try { window.sessionStorage.setItem("exposureiq-report-split", String(ratio)); } catch (_) {} }
    }
    // Only a bounded layout percentage is retained for this browser tab. No
    // session token, question, answer, settings or provider data is stored.
    try {
      const saved = window.sessionStorage.getItem("exposureiq-report-split");
      if (saved !== null && /^\d{2}(?:\.\d{1,6})?$/.test(saved)) setSplit(saved);
    } catch (_) {}
    function newConversation() {
      const bytes = new Uint8Array(16); window.crypto.getRandomValues(bytes);
      return Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
    }
    function node(tag, value, className = "") {
      const element = document.createElement(tag); element.textContent = String(value);
      if (className) element.className = className;
      return element;
    }
    function available() { return Boolean(sessionReady && health && health.enabled); }
    function ready() { return Boolean(available() && connectionReady && health.ready && health.scan_id); }
    function controls() {
      $("export-chat-toggle").hidden = !available();
      $("export-chat").hidden = !opened || !available();
      $("export-chat-toggle").setAttribute("aria-expanded", String(opened && available()));
      $("export-chat-toggle").setAttribute("aria-label", opened ? "Close AI chat" : "Open AI chat");
      $("export-chat-toggle").title = opened ? "Close AI chat" : "Open AI chat";
      document.body.classList.toggle("chat-open", opened && available());
      pane.inert = opened && narrow.matches;
      pane.setAttribute("aria-hidden", String(opened && narrow.matches));
      $("export-chat").setAttribute("aria-modal", String(opened && narrow.matches));
      $("export-chat-divider").hidden = !opened || !available() || narrow.matches;
      $("export-chat-ideas").hidden = turns > 0;
      $("export-chat-stage").hidden = !busy;
      for (const id of ["export-chat-send", "export-chat-input", "export-chat-common", "export-chat-mode"])
        $(id).disabled = busy || !ready();
      for (const button of $("export-chat-ideas").querySelectorAll("button")) button.disabled = busy || !ready();
    }
    function setOptions(wanted, focus = true) {
      optionsOpen = Boolean(wanted && opened);
      $("export-chat-options").hidden = !optionsOpen;
      $("export-chat-options-toggle").setAttribute("aria-expanded", String(optionsOpen));
      if (focus) (optionsOpen ? $("export-chat-scan") : $("export-chat-options-toggle")).focus({preventScroll: true});
    }
    function setOpen(wanted, focus = true) {
      const previous = opened, reportScroll = opened ? pane.scrollTop : window.scrollY;
      opened = Boolean(wanted && available());
      if (!opened) setOptions(false, false);
      controls();
      if (previous !== opened) {
        if (opened) pane.scrollTop = reportScroll;
        else window.scrollTo({top: reportScroll, behavior: "instant"});
      }
      if (focus && available()) {
        if (opened && !ready()) setOptions(true);
        else (opened ? $("export-chat-input") : $("export-chat-toggle")).focus({preventScroll: true});
      }
    }
    function resetContext(message = "Chat cleared. No conversation is saved.") {
      generation += 1; if (active) active.abort(); active = null; busy = false;
      if (stopProgress) stopProgress(); stopProgress = null;
      conversation = newConversation(); turns = 0;
      $("export-chat-log").replaceChildren(); $("export-chat-input").value = "";
      $("export-chat-status").textContent = message; controls();
    }
    async function api(path, payload, controller, timeout) {
      const options = {headers: {"X-ExposureIQ-Session": token}, credentials: "omit", redirect: "error", mode: "same-origin", cache: "no-store", referrerPolicy: "same-origin", signal: controller.signal};
      if (payload !== undefined) { options.method = "POST"; options.headers["Content-Type"] = "application/json"; options.body = JSON.stringify(payload); }
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        const response = await fetch(path, options);
        if (!response.ok) { const error = new Error("Local request rejected"); error.status = response.status; throw error; }
        const content = await response.text();
        if (content.length > 256000) throw new Error("Local response exceeded its budget");
        return JSON.parse(content);
      } finally { clearTimeout(timer); }
    }
    async function checkHealth() {
      const current = ++healthGeneration, signature = bundle.scans[selected].signature;
      if (healthController) healthController.abort();
      const controller = new AbortController(); healthController = controller;
      try {
        const result = await api("/api/health?signature=" + encodeURIComponent(signature), undefined, controller, 5000);
        if (current !== healthGeneration || signature !== bundle.scans[selected].signature) return;
        if (result.protocol !== "ExposureIQ-local-v1" || result.loopback !== true || !["off", "demo", "local", "remote"].includes(result.mode)
            || typeof result.ready !== "boolean" || typeof result.enabled !== "boolean" || result.enabled !== (result.mode !== "off")
            || typeof result.scan_id !== "string" || !/^(?:[a-f0-9]{24})?$/.test(result.scan_id)
            || typeof result.endpoint_host !== "string" || result.endpoint_host.length > 500
            || typeof result.model !== "string" || result.model.length > 200) throw new Error("Local protocol mismatch");
        clearSessionFragment();
        const previous = health;
        const changed = previous && ["mode", "endpoint_host", "model"].some(key => previous[key] !== result[key]);
        health = result; connectionReady = true;
        if (changed || (previous && previous.ready && (!health.ready || !health.scan_id)))
          resetContext(health.enabled ? "AI settings or saved evidence changed. Start a new question." : "AI is off. Chat cleared.");
        if (!health.enabled) { if (opened || busy) resetContext("AI is off. Chat cleared."); setOpen(false, false); }
        $("export-chat-source").textContent = health.mode === "demo" ? "Offline demo · no live model" : health.mode === "off" ? "AI is off" : (health.mode === "remote" ? "Remote AI · " : "Local AI · ") + health.model;
        $("export-live-status").textContent = !health.enabled ? "AI is off in terminal Settings." : !health.scan_id
          ? "This exact saved scan is no longer available on the server. Reload the report before asking."
          : !health.ready ? "AI is not ready. Finish configuration and any remote-sharing consent in terminal Settings, then check again."
          : health.mode === "remote" ? "Scan summaries (host names, findings) will be sent to " + health.endpoint_host + ". Consent was confirmed in terminal Settings."
          : health.mode === "demo" ? "This explicit demo uses an offline fake, not a real model."
          : "Uses the same local AI settings as the TUI. No key is sent to this page.";
        controls(); return result;
      } catch (_) {
        if (current !== healthGeneration) return;
        connectionReady = false; controls();
        $("export-live-status").textContent = "The local server could not be checked. Keep exposureiq web running, then check settings again. No answer is generated here.";
      } finally { if (current === healthGeneration) healthController = null; }
    }
    function watchProgress(requestId, current, selection) {
      const controller = new AbortController();
      let pending = false;
      async function poll() {
        if (pending || controller.signal.aborted || !busy || current !== generation || selection !== selected) return;
        pending = true;
        try {
          const result = await api("/api/ai/progress?conversation=" + conversation + "&request=" + requestId, undefined, controller, 5000);
          if (controller.signal.aborted || current !== generation || selection !== selected) return;
          if (result && typeof result.done === "boolean" && ["Reading your scan", "Phrasing your answer", "Checking the facts", "Reply ready", "Reply unavailable"].includes(result.stage))
            $("export-chat-stage").textContent = result.stage;
        } catch (_) { /* Status failure never substitutes an answer. */ }
        finally { pending = false; }
      }
      const timer = setInterval(poll, 300);
      poll();
      return () => { clearInterval(timer); controller.abort(); };
    }
    function renderReply(userText, result, existing = null) {
      const log = $("export-chat-log"), nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
      let preserveTop = log.scrollTop;
      const turn = existing || node("article", "", "export-chat-turn");
      const user = node("div", "", "export-chat-user"), reply = node("div", "", "export-chat-reply");
      user.append(node("strong", "You · sent"), node("pre", userText));
      const answer = node("pre", result.text);
      reply.append(node("strong", "ExposureIQ · " + (result.pending ? "thinking" : result.label || "AI draft")), answer);
      if (result.offline_notice) reply.append(node("p", result.offline_notice, "export-chat-note"));
      if (result.failure_kind && result.reason) reply.append(node("p", result.reason, "export-chat-note"));
      if (result.footer) reply.append(node("p", result.footer, "export-chat-checked"));
      const refs = result.evidence_refs || [];
      if (refs.length) {
        const evidence = node("details", "", "export-chat-evidence"); evidence.append(node("summary", "Evidence"));
        for (const ref of refs) evidence.append(node("span", ref, "export-chat-ref"));
        if (result.review_note) evidence.append(node("p", result.review_note, "export-chat-note"));
        reply.append(evidence);
      }
      const actions = node("div", "", "export-chat-reply-actions");
      if (!result.pending) {
        const copy = node("button", "Copy answer"); copy.type = "button";
        copy.addEventListener("click", async () => {
          try {
            await window.navigator.clipboard.writeText(result.text);
            copy.textContent = "Copied";
            setTimeout(() => { copy.textContent = "Copy answer"; }, 1500);
          } catch (_) {
            const range = document.createRange(); range.selectNodeContents(answer);
            const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
            $("export-chat-status").textContent = "Automatic copy is unavailable. The answer is selected for you to copy.";
          }
        });
        actions.append(copy);
      }
      if (result.retryable && typeof result.retry_id === "string" && /^[a-f0-9]{32}$/.test(result.retry_id)) {
        const retry = node("button", "Try again", "export-chat-retry"); retry.type = "button";
        retry.addEventListener("click", () => send(result.user, result.retry_id)); actions.append(retry);
      }
      if (actions.children.length) reply.append(actions);
      turn.replaceChildren(user, reply);
      if (!existing) { if (!turns) log.replaceChildren(); turns += 1; log.append(turn); }
      // UI turns remain in this page only. Model memory is still the last three
      // exchanges; viewing an older answer does not force the reader downward.
      while (log.children.length > 30) { preserveTop -= log.children[0].getBoundingClientRect().height; log.removeChild(log.children[0]); }
      $("export-chat-ideas").hidden = turns > 0;
      $("export-chat-status").textContent = result.pending ? "Sending your question…" : result.footer || "Reply ready. Review it with your team.";
      log.scrollTop = nearBottom ? log.scrollHeight : Math.max(0, preserveTop);
      return turn;
    }
    function cleanQuestion(value) {
      return value.normalize("NFKC").replace(/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, " ")
        .replace(/\b(?:sk-[A-Za-z0-9_-]{4,}|FAKE-[A-Z0-9_-]*KEY[A-Z0-9_-]*|(?:api[_-]?key|token|password)\s*[:=]\s*\S+)/gi, "[redacted]").trim();
    }
    async function send(value = $("export-chat-input").value, retryId = "") {
      if (busy || !ready()) return;
      const question = cleanQuestion(value);
      if (!question || [...question].length > 1000) { $("export-chat-status").textContent = "Ask a nonempty question of at most 1000 characters."; return; }
      const current = generation, selection = selected, mode = $("export-chat-mode").value, controller = new AbortController();
      const requestId = newConversation();
      let finishProgress = null;
      $("export-chat-stage").textContent = "Sending your question…";
      busy = true; active = controller; controls(); $("export-chat-input").value = "";
      const turn = renderReply("Question sent. Your text will appear after private redaction.", {pending: true, text: "Thinking…"});
      try {
        // Policy, friendly replies, focus and grounding all belong to the TUI's
        // server-side chat service. No browser intent matcher substitutes text.
        await checkHealth();
        if (current !== generation || selection !== selected) return;
        if (!ready()) throw new Error("Local AI not ready");
        const payload = {scan: health.scan_id, question, mode, conversation, progress_id: requestId};
        if (retryId) payload.retry_id = retryId;
        finishProgress = watchProgress(requestId, current, selection); stopProgress = finishProgress;
        const result = await api("/api/ai/ask", payload, controller, 125000);
        if (current !== generation || selection !== selected) return;
        if (!result || typeof result.text !== "string" || result.text.length > 32000 || typeof result.user !== "string" || result.user.length > 4000
            || !Array.isArray(result.evidence_refs || []) || (result.evidence_refs || []).length > 64
            || (result.evidence_refs || []).some(ref => typeof ref !== "string" || ref.length > 200)) throw new Error("Invalid local reply");
        await checkHealth();
        if (current !== generation || selection !== selected) return;
        if (!ready()) throw new Error("Local AI no longer ready");
        if (["simple", "technical"].includes(result.mode)) $("export-chat-mode").value = result.mode;
        renderReply(result.user, result, turn); return result;
      } catch (error) {
        if (current !== generation) return;
        if (error.status === 409) { await checkHealth(); if (current !== generation) return; }
        renderReply("Question sent. Private text is not displayed without the server's check.", {
          text: error.status === 409 ? "Another AI answer may still be running. Wait a moment and try again."
            : "The local AI server did not answer. Keep exposureiq web running, check settings and try again. No reply was generated by this page.",
          label: "Reply unavailable", footer: "No prepared answer was substituted. Your saved report is still available."
        }, turn);
      } finally {
        if (finishProgress) finishProgress();
        if (stopProgress === finishProgress) stopProgress = null;
        if (current === generation) { busy = false; active = null; controls(); }
      }
    }
    function selectScan(identifier, navigate = false) {
      if (!Object.hasOwn(bundle.scans, identifier) || identifier === selected) return;
      selected = identifier; $("export-chat-scan").value = identifier;
      healthGeneration += 1; if (healthController) healthController.abort(); healthController = null;
      health = null; connectionReady = false; resetContext("Selected scan changed. Chat cleared.");
      if (navigate) window.location.hash = "#" + identifier + "-overview";
      checkHealth();
    }
    function syncReportSelection() {
      for (const identifier of Object.keys(bundle.scans)) {
        const view = $(identifier);
        if (view && view.classList.contains("is-active")) { selectScan(identifier); return; }
      }
    }
    for (const [identifier, row] of Object.entries(bundle.scans)) {
      const option = node("option", row.scan_id + " · " + row.date); option.value = identifier; $("export-chat-scan").append(option);
    }
    $("export-chat-scan").value = selected;
    for (const question of bundle.questions) { const option = node("option", question); option.value = question; $("export-chat-common").append(option); }
    for (const question of ["What is the worst finding?", "What should I fix first?", "Explain this scan in simple words."]) {
      const chip = node("button", question); chip.type = "button"; chip.addEventListener("click", () => send(question)); $("export-chat-ideas").append(chip);
    }
    const divider = $("export-chat-divider");
    divider.addEventListener("pointerdown", event => { if (event.button === 0) { divider.setPointerCapture(event.pointerId); event.preventDefault(); } });
    divider.addEventListener("pointermove", event => { if (divider.hasPointerCapture(event.pointerId)) setSplit(event.clientX / window.innerWidth * 100, true); });
    divider.addEventListener("pointerup", event => { if (divider.hasPointerCapture(event.pointerId)) divider.releasePointerCapture(event.pointerId); });
    divider.addEventListener("dblclick", () => setSplit(50, true));
    divider.addEventListener("keydown", event => {
      const value = Number(divider.getAttribute("aria-valuenow"));
      const next = {ArrowLeft: value - 2, ArrowRight: value + 2, Home: 30, End: 70}[event.key];
      if (next !== undefined) { event.preventDefault(); setSplit(next, true); }
    });
    narrow.addEventListener("change", () => { controls(); if (opened && narrow.matches) (ready() && !busy ? $("export-chat-input") : $("export-chat-close")).focus({preventScroll: true}); });
    $("export-chat-toggle").addEventListener("click", () => setOpen(!opened));
    $("export-chat-close").addEventListener("click", () => setOpen(false));
    $("export-chat-options-toggle").addEventListener("click", () => setOptions(!optionsOpen));
    document.addEventListener("click", event => {
      if (optionsOpen && !$("export-chat-options").contains(event.target) && !$("export-chat-options-toggle").contains(event.target)) setOptions(false, false);
    });
    $("export-chat").addEventListener("keydown", event => {
      if (event.key === "Escape") { event.preventDefault(); if (optionsOpen) setOptions(false); else setOpen(false); }
      if (event.key === "Tab" && opened && narrow.matches) {
        const focusable = [...$("export-chat").querySelectorAll("button, select, textarea, summary")].filter(element => !element.disabled && element.getClientRects().length);
        const first = focusable[0], last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    });
    document.addEventListener("keydown", event => {
      // Disabling the composer during a request can move focus to the document.
      // Escape still restores the report; don't handle a bubbled event twice.
      if (event.key === "Escape" && opened && !event.defaultPrevented) {
        event.preventDefault(); if (optionsOpen) setOptions(false); else setOpen(false);
      }
    });
    $("export-chat-send").addEventListener("click", () => send());
    $("export-chat-clear").addEventListener("click", () => { resetContext(); setOptions(false, false); $("export-chat-input").focus({preventScroll: true}); });
    $("export-chat-input").addEventListener("keydown", event => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); send(); } });
    $("export-chat-scan").addEventListener("change", () => selectScan($("export-chat-scan").value, true));
    $("export-chat-common").addEventListener("change", () => { const question = $("export-chat-common").value; $("export-chat-common").value = ""; if (question) { setOptions(false, false); send(question); } });
    $("export-live-refresh").addEventListener("click", checkHealth);
    window.addEventListener("focus", checkHealth);
    window.addEventListener("hashchange", syncReportSelection); window.addEventListener("popstate", syncReportSelection);
    document.addEventListener("visibilitychange", () => { if (document.visibilityState !== "hidden") checkHealth(); });
    if (typeof MutationObserver !== "undefined") new MutationObserver(syncReportSelection).observe($("report-main"), {attributes: true, subtree: true, attributeFilter: ["class"]});
    window.ExposureIQLiveChat = Object.freeze({checkHealth});
    syncReportSelection(); controls();
    checkHealth().finally(() => {
      // Native form navigation may restore its anchor late. Reveal the icon
      // only after cleanup, never while the session string is in the address.
      setTimeout(() => { clearSessionFragment(); sessionReady = true; controls(); }, 50);
    });
    const poll = setInterval(() => { if (document.visibilityState !== "hidden") checkHealth(); }, 5000);
    window.addEventListener("pagehide", () => { clearInterval(poll); if (stopProgress) stopProgress(); if (active) active.abort(); if (healthController) healthController.abort(); });
  }
  // A native POST navigation may apply its fragment after inline scripts run.
  // Read the per-launch token only after that document has finished loading.
  if (document.readyState === "complete") start();
  else window.addEventListener("pageshow", () => setTimeout(start, 0), {once: true});
})();
