(() => {
  "use strict";
  // An AI-Off server report has no chat. Only clear its temporary session
  // fragment; do not retain it, connect anywhere or read browser storage.
  function clearFragment() {
    const location = window.location;
    if (location.protocol === "http:" && location.hostname === "127.0.0.1" && /^[A-Za-z0-9_-]{43}$/.test(location.hash.slice(1))) {
      const start = document.getElementById("report-main").dataset.startView;
      const initial = /^scan-[a-f0-9]{20}$/.test(start || "") && document.getElementById(start)?.classList.contains("scan-view") ? start : "domain-home";
      window.history.replaceState(null, "", location.pathname + location.search + "#" + initial);
      window.dispatchEvent(new Event("hashchange"));
    }
  }
  window.addEventListener("hashchange", clearFragment);
  window.addEventListener("pageshow", () => { clearFragment(); setTimeout(clearFragment, 50); });
  if (document.readyState === "complete") clearFragment();
})();
