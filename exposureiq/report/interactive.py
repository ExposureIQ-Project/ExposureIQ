"""Fixed, offline-only browser behaviour; report data never becomes JavaScript."""

SCRIPT = r"""(() => {
  "use strict";
  const root = document.documentElement;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const home = document.getElementById("domain-home");
  const views = Array.from(document.querySelectorAll(".scan-view"));

  function targetFor(hash) {
    try { return document.getElementById(decodeURIComponent(hash.replace(/^#/, ""))); }
    catch (_) { return null; }
  }

  function showTarget(hash, scroll) {
    const target = targetFor(hash);
    if (home) {
      const view = target && target.closest(".scan-view");
      home.classList.toggle("is-active", !view);
      views.forEach(item => item.classList.toggle("is-active", item === view));
      document.body.classList.toggle("showing-home", !view);
      document.querySelectorAll("[data-report-section]").forEach(link => {
        if (view) link.setAttribute("href", "#" + view.id + "-" + link.dataset.reportSection);
      });
    }
    if (scroll && target) {
      target.scrollIntoView({behavior: reducedMotion.matches ? "auto" : "smooth", block: "start"});
      if (target.hasAttribute("tabindex")) target.focus({preventScroll: true});
    }
  }

  function navigate(hash) {
    if (!targetFor(hash)) return;
    if (window.location.hash !== hash) window.history.pushState(null, "", hash);
    showTarget(hash, true);
  }

  document.addEventListener("click", event => {
    const link = event.target.closest && event.target.closest("a[href^='#']");
    if (!link || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey
        || event.shiftKey || event.altKey || !targetFor(link.getAttribute("href"))) return;
    event.preventDefault();
    navigate(link.getAttribute("href"));
  });
  window.addEventListener("popstate", () => showTarget(window.location.hash, true));
  window.addEventListener("hashchange", () => showTarget(window.location.hash, true));
  root.classList.add("interactive-ready");
  showTarget(window.location.hash, Boolean(window.location.hash));

  document.querySelectorAll(".chart-line").forEach(svg => {
    const nodes = Array.from(svg.querySelectorAll(".chart-node"));
    const cursor = svg.querySelector(".chart-cursor");
    const shell = svg.closest(".chart-shell");
    const tooltip = shell && shell.querySelector(".chart-tooltip");
    if (!nodes.length || !cursor || !tooltip) return;

    function hide() {
      cursor.classList.add("is-hidden");
      tooltip.hidden = true;
      nodes.forEach(node => node.classList.remove("is-nearest"));
    }

    function show(node) {
      if (!node) return;
      const x = Number(node.dataset.x), y = Number(node.dataset.y);
      cursor.setAttribute("x1", x);
      cursor.setAttribute("x2", x);
      cursor.classList.remove("is-hidden");
      nodes.forEach(item => item.classList.toggle("is-nearest", item === node));
      tooltip.querySelector(".tooltip-number").textContent = "Scan " + node.dataset.scanNumber;
      tooltip.querySelector(".tooltip-id").textContent = node.dataset.scanId;
      tooltip.querySelector(".tooltip-date").textContent = node.dataset.scanDate;
      tooltip.querySelector(".tooltip-counts").textContent = node.dataset.assets + " hosts · "
        + node.dataset.findings + " findings · " + node.dataset.high + " high";
      tooltip.hidden = false;
      const matrix = svg.getScreenCTM();
      if (!matrix) return;
      const point = svg.createSVGPoint();
      point.x = x; point.y = y;
      const screen = point.matrixTransform(matrix);
      const bounds = shell.getBoundingClientRect();
      const left = Math.max(8, Math.min(screen.x - bounds.left + 14,
                                      bounds.width - tooltip.offsetWidth - 8));
      const top = Math.max(8, screen.y - bounds.top - tooltip.offsetHeight - 12);
      tooltip.style.left = left + "px";
      tooltip.style.top = top + "px";
    }

    function nearest(event) {
      const matrix = svg.getScreenCTM();
      if (!matrix) return null;
      const point = svg.createSVGPoint();
      point.x = event.clientX; point.y = event.clientY;
      const local = point.matrixTransform(matrix.inverse());
      return nodes.reduce((best, node) => Math.abs(Number(node.dataset.x) - local.x)
        < Math.abs(Number(best.dataset.x) - local.x) ? node : best, nodes[0]);
    }

    svg.addEventListener("pointermove", event => show(nearest(event)));
    svg.addEventListener("pointerleave", hide);
    svg.addEventListener("focusin", event => show(event.target.closest(".chart-node")));
    svg.addEventListener("focusout", hide);
    svg.addEventListener("click", event => {
      if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      const node = event.target.closest(".chart-node") || nearest(event);
      if (!node || !node.dataset.anchor) return;
      event.preventDefault(); event.stopPropagation();
      hide();
      navigate("#" + node.dataset.anchor);
    });
    nodes.forEach((node, index) => node.addEventListener("keydown", event => {
      if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
        event.preventDefault();
        nodes[Math.max(0, Math.min(nodes.length - 1, index + (event.key === "ArrowLeft" ? -1 : 1)))].focus();
      } else if ((event.key === "Enter" || event.key === " ") && node.dataset.anchor) {
        event.preventDefault(); hide(); navigate("#" + node.dataset.anchor);
      } else if (event.key === "Escape") hide();
    }));
  });

  const charts = Array.from(document.querySelectorAll("svg.chart"));
  let observer = null;
  charts.forEach(chart => {
    function finish(event) {
      if (event.animationName === "trend-draw" || event.animationName === "graph-grow"
          && event.type === "animationcancel" || event.animationName === "segment-enter"
          && event.target.matches(".donut-segment:last-of-type")) chart.classList.add("reveal-finished");
    }
    chart.addEventListener("animationend", finish);
    chart.addEventListener("animationcancel", finish);
  });
  if (!reducedMotion.matches && "IntersectionObserver" in window) {
    root.classList.add("motion-ready");
    observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        entry.target.classList.remove("reveal-pending");
        entry.target.classList.add("is-revealed");
        observer.unobserve(entry.target);
      });
    }, {threshold: 0.2});
    charts.forEach(chart => {
      chart.classList.add("reveal-pending");
      observer.observe(chart);
    });
  }
  reducedMotion.addEventListener("change", event => {
    if (!event.matches) return;
    root.classList.remove("motion-ready");
    if (observer) observer.disconnect();
    charts.forEach(chart => chart.classList.remove("reveal-pending"));
  });
})();"""

CSS = """
[hidden], .is-hidden { display: none !important; }
.chart-shell { position: relative; }
.chart-tooltip { position: absolute; z-index: 4; max-width: min(280px, calc(100% - 16px));
  padding: 10px 12px; border: 1px solid var(--teal); border-radius: 9px;
  background: var(--panel); color: var(--text); box-shadow: 0 8px 24px #0006;
  pointer-events: none; font-size: 11px; overflow-wrap: anywhere; }
.chart-tooltip span, .chart-tooltip strong { display: block; }
.tooltip-number { color: var(--teal); font-size: 13px; }
.tooltip-id, .tooltip-date, .tooltip-counts { color: var(--muted); margin-top: 3px; }
.chart-cursor { stroke: var(--subtle); stroke-width: 1; stroke-dasharray: 4 4;
  pointer-events: none; }
.chart-node { cursor: pointer; outline: none; }
.chart-line .node-hit { fill: transparent; stroke: none; }
.chart-node.is-nearest .node-dot, .chart-node:focus-visible .node-dot {
  stroke-width: 3.5; fill: var(--teal); }
.chart-series { transform-box: view-box; }
.chart-area { pointer-events: none; }
@keyframes graph-grow { from { transform: scaleY(0); opacity: .25; }
                       to { transform: scaleY(1); opacity: 1; } }
@media screen {
  .motion-ready .reveal-pending .chart-series { transform: scaleY(0); opacity: 0; }
  .motion-ready .is-revealed:not(.reveal-finished) .chart-series { animation: graph-grow 1s cubic-bezier(.2,.7,.2,1) both; }
  .motion-ready .reveal-pending .donut-segment { opacity: 0; }
  .motion-ready .is-revealed:not(.reveal-finished) .donut-segment { animation: segment-enter .9s ease both; }
  .motion-ready .is-revealed .donut-segment:nth-of-type(3) { animation-delay: .12s; }
  .motion-ready .is-revealed .donut-segment:nth-of-type(4) { animation-delay: .24s; }
  .motion-ready .is-revealed:not(.reveal-finished) .trend-line { stroke-dasharray: 1; animation: trend-draw 1.3s ease both; }
}
@media print {
  .chart-tooltip, .chart-cursor, .portal-controls { display: none !important; }
  .chart-series { transform: none !important; opacity: 1 !important; }
  .donut-segment { opacity: 1 !important; }
}
"""
