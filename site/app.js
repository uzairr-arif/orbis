/* Orbis landing page: theme toggle, copy affordance, scroll reveals. No frameworks. */
(function () {
  "use strict";

  /* ============ Theme toggle ============ */

  var root = document.documentElement;
  var toggle = document.querySelector(".theme-toggle");

  function applyTheme(dark, persist) {
    root.dataset.theme = dark ? "dark" : "light";
    if (persist) {
      try { localStorage.setItem("theme", dark ? "dark" : "light"); } catch (e) {}
    }
    if (toggle) {
      toggle.querySelector("i").className = dark ? "ph ph-sun" : "ph ph-moon-stars";
      toggle.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
      toggle.setAttribute("aria-pressed", dark ? "true" : "false");
    }
  }

  applyTheme(root.dataset.theme === "dark", false);

  if (toggle) {
    toggle.addEventListener("click", function () {
      applyTheme(root.dataset.theme !== "dark", true);
    });
  }

  /* ============ Copy to clipboard ============ */

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* Copy-to-clipboard on the install chips, with inline feedback. */
  document.querySelectorAll("[data-copy]").forEach(function (chip) {
    chip.addEventListener("click", function () {
      var text = chip.getAttribute("data-copy");
      var btn = chip.querySelector(".copy-btn");
      var icon = btn ? btn.querySelector("i") : null;
      if (!navigator.clipboard) return;

      navigator.clipboard.writeText(text).then(function () {
        if (!btn || !icon) return;
        icon.className = "ph ph-check";
        btn.classList.add("copied");
        setTimeout(function () {
          icon.className = "ph ph-copy";
          btn.classList.remove("copied");
        }, 1600);
      });
    });
  });

  /* Reveal-on-scroll for sections, skipped entirely under reduced motion. */
  if (reduceMotion || !("IntersectionObserver" in window)) return;

  var observer = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          observer.unobserve(entry.target);
        }
      });
    },
    { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
  );

  document.querySelectorAll(".reveal").forEach(function (el) {
    observer.observe(el);
  });
})();
