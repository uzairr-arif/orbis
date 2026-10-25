/* Orbis landing page: copy affordance and scroll reveals. No frameworks. */
(function () {
  "use strict";

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
