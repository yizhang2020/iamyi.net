/**
 * Lightweight slide-by-slide viewer for Talks pages.
 * Markup: .talk-viewer[data-slides-base][data-slide-count][data-slide-pad]
 */
(function () {
  function pad(n, width) {
    const s = String(n);
    return s.length >= width ? s : "0".repeat(width - s.length) + s;
  }

  function initViewer(root) {
    const base = root.getAttribute("data-slides-base");
    const count = parseInt(root.getAttribute("data-slide-count") || "0", 10);
    const width = parseInt(root.getAttribute("data-slide-pad") || "2", 10);
    if (!base || !count) return;

    const img = root.querySelector(".talk-viewer__img");
    const status = root.querySelector(".talk-viewer__status");
    const prev = root.querySelector('[data-action="prev"]');
    const next = root.querySelector('[data-action="next"]');
    if (!img || !status || !prev || !next) return;

    let index = 1;

    function slideUrl(i) {
      return base.replace(/\/?$/, "/") + "slide-" + pad(i, width) + ".png";
    }

    function render() {
      img.src = slideUrl(index);
      img.alt = "Slide " + index + " of " + count;
      status.textContent = index + " / " + count;
      prev.disabled = index <= 1;
      next.disabled = index >= count;
    }

    function go(delta) {
      const nextIndex = Math.min(count, Math.max(1, index + delta));
      if (nextIndex === index) return;
      index = nextIndex;
      render();
    }

    prev.addEventListener("click", () => go(-1));
    next.addEventListener("click", () => go(1));

    root.addEventListener("keydown", (event) => {
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        go(-1);
      } else if (event.key === "ArrowRight" || event.key === " ") {
        event.preventDefault();
        go(1);
      } else if (event.key === "Home") {
        event.preventDefault();
        index = 1;
        render();
      } else if (event.key === "End") {
        event.preventDefault();
        index = count;
        render();
      }
    });

    // Prefetch neighbors for snappier navigation
    function prefetch(i) {
      if (i < 1 || i > count) return;
      const link = document.createElement("link");
      link.rel = "prefetch";
      link.as = "image";
      link.href = slideUrl(i);
      document.head.appendChild(link);
    }

    const observer = new MutationObserver(() => {
      prefetch(index - 1);
      prefetch(index + 1);
    });
    observer.observe(img, { attributes: true, attributeFilter: ["src"] });

    root.tabIndex = 0;
    render();
    prefetch(2);
  }

  function boot() {
    document.querySelectorAll(".talk-viewer").forEach(initViewer);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
