/* Sidebar accordion: expanding one nested item closes its siblings.
 * Active path stays open via server-rendered checked toggles.
 */
(function () {
  function directToggle(li) {
    for (var el = li.firstElementChild; el; el = el.nextElementSibling) {
      if (el.classList && el.classList.contains("md-nav__toggle")) {
        return el;
      }
    }
    return null;
  }

  function onChange(ev) {
    var input = ev.target;
    if (
      !input ||
      !input.classList ||
      !input.classList.contains("md-nav__toggle") ||
      input.id === "__toc" ||
      !input.checked
    ) {
      return;
    }
    var li = input.parentElement;
    if (!li || !li.classList.contains("md-nav__item--nested")) {
      return;
    }
    var list = li.parentElement;
    if (!list) {
      return;
    }
    for (var i = 0; i < list.children.length; i++) {
      var sib = list.children[i];
      if (sib === li || !sib.classList.contains("md-nav__item--nested")) {
        continue;
      }
      var toggle = directToggle(sib);
      if (toggle && toggle.checked) {
        toggle.checked = false;
      }
    }
  }

  function bind(root) {
    if (!root || root.dataset.navAccordion === "1") {
      return;
    }
    root.dataset.navAccordion = "1";
    root.addEventListener("change", onChange);
  }

  function init() {
    document
      .querySelectorAll(".md-sidebar--primary, nav.md-nav--primary")
      .forEach(bind);
  }

  if (typeof document$ !== "undefined") {
    document$.subscribe(init);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
