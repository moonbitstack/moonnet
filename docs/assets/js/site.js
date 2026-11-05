// moonnet docs — theme, menu, copy buttons, the page scroll bar's at-top state, and the
// showcase's protocol switch. No framework, no build step.
(function () {
  "use strict";

  var root = document.documentElement;

  // The page thumb is hidden while the page sits at the top and shown once it has moved.
  function markTop() {
    root.classList.toggle("at-top", window.scrollY === 0);
  }
  window.addEventListener("scroll", markTop, { passive: true });
  markTop();

  // ---- theme ----
  function applyTheme(t) {
    if (t === "dark") root.setAttribute("data-theme", "dark");
    else root.removeAttribute("data-theme");
    document.querySelectorAll(".nav__toggle").forEach(function (b) {
      b.setAttribute("aria-pressed", String(t === "dark"));
    });
    try {
      localStorage.setItem("moonnet-theme", t);
    } catch (e) {}
  }
  var saved = null;
  try {
    saved = localStorage.getItem("moonnet-theme");
  } catch (e) {}
  if (!saved) {
    saved =
      window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
  }
  applyTheme(saved);

  document.querySelectorAll(".nav__toggle").forEach(function (b) {
    b.addEventListener("click", function () {
      applyTheme(root.getAttribute("data-theme") === "dark" ? "light" : "dark");
    });
  });

  // ---- mobile menu ----
  var menuBtn = document.querySelector(".nav__menu");
  var navEl = document.querySelector(".nav");
  if (menuBtn && navEl) {
    menuBtn.addEventListener("click", function () {
      var open = navEl.classList.toggle("is-open");
      menuBtn.setAttribute("aria-expanded", String(open));
    });
  }

  // The packets on the hero's lanes are SVG motion, which CSS cannot switch off; the reader's
  // preference is asked for once and the animations are removed rather than hidden.
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    document.querySelectorAll("animateMotion").forEach(function (m) {
      m.remove();
    });
  }

  // ---- colour in the code blocks ----
  // Comments, strings, keywords and numbers, painted without touching the text: a copy of the
  // block still yields what the reader sees. Deliberately small — this is a documentation page,
  // not an editor, and a wrong colour is worse than none.
  var TOKEN =
    /(\/\/[^\n]*)|("(?:[^"\\\n]|\\.)*")|\b(async|fn|let|mut|match|if|else|guard|while|for|in|return|raise|try|catch|type|pub|struct|enum|trait|impl|using|const|true|false|Some|None)\b|\b(\d+(?:\.\d+)?)\b/g;
  var esc = function (t) {
    return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  };
  document.querySelectorAll(".codeblock pre code").forEach(function (code) {
    var text = code.textContent;
    code.innerHTML = esc(text).replace(TOKEN, function (all, com, str, kw, num) {
      if (com) return '<span class="com">' + com + "</span>";
      if (str) return '<span class="str">' + str + "</span>";
      if (kw) return '<span class="kw">' + kw + "</span>";
      if (num) return '<span class="num">' + num + "</span>";
      return all;
    });
  });

  // ---- copy ----
  document.querySelectorAll(".codeblock .copy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var block = btn.closest(".codeblock");
      var code = block && block.querySelector("pre code");
      if (!code) return;
      navigator.clipboard.writeText(code.innerText).then(function () {
        var old = btn.textContent;
        btn.textContent = "copied";
        setTimeout(function () {
          btn.textContent = old;
        }, 1200);
      });
    });
  });

  // ---- tab groups: each group switches only the panels it owns ----
  document.querySelectorAll(".tabs").forEach(function (group) {
    var tabs = Array.prototype.slice.call(group.querySelectorAll("[data-tab]"));
    var names = tabs.map(function (t) {
      return t.getAttribute("data-tab");
    });
    var show = function (name) {
      tabs.forEach(function (t) {
        var on = t.getAttribute("data-tab") === name;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
      });
      document.querySelectorAll("[data-panel]").forEach(function (p) {
        var mine = names.indexOf(p.getAttribute("data-panel")) >= 0;
        if (mine) p.hidden = p.getAttribute("data-panel") !== name;
      });
    };
    tabs.forEach(function (t) {
      t.addEventListener("click", function () {
        show(t.getAttribute("data-tab"));
      });
      t.addEventListener("keydown", function (e) {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
        var i = tabs.indexOf(t);
        var next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
        next.focus();
        show(next.getAttribute("data-tab"));
      });
    });
  });

  // ---- the step-through on the showcase page ----
  function visibleTrace() {
    var list = document.querySelectorAll("[data-panel]:not([hidden]) [data-trace]");
    return list.length ? list[0] : null;
  }
  document.querySelectorAll("[data-step]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var trace = visibleTrace();
      if (!trace) return;
      var items = Array.prototype.slice.call(trace.children);
      var at = Number(trace.getAttribute("data-at") || 0);
      if (btn.getAttribute("data-step") === "reset") {
        at = 0;
      } else if (at < items.length) {
        at += 1;
      }
      trace.setAttribute("data-at", String(at));
      items.forEach(function (li, i) {
        li.classList.toggle("is-on", i < at);
      });
    });
  });

  // The first step of a trace is shown, so the list reads as a sequence rather than as
  // greyed-out text waiting for a click.
  document.querySelectorAll("[data-trace]").forEach(function (t) {
    t.setAttribute("data-at", "1");
    if (t.children.length) t.children[0].classList.add("is-on");
  });

  // ---- scroll-spy ----
  var links = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (links.length) {
    var targets = links
      .map(function (a) {
        return document.getElementById(a.getAttribute("href").slice(1));
      })
      .filter(Boolean);
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (en) {
          if (!en.isIntersecting) return;
          links.forEach(function (a) {
            a.classList.toggle(
              "is-active",
              a.getAttribute("href") === "#" + en.target.id
            );
          });
        });
      },
      { rootMargin: "-84px 0px -68% 0px", threshold: 0 }
    );
    targets.forEach(function (t) {
      io.observe(t);
    });
  }
})();
