// telltale web UI: the copy buttons. This is the only script the pages
// load; their Content-Security-Policy allows no inline script.
//
// A copy button names an element by id (data-copy) and copies that
// element's text exactly as shown: a fix command byte for byte as telltale
// built it. Fix commands marked "do not paste" get no button.
(function () {
  "use strict";

  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.className = "offscreen";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  function show(button, ok) {
    if (!button.hasAttribute("data-label")) {
      button.setAttribute("data-label", button.textContent);
    }
    button.textContent = ok ? "Copied" : "Copy failed: select it by hand";
    window.setTimeout(function () {
      button.textContent = button.getAttribute("data-label");
    }, 2000);
  }

  document.addEventListener("click", function (ev) {
    var button = ev.target.closest ? ev.target.closest("button[data-copy]") : null;
    if (!button) {
      return;
    }
    var el = document.getElementById(button.getAttribute("data-copy"));
    if (!el) {
      return;
    }
    var text = el.textContent;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(
        function () { show(button, true); },
        function () { show(button, fallbackCopy(text)); }
      );
    } else {
      show(button, fallbackCopy(text));
    }
  });
})();
