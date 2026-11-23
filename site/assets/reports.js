// Builds the reports page from reports/index.json, which the lab writes
// (lab/sitegen_test.go). Everything from it goes into the page as text, never
// as markup: the reports hold strings from the machines.
"use strict";

(function () {
  var SEVERITIES = [
    ["tampering", "tampering", "Tampering"],
    ["backdoor sign", "backdoor", "Backdoor sign"],
    ["weak setting", "weak", "Weak setting"],
    ["note", "note", "Note"]
  ];
  var CLASS = {};
  SEVERITIES.forEach(function (s) { CLASS[s[0]] = s[1]; });

  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    (children || []).forEach(function (c) {
      e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return e;
  }

  function link(href, text) { return el("a", { href: href }, [text]); }

  function mark() {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "mark");
    svg.setAttribute("viewBox", "0 0 20 20");
    svg.setAttribute("aria-hidden", "true");
    var a = document.createElementNS(ns, "path");
    a.setAttribute("fill", "currentColor");
    a.setAttribute("d", "M1.5 6.5H9L7.8 8.3L9.6 10L7.8 11.7L9 13.5H1.5Z");
    var b = document.createElementNS(ns, "path");
    b.setAttribute("fill", "none");
    b.setAttribute("stroke", "currentColor");
    b.setAttribute("stroke-width", "1.3");
    b.setAttribute("stroke-linejoin", "round");
    b.setAttribute("d", "M10.2 7.3H18.5V14.3H10.2L9 12.5L10.8 10.8L9 9.1Z");
    svg.appendChild(a);
    svg.appendChild(b);
    return svg;
  }

  function where(r) {
    return r.machine + (r.snapshot ? ", with a snapshot" : ", without a snapshot");
  }

  function exitWords(code) {
    switch (code) {
      case 0: return "exit code 0: nothing found";
      case 1: return "exit code 1: notes or weak settings only";
      case 2: return "exit code 2: tampering or a backdoor sign";
    }
    return "exit code " + code;
  }

  function counts(r) {
    var ul = el("ul", { "class": "counts", "aria-label": "Findings by severity" });
    var total = 0;
    SEVERITIES.forEach(function (s) {
      var n = (r.counts && r.counts[s[0]]) || 0;
      total += n;
      if (n > 0) {
        ul.appendChild(el("li", {}, [el("span", { "class": "sev " + s[1] }, [el("b", {}, [String(n)]), s[2]])]));
      }
    });
    if (total === 0) {
      ul.appendChild(el("li", {}, [el("span", { "class": "sev none" }, ["No findings"])]));
    }
    var explained = (r.counts && r.counts.explained) || 0;
    if (explained > 0) {
      ul.appendChild(el("li", {}, [el("span", { "class": "sev none" }, [el("b", {}, [String(explained)]), "Explained"])]));
    }
    return { list: ul, total: total };
  }

  // fillCase fills the report's section (the page has one for each report,
  // with links to its files for a reader without JavaScript), or a new one.
  function fillCase(cases, r, i) {
    var num = String(i + 1).padStart(2, "0");
    var sec = document.getElementById(r.name);
    if (!sec) {
      sec = el("section", { "class": "case", id: r.name });
      cases.appendChild(sec);
    }
    sec.textContent = "";
    sec.setAttribute("aria-labelledby", r.name + "-h");
    sec.appendChild(el("div", { "class": "sec-head" }, [
      el("p", { "class": "folio" }, [mark(), el("span", {}, [num + " / " + where(r)])]),
      el("h2", { id: r.name + "-h" }, [r.title])
    ]));
    sec.appendChild(el("p", { "class": "prose intro" }, [r.summary]));

    var story = el("ol", { "class": "steps" });
    (r.story || []).forEach(function (s) { story.appendChild(el("li", {}, [s])); });
    var heading = r.kind === "clean" ? "What happened" :
      r.kind === "no-snapshot" ? "What the attacker did (the same break-in)" : "What the attacker did";

    var c = counts(r);
    var found = el("ul", { "class": "found" });
    (r.found || []).forEach(function (f) {
      found.appendChild(el("li", {}, [
        el("span", { "class": "sev " + (CLASS[f.severity] || "note") }, [f.severity]),
        el("span", {}, [f.title])
      ]));
    });
    var right = [el("h3", {}, ["What telltale found"]), c.list];
    if ((r.found || []).length > 0) {
      right.push(found);
    }
    var more = c.total - (r.found || []).length;
    if (more > 0) {
      right.push(el("p", { "class": "meta-line" }, ["and " + more + " more in the report"]));
    }
    right.push(el("p", { "class": "meta-line" }, [
      "Compared against: " + (r.compared_against || []).join(", ") + ". " + exitWords(r.exit_code) + "."
    ]));
    sec.appendChild(el("div", { "class": "case-grid" }, [
      el("div", {}, [el("h3", {}, [heading]), story]),
      el("div", {}, right)
    ]));

    var base = "reports/";
    sec.appendChild(el("figure", { "class": "report-fig" }, [
      el("iframe", {
        src: base + r.files.html, title: "The HTML report telltale wrote for " + r.machine,
        loading: "lazy", sandbox: ""
      }),
      el("figcaption", {}, [
        "The HTML report as telltale wrote it. ",
        link(base + r.files.html, "Open it on its own"), " · ",
        link(base + r.files.text, "terminal output"), " · ",
        link(base + r.files.json, "JSON")
      ])
    ]));

    var pre = el("pre", {
      "class": "term", tabindex: "0", role: "region",
      "aria-label": "Terminal output of telltale scan on " + r.machine
    }, ["Loading…"]);
    var details = el("details", { "class": "termbox" }, [el("summary", {}, ["Terminal output"]), pre]);
    var loaded = false;
    details.addEventListener("toggle", function () {
      if (!details.open || loaded) {
        return;
      }
      loaded = true;
      fetch(base + r.files.text).then(function (res) {
        if (!res.ok) { throw new Error(res.status + " " + res.statusText); }
        return res.text();
      }).then(function (text) {
        pre.textContent = text;
      }).catch(function (err) {
        pre.textContent = "Could not load " + r.files.text + " (" + err.message + ").";
      });
    });
    sec.appendChild(details);
  }

  function fail(err) {
    var made = document.getElementById("made");
    made.textContent = "";
    made.appendChild(el("p", {}, [
      "The stories could not be loaded (" + err.message + "). The reports themselves are linked below."
    ]));
  }

  function build(idx) {
    var made = document.getElementById("made");
    made.textContent = "";
    made.appendChild(el("p", {}, [
      "Made with " + idx.version + " on " + idx.distro + " lab machines. ",
      link("reports/index.json", "index.json"), " lists them."
    ]));
    var jump = document.getElementById("jump");
    var cases = document.getElementById("cases");
    (idx.reports || []).forEach(function (r, i) {
      jump.appendChild(el("li", {}, [el("a", { href: "#" + r.name }, [
        el("span", {}, [r.machine]), el("strong", {}, [r.title])
      ])]));
      fillCase(cases, r, i);
    });
    if (location.hash) {
      var target = document.getElementById(location.hash.slice(1));
      if (target) { target.scrollIntoView(); }
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    fetch("reports/index.json").then(function (res) {
      if (!res.ok) { throw new Error(res.status + " " + res.statusText); }
      return res.json();
    }).then(build).catch(fail);
  });
})();
