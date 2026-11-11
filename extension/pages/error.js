document.addEventListener("DOMContentLoaded", () => {
  function localize(container) {
    container.querySelectorAll("[data-i18n]").forEach((el) => {
      const substitutions = Array.from(el.children).map(
        (child) => child.outerHTML,
      );
      const msg = browser.i18n.getMessage(
        "WEBCAT_" + el.getAttribute("data-i18n"),
        substitutions,
      );
      if (msg === "") {
        return;
      }
      el.innerHTML = msg;
      localize(el);
    });
  }
  localize(document);

  const params = new URLSearchParams(location.hash.slice(1));
  const code = params.get("code") || "UNKNOWN";
  const host = params.get("host") || "";
  const file = params.get("file") || "";

  const variant = {
    ERR_WEBCAT_ENROLLMENT_SCHEMA_DEPRECATED: "schemaDeprecated",
    ERR_WEBCAT_MANIFEST_SCHEMA_DEPRECATED: "schemaDeprecated",
    ERR_WEBCAT_ENROLLMENT_SCHEMA_UNSUPPORTED: "schemaUnsupported",
    ERR_WEBCAT_MANIFEST_SCHEMA_UNSUPPORTED: "schemaUnsupported",
    ERR_WEBCAT_INTERNAL_UNEXPECTED: "internalError",
    ERR_WEBCAT_BUNDLE_FETCH_ERROR: "bundleFetchError",
    ERR_WEBCAT_MANIFEST_EXPIRED: "manifestExpired",
    ERR_WEBCAT_MANIFEST_NOT_YET_VALID: "clockSkew",
    ERR_WEBCAT_FRAME_ISOLATION_OAC_UNAVAILABLE: "frameIsolation",
    ERR_WEBCAT_FRAME_ISOLATION_OAC_UNSUPPORTED: "browserUnsupported",
  }[code];
  if (variant) {
    const msg = (suffix, ...subs) =>
      browser.i18n.getMessage("WEBCAT_" + variant + suffix, subs);
    document.title = msg("Title");
    document.querySelector("h1.title-text").textContent = msg("Title");
    document.getElementById("errorShortDesc").innerHTML = msg(
      "ShortDesc",
      '<span id="error-host"></span>',
    );
    const what = document.getElementById("whatCanYouDo");
    what.innerHTML = msg(
      "WhatYouCanDo",
      '<a href="https://github.com/freedomofpress/webcat" data-i18n="webcatRepository">WEBCAT repository</a>',
    );
    localize(what);
  }

  // Tab title names WEBCAT and the blocked host; <title> was localized above.
  document.title = `WEBCAT: ${document.title}${host ? ` — ${host}` : ""}`;
  setText("error-host", host || browser.i18n.getMessage("WEBCAT_thisSite"));
  setText("debug-code", code);

  if (file) {
    setText("debug-file", file);
    document.getElementById("debug-file-line").hidden = false;
  }

  const advancedButton = document.getElementById("advancedButton");
  const advancedPanel = document.getElementById("errorDebugInformation");
  advancedButton.addEventListener("click", () => {
    advancedPanel.hidden = !advancedPanel.hidden;
    advancedButton.setAttribute("aria-expanded", String(!advancedPanel.hidden));
    advancedButton.textContent = advancedPanel.hidden
      ? browser.i18n.getMessage("WEBCAT_advanced")
      : browser.i18n.getMessage("WEBCAT_hideAdvanced");
  });

  // The error page took a history slot
  document
    .getElementById("returnButton")
    .addEventListener("click", () => history.back());
});

function setText(id, text) {
  document.getElementById(id).textContent = text;
}
