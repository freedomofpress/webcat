document.addEventListener("DOMContentLoaded", () => {
  function localize(container) {
    container.querySelectorAll("[data-i18n]").forEach((el) => {
      const substitutions = Array.from(el.children).map((child) => child.outerHTML);
      const msg = browser.i18n.getMessage(el.getAttribute("data-i18n"), substitutions);
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

  setText("error-host", host || browser.i18n.getMessage("thisSite"));
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
      ? browser.i18n.getMessage("advanced")
      : browser.i18n.getMessage("hideAdvanced");
  });

  // The error page took a history slot
  document
    .getElementById("returnButton")
    .addEventListener("click", () => history.back());
});

function setText(id, text) {
  document.getElementById(id).textContent = text;
}
