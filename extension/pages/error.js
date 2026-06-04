document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(location.hash.slice(1));
  const code = params.get("code") || "UNKNOWN";
  const host = params.get("host") || "";
  const file = params.get("file") || "";

  setText("error-host", host || "this site");
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
      ? "Advanced"
      : "Hide advanced";
  });

  // The error page took a history slot
  document
    .getElementById("returnButton")
    .addEventListener("click", () => history.back());
});

function setText(id, text) {
  document.getElementById(id).textContent = text;
}
