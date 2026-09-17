document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(location.hash.slice(1));
  const warnings = JSON.parse(params.get("warnings") ?? "{}");
  for (const id in warnings) {
    const warning = document.createElement("div");
    warning.id = `warning-${id}`;
    warning.classList.add("warning");
    warning.textContent = warnings[id].message;
    if (warnings[id].url) {
      const info = document.createElement("a");
      info.textContent = "\u2139";
      info.href = warnings[id].url;
      info.target = "_blank";
      warning.prepend(info);
    }
    document.body.prepend(warning);
  }
});
