const renderers = {
  permissions: {
    message(missing) {
      return browser.i18n.getMessage(
        "WEBCAT_missingPermissions",
        Array.from(missing).join("\n"),
      );
    },
    button(missing) {
      const b = document.createElement("button");
      b.textContent = browser.i18n.getMessage("WEBCAT_fix");
      b.addEventListener("click", () => {
        const [permissions, origins] = [[], []];
        for (const permission of missing) {
          if (permission.includes("://") || permission === "<all_urls>") {
            origins.push(permission);
          } else {
            permissions.push(permission);
          }
        }
        try {
          browser.permissions.request({ permissions, origins });
          window.close();
        } catch {
          // TODO: browser.permissions.request may throw. Fall back to opening
          // a documentation page with guidance on resolving the issue manually
        }
      });
      return b;
    },
  },
};

document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(location.hash.slice(1));
  const warnings = JSON.parse(params.get("warnings") ?? "{}");
  for (const id in warnings) {
    const warning = document.createElement("div");
    warning.id = `warning-${id}`;
    warning.classList.add("warning");
    warning.textContent = renderers[id].message(...warnings[id]);
    if (renderers[id].button) {
      const button = renderers[id].button(...warnings[id]);
      warning.prepend(button);
    }
    document.body.prepend(warning);
  }
});
