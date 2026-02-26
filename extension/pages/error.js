document.addEventListener("DOMContentLoaded", () => {
  const code = decodeURIComponent(location.hash.slice(1));
  const el = document.getElementById("error-code");
  if (el) {
    el.textContent = code || "UNKNOWN";
  }
});
