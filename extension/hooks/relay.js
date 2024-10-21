window.addEventListener("message", function (event) {
  if (event.source !== window) return;

  if (event.data && event.data.type === "FROM_HOOK") {
    browser.runtime.sendMessage({
      type: event.data.hookType,
      details: event.data.details,
    });
  }
});
