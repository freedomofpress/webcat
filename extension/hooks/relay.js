window.addEventListener("message", function (event) {
  if (event.source !== window) return;

  if (event.data && event.data.type === "WASM_HASH") {
    browser.runtime
      .sendMessage({
        type: event.data.type,
        details: event.data.payload,
      })
      .then((response) => {
        window.postMessage({
          type: "WASM_RESPONSE",
          response: response,
        });
      })
      .catch((error) => {
        console.error("Error communicating with the background script:", error);
      });
  }
});
