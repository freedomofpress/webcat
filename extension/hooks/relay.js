window.addEventListener("message", async function (event) {
  if (event.source !== window) return;

  if (event.data && event.data.type === "WASM_HASH") {
    try {
      const response = await browser.runtime.sendMessage({
        type: event.data.type,
        details: event.data.payload,
      });

      window.postMessage({
        type: "WASM_RESPONSE",
        response: response,
      });
    } catch (error) {
      console.error("Error communicating with the background script:", error);
    }
  }
});
