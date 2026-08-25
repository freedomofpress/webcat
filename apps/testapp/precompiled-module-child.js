// Enrolled frame: receive WASM from the non-enrolled parent and report what ran.
const parentOrigin = new URLSearchParams(location.search).get("parentOrigin");

addEventListener("message", async (e) => {
  if (e.source !== parent || e.origin !== parentOrigin || e.data?.type !== "poc") return;

  // The raw-bytes path must be blocked by the WASM hook.
  let rawBytesRejected = false;
  try {
    await WebAssembly.instantiate(e.data.bytes);
  } catch (err) {
    rawBytesRejected = String(err).includes("[WEBCAT] Unauthorized WebAssembly bytecode");
  }

  // A precompiled Module must not be a bypass: it should be rejected too.
  let moduleValue = null;
  let moduleError = null;
  try {
    moduleValue = (await WebAssembly.instantiate(e.data.module)).exports.run();
  } catch (err) {
    moduleError = String(err);
  }

  parent.postMessage(
    {
      type: "result",
      receivedModule: e.data.module instanceof WebAssembly.Module,
      rawBytesRejected,
      moduleValue,
      moduleError,
    },
    parentOrigin,
  );
});

parent.postMessage({ type: "ready" }, parentOrigin);
