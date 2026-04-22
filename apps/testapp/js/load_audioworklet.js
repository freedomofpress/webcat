(async function () {
  const context = new AudioContext();
  await context.audioWorklet.addModule("/workers/audioworklet.js");
  const node = new AudioWorkletNode(context, "processor");
  node.port.addEventListener("message", (event) => {
    if (event.data === "audioworklet: active") {
      console.log("load_audioworklet.js:", true);
    } else {
      throw event.data;
    }
  });
  node.port.start();
  const res = await fetch("/wasm/aw_addTwo.wasm");
  const buf = await res.arrayBuffer();
  node.port.postMessage(buf, [ buf ]);
}());
