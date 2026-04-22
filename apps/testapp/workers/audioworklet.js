class MyAudioWorkletProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.port.addEventListener("message", this.onMessage.bind(this));
    this.port.start();
  }
  process() {
    return true;
  }
  async onMessage(event) {
    try {
      const { instance } = await WebAssembly.instantiate(event.data);
      if (instance.exports.addTwo(123, 456) === 123 + 456) {
        this.port.postMessage("audioworklet: active");
      }
    } catch (e) {
      this.port.postMessage(e);
    }
  }
}

registerProcessor("processor", MyAudioWorkletProcessor);
