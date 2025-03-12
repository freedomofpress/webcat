// This file is to be compiled, minified and embedded as a string to be
// dynamically updated with ALLOWED_HASHES and injected into scripts
// by response.ts

(async function () {
  // Check if the WebAssembly hook has already been injected.
  if (Object.prototype.hasOwnProperty.call(WebAssembly, "__hooked__")) {
    console.log("WebAssembly hook already injected.");
    return;
  }

  // ServiceWorkers persistence checker
  // see https://github.com/freedomofpress/webcat/issues/18
  if (
    "serviceWorker" in navigator &&
    typeof window !== "undefined" &&
    self === window &&
    !sessionStorage.getItem("__webcat_checked_sw__")
  ) {
    sessionStorage.setItem("__webcat_checked_sw__", "true");
    try {
      const registrations = await navigator.serviceWorker.getRegistrations();
      for (const registration of registrations) {
        // Check if there's an active service worker before calling update
        if (!registration.active) {
          console.warn(
            `No active service worker found for registration with scope: ${registration.scope}. Skipping update.`,
          );
          continue; // Skip this registration if there's no active worker
        }
        try {
          await registration.update();
          console.log(
            `Service worker at ${registration.active.scriptURL} updated successfully.`,
          );
        } catch (updateError) {
          console.error(
            `Service worker update failed for ${registration.active.scriptURL}:`,
            updateError,
          );
          try {
            const success = await registration.unregister();
            if (success) {
              console.log(
                `Service worker at ${registration.active.scriptURL} was unregistered due to update failure.`,
              );
            } else {
              console.warn(
                `Service worker at ${registration.active.scriptURL} could not be unregistered.`,
              );
            }
          } catch (unregisterError) {
            console.error(
              `Error while unregistering service worker at ${registration.active.scriptURL}:`,
              unregisterError,
            );
          }
        }
      }
    } catch (err) {
      console.error("Error fetching service worker registrations:", err);
    }
  }
  // Save the original crypto.subtle.
  const originalCryptoSubtle: SubtleCrypto = crypto.subtle;

  // Mark WebAssembly as hooked.
  Object.defineProperty(WebAssembly, "__hooked__", {
    value: true,
    writable: false,
    configurable: false,
    enumerable: false,
  });

  // Hardcoded allowlist of allowed SHA-256 hex digests.
  const ALLOWED_HASHES: string[] = ["__HASHES_PLACEHOLDER__"];

  // SHA-256 constants
  /* BEGIN HASH FUNCTION */
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function hashBlocks(
    w: Int32Array,
    v: Int32Array,
    p: Uint8Array,
    pos: number,
    len: number,
  ): number {
    let a: number,
      b: number,
      c: number,
      d: number,
      e: number,
      f: number,
      g: number,
      h: number,
      u: number,
      i: number,
      j: number,
      t1: number,
      t2: number;
    while (len >= 64) {
      a = v[0];
      b = v[1];
      c = v[2];
      d = v[3];
      e = v[4];
      f = v[5];
      g = v[6];
      h = v[7];

      for (i = 0; i < 16; i++) {
        j = pos + i * 4;
        w[i] =
          ((p[j] & 0xff) << 24) |
          ((p[j + 1] & 0xff) << 16) |
          ((p[j + 2] & 0xff) << 8) |
          (p[j + 3] & 0xff);
      }

      for (i = 16; i < 64; i++) {
        u = w[i - 2];
        t1 =
          ((u >>> 17) | (u << (32 - 17))) ^
          ((u >>> 19) | (u << (32 - 19))) ^
          (u >>> 10);

        u = w[i - 15];
        t2 =
          ((u >>> 7) | (u << (32 - 7))) ^
          ((u >>> 18) | (u << (32 - 18))) ^
          (u >>> 3);

        w[i] = ((t1 + w[i - 7]) | 0) + ((t2 + w[i - 16]) | 0);
      }

      for (i = 0; i < 64; i++) {
        t1 =
          ((((((e >>> 6) | (e << (32 - 6))) ^
            ((e >>> 11) | (e << (32 - 11))) ^
            ((e >>> 25) | (e << (32 - 25)))) +
            ((e & f) ^ (~e & g))) |
            0) +
            ((h + ((K[i] + w[i]) | 0)) | 0)) |
          0;

        t2 =
          ((((a >>> 2) | (a << (32 - 2))) ^
            ((a >>> 13) | (a << (32 - 13))) ^
            ((a >>> 22) | (a << (32 - 22)))) +
            ((a & b) ^ (a & c) ^ (b & c))) |
          0;

        h = g;
        g = f;
        f = e;
        e = (d + t1) | 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) | 0;
      }

      v[0] += a;
      v[1] += b;
      v[2] += c;
      v[3] += d;
      v[4] += e;
      v[5] += f;
      v[6] += g;
      v[7] += h;

      pos += 64;
      len -= 64;
    }
    return pos;
  }

  // Hash implements SHA256 hash algorithm.
  // From https://raw.githubusercontent.com/dchest/fast-sha256-js/refs/heads/master/src/sha256.ts
  class Hash {
    digestLength: number = 32;
    blockSize: number = 64;

    // Note: Int32Array is used instead of Uint32Array for performance reasons.
    private state: Int32Array = new Int32Array(8); // hash state
    private temp: Int32Array = new Int32Array(64); // temporary state
    private buffer: Uint8Array = new Uint8Array(128); // buffer for data to hash
    private bufferLength: number = 0; // number of bytes in buffer
    private bytesHashed: number = 0; // number of total bytes hashed

    finished: boolean = false; // indicates whether the hash was finalized

    constructor() {
      this.reset();
    }

    // Resets hash state making it possible
    // to re-use this instance to hash other data.
    reset(): this {
      this.state[0] = 0x6a09e667;
      this.state[1] = 0xbb67ae85;
      this.state[2] = 0x3c6ef372;
      this.state[3] = 0xa54ff53a;
      this.state[4] = 0x510e527f;
      this.state[5] = 0x9b05688c;
      this.state[6] = 0x1f83d9ab;
      this.state[7] = 0x5be0cd19;
      this.bufferLength = 0;
      this.bytesHashed = 0;
      this.finished = false;
      return this;
    }

    // Cleans internal buffers and re-initializes hash state.
    clean() {
      for (let i = 0; i < this.buffer.length; i++) {
        this.buffer[i] = 0;
      }
      for (let i = 0; i < this.temp.length; i++) {
        this.temp[i] = 0;
      }
      this.reset();
    }

    // Updates hash state with the given data.
    //
    // Optionally, length of the data can be specified to hash
    // fewer bytes than data.length.
    //
    // Throws error when trying to update already finalized hash:
    // instance must be reset to use it again.
    update(data: Uint8Array, dataLength: number = data.length): this {
      if (this.finished) {
        throw new Error("SHA256: can't update because hash was finished.");
      }
      let dataPos = 0;
      this.bytesHashed += dataLength;
      if (this.bufferLength > 0) {
        while (this.bufferLength < 64 && dataLength > 0) {
          this.buffer[this.bufferLength++] = data[dataPos++];
          dataLength--;
        }
        if (this.bufferLength === 64) {
          hashBlocks(this.temp, this.state, this.buffer, 0, 64);
          this.bufferLength = 0;
        }
      }
      if (dataLength >= 64) {
        dataPos = hashBlocks(this.temp, this.state, data, dataPos, dataLength);
        dataLength %= 64;
      }
      while (dataLength > 0) {
        this.buffer[this.bufferLength++] = data[dataPos++];
        dataLength--;
      }
      return this;
    }

    // Finalizes hash state and puts hash into out.
    //
    // If hash was already finalized, puts the same value.
    finish(out: Uint8Array): this {
      if (!this.finished) {
        const bytesHashed = this.bytesHashed;
        const left = this.bufferLength;
        const bitLenHi = (bytesHashed / 0x20000000) | 0;
        const bitLenLo = bytesHashed << 3;
        const padLength = bytesHashed % 64 < 56 ? 64 : 128;

        this.buffer[left] = 0x80;
        for (let i = left + 1; i < padLength - 8; i++) {
          this.buffer[i] = 0;
        }
        this.buffer[padLength - 8] = (bitLenHi >>> 24) & 0xff;
        this.buffer[padLength - 7] = (bitLenHi >>> 16) & 0xff;
        this.buffer[padLength - 6] = (bitLenHi >>> 8) & 0xff;
        this.buffer[padLength - 5] = (bitLenHi >>> 0) & 0xff;
        this.buffer[padLength - 4] = (bitLenLo >>> 24) & 0xff;
        this.buffer[padLength - 3] = (bitLenLo >>> 16) & 0xff;
        this.buffer[padLength - 2] = (bitLenLo >>> 8) & 0xff;
        this.buffer[padLength - 1] = (bitLenLo >>> 0) & 0xff;

        hashBlocks(this.temp, this.state, this.buffer, 0, padLength);

        this.finished = true;
      }

      for (let i = 0; i < 8; i++) {
        out[i * 4 + 0] = (this.state[i] >>> 24) & 0xff;
        out[i * 4 + 1] = (this.state[i] >>> 16) & 0xff;
        out[i * 4 + 2] = (this.state[i] >>> 8) & 0xff;
        out[i * 4 + 3] = (this.state[i] >>> 0) & 0xff;
      }

      return this;
    }

    // Returns the final hash digest.
    digest(): Uint8Array {
      const out = new Uint8Array(this.digestLength);
      this.finish(out);
      return out;
    }

    // Internal function for use in HMAC for optimization.
    _saveState(out: Uint32Array) {
      for (let i = 0; i < this.state.length; i++) {
        out[i] = this.state[i];
      }
    }

    // Internal function for use in HMAC for optimization.
    _restoreState(from: Uint32Array, bytesHashed: number) {
      for (let i = 0; i < this.state.length; i++) {
        this.state[i] = from[i];
      }
      this.bytesHashed = bytesHashed;
      this.finished = false;
      this.bufferLength = 0;
    }
  }

  function SHA256(data: Uint8Array): Uint8Array {
    const h = new Hash().update(data);
    const digest = h.digest();
    h.clean();
    return digest;
  }
  /* END HASH FUNCTION */

  // Helper: Convert ArrayBuffer digest to a hex string.
  function arrayBufferToHex(buffer: ArrayBuffer): string {
    const byteArray = new Uint8Array(buffer);
    const hexCodes: string[] = [];
    for (const byte of byteArray) {
      const hexCode = byte.toString(16).padStart(2, "0");
      hexCodes.push(hexCode);
    }
    return hexCodes.join("");
  }

  // Async bytecode verifier: uses crypto.subtle.digest.
  async function verifyBytecodeAsync(buffer: ArrayBuffer): Promise<void> {
    const digestBuffer: ArrayBuffer = await originalCryptoSubtle.digest(
      "SHA-256",
      buffer,
    );
    const hashHex: string = arrayBufferToHex(digestBuffer);
    if (!ALLOWED_HASHES.includes(hashHex)) {
      throw new Error(`Unauthorized WebAssembly bytecode: ${hashHex}`);
    }
    console.log(`Verified WASM (async) ${hashHex}`);
  }

  // Synchronous bytecode verifier: uses the synchronous SHA256(buffer).
  function verifyBytecodeSync(buffer: ArrayBuffer): void {
    const hashHex: string = arrayBufferToHex(SHA256(new Uint8Array(buffer)));
    if (!ALLOWED_HASHES.includes(hashHex)) {
      throw new Error(`Unauthorized WebAssembly bytecode: ${hashHex}`);
    }
    console.log(`Verified WASM (sync) ${hashHex}`);
  }

  // Helper: Extract an ArrayBuffer from a bufferSource.
  function extractBuffer(
    bufferSource: ArrayBuffer | ArrayBufferView,
  ): ArrayBuffer {
    if (bufferSource instanceof ArrayBuffer) {
      return bufferSource;
    }
    if (ArrayBuffer.isView(bufferSource)) {
      return bufferSource.buffer;
    }
    throw new TypeError(
      "WebAssembly bytecode must be provided as an ArrayBuffer or typed array",
    );
  }

  // ============================
  // Hooking WebAssembly Methods
  // ============================

  //
  // Hook WebAssembly.instantiate (async)
  //
  const originalInstantiate = WebAssembly.instantiate;
  // Overloads for WebAssembly.instantiate.
  function hookedInstantiate(
    source: WebAssembly.Module,
    importObject?: WebAssembly.Imports,
  ): Promise<WebAssembly.Instance>;
  function hookedInstantiate(
    source: BufferSource | Promise<BufferSource>,
    importObject?: WebAssembly.Imports,
  ): Promise<WebAssembly.WebAssemblyInstantiatedSource>;
  async function hookedInstantiate(
    this: unknown,
    source: WebAssembly.Module | BufferSource | Promise<BufferSource>,
    importObject?: WebAssembly.Imports,
  ): Promise<unknown> {
    // If the source is already a compiled module, bypass verification.
    if (source instanceof WebAssembly.Module) {
      return originalInstantiate.call(this, source, importObject);
    } else {
      // If source is a Promise, await it.
      const sourceBuffer: BufferSource =
        source instanceof Promise ? await source : source;
      const buffer: ArrayBuffer = extractBuffer(sourceBuffer);
      try {
        await verifyBytecodeAsync(buffer);
      } catch (e) {
        return Promise.reject(e);
      }
      return originalInstantiate.call(this, sourceBuffer, importObject);
    }
  }
  WebAssembly.instantiate = hookedInstantiate as typeof WebAssembly.instantiate;

  //
  // Hook WebAssembly.compile (async)
  //
  const originalCompile = WebAssembly.compile;
  WebAssembly.compile = async function (
    bufferSource: ArrayBuffer | ArrayBufferView,
  ): Promise<WebAssembly.Module> {
    try {
      const buffer: ArrayBuffer = extractBuffer(bufferSource);
      await verifyBytecodeAsync(buffer);
    } catch (e) {
      return Promise.reject(e);
    }
    return originalCompile.call(this, bufferSource);
  };

  //
  // Hook WebAssembly.validate (synchronous)
  //
  const originalValidate = WebAssembly.validate;
  WebAssembly.validate = function (
    bufferSource: ArrayBuffer | ArrayBufferView,
  ): boolean {
    const buffer: ArrayBuffer = extractBuffer(bufferSource);
    verifyBytecodeSync(buffer);
    return originalValidate.call(this, bufferSource);
  };

  //
  // Hook WebAssembly.instantiateStreaming (async)
  //
  const originalInstantiateStreaming = WebAssembly.instantiateStreaming;
  WebAssembly.instantiateStreaming = async function (
    this: unknown,
    responseOrPromise: Response | PromiseLike<Response>,
    importObject?: WebAssembly.Imports,
  ): Promise<WebAssembly.WebAssemblyInstantiatedSource> {
    const response: Response = await Promise.resolve(responseOrPromise);
    const clonedResponse: Response = response.clone();
    const buffer: ArrayBuffer = await clonedResponse.arrayBuffer();
    await verifyBytecodeAsync(buffer);
    return originalInstantiateStreaming.call(this, response, importObject);
  };

  //
  // Hook WebAssembly.compileStreaming (async)
  //
  const originalCompileStreaming = WebAssembly.compileStreaming;
  WebAssembly.compileStreaming = async function (
    this: unknown,
    responseOrPromise: Response | PromiseLike<Response>,
  ): Promise<WebAssembly.Module> {
    const response: Response = await Promise.resolve(responseOrPromise);
    const clonedResponse: Response = response.clone();
    const buffer: ArrayBuffer = await clonedResponse.arrayBuffer();
    await verifyBytecodeAsync(buffer);
    return originalCompileStreaming.call(this, response);
  };

  //
  // Hook the WebAssembly.Module constructor (synchronous)
  //
  type WebAssemblyModuleConstructor = {
    new (bytes: BufferSource): WebAssembly.Module;
    prototype: WebAssembly.Module;
    customSections(
      moduleObject: WebAssembly.Module,
      sectionName: string,
    ): ArrayBuffer[];
    exports(
      moduleObject: WebAssembly.Module,
    ): WebAssembly.ModuleExportDescriptor[];
    imports(
      moduleObject: WebAssembly.Module,
    ): WebAssembly.ModuleImportDescriptor[];
  };

  // Hook the WebAssembly.Module constructor (synchronous)
  const OriginalModule = WebAssembly.Module;

  function HookedModule(
    this: object,
    bufferSource: ArrayBuffer | ArrayBufferView,
  ): WebAssembly.Module {
    if (!(this instanceof HookedModule)) {
      throw new TypeError("Constructor WebAssembly.Module requires 'new'");
    }
    const buffer: ArrayBuffer = extractBuffer(bufferSource);
    verifyBytecodeSync(buffer);
    return new OriginalModule(bufferSource);
  }

  // Set up the prototype.
  HookedModule.prototype = OriginalModule.prototype;

  // Cast HookedModule to our complete constructor type.
  const hookedModule = HookedModule as unknown as WebAssemblyModuleConstructor;

  // Now assign the static methods.
  hookedModule.customSections =
    OriginalModule.customSections.bind(OriginalModule);
  hookedModule.exports = OriginalModule.exports.bind(OriginalModule);
  hookedModule.imports = OriginalModule.imports.bind(OriginalModule);

  // Finally, assign the hooked constructor to WebAssembly.Module.
  WebAssembly.Module = hookedModule as typeof WebAssembly.Module;

  // Use the universal global object.
  const globalObj = globalThis;

  // Lock the WebAssembly property by making it non-configurable, non-writable.
  Object.defineProperty(globalObj, "WebAssembly", {
    configurable: false,
    enumerable: true,
    writable: false,
    value: globalObj.WebAssembly,
  });

  // Freeze the WebAssembly object to prevent further modifications.
  Object.freeze(globalObj.WebAssembly);

  console.log(
    "WebAssembly successfully hooked: all bytecode entry points now require authorization.",
  );
})();
