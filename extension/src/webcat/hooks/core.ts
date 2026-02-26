// This file is to be compiled, minified and embedded as a string to be
// dynamically updated with ALLOWED_HASHES and injected into scripts
// by response.ts

import { SHA256 } from "./sha256";

export async function servieWorkersChecker() {
  // ServiceWorkers persistence checker
  // see https://github.com/freedomofpress/webcat/issues/18
  if (
    typeof window !== "undefined" &&
    "serviceWorker" in navigator &&
    self === window &&
    !sessionStorage.getItem("__webcat_checked_sw__")
  ) {
    sessionStorage.setItem("__webcat_checked_sw__", "true");
    try {
      const registrations =
        await globalThis.navigator.serviceWorker.getRegistrations();
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
            `[WEBCAT] Service worker at ${registration.active.scriptURL} updated successfully.`,
          );
        } catch (updateError) {
          console.error(
            `[WEBCAT] Service worker update failed for ${registration.active.scriptURL}:`,
            updateError,
          );
          try {
            const success = await registration.unregister();
            if (success) {
              console.log(
                `[WEBCAT] Service worker at ${registration.active.scriptURL} was unregistered due to update failure.`,
              );
            } else {
              console.warn(
                `Service worker at ${registration.active.scriptURL} could not be unregistered.`,
              );
            }
          } catch (unregisterError) {
            console.error(
              `[WEBCAT] Error while unregistering service worker at ${registration.active.scriptURL}:`,
              unregisterError,
            );
          }
        }
      }
    } catch (err) {
      console.error(
        "[WEBCAT] Error fetching service worker registrations:",
        err,
      );
    }
  }
}

export function wasmHook() {
  let wasm: typeof WebAssembly;
  if (typeof window !== "undefined") {
    wasm = window.getWebAssemblyPtr("__KEY_PLACEHOLDER__");
    //Reflect.deleteProperty(window, "getWebAssemblyPtr");
  } else {
    wasm = globalThis.WebAssembly;
  }

  // Check if the WebAssembly hook has already been injected.
  if (Object.prototype.hasOwnProperty.call(wasm, "__hooked__")) {
    console.log("WebAssembly hook already injected.");
    return;
  }

  // Save the original crypto.subtle.
  const originalCryptoSubtle: SubtleCrypto = globalThis.crypto.subtle;

  // Hardcoded allowlist of allowed SHA-256 hex digests.
  const ALLOWED_HASHES: string[] = ["__HASHES_PLACEHOLDER__"];

  // Helper: Convert ArrayBuffer digest to a hex string.
  function arrayBuffertoBase64Url(bytes: ArrayBuffer | Uint8Array): string {
    const byteArray =
      bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);

    return btoa(String.fromCharCode(...byteArray))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  // Async bytecode verifier: uses crypto.subtle.digest.
  async function verifyBytecodeAsync(buffer: ArrayBuffer): Promise<void> {
    const digestBuffer: ArrayBuffer = await originalCryptoSubtle.digest(
      "SHA-256",
      buffer,
    );
    const hashHex: string = arrayBuffertoBase64Url(digestBuffer);
    if (!ALLOWED_HASHES.includes(hashHex)) {
      throw new Error(`[WEBCAT] Unauthorized WebAssembly bytecode: ${hashHex}`);
    }
    console.log(`[WEBCAT] Verified WASM (async) ${hashHex}`);
  }

  // Synchronous bytecode verifier: uses the synchronous SHA256(buffer).
  function verifyBytecodeSync(buffer: ArrayBuffer): void {
    const hashHex: string = arrayBuffertoBase64Url(SHA256(buffer));
    if (!ALLOWED_HASHES.includes(hashHex)) {
      throw new Error(`[WEBCAT] Unauthorized WebAssembly bytecode: ${hashHex}`);
    }
    console.log(`[WEBCAT] Verified WASM (sync) ${hashHex}`);
  }

  // Helper: Extract an ArrayBuffer from a bufferSource.
  function extractBuffer(
    bufferSource: BufferSource | WebAssembly.Module,
  ): ArrayBuffer {
    if (bufferSource instanceof ArrayBuffer) {
      return bufferSource;
    }
    if (ArrayBuffer.isView(bufferSource)) {
      return bufferSource.buffer as ArrayBuffer;
    }
    throw new TypeError(
      "[WEBCAT] WebAssembly bytecode must be provided as an ArrayBuffer or typed array",
    );
  }

  // ============================
  // Hooking WebAssembly Methods
  // ============================

  //
  // Hook WebAssembly.instantiate (async)
  //
  const originalInstantiate = wasm.instantiate;
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
    if (source instanceof wasm.Module) {
      return originalInstantiate.call(this, source, importObject);
    } else {
      // If source is a Promise, await it.
      const sourceBuffer:
        | WebAssembly.Module
        | BufferSource
        | Promise<BufferSource> =
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
  wasm.instantiate = hookedInstantiate as typeof WebAssembly.instantiate;

  //
  // Hook WebAssembly.compile (async)
  //
  const originalCompile = wasm.compile;
  wasm.compile = async function (
    this: typeof wasm,
    bufferSource: BufferSource,
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
  const originalValidate = wasm.validate;
  wasm.validate = function (
    this: typeof wasm,
    bufferSource: BufferSource,
  ): boolean {
    const buffer: ArrayBuffer = extractBuffer(bufferSource);
    verifyBytecodeSync(buffer);
    return originalValidate.call(this, bufferSource);
  };

  //
  // Hook WebAssembly.instantiateStreaming (async)
  //
  const originalInstantiateStreaming = wasm.instantiateStreaming;
  wasm.instantiateStreaming = async function (
    this: typeof wasm,
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
  const originalCompileStreaming = wasm.compileStreaming;
  wasm.compileStreaming = async function (
    this: typeof wasm,
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
  const OriginalModule = wasm.Module;

  function HookedModule(
    this: object,
    bufferSource: BufferSource,
  ): WebAssembly.Module {
    if (!(this instanceof HookedModule)) {
      throw new TypeError(
        "[WEBCAT] Constructor WebAssembly.Module requires 'new'",
      );
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
  wasm.Module = hookedModule as typeof wasm.Module;

  // Mark WebAssembly as hooked.
  Object.defineProperty(wasm, "__hooked__", {
    value: true,
    writable: false,
    configurable: false,
    enumerable: false,
  });

  globalThis.WebAssembly = wasm;

  console.log(
    "[WEBCAT] WebAssembly successfully hooked: all bytecode entry points now require authorization.",
  );
}
