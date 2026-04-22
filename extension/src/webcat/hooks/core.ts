// This file is to be compiled, minified and embedded as a string to be
// dynamically updated with ALLOWED_HASHES and injected into scripts
// by response.ts

import { SHA256 } from "./sha256";

// Hook the WebAssembly object in either a content script or a Worker.
// In a content script, scope must be the the wrapped (Xray vision) window object,
// unwrappedScope the unwrapped (no Xray vision) window object, and exportFunction the
// built-in content script exportFunction. In a Worker, scope and unwrappedScope must
// be globalThis and exportFunction a function that assigns func directly to
// targetScope[options.defineAs].
export function wasmHook(
  scope: typeof globalThis,
  unwrappedScope: typeof globalThis,
  exportFunction: (
    func: Function, // eslint-disable-line @typescript-eslint/no-unsafe-function-type
    targetScope: object,
    options: { defineAs: string },
  ) => Function, // eslint-disable-line @typescript-eslint/no-unsafe-function-type
  notifyBackground: () => void,
) {
  const wasm = unwrappedScope.WebAssembly;

  // Check if the WebAssembly hook has already been injected.
  if (Object.prototype.hasOwnProperty.call(wasm, "__hooked__")) {
    console.log("[WEBCAT] WebAssembly hook already injected.");
    return;
  }

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

  // Async bytecode verifier: uses crypto.subtle.digest. Must always return
  // a scope.Promise, may never throw.
  function verifyBytecodeAsync(bufferSource: BufferSource): Promise<void> {
    try {
      const buffer = extractBuffer(bufferSource);
      return crypto.subtle.digest("SHA-256", buffer).then((digestBuffer) => {
        const hashHex: string = arrayBuffertoBase64Url(digestBuffer);
        if (!ALLOWED_HASHES.includes(hashHex)) {
          notifyBackground();
          throw new scope.Error(
            `[WEBCAT] Unauthorized WebAssembly bytecode: ${hashHex}`,
          );
        }
        console.log(`[WEBCAT] Verified WASM (async) ${hashHex}`);
      });
    } catch (e) {
      return scope.Promise.reject(e);
    }
  }

  // Synchronous bytecode verifier: uses the synchronous SHA256(buffer).
  function verifyBytecodeSync(bufferSource: BufferSource): void {
    const buffer = extractBuffer(bufferSource);
    const hashHex: string = arrayBuffertoBase64Url(SHA256(buffer));
    if (!ALLOWED_HASHES.includes(hashHex)) {
      notifyBackground();
      throw new scope.Error(
        `[WEBCAT] Unauthorized WebAssembly bytecode: ${hashHex}`,
      );
    }
    console.log(`[WEBCAT] Verified WASM (sync) ${hashHex}`);
  }

  // Helper: Extract an ArrayBuffer from a bufferSource.
  function extractBuffer(
    bufferSource: BufferSource | WebAssembly.Module,
  ): ArrayBuffer {
    if (bufferSource instanceof scope.ArrayBuffer) {
      return bufferSource;
    }
    if (scope.ArrayBuffer.isView(bufferSource)) {
      return bufferSource.buffer as ArrayBuffer;
    }
    throw new scope.TypeError(
      "[WEBCAT] WebAssembly bytecode must be provided as an ArrayBuffer or typed array",
    );
  }

  // ============================
  // Hooking WebAssembly Methods
  // ============================

  // Hook WebAssembly.instantiate (async)
  const originalInstantiate = wasm.instantiate;
  function hookedInstantiate(
    this: typeof WebAssembly,
    source: WebAssembly.Module | BufferSource,
    importObject?: WebAssembly.Imports,
    compileOptions?: object,
  ): Promise<unknown> {
    // If the source is already a compiled module, bypass verification.
    if (source instanceof wasm.Module) {
      return originalInstantiate.call(
        this,
        source,
        importObject,
        compileOptions,
      );
    } else {
      return verifyBytecodeAsync(source).then(
        originalInstantiate.bind(this, source, importObject, compileOptions),
      );
    }
  }
  exportFunction(hookedInstantiate, wasm, { defineAs: "instantiate" });

  // Hook WebAssembly.compile (async)
  const originalCompile = wasm.compile;
  function hookedCompile(
    this: typeof wasm,
    bufferSource: BufferSource,
    compileOptions?: object,
  ): Promise<WebAssembly.Module> {
    return verifyBytecodeAsync(bufferSource).then(
      originalCompile.bind(this, bufferSource, compileOptions),
    );
  }
  exportFunction(hookedCompile, wasm, { defineAs: "compile" });

  // Hook WebAssembly.validate (synchronous)
  const originalValidate = wasm.validate;
  function hookedValidate(
    this: typeof wasm,
    bufferSource: BufferSource,
  ): boolean {
    verifyBytecodeSync(bufferSource);
    return originalValidate.call(this, bufferSource);
  }
  exportFunction(hookedValidate, wasm, { defineAs: "validate" });

  // Hook WebAssembly.instantiateStreaming (async)
  const originalInstantiateStreaming = wasm.instantiateStreaming;
  function hookedInstantiateStreaming(
    this: typeof wasm,
    source: Response | PromiseLike<Response>,
    importObject?: WebAssembly.Imports,
    compileOptions?: object,
  ): Promise<WebAssembly.WebAssemblyInstantiatedSource> {
    return scope.Promise.resolve(source)
      .then((response) => response.clone().arrayBuffer())
      .then(verifyBytecodeAsync)
      .then(
        originalInstantiateStreaming.bind(
          this,
          source,
          importObject,
          compileOptions,
        ),
      );
  }
  exportFunction(hookedInstantiateStreaming, wasm, {
    defineAs: "instantiateStreaming",
  });

  // Hook WebAssembly.compileStreaming (async)
  const originalCompileStreaming = wasm.compileStreaming;
  function hookedCompileStreaming(
    this: typeof wasm,
    source: Response | PromiseLike<Response>,
    compileOptions?: object,
  ): Promise<WebAssembly.Module> {
    return scope.Promise.resolve(source)
      .then((response) => response.clone().arrayBuffer())
      .then(verifyBytecodeAsync)
      .then(originalCompileStreaming.bind(this, source, compileOptions));
  }
  exportFunction(hookedCompileStreaming, wasm, {
    defineAs: "compileStreaming",
  });

  // Hook the WebAssembly.Module constructor (synchronous)
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
    verifyBytecodeSync(bufferSource);
    return new OriginalModule(bufferSource);
  }
  const hookedModule = HookedModule as unknown as WebAssemblyModuleConstructor;
  hookedModule.customSections =
    OriginalModule.customSections.bind(OriginalModule);
  hookedModule.exports = OriginalModule.exports.bind(OriginalModule);
  hookedModule.imports = OriginalModule.imports.bind(OriginalModule);
  exportFunction(hookedModule, wasm, { defineAs: "Module" });
  wasm.Module.prototype = OriginalModule.prototype;

  // Mark WebAssembly as hooked.
  Object.defineProperty(wasm, "__hooked__", {
    value: true,
    writable: false,
    configurable: false,
    enumerable: false,
  });

  console.log(
    "[WEBCAT] WebAssembly successfully hooked: all bytecode entry points now require authorization.",
  );
}
