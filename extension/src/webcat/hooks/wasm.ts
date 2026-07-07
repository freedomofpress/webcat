import { exportFunc, global, unwrap, updatableHook } from "./core";
import { SHA256 } from "./sha256";

/**
 * Hooks the WebAssembly object to hash source bytes
 * and check the hash against a list of allowed hashes.
 */
export const wasmHook = updatableHook(
  "WASM",
  function (data: Promise<{ hashes?: string[] }>, scope) {
    const wasm = unwrap(global.WebAssembly);
    if (!wasm) {
      return;
    }

    // Helper: Convert ArrayBuffer digest to a hex string.
    function arrayBuffertoBase64Url(bytes: ArrayBuffer | Uint8Array): string {
      const byteArray =
        bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const options = new global.Object() as {
        alphabet?: "base64" | "base64url";
        omitPadding?: boolean;
      };
      options.alphabet = "base64url";
      options.omitPadding = true;
      return byteArray.toBase64(options);
    }

    // Async bytecode verifier: uses crypto.subtle.digest with a synchronous
    // fallback for Worklets. Must always return a global.Promise, may never throw.
    function verifyBytecodeAsync(bufferSource: BufferSource): Promise<void> {
      return data.then(({ hashes }) => {
        if (!("crypto" in globalThis)) {
          return Promise.resolve(verifyBytecodeSync(bufferSource));
        }
        const buffer = extractBuffer(bufferSource);
        return crypto.subtle.digest("SHA-256", buffer).then((digestBuffer) => {
          const hashHex: string = arrayBuffertoBase64Url(digestBuffer);
          if (!hashes?.includes(hashHex)) {
            throw new global.Error(
              `[WEBCAT] Unauthorized WebAssembly bytecode: ${hashHex}`,
            );
          }
          console.log(`[WEBCAT] Verified WASM (async) ${hashHex}`);
        });
      });
    }

    // Synchronous bytecode verifier: uses the synchronous SHA256(buffer).
    function verifyBytecodeSync(bufferSource: BufferSource): void {
      const buffer = extractBuffer(bufferSource);
      const hashHex: string = arrayBuffertoBase64Url(SHA256(buffer));
      if (!scope.data.hashes?.includes(hashHex)) {
        throw new global.Error(
          `[WEBCAT] Unauthorized WebAssembly bytecode: ${hashHex}`,
        );
      }
      console.log(`[WEBCAT] Verified WASM (sync) ${hashHex}`);
    }

    // Helper: Extract an ArrayBuffer from a bufferSource.
    function extractBuffer(bufferSource: BufferSource): ArrayBuffer {
      if (global.ArrayBuffer.isView(bufferSource)) {
        return bufferSource.buffer as ArrayBuffer;
      }
      return bufferSource as ArrayBuffer;
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
    exportFunc(hookedInstantiate, wasm, "instantiate");

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
    exportFunc(hookedCompile, wasm, "compile");

    // Hook WebAssembly.validate (synchronous)
    const originalValidate = wasm.validate;
    function hookedValidate(
      this: typeof wasm,
      bufferSource: BufferSource,
    ): boolean {
      verifyBytecodeSync(bufferSource);
      return originalValidate.call(this, bufferSource);
    }
    exportFunc(hookedValidate, wasm, "validate");

    // Hook WebAssembly.instantiateStreaming (async)
    const originalInstantiateStreaming = wasm.instantiateStreaming;
    function hookedInstantiateStreaming(
      this: typeof wasm,
      source: Response | PromiseLike<Response>,
      importObject?: WebAssembly.Imports,
      compileOptions?: object,
    ): Promise<WebAssembly.WebAssemblyInstantiatedSource> {
      return global.Promise.resolve(source)
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
    exportFunc(hookedInstantiateStreaming, wasm, "instantiateStreaming");

    // Hook WebAssembly.compileStreaming (async)
    const originalCompileStreaming = wasm.compileStreaming;
    function hookedCompileStreaming(
      this: typeof wasm,
      source: Response | PromiseLike<Response>,
      compileOptions?: object,
    ): Promise<WebAssembly.Module> {
      return global.Promise.resolve(source)
        .then((response) => response.clone().arrayBuffer())
        .then(verifyBytecodeAsync)
        .then(originalCompileStreaming.bind(this, source, compileOptions));
    }
    exportFunc(hookedCompileStreaming, wasm, "compileStreaming");

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
        throw new global.TypeError(
          "[WEBCAT] Constructor WebAssembly.Module requires 'new'",
        );
      }
      verifyBytecodeSync(bufferSource);
      return new OriginalModule(bufferSource);
    }
    const hookedModule =
      HookedModule as unknown as WebAssemblyModuleConstructor;
    hookedModule.customSections =
      OriginalModule.customSections.bind(OriginalModule);
    hookedModule.exports = OriginalModule.exports.bind(OriginalModule);
    hookedModule.imports = OriginalModule.imports.bind(OriginalModule);
    exportFunc(hookedModule, wasm, "Module");
    OriginalModule.prototype.constructor = wasm.Module;
    wasm.Module.prototype = OriginalModule.prototype;

    console.log(
      "[WEBCAT] WebAssembly successfully hooked: all bytecode entry points now require authorization.",
    );
  },
);
