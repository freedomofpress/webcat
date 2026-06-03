// This file is to be compiled, minified and embedded as a string to be
// dynamically updated with ALLOWED_HASHES and injected into scripts
// by response.ts

import { SHA256 } from "./sha256";

type HookConfig<T> = {
  key: string;
  data: T | string;
};

type LocalScope<T> = Record<string, { data: T; ready: Promise<void> }>;

type HookInputs<T> = {
  /**
   * A private object that persists across multiple calls to the hook.
   */
  localScope: LocalScope<T> | unknown;

  /**
   * An object exposing properties that the hook refers to. In a content
   * script, it is a wrapped object accessed via Xray vision.
   */
  scope: typeof globalThis;

  /**
   * The unwrapped (no Xray vision) equivalent of scope. Outside content
   * scripts, scope and unwrappedScope are the same object.
   */
  unwrappedScope: typeof globalThis;

  /**
   * A function that exports func to targetScope with the name specified in
   * options.defineAs.
   */
  exportFunction: (
    func: Function, // eslint-disable-line @typescript-eslint/no-unsafe-function-type
    targetScope: object,
    options: { defineAs: string },
  ) => Function; // eslint-disable-line @typescript-eslint/no-unsafe-function-type
};

function updatableHook<T>(
  hook: (config: HookConfig<T> & HookInputs<T>, data: Promise<T>) => void,
  config: HookConfig<T>,
) {
  return function (inputs: HookInputs<T>) {
    const args = Object.assign({}, config, inputs);
    const key = args.key;
    const scope = args.scope;
    const localScope = args.localScope as LocalScope<T>;
    let data = args.data;

    // Check if the hook has already been injected.
    if (key in localScope) {
      console.log(`[WEBCAT] Hook already injected: ${key}`);
      console.log(data);
      localScope[key].data = data as T; // update data
      return;
    }

    // Allow updating data through localScope
    const { promise: ready, resolve } = scope.Promise.withResolvers<void>();
    localScope[key] = { ready, data: data as T };
    Object.defineProperty(localScope[key], "data", {
      set: (v) => {
        data = v;
        resolve();
      },
      get: () => data,
    });
    if (data !== `__${key}_PLACEHOLDER__`) {
      localScope[key].data = data as T;
    }

    hook(
      args,
      ready.then(() => data as T),
    );
  };
}

/**
 * Hooks the WebAssembly object to hash source bytes
 * and check the hash against a list of allowed hashes.
 */
export const wasmHook = updatableHook<string[]>(
  function (config, data) {
    const { unwrappedScope, scope, key, exportFunction } = config;
    const wasm = unwrappedScope.WebAssembly;

    // Helper: Convert ArrayBuffer digest to a hex string.
    function arrayBuffertoBase64Url(bytes: ArrayBuffer | Uint8Array): string {
      const byteArray =
        bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const options = new unwrappedScope.Object() as {
        alphabet?: "base64" | "base64url";
        omitPadding?: boolean;
      };
      options.alphabet = "base64url";
      options.omitPadding = true;
      return byteArray.toBase64(options);
    }

    // Async bytecode verifier: uses crypto.subtle.digest with a synchronous
    // fallback for Worklets. Must always return a scope.Promise, may never throw.
    function verifyBytecodeAsync(bufferSource: BufferSource): Promise<void> {
      return data.then((hashes) => {
        if (!("crypto" in globalThis)) {
          return Promise.resolve(verifyBytecodeSync(bufferSource));
        }
        const buffer = extractBuffer(bufferSource);
        return crypto.subtle.digest("SHA-256", buffer).then((digestBuffer) => {
          const hashHex: string = arrayBuffertoBase64Url(digestBuffer);
          if (!hashes.includes(hashHex)) {
            throw new scope.Error(
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
      const localScope = config.localScope as LocalScope<string[]>;
      if (!localScope[key].data.includes(hashHex)) {
        throw new scope.Error(
          `[WEBCAT] Unauthorized WebAssembly bytecode: ${hashHex}`,
        );
      }
      console.log(`[WEBCAT] Verified WASM (sync) ${hashHex}`);
    }

    // Helper: Extract an ArrayBuffer from a bufferSource.
    function extractBuffer(bufferSource: BufferSource): ArrayBuffer {
      if (scope.ArrayBuffer.isView(bufferSource)) {
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
    const hookedModule =
      HookedModule as unknown as WebAssemblyModuleConstructor;
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
  },
  { key: "ALLOWED_HASHES", data: "__ALLOWED_HASHES_PLACEHOLDER__" },
);

/**
 * Hooks the ServiceWorker API to expose information about the first-party
 * origin to the webRequest API.
 */
export const sharedWorkerHook = updatableHook<string>(
  function (config, data) {
    // TODO
    data.then((data) => {
      console.log(
        `[WEBCAT] SharedWorker successfully hooked: first-party origin '${data}'.`,
      );
    });
  },
  {
    key: "SHARED_WORKER_FIRST_PARTY",
    data: "__SHARED_WORKER_FIRST_PARTY_PLACEHOLDER__",
  },
);

/**
 * Hooks the ServiceWorker API to expose information about the first-party
 * origin to the webRequest API.
 */
export const serviceWorkerHook = updatableHook<string>(
  function (config, data) {
    // TODO
    data.then((data) => {
      console.log(
        `[WEBCAT] ServiceWorker successfully hooked: first-party origin '${data}'.`,
      );
    });
  },
  {
    key: "SERVICE_WORKER_FIRST_PARTY",
    data: "__SERVICE_WORKER_FIRST_PARTY_PLACEHOLDER__",
  },
);

interface WorkerLocation {
  hash: string;
  href: string;
  toString: () => string;
}
declare const WorkerLocation: {
  new (): WorkerLocation;
  prototype: WorkerLocation;
};

/**
 * Hooks WorkerGlobalScope.location to hide parts of the URL hash injected by
 * sharedWorkerHook or serviceWorkerHook.
 */
export function workerLocationHook() {
  const {
    hash: { get: hash },
    href: { get: href },
    toString: { value: toString },
  }: {
    [K in keyof WorkerLocation]: TypedPropertyDescriptor<WorkerLocation[K]>;
  } = Object.getOwnPropertyDescriptors(WorkerLocation.prototype);

  function hook(f: (() => string) | undefined) {
    return function (this: WorkerLocation) {
      const v = f?.apply(this);
      return v?.substring(0, v?.lastIndexOf("#"));
    };
  }

  Object.defineProperties(WorkerLocation.prototype, {
    hash: { get: hook(hash) },
    href: { get: hook(href) },
    toString: { value: hook(toString) },
  });
}
