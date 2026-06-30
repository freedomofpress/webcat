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
    options?: { defineAs?: string },
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
    if (!wasm) {
      return;
    }

    // Helper: Convert ArrayBuffer digest to a hex string.
    function arrayBuffertoBase64Url(bytes: ArrayBuffer | Uint8Array): string {
      const byteArray =
        bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const options = new scope.Object() as {
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
        throw new scope.TypeError(
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
    OriginalModule.prototype.constructor = wasm.Module;
    wasm.Module.prototype = OriginalModule.prototype;

    console.log(
      "[WEBCAT] WebAssembly successfully hooked: all bytecode entry points now require authorization.",
    );
  },
  { key: "ALLOWED_HASHES", data: "__ALLOWED_HASHES_PLACEHOLDER__" },
);

/**
 * Hooks the SharedWorker API to expose information about the first-party
 * origin to the webRequest API.
 */
export const sharedWorkerHook = updatableHook<string>(
  function (config, data) {
    const { scope, unwrappedScope, exportFunction } = config;
    if (!unwrappedScope.SharedWorker) {
      return;
    }

    type SharedWorkerInternal = {
      instance: SharedWorker;
      port: MessagePort;
      relay: MessagePort;
      onerror: ((e: Event) => unknown) | null;
    };
    const internal = Symbol("WEBCAT");
    type HookedSharedWorker = SharedWorker & {
      [internal]: SharedWorkerInternal;
      wrappedJSObject?: HookedSharedWorker;
    };
    type EventHandler = ((e: Event) => unknown) & {
      wrappedJSObject?: EventHandler;
    };

    function makeHookedHandler(v: EventHandler | null) {
      v = v?.wrappedJSObject || v;
      if (typeof v === "function") {
        return exportFunction(function (...args: [e: Event]) {
          // TODO: wrap the event
          return v(...args);
        }, unwrappedScope) as (e: Event) => unknown;
      } else {
        return null;
      }
    }

    // Hook the SharedWorker constructor
    const OriginalSharedWorker = unwrappedScope.SharedWorker;
    function HookedSharedWorker(
      this: object,
      ...args: [url: string | URL, options?: string | WorkerOptions]
    ) {
      if (!(this instanceof HookedSharedWorker)) {
        throw new scope.TypeError(
          "SharedWorker constructor: 'new' is required",
        );
      }
      if ((args.length as number) === 0) {
        throw new scope.TypeError(
          "SharedWorker constructor: At least 1 argument required, but only 0 passed",
        );
      }
      const self = unwrappedScope.Object.create(
        OriginalSharedWorker.prototype,
      ) as HookedSharedWorker;
      const channel = new scope.MessageChannel();
      self[internal] = new scope.Object() as SharedWorkerInternal;
      self[internal].port = channel.port1;
      self[internal].relay = channel.port2;
      self[internal].onerror = null;
      data.then((firstParty) => {
        // Initialize the actual SharedWorker instance and relay messages
        // TODO: relay messageerror events
        args[0] = `${args[0]}#${firstParty}`;
        self[internal].instance = new OriginalSharedWorker(...args);
        self[internal].instance.port.onmessage = exportFunction(
          (e: MessageEvent<unknown>) => {
            self[internal].relay.postMessage(e.data);
          },
          unwrappedScope,
        ) as typeof MessagePort.prototype.onmessage;
        self[internal].relay.onmessage = exportFunction(
          (e: MessageEvent<unknown>) => {
            self[internal].instance.port.postMessage(e.data);
          },
          unwrappedScope,
        ) as typeof MessagePort.prototype.onmessage;
        self[internal].instance.onerror = makeHookedHandler(
          self[internal].onerror,
        );
      });
      return self;
    }
    exportFunction(HookedSharedWorker, unwrappedScope, {
      defineAs: "SharedWorker",
    });
    OriginalSharedWorker.prototype.constructor = unwrappedScope.SharedWorker;
    unwrappedScope.SharedWorker.prototype = OriginalSharedWorker.prototype;

    // Hook SharedWorker.port
    const { get: originalPort } = Object.getOwnPropertyDescriptor(
      OriginalSharedWorker.prototype,
      "port",
    ) as PropertyDescriptor;
    function hookedPort(this: HookedSharedWorker) {
      if (internal in this) {
        return this[internal].port;
      }
      return originalPort?.apply(this);
    }
    Object.defineProperty(OriginalSharedWorker.prototype, "port", {
      get: exportFunction(hookedPort, unwrappedScope) as () => unknown,
    });

    const { get: originalGetOnerror, set: originalSetOnerror } =
      Object.getOwnPropertyDescriptor(
        OriginalSharedWorker.prototype,
        "onerror",
      ) as PropertyDescriptor;
    function hookedGetOnerror(this: HookedSharedWorker) {
      const unwrappedThis = this.wrappedJSObject || this;
      if (internal in unwrappedThis) {
        return unwrappedThis[internal].onerror;
      }
      return originalGetOnerror?.call(this);
    }
    function hookedSetOnerror(
      this: HookedSharedWorker,
      v: OnErrorEventHandler,
    ) {
      const unwrappedThis = this.wrappedJSObject || this;
      if (internal in unwrappedThis) {
        unwrappedThis[internal].onerror = v;
        if (unwrappedThis[internal].instance) {
          unwrappedThis[internal].instance.onerror = makeHookedHandler(v);
        }
      } else {
        originalSetOnerror?.call(this, v);
      }
    }
    Object.defineProperty(OriginalSharedWorker.prototype, "onerror", {
      get: exportFunction(hookedGetOnerror, unwrappedScope) as () => unknown,
      set: exportFunction(hookedSetOnerror, unwrappedScope) as (
        v: unknown,
      ) => void,
    });

    // TODO: Hook addEventListener, removeEventListener, and dispatchEvent
  },
  {
    key: "SHARED_WORKER_FIRST_PARTY",
    data: "__SHARED_WORKER_FIRST_PARTY_PLACEHOLDER__",
  },
);

declare global {
  var WorkerNavigator: typeof Navigator;
}

/**
 * Disables the ServiceWorker API when not in a first-party origin.
 */
export const serviceWorkerHook = updatableHook<boolean>(
  function ({ unwrappedScope, data }) {
    if (typeof data === "string") {
      // data is the placeholder, so we're in a frame
      try {
        Object.hasOwn(window.top || {}, "name");
        // top is same-origin, so there's nothing to do
        return;
      } catch {
        // top is cross-origin, continue
      }
    } else if ((data as unknown as boolean) === true) {
      // we're in a worker that's same-origin with
      // the first party; nothing to do
      return;
    }
    delete (
      (unwrappedScope.Navigator || unwrappedScope.WorkerNavigator || Object)
        .prototype as unknown as Record<string, unknown>
    ).serviceWorker;
    delete (unwrappedScope as unknown as Record<string, unknown>).ServiceWorker;
    delete (unwrappedScope as unknown as Record<string, unknown>)
      .ServiceWorkerContainer;
    delete (unwrappedScope as unknown as Record<string, unknown>)
      .ServiceWorkerRegistration;
  },
  {
    key: "SERVICE_WORKER_FIRST_PARTY",
    data: "__SERVICE_WORKER_FIRST_PARTY_PLACEHOLDER__",
  },
);

/**
 * Hooks the Worker API as a workaround to
 * https://bugzilla.mozilla.org/show_bug.cgi?id=2048884
 */
export const workerHook = updatableHook<string>(
  function (config, data) {
    const { scope, unwrappedScope, exportFunction } = config;
    if (!unwrappedScope.SharedWorker) {
      return;
    }

    type MessageListener = (this: Worker, ev: MessageEvent<unknown>) => unknown;
    type WorkerInternal = {
      instance?: Worker;
      onmessage: MessageListener | null;
      messages: [message: unknown, options?: StructuredSerializeOptions][];
    };
    const internal = Symbol("WEBCAT");
    type HookedWorker = Worker & {
      [internal]: WorkerInternal;
      wrappedJSObject?: HookedWorker;
    };

    // Hook the Worker constructor
    const OriginalWorker = unwrappedScope.Worker;
    const EventTarget = unwrappedScope.EventTarget;
    const construct = unwrappedScope.Reflect.construct.bind(
      unwrappedScope.Reflect,
    );
    function HookedWorker(
      this: object,
      ...args: [scriptUrl: string | URL, options?: WorkerOptions]
    ) {
      if (!(this instanceof HookedWorker)) {
        throw new TypeError("Worker constructor: 'new' is required");
      }
      if ((args.length as number) === 0) {
        throw new scope.TypeError(
          "Worker constructor: At least 1 argument required, but only 0 passed",
        );
      }
      const self = construct(
        EventTarget,
        new scope.Array(),
        OriginalWorker,
      ) as HookedWorker;
      self[internal] = new scope.Object() as WorkerInternal;
      self[internal].onmessage = null;
      self[internal].messages = [];
      data.then((firstParty) => {
        // Initialize the actual Worker instance and relay messages
        args[0] = `${args[0]}#${firstParty}`;
        self[internal].instance = new OriginalWorker(...args);
        self[internal].instance.onmessage = self[internal].onmessage;
        self[internal].messages.forEach((args) => {
          self[internal].instance?.postMessage(...args);
        });
      });
      return self;
    }
    exportFunction(HookedWorker, unwrappedScope, { defineAs: "Worker" });
    OriginalWorker.prototype.constructor = unwrappedScope.Worker;
    unwrappedScope.Worker.prototype = OriginalWorker.prototype;

    // Hook Worker.onmessage
    const { get: originalGetOnmessage, set: originalSetOnmessage } =
      Object.getOwnPropertyDescriptor(
        OriginalWorker.prototype,
        "onmessage",
      ) as PropertyDescriptor;
    function hookedGetOnmessage(this: HookedWorker) {
      const unwrappedThis = this.wrappedJSObject || this;
      if (internal in unwrappedThis) {
        if (unwrappedThis[internal].instance) {
          return originalGetOnmessage?.call(unwrappedThis[internal].instance);
        }
        return unwrappedThis[internal].onmessage;
      }
      return originalGetOnmessage?.call(this);
    }
    function hookedSetOnmessage(this: HookedWorker, v: MessageListener | null) {
      const unwrappedThis = this.wrappedJSObject || this;
      if (internal in unwrappedThis) {
        if (unwrappedThis[internal].instance) {
          originalSetOnmessage?.call(unwrappedThis[internal].instance, v);
        } else {
          unwrappedThis[internal].onmessage = v;
        }
      } else {
        originalSetOnmessage?.call(this, v);
      }
    }
    Object.defineProperty(OriginalWorker.prototype, "onmessage", {
      get: exportFunction(hookedGetOnmessage, unwrappedScope) as () => unknown,
      set: exportFunction(hookedSetOnmessage, unwrappedScope) as (
        v: unknown,
      ) => void,
    });

    // Hook Worker.postMessage
    const originalPostMessage = OriginalWorker.prototype.postMessage;
    function hookedPostMessage(
      this: HookedWorker,
      ...args: [message: unknown, options?: StructuredSerializeOptions]
    ) {
      const unwrappedThis = this.wrappedJSObject || this;
      if (internal in unwrappedThis) {
        if (unwrappedThis[internal].instance) {
          originalPostMessage.call(unwrappedThis[internal].instance, ...args);
        } else {
          let options = args[1];
          if (options && scope.Symbol.iterator in options) {
            const transfer = options as Transferable[];
            options = new scope.Object();
            options.transfer = transfer;
          }
          args[0] = scope.structuredClone(args[0], options);
          unwrappedThis[internal].messages.push(args);
        }
      } else {
        originalPostMessage.call(this, ...args);
      }
    }
    exportFunction(hookedPostMessage, OriginalWorker.prototype, {
      defineAs: "postMessage",
    });

    // TODO: hook onerror, onmessageerror, addEventListener, removeEventListener, dispatchEvent, and terminate
  },
  {
    key: "WORKER_FIRST_PARTY",
    data: "__WORKER_FIRST_PARTY_PLACEHOLDER__",
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
 * Hooks WorkerGlobalScope.location to hide parts of
 * the URL hash injected by sharedWorkerHook.
 */
export function workerLocationHook({ unwrappedScope }: HookInputs<void>) {
  if (
    !("SharedWorkerGlobalScope" in unwrappedScope) &&
    !("DedicatedWorkerGlobalScope" in unwrappedScope)
  ) {
    // Not in a SharedWorker or a Worker; nothing to do
    return;
  }

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
