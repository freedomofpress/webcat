// This file is to be compiled, minified and embedded as a string to be
// dynamically updated with ALLOWED_HASHES and injected into scripts
// by response.ts

import { SHA256 } from "./sha256";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
  function exportFunction<T extends Function>(
    func: T,
    targetScope: object,
    options?: { defineAs?: string },
  ): T;
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace XPCNativeWrapper {
    function unwrap<T>(obj: T): T;
  }
}

type HookConfig<T> = {
  key: string;
  data: T | string;
};

type LocalScope<T> = Record<string, { data: T; ready: Promise<void> }>;

const hooked = Symbol("WEBCAT");
const global = globalThis.self || globalThis;
const isolated = typeof globalThis.exportFunction === "function";

function unwrap<T>(object: T) {
  if (isolated) {
    return XPCNativeWrapper.unwrap(object);
  }
  return object;
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
function exportFunc<T extends Function>(
  func: T,
  object: object = global,
  prop: string | undefined = undefined,
) {
  if (isolated) {
    const options = {} as { defineAs?: string };
    if (prop !== undefined) {
      options.defineAs = prop;
    }
    return exportFunction(func, XPCNativeWrapper.unwrap(object), options);
  } else if (prop !== undefined) {
    (object as { [prop]: T })[prop] = func;
  }
  return func;
}

// Map.prototype.getOrInsert is not yet available in Firefox ESR & TBB
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map/getOrInsert
function getOrInsert<M extends Map<K, V>, K, V>(
  map: M,
  key: K,
  defaultValue: V,
) {
  if (map.has(key)) {
    return map.get(key) as V;
  }
  map.set(key, defaultValue);
  return defaultValue;
}

function updatableHook<T>(
  hook: (data: Promise<T>, config: HookConfig<T>, scope: LocalScope<T>) => void,
  config: HookConfig<T>,
) {
  return function (scopeObject: object) {
    const scope = scopeObject as LocalScope<T>;
    let data = config.data;

    // Check if the hook has already been injected.
    if (config.key in scope) {
      console.log(`[WEBCAT] Hook already injected: ${config.key}`);
      scope[config.key].data = data as T; // update data
      return;
    }

    // Allow updating data through localScope
    const { promise: ready, resolve } = global.Promise.withResolvers<void>();
    scope[config.key] = { ready, data: data as T };
    Object.defineProperty(scope[config.key], "data", {
      set: (v) => {
        data = v;
        resolve();
      },
      get: () => data,
    });
    if (data !== `__${config.key}_PLACEHOLDER__`) {
      scope[config.key].data = data as T;
    }

    hook(
      ready.then(() => data as T),
      config,
      scope,
    );
  };
}

/**
 * Hooks the WebAssembly object to hash source bytes
 * and check the hash against a list of allowed hashes.
 */
export const wasmHook = updatableHook<string[]>(
  function (data, { key }, scope) {
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
      if (!scope[key].data.includes(hashHex)) {
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
  { key: "ALLOWED_HASHES", data: "__ALLOWED_HASHES_PLACEHOLDER__" },
);

/**
 * Hooks the SharedWorker API to expose information about the first-party
 * origin to the webRequest API.
 */
export const sharedWorkerHook = updatableHook<string>(
  function (data) {
    if (!global.SharedWorker) {
      return;
    }

    type EventListenerArgs = [
      type: string,
      callback: EventListenerOrEventListenerObject,
      options: AddEventListenerOptions | boolean,
    ];
    type EventListenerArgsByKind = {
      nonCapturingArgs?: EventListenerArgs;
      capturingArgs?: EventListenerArgs;
    };
    type SharedWorkerInternal = {
      instance: SharedWorker & { [hooked]?: HookedSharedWorker };
      port: MessagePort;
      relay: MessagePort;
      onerror: ((e: Event) => unknown) | null;
      listeners: Map<
        string,
        Map<EventListenerOrEventListenerObject, EventListenerArgsByKind>
      >;
    };
    const internal = Symbol("WEBCAT");
    type HookedSharedWorker = SharedWorker & {
      [internal]: SharedWorkerInternal;
    };

    function bindEventListenerArgs(
      thisArg: HookedSharedWorker,
      args: EventListenerArgs,
    ) {
      const callback = unwrap(args[1]);
      args = Array.from(args) as EventListenerArgs;
      if (typeof callback === "function") {
        args[1] = callback.bind(thisArg);
      } else {
        args[1] = exportFunc(
          (...args: [event: Event]) =>
            callback.handleEvent?.call(thisArg, ...args),
          global,
        ) as EventListener;
      }
      return args;
    }

    // Hook the SharedWorker constructor
    const OriginalSharedWorker = unwrap(global.SharedWorker);
    function HookedSharedWorker(
      this: object,
      ...args: [url: string | URL, options?: string | WorkerOptions]
    ) {
      if (!(this instanceof HookedSharedWorker)) {
        throw new global.TypeError(
          "SharedWorker constructor: 'new' is required",
        );
      }
      if ((args.length as number) === 0) {
        throw new global.TypeError(
          "SharedWorker constructor: At least 1 argument required, but only 0 passed",
        );
      }
      const self = unwrap(global.Object).create(
        OriginalSharedWorker.prototype,
      ) as HookedSharedWorker;
      const channel = new global.MessageChannel();
      self[internal] = new global.Object() as SharedWorkerInternal;
      self[internal].port = channel.port1;
      self[internal].relay = channel.port2;
      self[internal].onerror = null;
      self[internal].listeners = new Map();
      data.then((firstParty) => {
        // Initialize the actual SharedWorker instance and relay messages
        // TODO: relay messageerror events
        args[0] = `${args[0]}#${firstParty}`;
        self[internal].instance = new OriginalSharedWorker(...args);
        self[internal].instance[hooked] = self;
        self[internal].instance.port.onmessage = exportFunc(
          (e: MessageEvent<unknown>) => {
            self[internal].relay.postMessage(e.data);
          },
          global,
        ) as typeof MessagePort.prototype.onmessage;
        self[internal].relay.onmessage = exportFunc(
          (e: MessageEvent<unknown>) => {
            self[internal].instance.port.postMessage(e.data);
          },
          global,
        ) as typeof MessagePort.prototype.onmessage;
        self[internal].instance.onerror =
          self[internal].onerror?.bind(self) || null;
        for (const listeners of self[internal].listeners.values()) {
          for (const {
            nonCapturingArgs,
            capturingArgs,
          } of listeners.values()) {
            if (nonCapturingArgs) {
              self[internal].instance.addEventListener(...nonCapturingArgs);
            }
            if (capturingArgs) {
              self[internal].instance.addEventListener(...capturingArgs);
            }
          }
        }
      });
      return self;
    }
    exportFunc(HookedSharedWorker, global, "SharedWorker");
    OriginalSharedWorker.prototype.constructor = unwrap(global.SharedWorker);
    unwrap(global).SharedWorker.prototype = OriginalSharedWorker.prototype;

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
      get: exportFunc(hookedPort, global) as () => unknown,
    });

    // Hook SharedWorker.onerror
    const { get: originalGetOnerror, set: originalSetOnerror } =
      Object.getOwnPropertyDescriptor(
        OriginalSharedWorker.prototype,
        "onerror",
      ) as PropertyDescriptor;
    function hookedGetOnerror(this: HookedSharedWorker) {
      if (internal in unwrap(this)) {
        return unwrap(this)[internal].onerror;
      }
      return originalGetOnerror?.call(this);
    }
    function hookedSetOnerror(
      this: HookedSharedWorker,
      v: OnErrorEventHandler,
    ) {
      if (internal in unwrap(this)) {
        unwrap(this)[internal].onerror = v;
        if (unwrap(this)[internal].instance) {
          unwrap(this)[internal].instance.onerror =
            v?.bind(unwrap(this)) || null;
        }
      } else {
        originalSetOnerror?.call(this, v);
      }
    }
    Object.defineProperty(OriginalSharedWorker.prototype, "onerror", {
      get: exportFunc(hookedGetOnerror, global) as () => unknown,
      set: exportFunc(hookedSetOnerror, global) as (v: unknown) => void,
    });

    // Hook SharedWorker.addEventListener
    const { value: originalAddEventListener } = Object.getOwnPropertyDescriptor(
      unwrap(global.EventTarget.prototype),
      "addEventListener",
    ) as PropertyDescriptor;
    function hookedAddEventListener(
      this: HookedSharedWorker,
      ...args: EventListenerArgs
    ) {
      const [type, callback, options] = args;
      if (internal in unwrap(this)) {
        const listeners = getOrInsert(
          getOrInsert(unwrap(this)[internal].listeners, type, new Map()),
          callback,
          {} as EventListenerArgsByKind,
        );
        const useCapture =
          options instanceof window.Object
            ? !!unwrap(options).capture
            : !!unwrap(options);
        const kind = useCapture ? "capturingArgs" : "nonCapturingArgs";
        if (!listeners[kind]) {
          // Listener doesn't exist; bind args and memorize
          const boundArgs = bindEventListenerArgs(unwrap(this), args);
          listeners[kind] = boundArgs;
          if (unwrap(this)[internal].instance) {
            // Instance exists, add the listener for real
            unwrap(this)[internal].instance.addEventListener(...boundArgs);
          }
        }
      } else {
        originalAddEventListener.call(this, ...args);
      }
    }
    Object.defineProperty(
      unwrap(global.EventTarget.prototype),
      "addEventListener",
      {
        value: exportFunc(hookedAddEventListener, global),
      },
    );

    // Hook SharedWorker.removeEventListener
    const { value: originalRemoveEventListener } =
      Object.getOwnPropertyDescriptor(
        unwrap(global.EventTarget.prototype),
        "removeEventListener",
      ) as PropertyDescriptor;
    function hookedRemoveEventListener(
      this: HookedSharedWorker,
      ...args: EventListenerArgs
    ) {
      const [type, callback, options] = args;
      if (internal in unwrap(this)) {
        const listeners = getOrInsert(
          getOrInsert(unwrap(this)[internal].listeners, type, new Map()),
          callback,
          {} as EventListenerArgsByKind,
        );
        const useCapture =
          options instanceof window.Object
            ? !!unwrap(options).capture
            : !!unwrap(options);
        const kind = useCapture ? "capturingArgs" : "nonCapturingArgs";
        if (listeners[kind]) {
          // Listener exists; remove
          if (unwrap(this)[internal].instance) {
            // Instance exists, remove for real
            unwrap(this)[internal].instance.removeEventListener(
              ...listeners[kind],
            );
          }
          delete listeners[kind];
        }
      } else {
        originalRemoveEventListener.call(this, ...args);
      }
    }
    Object.defineProperty(
      unwrap(global.EventTarget.prototype),
      "removeEventListener",
      {
        value: exportFunc(hookedRemoveEventListener, global),
      },
    );

    // TODO: Hook dispatchEvent
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
  function (_, { data }) {
    if (typeof data === "string") {
      // data is the placeholder, so we're in a frame
      try {
        Object.hasOwn(global.top || {}, "name");
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
    delete unwrap(
      (global.Navigator || global.WorkerNavigator || global.Object)
        .prototype as unknown as Record<string, unknown>,
    ).serviceWorker;
    delete unwrap(global as unknown as Record<string, unknown>).ServiceWorker;
    delete unwrap(global as unknown as Record<string, unknown>)
      .ServiceWorkerContainer;
    delete unwrap(global as unknown as Record<string, unknown>)
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
  function (data) {
    if (!global.SharedWorker) {
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
    };

    // Hook the Worker constructor
    const OriginalWorker = unwrap(global.Worker);
    const EventTarget = unwrap(global.EventTarget);
    const construct = unwrap(global.Reflect).construct.bind(
      unwrap(global.Reflect),
    );
    function HookedWorker(
      this: object,
      ...args: [scriptUrl: string | URL, options?: WorkerOptions]
    ) {
      if (!(this instanceof HookedWorker)) {
        throw new TypeError("Worker constructor: 'new' is required");
      }
      if ((args.length as number) === 0) {
        throw new global.TypeError(
          "Worker constructor: At least 1 argument required, but only 0 passed",
        );
      }
      const self = construct(
        EventTarget,
        new global.Array(),
        OriginalWorker,
      ) as HookedWorker;
      self[internal] = new global.Object() as WorkerInternal;
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
    exportFunc(HookedWorker, global, "Worker");
    OriginalWorker.prototype.constructor = unwrap(global.Worker);
    unwrap(global).Worker.prototype = OriginalWorker.prototype;

    // Hook Worker.onmessage
    const { get: originalGetOnmessage, set: originalSetOnmessage } =
      Object.getOwnPropertyDescriptor(
        OriginalWorker.prototype,
        "onmessage",
      ) as PropertyDescriptor;
    function hookedGetOnmessage(this: HookedWorker) {
      if (internal in unwrap(this)) {
        if (unwrap(this)[internal].instance) {
          return originalGetOnmessage?.call(unwrap(this)[internal].instance);
        }
        return unwrap(this)[internal].onmessage;
      }
      return originalGetOnmessage?.call(this);
    }
    function hookedSetOnmessage(this: HookedWorker, v: MessageListener | null) {
      if (internal in unwrap(this)) {
        if (unwrap(this)[internal].instance) {
          originalSetOnmessage?.call(unwrap(this)[internal].instance, v);
        } else {
          unwrap(this)[internal].onmessage = v;
        }
      } else {
        originalSetOnmessage?.call(this, v);
      }
    }
    Object.defineProperty(OriginalWorker.prototype, "onmessage", {
      get: exportFunc(hookedGetOnmessage, global) as () => unknown,
      set: exportFunc(hookedSetOnmessage, global) as (v: unknown) => void,
    });

    // Hook Worker.postMessage
    const originalPostMessage = OriginalWorker.prototype.postMessage;
    function hookedPostMessage(
      this: HookedWorker,
      ...args: [message: unknown, options?: StructuredSerializeOptions]
    ) {
      if (internal in unwrap(this)) {
        if (unwrap(this)[internal].instance) {
          originalPostMessage.call(unwrap(this)[internal].instance, ...args);
        } else {
          let options = args[1];
          if (options && global.Symbol.iterator in options) {
            const transfer = options as Transferable[];
            options = new global.Object();
            options.transfer = transfer;
          }
          args[0] = global.structuredClone(args[0], options);
          unwrap(this)[internal].messages.push(args);
        }
      } else {
        originalPostMessage.call(this, ...args);
      }
    }
    exportFunc(hookedPostMessage, OriginalWorker.prototype, "postMessage");

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
 * Hooks the Event prototype to return hooked targets
 */
export const eventHook = updatableHook<void>(
  function () {
    for (const prop of [
      "target",
      "currentTarget",
      "originalTarget",
      "explicitOriginalTarget",
      "srcElement",
    ]) {
      const { get: originalGet } = Object.getOwnPropertyDescriptor(
        unwrap(global.Event.prototype),
        prop,
      ) as PropertyDescriptor;
      function hookedGet(this: Event) {
        const val = unwrap(originalGet?.call(this));
        return val?.[hooked] || val;
      }
      Object.defineProperty(unwrap(global.Event.prototype), prop, {
        get: exportFunc(hookedGet, global) as () => unknown,
      });
    }
  },
  {
    key: "EVENT",
    data: undefined,
  },
);
