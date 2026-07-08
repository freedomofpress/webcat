import {
  exportFunc,
  global,
  Hooked,
  hooked,
  Internal,
  internal,
  unwrap,
  updatableHook,
} from "./core";
import { hookEventProperty } from "./events";

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

/**
 * Hooks the SharedWorker API to expose information about the first-party
 * origin to the webRequest API.
 */
export const sharedWorkerHook = updatableHook(
  "SharedWorker",
  function (data: Promise<{ firstParty: string }>) {
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
    type SharedWorkerInternal = Internal<SharedWorker> & {
      port: MessagePort;
      relay: MessagePort;
      onerror: ((e: Event) => unknown) | null;
      listeners: Map<
        string,
        Map<EventListenerOrEventListenerObject, EventListenerArgsByKind>
      >;
    };

    function bindEventListenerArgs(
      thisArg: Hooked<SharedWorker, SharedWorkerInternal>,
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
      ) as Hooked<SharedWorker, SharedWorkerInternal>;
      const channel = new global.MessageChannel();
      self[internal] = new global.Object() as SharedWorkerInternal;
      self[internal].port = channel.port1;
      self[internal].relay = channel.port2;
      self[internal].onerror = null;
      self[internal].listeners = new Map();
      data.then(({ firstParty }) => {
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
    function hookedPort(this: Hooked<SharedWorker, SharedWorkerInternal>) {
      if (internal in this) {
        return this[internal].port;
      }
      return originalPort?.apply(this);
    }
    Object.defineProperty(OriginalSharedWorker.prototype, "port", {
      get: exportFunc(hookedPort, global) as () => unknown,
    });

    // Hook SharedWorker.onerror
    hookEventProperty(OriginalSharedWorker.prototype, "onerror");

    // Hook SharedWorker.addEventListener
    const { value: originalAddEventListener } = Object.getOwnPropertyDescriptor(
      unwrap(global.EventTarget.prototype),
      "addEventListener",
    ) as PropertyDescriptor;
    function hookedAddEventListener(
      this: Hooked<SharedWorker, SharedWorkerInternal>,
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
      this: Hooked<SharedWorker, SharedWorkerInternal>,
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

    // Hook SharedWorker.dispatchEvent
    const { value: originalDispatchEvent } = Object.getOwnPropertyDescriptor(
      unwrap(global.EventTarget.prototype),
      "dispatchEvent",
    ) as PropertyDescriptor;
    function hookedDispatchEvent(
      this: Hooked<SharedWorker, SharedWorkerInternal>,
      ...args: [event: Event]
    ) {
      if (internal in unwrap(this)) {
        if (unwrap(this)[internal].instance) {
          return unwrap(this)[internal].instance.dispatchEvent(...args);
        }
        // TODO: handle synchronous case
        return true;
      }
      return originalDispatchEvent.call(this, ...args);
    }
    Object.defineProperty(
      unwrap(global.EventTarget.prototype),
      "dispatchEvent",
      {
        value: exportFunc(hookedDispatchEvent, global),
      },
    );
  },
);

declare global {
  var WorkerNavigator: typeof Navigator;
}

/**
 * Disables the ServiceWorker API when not in a first-party origin.
 */
export const serviceWorkerHook = updatableHook(
  "ServiceWorker",
  function (
    _: Promise<{ sameOriginWithFirstParty: boolean }>,
    { data }: { data: { sameOriginWithFirstParty: boolean } },
  ) {
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
);

/**
 * Hooks the Worker API as a workaround to
 * https://bugzilla.mozilla.org/show_bug.cgi?id=2048884
 */
export const workerHook = updatableHook(
  "Worker",
  function (data: Promise<{ firstParty: string }>) {
    if (!global.SharedWorker) {
      return;
    }

    type MessageListener = (this: Worker, ev: MessageEvent<unknown>) => unknown;
    type WorkerInternal = Internal<Worker> & {
      onmessage: MessageListener | null;
      messages: [message: unknown, options?: StructuredSerializeOptions][];
      onerror: ((e: Event) => unknown) | null;
      terminated?: boolean;
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
      ) as Hooked<Worker, WorkerInternal>;
      self[internal] = new global.Object() as WorkerInternal;
      self[internal].onmessage = null;
      self[internal].messages = [];
      self[internal].onerror = null;
      data.then(({ firstParty }) => {
        // Initialize the actual Worker instance and relay messages
        args[0] = `${args[0]}#${firstParty}`;
        self[internal].instance = new OriginalWorker(...args);
        self[internal].instance[hooked] = self;
        if (self[internal].terminated) {
          self[internal].instance.terminate();
        }
        self[internal].instance.onmessage = self[internal].onmessage;
        self[internal].messages.forEach((args) => {
          self[internal].instance?.postMessage(...args);
        });
        self[internal].instance.onerror =
          self[internal].onerror?.bind(self) || null;
      });
      return self;
    }
    exportFunc(HookedWorker, global, "Worker");
    OriginalWorker.prototype.constructor = unwrap(global.Worker);
    unwrap(global).Worker.prototype = OriginalWorker.prototype;

    // Hook Worker.postMessage
    const originalPostMessage = OriginalWorker.prototype.postMessage;
    function hookedPostMessage(
      this: Hooked<Worker, WorkerInternal>,
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

    // Hook Worker.terminate
    const originalTerminate = OriginalWorker.prototype.terminate;
    function hookedTerminate(this: Hooked<Worker, WorkerInternal>) {
      if (internal in unwrap(this)) {
        if (unwrap(this)[internal].instance) {
          originalTerminate.call(unwrap(this)[internal].instance);
        } else {
          unwrap(this)[internal].terminated = true;
        }
      } else {
        originalTerminate.call(this);
      }
    }
    exportFunc(hookedTerminate, OriginalWorker.prototype, "terminate");

    // Hook Worker.onmessage, Worker.onerror, and Worker.onmessageerror
    hookEventProperty(OriginalWorker.prototype, "onmessage");
    hookEventProperty(OriginalWorker.prototype, "onerror");
    hookEventProperty(OriginalWorker.prototype, "onmessageerror");

    // TODO: hook addEventListener, removeEventListener, dispatchEvent
  },
);
